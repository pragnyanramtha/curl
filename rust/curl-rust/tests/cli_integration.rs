use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, UdpSocket};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use tempfile::{TempDir, tempdir, tempdir_in};
use url::Url;

const DICT_GREETING: &[u8] = b"220 dictserver <xnooptions> <msgid@msgid>\n";
const IPFS_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\nHello curl from IPFS\n";
const IPFS_CID: &str = "bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u";
const TELNET_IAC: u8 = 255;
const TELNET_DONT: u8 = 254;
const TELNET_DO: u8 = 253;
const TELNET_WONT: u8 = 252;
const TELNET_WILL: u8 = 251;
const TELNET_NEW_ENVIRON: u8 = 39;
const TELNET_NAWS: u8 = 31;
const TEST_SMB_COM_CLOSE: u8 = 0x04;
const TEST_SMB_COM_READ_ANDX: u8 = 0x2e;
const TEST_SMB_COM_TREE_DISCONNECT: u8 = 0x71;
const TEST_SMB_COM_NEGOTIATE: u8 = 0x72;
const TEST_SMB_COM_SETUP_ANDX: u8 = 0x73;
const TEST_SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
const TEST_SMB_COM_NT_CREATE_ANDX: u8 = 0xa2;
const TEST_SMB_ERR_NOACCESS: u32 = 0x0005_0001;
const COMPRESSED_BODY: &[u8] = b"hello compressed\n";
const GZIP_COMPRESSED_BODY: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57,
    0x48, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d, 0x2e, 0x4e, 0x4d, 0xe1, 0x02, 0x00, 0x7b, 0x43, 0x9b,
    0x2c, 0x11, 0x00, 0x00, 0x00,
];
const DEFLATE_COMPRESSED_BODY: &[u8] = &[
    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x48, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d, 0x2e,
    0x4e, 0x4d, 0xe1, 0x02, 0x00, 0x3c, 0x1c, 0x06, 0x74,
];
const RAW_DEFLATE_COMPRESSED_BODY: &[u8] = &[
    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x48, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d, 0x2e, 0x4e, 0x4d,
    0xe1, 0x02, 0x00,
];
const BROTLI_COMPRESSED_BODY: &[u8] = &[
    0x0f, 0x08, 0x80, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73,
    0x73, 0x65, 0x64, 0x0a, 0x03,
];
const TELNET_NEGOTIATION_GREETING: &[u8] = &[
    TELNET_IAC,
    TELNET_DO,
    TELNET_NEW_ENVIRON,
    TELNET_IAC,
    TELNET_WILL,
    TELNET_NEW_ENVIRON,
    TELNET_IAC,
    TELNET_DONT,
    TELNET_NAWS,
    TELNET_IAC,
    TELNET_WONT,
    TELNET_NAWS,
];

#[derive(Debug)]
struct RequestRecord {
    start_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct SmtpRecord {
    commands: Vec<u8>,
    upload: Vec<u8>,
}

#[derive(Debug)]
struct TftpRecord {
    request: Vec<u8>,
    peer: SocketAddr,
    acknowledgements: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct TftpUploadRecord {
    request: Vec<u8>,
    data_blocks: Vec<(u16, Vec<u8>)>,
}

#[derive(Debug)]
struct TftpSequenceRecord {
    requests: Vec<Vec<u8>>,
    acknowledgements: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct FtpRecord {
    commands: Vec<u8>,
    data_connections: usize,
    upload: Vec<u8>,
}

#[derive(Debug)]
struct WsRecord {
    request: RequestRecord,
    frames: Vec<(u8, Vec<u8>)>,
}

#[derive(Debug)]
struct LdapRecord {
    bind: Vec<u8>,
    search: Vec<u8>,
    unbind: Vec<u8>,
}

#[derive(Debug)]
struct SmbRecord {
    packets: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct SmbFixture {
    body: Vec<u8>,
    tree_status: u32,
    open_status: u32,
    malformed_read: bool,
}

struct DualFamilyServer {
    target: String,
    resolve: String,
    rx: Receiver<(String, RequestRecord)>,
}

struct SshdFixture {
    _temp: TempDir,
    child: Child,
    port: u16,
    root: PathBuf,
    private_key: PathBuf,
    public_key: PathBuf,
    bad_private_key: PathBuf,
    known_hosts: PathBuf,
    user: String,
}

impl SshdFixture {
    fn new() -> Option<Self> {
        let sshd = Path::new("/usr/sbin/sshd");
        let sftp_server = Path::new("/usr/lib/openssh/sftp-server");
        if !sshd.is_file() || !sftp_server.is_file() {
            return None;
        }

        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("data.txt"), "ssh fixture body\n").unwrap();
        let directory = root.join("dir");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("alpha.txt"), "alpha").unwrap();
        std::fs::write(directory.join("beta.txt"), "beta").unwrap();

        let host_key = temp.path().join("host_ed25519");
        let private_key = temp.path().join("client_ed25519");
        let bad_private_key = temp.path().join("bad_ed25519");
        generate_ssh_key(&host_key);
        generate_ssh_key(&private_key);
        generate_ssh_key(&bad_private_key);

        let public_key = private_key.with_extension("pub");
        let authorized_keys = temp.path().join("authorized_keys");
        std::fs::copy(&public_key, &authorized_keys).unwrap();
        set_private_file_mode(&authorized_keys);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let known_hosts = temp.path().join("known_hosts");
        write_known_hosts(&known_hosts, port, &host_key.with_extension("pub"));

        let config = temp.path().join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "Port {port}\n\
                 ListenAddress 127.0.0.1\n\
                 HostKey {}\n\
                 PidFile {}\n\
                 AuthorizedKeysFile {}\n\
                 PasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\n\
                 ChallengeResponseAuthentication no\n\
                 PubkeyAuthentication yes\n\
                 StrictModes no\n\
                 UsePAM no\n\
                 PermitRootLogin yes\n\
                 LogLevel ERROR\n\
                 Subsystem sftp {}\n",
                host_key.display(),
                temp.path().join("sshd.pid").display(),
                authorized_keys.display(),
                sftp_server.display()
            ),
        )
        .unwrap();

        let mut child = StdCommand::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_sshd(port, &mut child);

        Some(Self {
            _temp: temp,
            child,
            port,
            root,
            private_key,
            public_key,
            bad_private_key,
            known_hosts,
            user: std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "ubuntu".to_string()),
        })
    }

    fn url_for(&self, scheme: &str, path: &Path) -> String {
        format!(
            "{scheme}://127.0.0.1:{}{}",
            self.port,
            path.to_str().unwrap()
        )
    }

    fn auth_args(&self) -> Vec<String> {
        vec![
            "--knownhosts".to_string(),
            self.known_hosts.display().to_string(),
            "--key".to_string(),
            self.private_key.display().to_string(),
            "--pubkey".to_string(),
            self.public_key.display().to_string(),
            "--user".to_string(),
            self.user.clone(),
        ]
    }
}

impl Drop for SshdFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
struct FtpServerOptions {
    greeting: &'static [u8],
    data: Vec<u8>,
    epsv_fails: bool,
    epsv_bad_port: bool,
    pasv_denied: bool,
    pasv_reply: Option<&'static [u8]>,
    pasv_host: [u8; 4],
    login_denied: bool,
    pwd_denied: bool,
    cwd_denied: bool,
    missing_directories: Vec<&'static str>,
    mkd_denied: bool,
    type_denied: bool,
    rest_denied: bool,
    retr_denied: bool,
    stor_denied: bool,
    stor_final: &'static [u8],
    size: Option<u64>,
    mdtm: Option<&'static str>,
}

#[derive(Debug)]
struct MqttRecord {
    connect: Vec<u8>,
    subscribe: Option<Vec<u8>>,
    publish: Option<Vec<u8>>,
    disconnect: Option<Vec<u8>>,
}

fn spawn_server(response: &'static [u8]) -> (String, Receiver<RequestRecord>) {
    spawn_sequence_server(vec![response])
}

fn spawn_server_bytes(response: Vec<u8>) -> (String, Receiver<RequestRecord>) {
    spawn_sequence_server_bytes(vec![response])
}

fn spawn_cross_origin_redirect(
    final_response: &'static [u8],
) -> (String, Receiver<RequestRecord>, Receiver<RequestRecord>) {
    let (target_url, target_rx) = spawn_server(final_response);
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (start_url, start_rx) = spawn_sequence_server_bytes(vec![redirect]);
    (start_url, start_rx, target_rx)
}

fn gateway_origin(url: &str) -> String {
    let url = Url::parse(url).unwrap();
    let host = url.host_str().unwrap();
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{host}{port}", url.scheme())
}

fn generate_ssh_key(path: &Path) {
    let status = StdCommand::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    set_private_file_mode(path);
}

fn write_known_hosts(path: &Path, port: u16, host_public_key: &Path) {
    let public = std::fs::read_to_string(host_public_key).unwrap();
    let mut fields = public.split_whitespace();
    let key_type = fields.next().unwrap();
    let key = fields.next().unwrap();
    std::fs::write(path, format!("[127.0.0.1]:{port} {key_type} {key}\n")).unwrap();
}

fn wait_for_sshd(port: u16, child: &mut Child) {
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("sshd exited before accepting connections: {status}");
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("sshd did not start on port {port}");
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) {}

fn spawn_sequence_server(responses: Vec<&'static [u8]>) -> (String, Receiver<RequestRecord>) {
    spawn_sequence_server_bytes(responses.into_iter().map(Vec::from).collect())
}

fn spawn_sequence_server_bytes(responses: Vec<Vec<u8>>) -> (String, Receiver<RequestRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            tx.send(read_request(&mut stream)).unwrap();
            stream.write_all(&response).unwrap();
        }
    });

    (format!("http://{addr}/resource"), rx)
}

fn spawn_request_target_https_redirect_server() -> (String, Receiver<RequestRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        tx.send(read_request(&mut stream)).unwrap();
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: https://{addr}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();

        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    tx.send(read_request(&mut stream)).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad",
                        )
                        .unwrap();
                    break;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    (format!("http://{addr}/resource"), rx)
}

fn spawn_request_target_chunked_redirect_server() -> (String, Receiver<RequestRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        tx.send(read_request(&mut first)).unwrap();
        first
            .write_all(
                b"HTTP/1.1 302 Found\r\nLocation: /next\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
            )
            .unwrap();

        let (mut second, _) = listener.accept().unwrap();
        tx.send(read_request(&mut second)).unwrap();
        second
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        let _ = first.shutdown(Shutdown::Both);
    });

    (format!("http://{addr}/resource"), rx)
}

fn spawn_dual_family_server() -> Option<DualFamilyServer> {
    let ipv6 = TcpListener::bind("[::1]:0").ok()?;
    let port = ipv6.local_addr().ok()?.port();
    let ipv4 = TcpListener::bind(("127.0.0.1", port)).ok()?;
    let (tx, rx) = mpsc::channel();

    for (family, listener, response) in [
        (
            "v4",
            ipv4,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nv4" as &'static [u8],
        ),
        (
            "v6",
            ipv6,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nv6" as &'static [u8],
        ),
    ] {
        let tx = tx.clone();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            stream.write_all(response).unwrap();
            tx.send((family.to_string(), request)).unwrap();
        });
    }
    drop(tx);

    Some(DualFamilyServer {
        target: format!("http://example.test:{port}/resource"),
        resolve: format!("example.test:{port}:[::1],127.0.0.1"),
        rx,
    })
}

fn spawn_dict_server(response: &'static [u8]) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(DICT_GREETING).unwrap();

        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];

        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.ends_with(b"QUIT\r\n") {
                break;
            }
        }

        tx.send(bytes).unwrap();
        let _ = stream.write_all(response);
    });

    (format!("dict://{addr}/d:basic"), rx)
}

fn ftp_options(data: impl Into<Vec<u8>>) -> FtpServerOptions {
    let data = data.into();
    let size = Some(data.len() as u64);
    FtpServerOptions {
        greeting: b"220 curl FTP test server\r\n",
        data,
        epsv_fails: false,
        epsv_bad_port: false,
        pasv_denied: false,
        pasv_reply: None,
        pasv_host: [127, 0, 0, 1],
        login_denied: false,
        pwd_denied: false,
        cwd_denied: false,
        missing_directories: Vec::new(),
        mkd_denied: false,
        type_denied: false,
        rest_denied: false,
        retr_denied: false,
        stor_denied: false,
        stor_final: b"226 Transfer complete\r\n",
        size,
        mdtm: Some("20030409102659"),
    }
}

fn spawn_ftp_server(path: &str, options: FtpServerOptions) -> (String, Receiver<FtpRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    spawn_ftp_server_with_listener(path, options, listener)
}

fn spawn_ftp_server_ipv6(
    path: &str,
    options: FtpServerOptions,
) -> Option<(String, Receiver<FtpRecord>)> {
    let listener = TcpListener::bind("[::1]:0").ok()?;
    Some(spawn_ftp_server_with_listener(path, options, listener))
}

fn spawn_ftp_server_with_listener(
    path: &str,
    options: FtpServerOptions,
    listener: TcpListener,
) -> (String, Receiver<FtpRecord>) {
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let control_is_ipv6 = stream.local_addr().unwrap().is_ipv6();
        stream.write_all(options.greeting).unwrap();

        let mut commands = Vec::new();
        let mut upload = Vec::new();
        let mut data_connections = 0_usize;
        let mut passive_listener: Option<TcpListener> = None;
        let mut restart_offset = 0_usize;
        let mut created_directories: Vec<String> = Vec::new();

        while let Some(line) = read_pop3_client_line(&mut stream) {
            commands.extend_from_slice(&line);
            let command = String::from_utf8_lossy(&line);
            let command = command.trim_end_matches(['\r', '\n']);

            if command.starts_with("USER ") {
                if options.login_denied {
                    stream.write_all(b"530 Login incorrect\r\n").unwrap();
                    break;
                }
                stream.write_all(b"331 Password required\r\n").unwrap();
            } else if command.starts_with("PASS ") {
                stream.write_all(b"230 Login successful\r\n").unwrap();
            } else if command == "PWD" {
                if options.pwd_denied {
                    stream.write_all(b"500 PWD failed\r\n").unwrap();
                    continue;
                }
                stream
                    .write_all(b"257 \"/\" is the current directory\r\n")
                    .unwrap();
            } else if command.starts_with("CWD ") {
                let directory = command.strip_prefix("CWD ").unwrap();
                if options.cwd_denied
                    || (options.missing_directories.contains(&directory)
                        && !created_directories
                            .iter()
                            .any(|created| created.as_str() == directory))
                {
                    stream
                        .write_all(b"550 Failed to change directory\r\n")
                        .unwrap();
                    continue;
                }
                stream.write_all(b"250 Directory changed\r\n").unwrap();
            } else if let Some(directory) = command.strip_prefix("MKD ") {
                if options.mkd_denied {
                    stream
                        .write_all(b"550 Failed to create directory\r\n")
                        .unwrap();
                    continue;
                }
                created_directories.push(directory.to_string());
                stream
                    .write_all(b"257 Created your requested directory\r\n")
                    .unwrap();
            } else if command == "EPSV" {
                if options.epsv_fails {
                    stream.write_all(b"500 EPSV unsupported\r\n").unwrap();
                } else if options.epsv_bad_port {
                    let port = unused_local_port();
                    stream
                        .write_all(
                            format!("229 Entering Extended Passive Mode (|||{port}|)\r\n")
                                .as_bytes(),
                        )
                        .unwrap();
                } else {
                    let (listener, port) = ftp_passive_listener(control_is_ipv6);
                    passive_listener = Some(listener);
                    stream
                        .write_all(
                            format!("229 Entering Extended Passive Mode (|||{port}|)\r\n")
                                .as_bytes(),
                        )
                        .unwrap();
                }
            } else if command == "PASV" {
                if options.pasv_denied {
                    stream.write_all(b"500 PASV unsupported\r\n").unwrap();
                    continue;
                }
                if let Some(reply) = options.pasv_reply {
                    stream.write_all(reply).unwrap();
                    continue;
                }
                let (listener, port) = ftp_passive_listener(false);
                passive_listener = Some(listener);
                let p1 = port / 256;
                let p2 = port % 256;
                let [h1, h2, h3, h4] = options.pasv_host;
                stream
                    .write_all(
                        format!("227 Entering Passive Mode ({h1},{h2},{h3},{h4},{p1},{p2})\r\n")
                            .as_bytes(),
                    )
                    .unwrap();
            } else if command.starts_with("TYPE ") {
                if options.type_denied {
                    stream.write_all(b"500 Type failed\r\n").unwrap();
                    continue;
                }
                stream.write_all(b"200 Type set\r\n").unwrap();
            } else if command.starts_with("SIZE ") {
                if let Some(size) = options.size {
                    stream
                        .write_all(format!("213 {size}\r\n").as_bytes())
                        .unwrap();
                } else {
                    stream.write_all(b"550 SIZE failed\r\n").unwrap();
                }
            } else if command.starts_with("MDTM ") {
                if let Some(mdtm) = options.mdtm {
                    stream
                        .write_all(format!("213 {mdtm}\r\n").as_bytes())
                        .unwrap();
                } else {
                    stream.write_all(b"550 MDTM failed\r\n").unwrap();
                }
            } else if let Some(offset) = command.strip_prefix("REST ") {
                if options.rest_denied {
                    stream.write_all(b"500 REST failed\r\n").unwrap();
                    continue;
                }
                restart_offset = offset.parse::<usize>().unwrap();
                stream
                    .write_all(format!("350 Restarting at {restart_offset}\r\n").as_bytes())
                    .unwrap();
            } else if command.starts_with("RETR ") || command == "LIST" || command == "NLST" {
                if options.retr_denied {
                    stream.write_all(b"550 File unavailable\r\n").unwrap();
                    continue;
                }
                stream
                    .write_all(b"150 Opening data connection\r\n")
                    .unwrap();
                let listener = passive_listener.take().expect("passive listener");
                let (mut data_stream, _) = listener.accept().unwrap();
                let body = options.data.get(restart_offset..).unwrap_or_default();
                data_stream.write_all(body).unwrap();
                let _ = data_stream.shutdown(Shutdown::Both);
                data_connections += 1;
                restart_offset = 0;
                stream.write_all(b"226 Transfer complete\r\n").unwrap();
            } else if command.starts_with("STOR ") || command.starts_with("APPE ") {
                if options.stor_denied {
                    stream.write_all(b"550 Upload denied\r\n").unwrap();
                    continue;
                }
                stream
                    .write_all(b"150 Opening data connection\r\n")
                    .unwrap();
                let listener = passive_listener.take().expect("passive listener");
                let (mut data_stream, _) = listener.accept().unwrap();
                data_stream.read_to_end(&mut upload).unwrap();
                data_connections += 1;
                stream.write_all(options.stor_final).unwrap();
            } else if command.starts_with("NOOP") {
                stream.write_all(b"200 NOOP ok\r\n").unwrap();
            } else if command.starts_with("DELE ") {
                stream.write_all(b"250 File deleted\r\n").unwrap();
            } else if command.starts_with("RNFR ") {
                stream.write_all(b"350 Ready for RNTO\r\n").unwrap();
            } else if command.starts_with("RNTO ") {
                stream.write_all(b"250 File renamed\r\n").unwrap();
            } else if command.starts_with("FAIL") {
                stream
                    .write_all(b"500 Requested quote failure\r\n")
                    .unwrap();
            } else if command == "QUIT" {
                let _ = stream.write_all(b"221 Bye\r\n");
                break;
            } else {
                stream.write_all(b"500 Unknown command\r\n").unwrap();
            }
        }

        tx.send(FtpRecord {
            commands,
            data_connections,
            upload,
        })
        .unwrap();
    });

    (format!("ftp://{addr}{path}"), rx)
}

fn ftp_passive_listener(ipv6: bool) -> (TcpListener, u16) {
    let addr = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
    let listener = TcpListener::bind(addr).unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn unused_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn unused_local_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn spawn_pop3_server(path: &str, command_response: &'static [u8]) -> (String, Receiver<Vec<u8>>) {
    spawn_pop3_server_with_greeting(path, b"+OK curl POP3 test server\r\n", command_response)
}

fn spawn_pop3_server_with_greeting(
    path: &str,
    greeting: &'static [u8],
    command_response: &'static [u8],
) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(greeting).unwrap();

        let mut commands = Vec::new();
        while let Some(line) = read_pop3_client_line(&mut stream) {
            commands.extend_from_slice(&line);
            let command = String::from_utf8_lossy(&line);
            let command = command.trim_end_matches(['\r', '\n']);
            let response = if command == "CAPA" {
                b"+OK capabilities\r\nUSER\r\n.\r\n".as_slice()
            } else if command.starts_with("USER ") || command.starts_with("PASS ") {
                b"+OK\r\n".as_slice()
            } else if command == "QUIT" {
                let _ = stream.write_all(b"+OK bye\r\n");
                break;
            } else {
                command_response
            };
            stream.write_all(response).unwrap();
        }

        tx.send(commands).unwrap();
    });

    (format!("pop3://{addr}{path}"), rx)
}

fn spawn_pop3_login_denied_server(path: &str) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"+OK curl POP3 test server\r\n").unwrap();
        let mut commands = Vec::new();
        while let Some(line) = read_pop3_client_line(&mut stream) {
            commands.extend_from_slice(&line);
            let command = String::from_utf8_lossy(&line);
            let command = command.trim_end_matches(['\r', '\n']);
            if command == "CAPA" {
                stream
                    .write_all(b"+OK capabilities\r\nUSER\r\n.\r\n")
                    .unwrap();
            } else if command.starts_with("USER ") {
                stream.write_all(b"+OK\r\n").unwrap();
            } else if command.starts_with("PASS ") {
                stream.write_all(b"-ERR Login failure\r\n").unwrap();
                break;
            }
        }

        tx.send(commands).unwrap();
    });

    (format!("pop3://{addr}{path}"), rx)
}

fn spawn_imap_server(
    path: &str,
    command_responses: Vec<(&'static str, &'static [u8])>,
) -> (String, Receiver<Vec<u8>>) {
    spawn_imap_server_with_greeting(
        path,
        b"* OK curl IMAP test server ready\r\n",
        command_responses,
    )
}

fn spawn_imap_server_with_greeting(
    path: &str,
    greeting: &'static [u8],
    command_responses: Vec<(&'static str, &'static [u8])>,
) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let url = format!("imap://{addr}{path}");

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(greeting).unwrap();
        let mut commands = Vec::new();
        while let Some(line) = read_pop3_client_line(&mut stream) {
            commands.extend_from_slice(&line);
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end_matches(['\r', '\n']);
            let Some((tag, command)) = text.split_once(' ') else {
                continue;
            };

            if let Some((_, response)) = command_responses
                .iter()
                .find(|(expected, _)| *expected == command)
            {
                write_imap_response(&mut stream, tag, response);
            } else if command == "CAPABILITY" {
                write_imap_response(
                    &mut stream,
                    tag,
                    b"* CAPABILITY IMAP4rev1\r\n{tag} OK CAPABILITY completed\r\n",
                );
            } else if command.starts_with("LOGIN ") {
                write_imap_response(&mut stream, tag, b"{tag} OK LOGIN completed\r\n");
            } else if command.starts_with("SELECT ") {
                write_imap_response(
                    &mut stream,
                    tag,
                    b"* OK [UIDVALIDITY 3857529045] UIDs valid\r\n{tag} OK [READ-WRITE] SELECT completed\r\n",
                );
            } else if command == "LOGOUT" {
                write_imap_response(
                    &mut stream,
                    tag,
                    b"* BYE logging out\r\n{tag} OK LOGOUT completed\r\n",
                );
                break;
            } else {
                write_imap_response(&mut stream, tag, b"{tag} OK completed\r\n");
            }
        }

        tx.send(commands).unwrap();
    });

    (url, rx)
}

fn spawn_imap_login_denied_server(path: &str) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let url = format!("imap://{addr}{path}");

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .write_all(b"* OK curl IMAP test server ready\r\n")
            .unwrap();
        let mut commands = Vec::new();
        while let Some(line) = read_pop3_client_line(&mut stream) {
            commands.extend_from_slice(&line);
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end_matches(['\r', '\n']);
            let Some((tag, command)) = text.split_once(' ') else {
                continue;
            };
            if command == "CAPABILITY" {
                write_imap_response(
                    &mut stream,
                    tag,
                    b"* CAPABILITY IMAP4rev1\r\n{tag} OK CAPABILITY completed\r\n",
                );
            } else if command.starts_with("LOGIN ") {
                write_imap_response(&mut stream, tag, b"{tag} NO LOGIN failed\r\n");
                break;
            }
        }

        tx.send(commands).unwrap();
    });

    (url, rx)
}

fn write_imap_response(stream: &mut impl Write, tag: &str, template: &'static [u8]) {
    let text = String::from_utf8_lossy(template);
    let text = text.replace("{tag}", tag);
    stream.write_all(text.as_bytes()).unwrap();
}

fn read_pop3_client_line(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) if line.is_empty() => return None,
            Ok(0) => return Some(line),
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return Some(line);
                }
            }
            Err(error) => panic!("failed to read POP3 client bytes: {error}"),
        }
    }
}

fn spawn_smtp_server(
    path: &str,
    ehlo_response: &'static [u8],
    command_response: &'static [u8],
) -> (String, Receiver<SmtpRecord>) {
    spawn_smtp_server_with_rcpt_responses(path, ehlo_response, command_response, Vec::new())
}

fn spawn_smtp_server_with_rcpt_responses(
    path: &str,
    ehlo_response: &'static [u8],
    command_response: &'static [u8],
    rcpt_responses: Vec<&'static [u8]>,
) -> (String, Receiver<SmtpRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let path = path.to_string();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"220 curl SMTP test server\r\n").unwrap();
        let mut commands = Vec::new();
        let mut upload = Vec::new();
        let mut rcpt_responses = rcpt_responses.into_iter();
        let mut reading_upload = false;

        while let Some(line) = read_smtp_client_line(&mut stream) {
            if reading_upload {
                upload.extend_from_slice(&line);
                if line == b".\r\n" {
                    stream.write_all(b"250 message accepted\r\n").unwrap();
                    reading_upload = false;
                }
                continue;
            }

            commands.extend_from_slice(&line);
            let command = String::from_utf8_lossy(&line);
            let command = command.trim_end_matches(['\r', '\n']);
            let response = if command.starts_with("EHLO ") {
                ehlo_response
            } else if command.starts_with("HELO ") {
                b"250 helo ok\r\n".as_slice()
            } else if command.starts_with("MAIL FROM:") {
                b"250 sender ok\r\n".as_slice()
            } else if command.starts_with("RCPT TO:") {
                rcpt_responses
                    .next()
                    .unwrap_or(b"250 recipient ok\r\n".as_slice())
            } else if command == "DATA" {
                reading_upload = true;
                b"354 upload mail data\r\n".as_slice()
            } else if command == "QUIT" {
                let _ = stream.write_all(b"221 bye\r\n");
                break;
            } else {
                command_response
            };
            stream.write_all(response).unwrap();
        }

        tx.send(SmtpRecord { commands, upload }).unwrap();
    });

    (format!("smtp://{addr}{path}"), rx)
}

fn read_smtp_client_line(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) if line.is_empty() => return None,
            Ok(0) => return Some(line),
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return Some(line);
                }
            }
            Err(error) => panic!("failed to read SMTP client bytes: {error}"),
        }
    }
}

fn spawn_tftp_server(blocks: Vec<Vec<u8>>) -> (String, Receiver<TftpRecord>) {
    spawn_tftp_server_with_oack(blocks, None)
}

fn spawn_slow_tftp_server(delay: Duration) -> (String, Receiver<TftpRecord>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = vec![0; 70_000];
        let (read, peer) = socket.recv_from(&mut buffer).unwrap();
        let request = buffer[..read].to_vec();
        let mut acknowledgements = Vec::new();

        for block_number in 1..=2_u16 {
            let mut packet = Vec::with_capacity(516);
            packet.extend_from_slice(&3_u16.to_be_bytes());
            packet.extend_from_slice(&block_number.to_be_bytes());
            packet.extend(std::iter::repeat_n(b'x', 512));
            socket.send_to(&packet, peer).unwrap();

            let (read, ack_peer) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(ack_peer, peer);
            acknowledgements.push(buffer[..read].to_vec());
            thread::sleep(delay);
        }

        tx.send(TftpRecord {
            request,
            peer,
            acknowledgements,
        })
        .unwrap();
    });

    (format!("tftp://{addr}/file.txt"), rx)
}

fn spawn_tftp_server_with_oack(
    blocks: Vec<Vec<u8>>,
    oack: Option<Vec<u8>>,
) -> (String, Receiver<TftpRecord>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = vec![0; 70_000];
        let (read, peer) = socket.recv_from(&mut buffer).unwrap();
        let request = buffer[..read].to_vec();
        let mut acknowledgements = Vec::new();

        if let Some(oack) = oack {
            socket.send_to(&oack, peer).unwrap();
            let (read, ack_peer) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(ack_peer, peer);
            acknowledgements.push(buffer[..read].to_vec());
        }

        for (index, block) in blocks.iter().enumerate() {
            let block_number = u16::try_from(index + 1).unwrap();
            let mut packet = Vec::with_capacity(block.len() + 4);
            packet.extend_from_slice(&3_u16.to_be_bytes());
            packet.extend_from_slice(&block_number.to_be_bytes());
            packet.extend_from_slice(block);
            socket.send_to(&packet, peer).unwrap();

            let (read, ack_peer) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(ack_peer, peer);
            acknowledgements.push(buffer[..read].to_vec());
        }

        tx.send(TftpRecord {
            request,
            peer,
            acknowledgements,
        })
        .unwrap();
    });

    (format!("tftp://{addr}/file.txt"), rx)
}

fn spawn_tftp_missing_then_success_server(
    blocks: Vec<Vec<u8>>,
) -> (String, Receiver<TftpSequenceRecord>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = vec![0; 70_000];
        let mut requests = Vec::new();
        let mut acknowledgements = Vec::new();

        let (read, first_peer) = socket.recv_from(&mut buffer).unwrap();
        requests.push(buffer[..read].to_vec());
        let mut error = Vec::from(&5_u16.to_be_bytes()[..]);
        error.extend_from_slice(&1_u16.to_be_bytes());
        error.extend_from_slice(b"missing");
        error.push(0);
        socket.send_to(&error, first_peer).unwrap();

        let (read, second_peer) = socket.recv_from(&mut buffer).unwrap();
        requests.push(buffer[..read].to_vec());
        for (index, block) in blocks.iter().enumerate() {
            let block_number = u16::try_from(index + 1).unwrap();
            let mut packet = Vec::with_capacity(block.len() + 4);
            packet.extend_from_slice(&3_u16.to_be_bytes());
            packet.extend_from_slice(&block_number.to_be_bytes());
            packet.extend_from_slice(block);
            socket.send_to(&packet, second_peer).unwrap();

            let (read, ack_peer) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(ack_peer, second_peer);
            acknowledgements.push(buffer[..read].to_vec());
        }

        tx.send(TftpSequenceRecord {
            requests,
            acknowledgements,
        })
        .unwrap();
    });

    (format!("tftp://{addr}"), rx)
}

fn tftp_oack(options: &[(&str, &str)]) -> Vec<u8> {
    let mut packet = Vec::from(&6_u16.to_be_bytes()[..]);
    for (name, value) in options {
        packet.extend_from_slice(name.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
    }
    packet
}

fn spawn_tftp_oack_once(oack: Vec<u8>) -> (String, Receiver<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = vec![0; 70_000];
        let (read, peer) = socket.recv_from(&mut buffer).unwrap();
        tx.send(buffer[..read].to_vec()).unwrap();
        socket.send_to(&oack, peer).unwrap();
    });

    (format!("tftp://{addr}/file.txt"), rx)
}

fn tftp_ack(block: u16) -> Vec<u8> {
    let mut packet = Vec::from(&4_u16.to_be_bytes()[..]);
    packet.extend_from_slice(&block.to_be_bytes());
    packet
}

fn mqtt_packet(packet_type: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![packet_type];
    mqtt_encode_remaining_len(body.len(), &mut packet);
    packet.extend_from_slice(body);
    packet
}

fn mqtt_encode_remaining_len(mut len: usize, output: &mut Vec<u8>) {
    loop {
        let mut encoded = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            encoded |= 128;
        }
        output.push(encoded);
        if len == 0 {
            break;
        }
    }
}

fn mqtt_connack(code: u8) -> Vec<u8> {
    mqtt_packet(0x20, &[0, code])
}

fn mqtt_suback() -> Vec<u8> {
    mqtt_packet(0x90, &[0, 1, 0])
}

fn mqtt_publish(topic: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic);
    body.extend_from_slice(payload);
    mqtt_packet(0x30, &body)
}

fn mqtt_disconnect() -> Vec<u8> {
    mqtt_packet(0xe0, &[])
}

fn ldap_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(tag);
    if content.len() < 128 {
        bytes.push(content.len() as u8);
    } else {
        let mut length = Vec::new();
        let mut remaining = content.len();
        while remaining > 0 {
            length.push((remaining & 0xff) as u8);
            remaining >>= 8;
        }
        length.reverse();
        bytes.push(0x80 | length.len() as u8);
        bytes.extend_from_slice(&length);
    }
    bytes.extend_from_slice(content);
    bytes
}

fn ldap_integer(value: i32) -> Vec<u8> {
    let mut content = value.to_be_bytes().to_vec();
    while content.len() > 1
        && ((content[0] == 0x00 && content[1] & 0x80 == 0)
            || (content[0] == 0xff && content[1] & 0x80 != 0))
    {
        content.remove(0);
    }
    ldap_tlv(0x02, &content)
}

fn ldap_enumerated(value: i32) -> Vec<u8> {
    let mut content = value.to_be_bytes().to_vec();
    while content.len() > 1
        && ((content[0] == 0x00 && content[1] & 0x80 == 0)
            || (content[0] == 0xff && content[1] & 0x80 != 0))
    {
        content.remove(0);
    }
    ldap_tlv(0x0a, &content)
}

fn ldap_octet(value: &[u8]) -> Vec<u8> {
    ldap_tlv(0x04, value)
}

fn ldap_sequence(content: &[u8]) -> Vec<u8> {
    ldap_tlv(0x30, content)
}

fn ldap_message(id: i32, protocol_op: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&ldap_integer(id));
    body.extend_from_slice(protocol_op);
    ldap_sequence(&body)
}

fn ldap_result_message(id: i32, tag: u8, code: i32) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&ldap_enumerated(code));
    result.extend_from_slice(&ldap_octet(b""));
    result.extend_from_slice(&ldap_octet(b""));
    ldap_message(id, &ldap_tlv(tag, &result))
}

fn ldap_bind_response(code: i32) -> Vec<u8> {
    ldap_result_message(1, 0x61, code)
}

fn ldap_search_done(code: i32) -> Vec<u8> {
    ldap_result_message(2, 0x65, code)
}

fn ldap_attribute(name: &[u8], values: &[&[u8]]) -> Vec<u8> {
    let mut set = Vec::new();
    for value in values {
        set.extend_from_slice(&ldap_octet(value));
    }

    let mut body = Vec::new();
    body.extend_from_slice(&ldap_octet(name));
    body.extend_from_slice(&ldap_tlv(0x31, &set));
    ldap_sequence(&body)
}

fn ldap_search_entry(dn: &[u8], attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut attribute_list = Vec::new();
    for attribute in attributes {
        attribute_list.extend_from_slice(attribute);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&ldap_octet(dn));
    body.extend_from_slice(&ldap_sequence(&attribute_list));
    ldap_message(2, &ldap_tlv(0x64, &body))
}

fn ldap_read_client_message(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut tag = [0; 1];
    stream.read_exact(&mut tag).ok()?;
    let mut first = [0; 1];
    stream.read_exact(&mut first).ok()?;
    let mut message = vec![tag[0], first[0]];
    let length = if first[0] & 0x80 == 0 {
        first[0] as usize
    } else {
        let count = (first[0] & 0x7f) as usize;
        let mut length_bytes = vec![0; count];
        stream.read_exact(&mut length_bytes).ok()?;
        message.extend_from_slice(&length_bytes);
        length_bytes
            .into_iter()
            .fold(0_usize, |length, byte| (length << 8) | byte as usize)
    };
    let mut content = vec![0; length];
    stream.read_exact(&mut content).ok()?;
    message.extend_from_slice(&content);
    Some(message)
}

fn spawn_ldap_server(
    path: &'static str,
    bind_code: i32,
    entries: Vec<Vec<u8>>,
    done_code: i32,
) -> (String, Receiver<LdapRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let bind = ldap_read_client_message(&mut stream).unwrap();
        stream.write_all(&ldap_bind_response(bind_code)).unwrap();

        let mut search = Vec::new();
        let mut unbind = Vec::new();
        if bind_code == 0 {
            search = ldap_read_client_message(&mut stream).unwrap();
            for entry in entries {
                stream.write_all(&entry).unwrap();
            }
            stream.write_all(&ldap_search_done(done_code)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            unbind = ldap_read_client_message(&mut stream).unwrap_or_default();
        }

        tx.send(LdapRecord {
            bind,
            search,
            unbind,
        })
        .unwrap();
    });

    (format!("ldap://{addr}{path}"), rx)
}

impl SmbFixture {
    fn body(body: &[u8]) -> Self {
        Self {
            body: body.to_vec(),
            tree_status: 0,
            open_status: 0,
            malformed_read: false,
        }
    }
}

fn spawn_smb_server(path: &'static str, fixture: SmbFixture) -> (String, Receiver<SmbRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut packets = Vec::new();
        let uid = 0x2001;
        let tid = 0x3001;
        let fid = 0x4001;

        packets.push(smb_read_client_packet(&mut stream).unwrap());
        stream
            .write_all(&smb_test_packet(TEST_SMB_COM_NEGOTIATE, 0, 0, 0, &[0]))
            .unwrap();

        packets.push(smb_read_client_packet(&mut stream).unwrap());
        stream
            .write_all(&smb_test_packet(TEST_SMB_COM_SETUP_ANDX, 0, 0, uid, &[0]))
            .unwrap();

        packets.push(smb_read_client_packet(&mut stream).unwrap());
        stream
            .write_all(&smb_test_packet(
                TEST_SMB_COM_TREE_CONNECT_ANDX,
                fixture.tree_status,
                tid,
                uid,
                &[0],
            ))
            .unwrap();
        if fixture.tree_status != 0 {
            tx.send(SmbRecord { packets }).unwrap();
            return;
        }

        packets.push(smb_read_client_packet(&mut stream).unwrap());
        let open_body = if fixture.open_status == 0 {
            smb_open_response_body(fid, fixture.body.len() as u64)
        } else {
            Vec::new()
        };
        stream
            .write_all(&smb_test_packet(
                TEST_SMB_COM_NT_CREATE_ANDX,
                fixture.open_status,
                tid,
                uid,
                &open_body,
            ))
            .unwrap();
        if fixture.open_status != 0 {
            if let Some(packet) = smb_read_client_packet(&mut stream) {
                let command = smb_packet_command(&packet);
                packets.push(packet);
                if command == TEST_SMB_COM_TREE_DISCONNECT {
                    let _ = stream.write_all(&smb_test_packet(
                        TEST_SMB_COM_TREE_DISCONNECT,
                        0,
                        tid,
                        uid,
                        &[0, 0, 0],
                    ));
                }
            }
            tx.send(SmbRecord { packets }).unwrap();
            return;
        }

        while let Some(packet) = smb_read_client_packet(&mut stream) {
            let command = smb_packet_command(&packet);
            packets.push(packet);
            match command {
                TEST_SMB_COM_READ_ANDX => {
                    if fixture.malformed_read {
                        let _ = stream.write_all(&[0, 0, 0, 1, 0]);
                        break;
                    }
                    stream
                        .write_all(&smb_test_packet(
                            TEST_SMB_COM_READ_ANDX,
                            0,
                            tid,
                            uid,
                            &smb_read_response_body(&fixture.body),
                        ))
                        .unwrap();
                }
                TEST_SMB_COM_CLOSE => {
                    stream
                        .write_all(&smb_test_packet(
                            TEST_SMB_COM_CLOSE,
                            0,
                            tid,
                            uid,
                            &[0, 0, 0],
                        ))
                        .unwrap();
                }
                TEST_SMB_COM_TREE_DISCONNECT => {
                    stream
                        .write_all(&smb_test_packet(
                            TEST_SMB_COM_TREE_DISCONNECT,
                            0,
                            tid,
                            uid,
                            &[0, 0, 0],
                        ))
                        .unwrap();
                    break;
                }
                _ => break,
            }
        }

        tx.send(SmbRecord { packets }).unwrap();
    });

    (format!("smb://{addr}{path}"), rx)
}

fn smb_read_client_packet(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut nbt = [0; 4];
    stream.read_exact(&mut nbt).ok()?;
    let length = (((nbt[1] & 0x01) as usize) << 16) | ((nbt[2] as usize) << 8) | nbt[3] as usize;
    let mut packet = Vec::with_capacity(4 + length);
    packet.extend_from_slice(&nbt);
    packet.resize(4 + length, 0);
    stream.read_exact(&mut packet[4..]).ok()?;
    Some(packet)
}

fn smb_test_packet(command: u8, status: u32, tid: u16, uid: u16, body: &[u8]) -> Vec<u8> {
    let length = 32 + body.len();
    let mut packet = Vec::with_capacity(4 + length);
    packet.push(0);
    packet.push(0);
    packet.push((length >> 8) as u8);
    packet.push(length as u8);
    packet.extend_from_slice(b"\xffSMB");
    packet.push(command);
    packet.extend_from_slice(&status.to_le_bytes());
    packet.push(0x18);
    packet.extend_from_slice(&0x0041_u16.to_le_bytes());
    packet.extend_from_slice(&0_u16.to_le_bytes());
    packet.extend_from_slice(&[0; 8]);
    packet.extend_from_slice(&0_u16.to_le_bytes());
    packet.extend_from_slice(&tid.to_le_bytes());
    packet.extend_from_slice(&0x5151_u16.to_le_bytes());
    packet.extend_from_slice(&uid.to_le_bytes());
    packet.extend_from_slice(&1_u16.to_le_bytes());
    packet.extend_from_slice(body);
    packet
}

fn smb_open_response_body(fid: u16, size: u64) -> Vec<u8> {
    let mut body = vec![0; 64];
    body[0] = 0x22;
    body[1] = 0xff;
    body[6..8].copy_from_slice(&fid.to_le_bytes());
    body[56..64].copy_from_slice(&size.to_le_bytes());
    body
}

fn smb_read_response_body(data: &[u8]) -> Vec<u8> {
    let header_len = 27;
    let data_offset = 32 + header_len;
    let mut body = vec![0; header_len];
    body[0] = 0x0c;
    body[1] = 0xff;
    body[11..13].copy_from_slice(&(data.len() as u16).to_le_bytes());
    body[13..15].copy_from_slice(&(data_offset as u16).to_le_bytes());
    body.extend_from_slice(data);
    body
}

fn smb_packet_command(packet: &[u8]) -> u8 {
    packet.get(8).copied().unwrap_or_default()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn ws_server_response() -> Vec<u8> {
    b"HTTP/1.1 101 Switching Protocols\r\n\
Server: curl-rust-test\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: HkPsVga7+8LuxM4RGQ5p9tZHeYs=\r\n\
\r\n"
        .to_vec()
}

fn ws_server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(0x80 | opcode);
    if payload.len() <= 125 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

fn spawn_ws_server(frames: Vec<Vec<u8>>) -> (String, Receiver<WsRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        stream.write_all(&ws_server_response()).unwrap();
        for frame in frames {
            stream.write_all(&frame).unwrap();
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let frames = read_ws_client_frames(&mut stream);
        tx.send(WsRecord { request, frames }).unwrap();
        let _ = stream.shutdown(Shutdown::Both);
    });

    (format!("ws://{addr}/chat?room=rust"), rx)
}

fn spawn_ws_upload_server() -> (String, Receiver<WsRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        stream.write_all(&ws_server_response()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let frames = read_ws_client_frames(&mut stream);
        stream.write_all(&ws_server_frame(0x8, &[])).unwrap();
        tx.send(WsRecord { request, frames }).unwrap();
        let _ = stream.shutdown(Shutdown::Both);
    });

    (format!("ws://{addr}/upload"), rx)
}

fn spawn_ws_raw_response(response: &'static [u8]) -> (String, Receiver<RequestRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        tx.send(request).unwrap();
        stream.write_all(response).unwrap();
    });

    (format!("ws://{addr}/chat"), rx)
}

fn read_ws_client_frames(stream: &mut impl Read) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    while let Some(frame) = read_ws_client_frame(stream) {
        frames.push(frame);
    }
    frames
}

fn read_ws_client_frame(stream: &mut impl Read) -> Option<(u8, Vec<u8>)> {
    let mut head = [0; 2];
    match stream.read_exact(&mut head) {
        Ok(()) => {}
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            return None;
        }
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return None,
        Err(error) => panic!("failed to read WebSocket frame header: {error}"),
    }
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    assert!(masked, "client WebSocket frame must be masked");
    let mut length = usize::from(head[1] & 0x7f);
    if length == 126 {
        let mut bytes = [0; 2];
        stream.read_exact(&mut bytes).unwrap();
        length = usize::from(u16::from_be_bytes(bytes));
    } else if length == 127 {
        let mut bytes = [0; 8];
        stream.read_exact(&mut bytes).unwrap();
        length = usize::try_from(u64::from_be_bytes(bytes)).unwrap();
    }
    let mut mask = [0; 4];
    stream.read_exact(&mut mask).unwrap();
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).unwrap();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Some((opcode, payload))
}

fn read_mqtt_frame(stream: &mut impl Read) -> (u8, Vec<u8>) {
    let mut first = [0; 1];
    stream.read_exact(&mut first).unwrap();
    let mut multiplier = 1_usize;
    let mut remaining_len = 0_usize;
    loop {
        let mut byte = [0; 1];
        stream.read_exact(&mut byte).unwrap();
        remaining_len += usize::from(byte[0] & 127) * multiplier;
        if byte[0] & 128 == 0 {
            break;
        }
        multiplier *= 128;
    }
    let mut body = vec![0; remaining_len];
    stream.read_exact(&mut body).unwrap();
    (first[0], body)
}

fn spawn_mqtt_subscribe_server(topic: Vec<u8>, payload: Vec<u8>) -> (String, Receiver<MqttRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (connect_type, connect) = read_mqtt_frame(&mut stream);
        assert_eq!(connect_type, 0x10);
        stream.write_all(&mqtt_connack(0)).unwrap();

        let (subscribe_type, subscribe) = read_mqtt_frame(&mut stream);
        assert_eq!(subscribe_type, 0x82);
        stream.write_all(&mqtt_suback()).unwrap();
        stream.write_all(&mqtt_publish(&topic, &payload)).unwrap();
        stream.write_all(&mqtt_disconnect()).unwrap();

        tx.send(MqttRecord {
            connect,
            subscribe: Some(subscribe),
            publish: None,
            disconnect: None,
        })
        .unwrap();
    });

    (format!("mqtt://{addr}/sensor"), rx)
}

fn spawn_mqtt_publish_server() -> (String, Receiver<MqttRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (connect_type, connect) = read_mqtt_frame(&mut stream);
        assert_eq!(connect_type, 0x10);
        stream.write_all(&mqtt_connack(0)).unwrap();

        let (publish_type, publish) = read_mqtt_frame(&mut stream);
        assert_eq!(publish_type, 0x30);
        let (disconnect_type, disconnect) = read_mqtt_frame(&mut stream);
        assert_eq!(disconnect_type, 0xe0);

        tx.send(MqttRecord {
            connect,
            subscribe: None,
            publish: Some(publish),
            disconnect: Some(disconnect),
        })
        .unwrap();
    });

    (format!("mqtt://{addr}/sensor"), rx)
}

fn spawn_mqtt_connack_server(code: u8) -> (String, Receiver<MqttRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (connect_type, connect) = read_mqtt_frame(&mut stream);
        assert_eq!(connect_type, 0x10);
        stream.write_all(&mqtt_connack(code)).unwrap();

        tx.send(MqttRecord {
            connect,
            subscribe: None,
            publish: None,
            disconnect: None,
        })
        .unwrap();
    });

    (format!("mqtt://{addr}/sensor"), rx)
}

fn spawn_rtsp_server(response: &'static [u8]) -> (String, Receiver<RequestRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        tx.send(read_request(&mut stream)).unwrap();
        stream.write_all(response).unwrap();
    });

    (format!("rtsp://{addr}/media"), rx)
}

fn spawn_tftp_upload_server(
    first_response: Vec<u8>,
    block_size: usize,
) -> (String, Receiver<TftpUploadRecord>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = vec![0; 70_000];
        let (read, peer) = socket.recv_from(&mut buffer).unwrap();
        let request = buffer[..read].to_vec();
        socket.send_to(&first_response, peer).unwrap();

        let mut data_blocks = Vec::new();
        loop {
            let (read, data_peer) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(data_peer, peer);
            assert!(read >= 4);
            assert_eq!(&buffer[..2], &3_u16.to_be_bytes());
            let block = u16::from_be_bytes([buffer[2], buffer[3]]);
            let data = buffer[4..read].to_vec();
            socket.send_to(&tftp_ack(block), peer).unwrap();
            let done = data.len() < block_size;
            data_blocks.push((block, data));
            if done {
                break;
            }
        }

        tx.send(TftpUploadRecord {
            request,
            data_blocks,
        })
        .unwrap();
    });

    (format!("tftp://{addr}/upload.bin"), rx)
}

fn spawn_delayed_tftp_upload_ack_server(delay: Duration) -> (String, Receiver<TftpUploadRecord>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = vec![0; 70_000];
        let (read, peer) = socket.recv_from(&mut buffer).unwrap();
        let request = buffer[..read].to_vec();
        socket.send_to(&tftp_ack(0), peer).unwrap();

        let (read, data_peer) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(data_peer, peer);
        assert!(read >= 4);
        assert_eq!(&buffer[..2], &3_u16.to_be_bytes());
        let block = u16::from_be_bytes([buffer[2], buffer[3]]);
        let data = buffer[4..read].to_vec();

        tx.send(TftpUploadRecord {
            request,
            data_blocks: vec![(block, data)],
        })
        .unwrap();

        thread::sleep(delay);
        let _ = socket.send_to(&tftp_ack(block), peer);
    });

    (format!("tftp://{addr}/upload.bin"), rx)
}

fn spawn_tftp_upload_error_server(code: u16) -> (String, Receiver<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = vec![0; 2048];
        let (read, peer) = socket.recv_from(&mut buffer).unwrap();
        tx.send(buffer[..read].to_vec()).unwrap();
        let mut packet = Vec::from(&5_u16.to_be_bytes()[..]);
        packet.extend_from_slice(&code.to_be_bytes());
        packet.extend_from_slice(b"upload denied");
        packet.push(0);
        socket.send_to(&packet, peer).unwrap();
    });

    (format!("tftp://{addr}/upload.bin"), rx)
}

fn spawn_telnet_server(
    response: &'static [u8],
    greeting: &'static [u8],
    stop_suffix: &'static [u8],
) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        if !greeting.is_empty() {
            stream.write_all(greeting).unwrap();
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let mut bytes = read_telnet_client_bytes(&mut stream, stop_suffix);
        let _ = stream.write_all(response);
        bytes.extend(read_telnet_client_bytes(&mut stream, b""));
        tx.send(bytes).unwrap();
        let _ = stream.shutdown(Shutdown::Both);
    });

    (format!("telnet://{addr}/"), rx)
}

fn spawn_telnet_echo_server(
    greeting: &'static [u8],
    stop_suffix: &'static [u8],
) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        if !greeting.is_empty() {
            stream.write_all(greeting).unwrap();
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let mut bytes = read_telnet_client_bytes(&mut stream, stop_suffix);
        let plain = strip_telnet_client_negotiation(&bytes);
        let _ = stream.write_all(&plain);
        bytes.extend(read_telnet_client_bytes(&mut stream, b""));
        tx.send(bytes).unwrap();
        let _ = stream.shutdown(Shutdown::Both);
    });

    (format!("telnet://{addr}/"), rx)
}

fn read_telnet_client_bytes(stream: &mut impl Read, stop_suffix: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                if !stop_suffix.is_empty() && bytes.ends_with(stop_suffix) {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(error) => panic!("failed to read telnet client bytes: {error}"),
        }
    }

    bytes
}

fn strip_telnet_client_negotiation(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == TELNET_IAC {
            if bytes.get(index + 1) == Some(&TELNET_IAC) {
                output.push(TELNET_IAC);
                index += 2;
            } else {
                index += 3.min(bytes.len() - index);
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    output
}

fn spawn_timed_server(
    response: &'static [u8],
    response_delay: Duration,
) -> (String, Receiver<Instant>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _request = read_request(&mut stream);
        tx.send(Instant::now()).unwrap();
        thread::sleep(response_delay);
        stream.write_all(response).unwrap();
    });

    (format!("http://{addr}/resource"), rx)
}

fn spawn_gopher_server(response: &'static [u8]) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    spawn_gopher_server_with_listener(listener, format!("gopher://{addr}/1/resource"), response)
}

fn spawn_gopher_ipv6_server(response: &'static [u8]) -> Option<(String, Receiver<Vec<u8>>)> {
    let listener = TcpListener::bind("[::1]:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    Some(spawn_gopher_server_with_listener(
        listener,
        format!("gopher://[::1]:{port}/1/resource"),
        response,
    ))
}

fn spawn_gopher_server_with_listener(
    listener: TcpListener,
    url: String,
    response: &'static [u8],
) -> (String, Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];

        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.ends_with(b"\r\n") {
                break;
            }
        }

        tx.send(bytes).unwrap();
        stream.write_all(response).unwrap();
    });

    (url, rx)
}

fn read_request(stream: &mut impl Read) -> RequestRecord {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];

    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .unwrap();
    let header_text = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let start_line = lines.next().unwrap_or("").to_string();
    let headers: Vec<_> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);

    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }

    let body = bytes[header_end..header_end + content_length].to_vec();
    RequestRecord {
        start_line,
        headers,
        body,
    }
}

fn header<'a>(request: &'a RequestRecord, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header_name, _)| header_name == name)
        .map(|(_, value)| value.as_str())
}

fn header_count(request: &RequestRecord, name: &str) -> usize {
    request
        .headers
        .iter()
        .filter(|(header_name, _)| header_name == name)
        .count()
}

fn expected_dict_request(command: &[u8]) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(
        format!("CLIENT curl-rust {}\r\n", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    request.extend_from_slice(command);
    request.extend_from_slice(b"\r\nQUIT\r\n");
    request
}

fn compressed_response(encoding: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

#[test]
fn downloads_http_and_renders_writeout() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-w", " %{http_code} %{size_download}", &url]);
    command.assert().success().stdout("hello 200 5");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert!(header(&request, "user-agent").unwrap().starts_with("curl/"));
    assert_eq!(header(&request, "accept"), Some("*/*"));
    assert_eq!(header(&request, "accept-encoding"), None);
}

#[test]
fn legacy_tls_max_values_do_not_break_plain_http() {
    for version in ["1.0", "1.1"] {
        let (url, rx) =
            spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");

        let mut command = Command::cargo_bin("curl").unwrap();
        command.args(["-q", "-sS", "--tls-max", version, &url]);
        command.assert().success().stdout("ok");

        let request = rx.recv().unwrap();
        assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    }
}

#[test]
fn out_null_discards_one_url_and_keeps_later_output_slot() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
    ]);
    let origin = gateway_origin(&url);
    let first = format!("{origin}/first");
    let second = format!("{origin}/second");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &first, &second, "--out-null", "-o", "-"]);
    command.assert().success().stdout("two");

    let first_request = rx.recv().unwrap();
    let second_request = rx.recv().unwrap();
    assert!(first_request.start_line.starts_with("GET /first HTTP/1.1"));
    assert!(
        second_request
            .start_line
            .starts_with("GET /second HTTP/1.1")
    );
}

#[test]
fn out_null_discards_included_headers_and_body() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-i", "--out-null", &url]);
    command.assert().success().stdout("");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn remote_name_output_slot_precedes_out_null() {
    let temp = tempdir().unwrap();
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
    ]);
    let origin = gateway_origin(&url);
    let first = format!("{origin}/one.txt");
    let second = format!("{origin}/two.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .current_dir(temp.path())
        .args(["-q", "-sS", &first, &second, "-O", "--out-null"]);
    command.assert().success().stdout("");

    assert_eq!(
        std::fs::read_to_string(temp.path().join("one.txt")).unwrap(),
        "one"
    );
    assert!(!temp.path().join("two.txt").exists());
    let first_request = rx.recv().unwrap();
    let second_request = rx.recv().unwrap();
    assert!(
        first_request
            .start_line
            .starts_with("GET /one.txt HTTP/1.1")
    );
    assert!(
        second_request
            .start_line
            .starts_with("GET /two.txt HTTP/1.1")
    );
}

#[test]
fn out_null_output_slot_precedes_remote_name() {
    let temp = tempdir().unwrap();
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
    ]);
    let origin = gateway_origin(&url);
    let first = format!("{origin}/one.txt");
    let second = format!("{origin}/two.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .current_dir(temp.path())
        .args(["-q", "-sS", &first, &second, "--out-null", "-O"]);
    command.assert().success().stdout("");

    assert!(!temp.path().join("one.txt").exists());
    assert_eq!(
        std::fs::read_to_string(temp.path().join("two.txt")).unwrap(),
        "two"
    );
    let first_request = rx.recv().unwrap();
    let second_request = rx.recv().unwrap();
    assert!(
        first_request
            .start_line
            .starts_with("GET /one.txt HTTP/1.1")
    );
    assert!(
        second_request
            .start_line
            .starts_with("GET /two.txt HTTP/1.1")
    );
}

#[test]
fn extra_output_slots_emit_warning() {
    let temp = tempdir().unwrap();
    let file = temp.path().join("plain.txt");
    std::fs::write(&file, "hello").unwrap();
    let url = Url::from_file_path(&file).unwrap().to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url, "--out-null", "--out-null"]);
    command
        .assert()
        .success()
        .stdout("")
        .stderr("Warning: Got more output options than URLs\n");
}

#[test]
fn duplicate_location_headers_accept_exact_repeat() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nLocation: this\r\nLocation: this\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn conflicting_location_headers_return_weird_reply() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 302 Found\r\nLocation: /one\r\nLocation: /two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(8).stdout("");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn location_duplicate_headers_accept_exact_repeat() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", &url]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("GET /resource HTTP/1.1"));
    assert!(second.start_line.starts_with("GET /next HTTP/1.1"));
}

#[test]
fn location_conflicting_headers_fail_before_follow() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /one\r\nLocation: /two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", &url]);
    command.assert().failure().code(8).stdout("");

    let first = rx.recv().unwrap();
    assert!(first.start_line.starts_with("GET /resource HTTP/1.1"));
    assert!(rx.try_recv().is_err());
}

#[test]
fn compressed_decodes_supported_response_bodies() {
    for (label, encoding, compressed_body) in [
        ("gzip", "gzip", GZIP_COMPRESSED_BODY),
        ("zlib deflate", "deflate", DEFLATE_COMPRESSED_BODY),
        ("raw deflate", "deflate", RAW_DEFLATE_COMPRESSED_BODY),
        ("brotli", "br", BROTLI_COMPRESSED_BODY),
    ] {
        let (url, rx) = spawn_server_bytes(compressed_response(encoding, compressed_body));

        let output = Command::cargo_bin("curl")
            .unwrap()
            .args(["-q", "-sS", "--compressed", &url])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, COMPRESSED_BODY, "{label}");

        let request = rx.recv().unwrap();
        assert_eq!(
            header(&request, "accept-encoding"),
            Some("deflate, gzip, br"),
            "{label}"
        );
    }
}

#[test]
fn compressed_include_preserves_encoded_response_headers() {
    let (url, _rx) = spawn_server_bytes(compressed_response("gzip", GZIP_COMPRESSED_BODY));

    let output = Command::cargo_bin("curl")
        .unwrap()
        .args(["-q", "-sS", "--compressed", "-i", &url])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(stdout.contains("content-encoding: gzip\r\n"));
    assert!(stdout.contains("content-length: 37\r\n"));
    assert!(stdout.ends_with("\r\n\r\nhello compressed\n"));
}

#[test]
fn compressed_dump_header_preserves_encoded_response_headers() {
    let temp = tempdir().unwrap();
    let headers = temp.path().join("headers.txt");
    let (url, _rx) = spawn_server_bytes(compressed_response("gzip", GZIP_COMPRESSED_BODY));

    let output = Command::cargo_bin("curl")
        .unwrap()
        .args([
            "-q",
            "-sS",
            "--compressed",
            "--dump-header",
            headers.to_str().unwrap(),
            &url,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, COMPRESSED_BODY);

    let dumped = std::fs::read_to_string(headers).unwrap();
    assert!(dumped.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(dumped.contains("content-encoding: gzip\r\n"));
    assert!(dumped.contains("content-length: 37\r\n"));
}

#[test]
fn raw_http_compressed_request_target_decodes_body_and_preserves_headers() {
    let (url, rx) = spawn_server_bytes(compressed_response("gzip", GZIP_COMPRESSED_BODY));

    let output = Command::cargo_bin("curl")
        .unwrap()
        .args([
            "-q",
            "-sS",
            "--compressed",
            "--request-target",
            "/raw",
            "-i",
            &url,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(stdout.contains("Content-Encoding: gzip\r\n"));
    assert!(stdout.contains("Content-Length: 37\r\n"));
    assert!(stdout.ends_with("\r\n\r\nhello compressed\n"));

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /raw HTTP/1.1"));
}

#[test]
fn compressed_custom_accept_encoding_still_decodes_response_body() {
    let (url, rx) = spawn_server_bytes(compressed_response("gzip", GZIP_COMPRESSED_BODY));

    let output = Command::cargo_bin("curl")
        .unwrap()
        .args([
            "-q",
            "-sS",
            "--compressed",
            "-H",
            "Accept-Encoding: identity",
            &url,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, COMPRESSED_BODY);

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "accept-encoding"), Some("identity"));
    assert_eq!(header_count(&request, "accept-encoding"), 1);
}

#[test]
fn http_does_not_decode_content_encoding_without_compressed() {
    let (url, rx) = spawn_server_bytes(compressed_response("gzip", GZIP_COMPRESSED_BODY));

    let output = Command::cargo_bin("curl")
        .unwrap()
        .args(["-q", "-sS", &url])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, GZIP_COMPRESSED_BODY);

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "accept-encoding"), None);
}

#[test]
fn compressed_unknown_content_encoding_returns_bad_content_encoding() {
    let (url, _rx) = spawn_server_bytes(compressed_response("zstd", b"encoded"));

    let output = Command::cargo_bin("curl")
        .unwrap()
        .args(["-q", "-sS", "--compressed", &url])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(61));
    assert_eq!(output.stdout, b"");
    assert!(String::from_utf8_lossy(&output.stderr).contains("content encoding"));
}

#[test]
fn write_out_at_file_reads_format() {
    let temp = tempdir().unwrap();
    let format = temp.path().join("writeout.txt");
    std::fs::write(&format, " code=%{http_code}\n").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-w", &format!("@{}", format.display()), &url]);
    command.assert().success().stdout("hello code=200");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn default_config_continues_from_empty_curl_home_to_xdg_config_home() {
    let temp = tempdir().unwrap();
    let curl_home = temp.path().join("curl-home");
    let xdg_config = temp.path().join("xdg");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&curl_home).unwrap();
    std::fs::create_dir_all(&xdg_config).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxdg");
    std::fs::write(
        xdg_config.join("curlrc"),
        format!("silent\nurl = {url}\nheader = \"X-Config: xdg\"\n"),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env("CURL_HOME", &curl_home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("HOME", &home);
    command.assert().success().stdout("xdg");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-config"), Some("xdg"));
}

#[test]
fn default_config_prefers_curl_home_over_xdg_config_home() {
    let temp = tempdir().unwrap();
    let curl_home = temp.path().join("curl-home");
    let xdg_config = temp.path().join("xdg");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&curl_home).unwrap();
    std::fs::create_dir_all(&xdg_config).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ncurl");
    std::fs::write(
        curl_home.join(".curlrc"),
        format!("silent\nurl = {url}\nheader = \"X-Config: curl\"\n"),
    )
    .unwrap();
    std::fs::write(
        xdg_config.join("curlrc"),
        "silent\nurl = http://127.0.0.1:1/xdg\n",
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env("CURL_HOME", &curl_home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("HOME", &home);
    command.assert().success().stdout("curl");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-config"), Some("curl"));
}

#[cfg(unix)]
#[test]
fn default_config_skips_unreadable_xdg_candidate() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let xdg_config = temp.path().join("xdg");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&xdg_config).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let unreadable = xdg_config.join("curlrc");
    std::fs::write(&unreadable, "url = http://127.0.0.1:1/xdg\n").unwrap();
    let mut permissions = std::fs::metadata(&unreadable).unwrap().permissions();
    permissions.set_mode(0o000);
    std::fs::set_permissions(&unreadable, permissions).unwrap();
    if std::fs::File::open(&unreadable).is_ok() {
        return;
    }

    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhome");
    std::fs::write(
        home.join(".curlrc"),
        format!("silent\nurl = {url}\nheader = \"X-Config: home\"\n"),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("CURL_HOME")
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("HOME", &home);
    command.assert().success().stdout("home");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-config"), Some("home"));
}

#[test]
fn default_config_falls_back_to_home_config_dir_without_xdg_config_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir_all(home.join(".config")).unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nconfig");
    std::fs::write(
        home.join(".config").join("curlrc"),
        format!("silent\nurl = {url}\nheader = \"X-Config: home-config\"\n"),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("CURL_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", &home);
    command.assert().success().stdout("config");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-config"), Some("home-config"));
}

#[test]
fn default_config_is_skipped_by_disable_flag() {
    let temp = tempdir().unwrap();
    let xdg_config = temp.path().join("xdg");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&xdg_config).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(xdg_config.join("curlrc"), "header = X-Config: xdg\n").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("CURL_HOME")
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("HOME", &home)
        .args(["--disable", "-sS", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-config"), None);
}

#[test]
fn default_config_is_skipped_by_q_cluster() {
    let temp = tempdir().unwrap();
    let xdg_config = temp.path().join("xdg");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&xdg_config).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(xdg_config.join("curlrc"), "header = X-Config: xdg\n").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("CURL_HOME")
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("HOME", &home)
        .args(["-qsS", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-config"), None);
}

#[test]
fn url_at_file_downloads_each_url_as_remote_name() {
    let temp = tempdir().unwrap();
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
    ]);
    let origin = gateway_origin(&url);
    let urls = temp.path().join("urls.txt");
    std::fs::write(
        &urls,
        format!("# skipped\n{origin}/one.txt\n\n{origin}/two.txt\n"),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .current_dir(temp.path())
        .args(["-q", "-sS", "--url", &format!("@{}", urls.display())]);
    command.assert().success().stdout("");

    assert_eq!(
        std::fs::read_to_string(temp.path().join("one.txt")).unwrap(),
        "one"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("two.txt")).unwrap(),
        "two"
    );
    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("GET /one.txt HTTP/1.1"));
    assert!(second.start_line.starts_with("GET /two.txt HTTP/1.1"));
}

#[test]
fn custom_user_agent_and_accept_headers_suppress_defaults() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-H",
        "User-Agent: fixture-agent",
        "-H",
        "Accept: application/xml",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "user-agent"), Some("fixture-agent"));
    assert_eq!(header_count(&request, "user-agent"), 1);
    assert_eq!(header(&request, "accept"), Some("application/xml"));
    assert_eq!(header_count(&request, "accept"), 1);
}

#[test]
fn empty_custom_headers_suppress_defaults_and_semicolon_sends_blank() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-H",
        "Accept:",
        "-H",
        "User-Agent:",
        "-H",
        "Host:",
        "-H",
        "X-Blank;",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "accept"), None);
    assert_eq!(header(&request, "user-agent"), None);
    assert_eq!(header(&request, "host"), None);
    assert_eq!(header(&request, "x-blank"), Some(""));
}

#[test]
fn header_file_uses_empty_and_semicolon_custom_header_semantics() {
    let temp = tempdir().unwrap();
    let headers = temp.path().join("headers.txt");
    std::fs::write(&headers, "Accept:\nX-File-Blank;\n").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-H", &format!("@{}", headers.display()), &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "accept"), None);
    assert_eq!(header(&request, "x-file-blank"), Some(""));
}

#[test]
fn generated_headers_respect_non_empty_custom_overrides() {
    let temp = tempdir().unwrap();
    let etag = temp.path().join("etag.txt");
    std::fs::write(&etag, "\"generated\"\n").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--compressed",
        "-b",
        "tool=curl",
        "--oauth2-bearer",
        "generated-token",
        "--etag-compare",
        etag.to_str().unwrap(),
        "--data",
        "a",
        "-H",
        "Accept-Encoding: identity",
        "-H",
        "Authorization: Custom auth",
        "-H",
        "Cookie: explicit=yes",
        "-H",
        "If-None-Match: \"override\"",
        "-H",
        "Content-Length: 1",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "accept-encoding"), Some("identity"));
    assert_eq!(header_count(&request, "accept-encoding"), 1);
    assert_eq!(header(&request, "authorization"), Some("Custom auth"));
    assert_eq!(header_count(&request, "authorization"), 1);
    assert_eq!(header(&request, "cookie"), Some("explicit=yes"));
    assert_eq!(header_count(&request, "cookie"), 1);
    assert_eq!(header(&request, "if-none-match"), Some("\"override\""));
    assert_eq!(header_count(&request, "if-none-match"), 1);
    assert_eq!(header(&request, "content-length"), Some("1"));
    assert_eq!(header_count(&request, "content-length"), 1);
    assert_eq!(request.body, b"a");
}

#[test]
fn range_and_time_condition_headers_respect_custom_overrides() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-r",
        "2-5",
        "-z",
        "Wed, 21 Oct 2015 07:28:00 GMT",
        "-H",
        "Range: bytes=0-0",
        "-H",
        "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=0-0"));
    assert_eq!(header_count(&request, "range"), 1);
    assert_eq!(
        header(&request, "if-modified-since"),
        Some("Thu, 01 Jan 1970 00:00:00 GMT")
    );
    assert_eq!(header_count(&request, "if-modified-since"), 1);
}

#[test]
fn user_agent_option_sets_header_and_empty_value_suppresses_default() {
    let (custom_url, custom_rx) =
        spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ncustom");

    let mut custom = Command::cargo_bin("curl").unwrap();
    custom.args(["-q", "-sS", "-A", "fixture-agent", &custom_url]);
    custom.assert().success().stdout("custom");
    let custom_request = custom_rx.recv().unwrap();
    assert_eq!(header(&custom_request, "user-agent"), Some("fixture-agent"));
    assert_eq!(header_count(&custom_request, "user-agent"), 1);

    let (empty_url, empty_rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nempty");

    let mut empty = Command::cargo_bin("curl").unwrap();
    empty.args(["-q", "-sS", "-A", "", &empty_url]);
    empty.assert().success().stdout("empty");
    assert_eq!(header(&empty_rx.recv().unwrap(), "user-agent"), None);
}

#[test]
fn request_target_sets_direct_http_request_line() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--request-target", "*", "-X", "OPTIONS", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "OPTIONS * HTTP/1.1");
    assert!(header(&request, "user-agent").unwrap().starts_with("curl/"));
    assert_eq!(header(&request, "accept"), Some("*/*"));
}

#[test]
fn request_target_location_follows_redirect_with_same_target() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--request-target", "/raw", &url]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /raw HTTP/1.1");
    assert_eq!(second.start_line, "GET /raw HTTP/1.1");
}

#[test]
fn request_target_location_allows_duplicate_location_repeat() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--request-target", "/raw", &url]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /raw HTTP/1.1");
    assert_eq!(second.start_line, "GET /raw HTTP/1.1");
}

#[test]
fn request_target_location_rejects_conflicting_location_headers() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /one\r\nLocation: /two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--request-target", "/raw", &url]);
    command.assert().failure().code(8).stdout("");

    let first = rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /raw HTTP/1.1");
    assert!(rx.try_recv().is_err());
}

#[test]
fn request_target_location_regenerates_host_on_cross_origin_redirect() {
    let (target_url, target_rx) =
        spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    let target = Url::parse(&target_url).unwrap();
    let target_host = format!(
        "{}:{}",
        target.host_str().unwrap(),
        target.port_or_known_default().unwrap()
    );
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (url, first_rx) = spawn_sequence_server_bytes(vec![redirect]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--location-trusted",
        "--request-target",
        "/raw",
        "-H",
        "Host: first.example",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = target_rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /raw HTTP/1.1");
    assert_eq!(second.start_line, "GET /raw HTTP/1.1");
    assert_eq!(header(&first, "host"), Some("first.example"));
    assert_eq!(header(&second, "host"), Some(target_host.as_str()));
}

#[test]
fn request_target_location_decodes_chunked_redirect_body() {
    let (url, rx) = spawn_request_target_chunked_redirect_server();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.timeout(Duration::from_secs(2));
    command.args(["-q", "-sS", "-L", "--request-target", "/raw", &url]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /raw HTTP/1.1");
    assert_eq!(second.start_line, "GET /raw HTTP/1.1");
}

#[test]
fn request_target_location_rejects_non_http_redirect_before_plaintext_follow() {
    let (url, rx) = spawn_request_target_https_redirect_server();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--request-target", "/raw", &url]);
    command.assert().failure().code(2).stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "GET /raw HTTP/1.1");
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
}

#[test]
fn request_target_location_respects_max_redirs() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--max-redirs",
        "0",
        "--request-target",
        "/raw",
        &url,
    ]);
    command.assert().failure().code(47).stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "GET /raw HTTP/1.1");
    assert!(rx.try_recv().is_err());
}

#[test]
fn request_target_proxy_location_follows_redirect_with_same_target() {
    let (proxy_url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: http://second.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--request-target",
        "/raw",
        "-x",
        &proxy_url,
        "http://first.example/path",
    ]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /raw HTTP/1.1");
    assert_eq!(second.start_line, "GET /raw HTTP/1.1");
    assert_eq!(header(&first, "host"), Some("first.example"));
    assert_eq!(header(&second, "host"), Some("second.example"));
    assert_eq!(header(&second, "proxy-connection"), Some("Keep-Alive"));
}

#[test]
fn request_target_proxy_location_strips_cross_origin_target_headers() {
    let (proxy_url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: http://second.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--request-target",
        "/raw",
        "-x",
        &proxy_url,
        "-H",
        "Host: first.example",
        "-H",
        "Authorization: Bearer secret",
        "-H",
        "Cookie: a=b",
        "-U",
        "proxy:secret",
        "http://first.example/path",
    ]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "host"), Some("first.example"));
    assert_eq!(header(&second, "host"), Some("second.example"));
    assert_eq!(header(&first, "authorization"), Some("Bearer secret"));
    assert_eq!(header(&second, "authorization"), None);
    assert_eq!(header(&first, "cookie"), Some("a=b"));
    assert_eq!(header(&second, "cookie"), None);
    assert_eq!(
        header(&second, "proxy-authorization"),
        Some("Basic cHJveHk6c2VjcmV0")
    );
}

#[test]
fn request_target_proxy_location_trusted_keeps_target_headers() {
    let (proxy_url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: http://second.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--location-trusted",
        "--request-target",
        "/raw",
        "-x",
        &proxy_url,
        "-H",
        "Host: first.example",
        "-H",
        "Authorization: Bearer secret",
        "-H",
        "Cookie: a=b",
        "http://first.example/path",
    ]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "host"), Some("first.example"));
    assert_eq!(header(&second, "host"), Some("second.example"));
    assert_eq!(header(&second, "authorization"), Some("Bearer secret"));
    assert_eq!(header(&second, "cookie"), Some("a=b"));
}

#[test]
fn request_target_proxy_location_respects_max_redirs() {
    let (proxy_url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: http://second.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--max-redirs",
        "0",
        "--request-target",
        "/raw",
        "-x",
        &proxy_url,
        "http://first.example/path",
    ]);
    command.assert().failure().code(47).stdout("");

    let first = rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /raw HTTP/1.1");
    assert_eq!(header(&first, "host"), Some("first.example"));
    assert!(rx.try_recv().is_err());
}

#[test]
fn http09_allows_headerless_response() {
    let (url, rx) = spawn_server(b"hello http09");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--http0.9",
        "-w",
        " %{response_code} %{size_download}",
        &url,
    ]);
    command.assert().success().stdout("hello http09 000 12");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn http09_response_is_denied_by_default() {
    let (url, rx) = spawn_server(b"hello http09");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(1).stdout("");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn no_http09_denies_headerless_response_after_enable() {
    let (url, rx) = spawn_server(b"hello http09");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--http0.9", "--no-http0.9", &url]);
    command.assert().failure().code(1).stdout("");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn http09_denial_with_writeout_uses_unsupported_protocol_exit() {
    let (url, rx) = spawn_server(b"hello http09");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-w",
        " code=%{response_code} exit=%{exitcode}",
        &url,
    ]);
    command
        .assert()
        .failure()
        .code(1)
        .stdout(" code=000 exit=1");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn default_http_get_decodes_chunked_response() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("hello");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn raw_http09_response_requires_opt_in() {
    let (url, rx) = spawn_server(b"raw http09");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--request-target", "*", "-X", "OPTIONS", &url]);
    command.assert().failure().code(1).stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "OPTIONS * HTTP/1.1");
}

#[test]
fn raw_http09_allows_headerless_response() {
    let (url, rx) = spawn_server(b"raw http09");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--http0.9",
        "--request-target",
        "*",
        "-X",
        "OPTIONS",
        &url,
    ]);
    command.assert().success().stdout("raw http09");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "OPTIONS * HTTP/1.1");
}

#[test]
fn raw_http09_head_is_weird_reply() {
    let (url, rx) = spawn_server(b"raw http09");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--http0.9",
        "--request-target",
        "*",
        "-I",
        &url,
    ]);
    command.assert().failure().code(8).stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "HEAD * HTTP/1.1");
}

#[test]
fn resolve_maps_host_to_address() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let port = Url::parse(&url).unwrap().port().unwrap();
    let target = format!("http://example.test:{port}/resource");
    let resolve = format!("example.test:{port}:127.0.0.1");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--resolve", &resolve, &target]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_eq!(
        header(&request, "host"),
        Some(format!("example.test:{port}").as_str())
    );
}

#[test]
fn ip_version_filters_resolved_address_families() {
    let Some(server) = spawn_dual_family_server() else {
        return;
    };

    let mut ipv4 = Command::cargo_bin("curl").unwrap();
    ipv4.args([
        "-q",
        "-sS",
        "--resolve",
        &server.resolve,
        "--ipv4",
        &server.target,
    ]);
    ipv4.assert().success().stdout("v4");

    let mut ipv6 = Command::cargo_bin("curl").unwrap();
    ipv6.args([
        "-q",
        "-sS",
        "--resolve",
        &server.resolve,
        "--ipv6",
        &server.target,
    ]);
    ipv6.assert().success().stdout("v6");

    let first = server.rx.recv().unwrap();
    let second = server.rx.recv().unwrap();
    assert_eq!(first.0, "v4");
    assert_eq!(second.0, "v6");
    assert_eq!(header(&first.1, "host"), header(&second.1, "host"));
}

#[test]
fn resolve_invalid_syntax_exits_option_syntax_error() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--resolve",
        "127.0.0.1:example.test:127.0.0.1",
        "http://example.test/",
    ]);
    command
        .assert()
        .failure()
        .code(49)
        .stdout("")
        .stderr("curl: Could not parse CURLOPT_RESOLVE entry '127.0.0.1:example.test:127.0.0.1'\n");
}

#[test]
fn connect_to_invalid_syntax_exits_option_syntax_error() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--connect-to",
        "::example.com:example.com",
        "http://example.com/",
    ]);
    command
        .assert()
        .failure()
        .code(49)
        .stdout("")
        .stderr("curl: No valid port number in 'example.com:example.com'\n");
}

#[test]
fn connect_to_remaps_plain_http_destination() {
    let (backend_url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let backend_port = Url::parse(&backend_url).unwrap().port().unwrap();
    let rule = format!("example.test:80:127.0.0.1:{backend_port}");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--connect-to",
        &rule,
        "http://example.test/resource",
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "GET /resource HTTP/1.1");
    assert_eq!(header(&request, "host"), Some("example.test"));
}

#[test]
fn connect_to_location_follows_redirect_through_remap() {
    let (backend_url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let backend_port = Url::parse(&backend_url).unwrap().port().unwrap();
    let rule = format!("example.test:80:127.0.0.1:{backend_port}");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--connect-to",
        &rule,
        "http://example.test/resource",
    ]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(first.start_line, "GET /resource HTTP/1.1");
    assert_eq!(second.start_line, "GET /next HTTP/1.1");
    assert_eq!(header(&first, "host"), Some("example.test"));
    assert_eq!(header(&second, "host"), Some("example.test"));
}

#[test]
fn connect_to_nonmatching_rule_does_not_remap_or_fail() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--connect-to",
        "example.test:80:127.0.0.1:9",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert_ne!(header(&request, "host"), Some("example.test"));
}

#[test]
fn disallow_username_in_url_rejects_url_userinfo() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--disallow-username-in-url",
        "http://username:password@example.com/",
    ]);
    command
        .assert()
        .failure()
        .code(67)
        .stdout("")
        .stderr("curl: (67) URL rejected: Credentials was passed in the URL when prohibited\n");
}

#[test]
fn max_filesize_allows_http_body_within_limit() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--max-filesize", "5", &url]);
    command.assert().success().stdout("hello");

    rx.recv().unwrap();
}

#[test]
fn max_filesize_zero_disables_limit() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ntoolong");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--max-filesize", "0", &url]);
    command.assert().success().stdout("toolong");

    rx.recv().unwrap();
}

#[test]
fn max_filesize_rejects_http_content_length_before_body_output() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ntoolong");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--max-filesize",
        "2",
        "-w",
        " %{exitcode} %{errormsg} %{size_download}",
        &url,
    ]);
    command
        .assert()
        .failure()
        .code(63)
        .stdout(" 63 Maximum file size exceeded 0");

    rx.recv().unwrap();
}

#[test]
fn max_filesize_truncates_unknown_http_body_then_fails() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcdef");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--max-filesize", "3", &url]);
    command.assert().failure().code(63).stdout("abc");

    rx.recv().unwrap();
}

#[test]
fn max_filesize_does_not_fail_head_with_large_content_length() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args(["-q", "-sS", "-I", "--max-filesize", "2", &url])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(stdout.contains("content-length: 7\r\n"));

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("HEAD /resource HTTP/1.1"));
}

#[test]
fn max_filesize_truncates_telnet_body_then_fails() {
    let (url, rx) = spawn_telnet_server(b"abcdef", b"", b"");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--max-filesize", "3", &url]);
    command.assert().failure().code(63).stdout("abc");

    rx.recv().unwrap();
}

#[test]
fn retries_transient_http_status_then_succeeds() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nbad",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--retry",
        "1",
        "--retry-delay",
        "0.001",
        "-w",
        " %{num_retries}",
        &url,
    ]);
    command.assert().success().stdout("ok 1");

    rx.recv().unwrap();
    rx.recv().unwrap();
}

#[test]
fn retry_all_errors_retries_failed_http_status() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--fail",
        "--retry",
        "1",
        "--retry-all-errors",
        "--retry-delay",
        "0.001",
        &url,
    ]);
    command.assert().success().stdout("ok");

    rx.recv().unwrap();
    rx.recv().unwrap();
}

#[test]
fn nontransient_http_status_is_not_retried_without_retry_all_errors() {
    let (url, rx) = spawn_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--fail", "--retry", "1", &url]);
    command.assert().failure().code(22).stdout("");

    rx.recv().unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
}

#[test]
fn fail_suppresses_http_error_body() {
    let (url, rx) = spawn_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--fail", &url]);
    command.assert().failure().code(22).stdout("");

    rx.recv().unwrap();
}

#[test]
fn fail_with_body_outputs_http_error_body_and_fails() {
    let (url, rx) = spawn_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--fail-with-body", &url]);
    command.assert().failure().code(22).stdout("missing");

    rx.recv().unwrap();
}

#[test]
fn fail_after_fail_with_body_suppresses_error_body() {
    let (url, rx) = spawn_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args(["-q", "-sS", "--fail-with-body", "--fail", &url])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(22));
    assert_eq!(output.stdout, b"");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Warning: --fail deselects --fail-with-body here")
    );
    rx.recv().unwrap();
}

#[test]
fn fail_with_body_after_fail_outputs_error_body() {
    let (url, rx) = spawn_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args(["-q", "-sS", "--fail", "--fail-with-body", &url])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(22));
    assert_eq!(output.stdout, b"missing");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Warning: --fail-with-body deselects --fail here")
    );
    rx.recv().unwrap();
}

#[test]
fn no_fail_with_body_disables_http_error_failure() {
    let (url, rx) = spawn_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--fail-with-body", "--no-fail-with-body", &url]);
    command.assert().success().stdout("missing");

    rx.recv().unwrap();
}

#[test]
fn fail_include_outputs_headers_without_error_body() {
    let (url, rx) =
        spawn_server(b"HTTP/1.1 404 Not Found\r\nX-Test: yes\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args(["-q", "-sS", "--fail", "-i", &url])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(22));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(stdout.contains("x-test: yes\r\n"));
    assert!(!stdout.contains("missing"));
    rx.recv().unwrap();
}

#[test]
fn fail_writeout_reports_zero_delivered_body_bytes() {
    let (url, rx) = spawn_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--fail",
        "-w",
        " %{http_code} %{size_download} %{exitcode}",
        &url,
    ]);
    command.assert().failure().code(22).stdout(" 404 0 22");

    rx.recv().unwrap();
}

#[test]
fn fail_with_body_retry_outputs_failed_and_successful_bodies() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nmoo",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nhey",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--fail-with-body",
        "--retry",
        "1",
        "--retry-delay",
        "0.001",
        &url,
    ]);
    command.assert().success().stdout("moohey");

    rx.recv().unwrap();
    rx.recv().unwrap();
}

#[test]
fn retry_after_respects_retry_max_time() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 200\r\nContent-Length: 4\r\n\r\nslow",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--retry",
        "2",
        "--retry-max-time",
        "10",
        "-w",
        " %{num_retries}",
        &url,
    ]);
    command.assert().success().stdout("slow 0");

    rx.recv().unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
}

#[test]
fn sends_json_body_and_default_json_headers() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "--json", r#"{"drink":"coffee"}"#, &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(header(&request, "content-type"), Some("application/json"));
    assert_eq!(header(&request, "accept"), Some("application/json"));
    assert_eq!(request.body, br#"{"drink":"coffee"}"#);
}

#[test]
fn http2_does_not_force_prior_knowledge() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--http2", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
}

#[test]
fn dict_define_outputs_server_lines_and_sends_request() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command
        .assert()
        .success()
        .stdout("220 dictserver <xnooptions> <msgid@msgid>\n552 No matches\n");

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"DEFINE ! basic"));
}

#[test]
fn dict_aliases_preserve_case_and_ignore_extra_fields() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let url = url.replace("/d:basic", "/Lookup:Basic:gcide:ignored");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success();

    assert_eq!(
        rx.recv().unwrap(),
        expected_dict_request(b"DEFINE gcide Basic")
    );
}

#[test]
fn dict_match_alias_sends_database_strategy_and_word() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let url = url.replace("/d:basic", "/find:curl:db:strat:ignored");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success();

    assert_eq!(
        rx.recv().unwrap(),
        expected_dict_request(b"MATCH db strat curl")
    );
}

#[test]
fn dict_empty_fields_use_curl_defaults() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let url = url.replace("/d:basic", "/m:word::");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success();

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"MATCH ! . word"));
}

#[test]
fn dict_generic_command_replaces_colons_with_spaces() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let url = url.replace("/d:basic", "/show:db:extra");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success();

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"show db extra"));
}

#[test]
fn dict_percent_decodes_and_escapes_words() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let url = url.replace("/d:basic", "/d:hello%20%22%27%5C%7F");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success();

    let mut expected = b"DEFINE ! hello\\ \\\"\\'".to_vec();
    expected.extend_from_slice(b"\\\\");
    expected.extend_from_slice(&[b'\\', 0x7f]);
    assert_eq!(rx.recv().unwrap(), expected_dict_request(&expected));
}

#[test]
fn dict_query_is_ignored_when_building_request() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let url = format!("{url}?ignored");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success();

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"DEFINE ! basic"));
}

#[test]
fn dict_head_sends_request_without_output_body() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-I",
        "-w",
        "%{size_download} %{http_code}",
        &url,
    ]);
    command.assert().success().stdout("0 000");

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"DEFINE ! basic"));
}

#[test]
fn dict_dump_header_creates_empty_file() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("dict.headers");
    let (url, rx) = spawn_dict_server(b"552 No matches\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-D", dump.to_str().unwrap(), &url]);
    command
        .assert()
        .success()
        .stdout("220 dictserver <xnooptions> <msgid@msgid>\n552 No matches\n");

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"DEFINE ! basic"));
    assert_eq!(std::fs::read(dump).unwrap(), b"");
}

#[test]
fn dict_dump_header_dash_writes_no_extra_output() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-D", "-", &url]);
    command
        .assert()
        .success()
        .stdout("220 dictserver <xnooptions> <msgid@msgid>\n552 No matches\n");

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"DEFINE ! basic"));
}

#[test]
fn dict_include_does_not_add_header_bytes() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-i", &url]);
    command
        .assert()
        .success()
        .stdout("220 dictserver <xnooptions> <msgid@msgid>\n552 No matches\n");

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"DEFINE ! basic"));
}

#[test]
fn dict_writeout_reports_zero_http_code_and_download_size() {
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let expected_size = DICT_GREETING.len() + b"552 No matches\n".len();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-w",
        " %{http_code} %{size_download} %{header_json}",
        &url,
    ]);
    command.assert().success().stdout(format!(
        "220 dictserver <xnooptions> <msgid@msgid>\n552 No matches\n 000 {expected_size} {{}}"
    ));

    assert_eq!(rx.recv().unwrap(), expected_dict_request(b"DEFINE ! basic"));
}

#[test]
fn dict_remote_name_writes_url_filename() {
    let temp = tempdir().unwrap();
    let (url, rx) = spawn_dict_server(b"552 No matches\n");
    let url = url.replace("/d:basic", "/d:result.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .current_dir(temp.path())
        .args(["-q", "-sS", "-O", &url]);
    command.assert().success().stdout("");

    assert_eq!(
        rx.recv().unwrap(),
        expected_dict_request(b"DEFINE ! result.txt")
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("d:result.txt")).unwrap(),
        "220 dictserver <xnooptions> <msgid@msgid>\n552 No matches\n"
    );
}

#[test]
fn dict_rejects_decoded_control_path() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "dict://example.invalid/d:%0A"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn version_lists_dict_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("DICT"));
}

#[test]
fn help_unknown_category_lists_categories() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args(["-q", "--help", "sdfafdsfadsfsd"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("Unknown category provided"));
    assert!(stdout.contains("\n ldap        LDAP protocol\n"));
    assert!(!stdout.contains("Usage: curl"));
}

#[test]
fn ftp_retr_downloads_file_and_sends_default_sequence() {
    let (url, rx) = spawn_ftp_server("/path/file.txt", ftp_options(b"hello from ftp"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("hello from ftp");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD path\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 1);
}

#[test]
fn ftp_directory_url_lists_with_type_a_and_list() {
    let listing = b"drwxr-xr-x pub\r\n-rw-r--r-- README\r\n";
    let (url, rx) = spawn_ftp_server("/pub/", ftp_options(&listing[..]));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command
        .assert()
        .success()
        .stdout("drwxr-xr-x pub\r\n-rw-r--r-- README\r\n");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD pub\r\nEPSV\r\nTYPE A\r\nLIST\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_list_only_uses_nlst_without_cwd_for_root() {
    let (url, rx) = spawn_ftp_server("/", ftp_options(b"one\r\ntwo\r\n"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-l", &url]);
    command.assert().success().stdout("one\r\ntwo\r\n");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE A\r\nNLST\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_uses_url_userinfo_and_falls_back_to_pasv() {
    let mut options = ftp_options(b"fallback ok");
    options.epsv_fails = true;
    let (url, rx) = spawn_ftp_server("/file.bin", options);
    let url = url.replacen("ftp://", "ftp://alice:secret@", 1);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("fallback ok");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER alice\r\nPASS secret\r\nPWD\r\nEPSV\r\nPASV\r\nTYPE I\r\nSIZE file.bin\r\nRETR file.bin\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_230_greeting_skips_user_and_password() {
    let mut options = ftp_options(b"already logged in");
    options.greeting = b"230 welcome without password\r\n";
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("already logged in");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"PWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_double_slash_cwds_to_root_before_file() {
    let (url, rx) = spawn_ftp_server("//rooted.txt", ftp_options(b"rooted"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("rooted");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD /\r\nEPSV\r\nTYPE I\r\nSIZE rooted.txt\r\nRETR rooted.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_head_outputs_synthetic_file_headers_without_data_connection() {
    let (url, rx) = spawn_ftp_server("/blalbla/141", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-sS", "-I", &url]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("last-modified: Wed, 09 Apr 2003 10:26:59 GMT\r\n"));
    assert!(stdout.contains("content-length: 0\r\n"));
    assert!(stdout.contains("accept-ranges: bytes\r\n"));

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD blalbla\r\nMDTM 141\r\nTYPE I\r\nSIZE 141\r\nREST 0\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 0);
}

#[test]
fn ftp_head_directory_only_logs_in_and_cwds() {
    let (url, rx) = spawn_ftp_server("/pub/", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-I", &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD pub\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 0);
}

#[test]
fn ftp_writeout_reports_transfer_code_and_download_size() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"abcdef"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-w",
        " code=%{response_code} size=%{size_download}",
        &url,
    ]);
    command.assert().success().stdout("abcdef code=226 size=6");

    rx.recv().unwrap();
}

#[test]
fn ftp_upload_file_sends_stor_and_body() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"uploaded over ftp\n").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSTOR target.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"uploaded over ftp\n");
    assert_eq!(record.data_connections, 1);
}

#[test]
fn ftp_upload_to_directory_url_appends_local_filename() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("client-name.txt");
    std::fs::write(&upload, b"directory upload\n").unwrap();
    let (url, rx) = spawn_ftp_server("/incoming/", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD incoming\r\nEPSV\r\nTYPE I\r\nSTOR client-name.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"directory upload\n");
}

#[test]
fn ftp_upload_stdin_uses_explicit_remote_filename() {
    let (url, rx) = spawn_ftp_server("/stdin.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", "-", &url]);
    command.write_stdin("stdin upload\n");
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSTOR stdin.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"stdin upload\n");
}

#[test]
fn ftp_upload_append_uses_appe() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"append me").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--append",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nAPPE target.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"append me");
}

#[test]
fn ftp_upload_continue_at_fixed_offset_skips_local_bytes_and_appends() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"hello").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "2", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nAPPE target.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"llo");
}

#[test]
fn ftp_upload_continue_at_auto_uses_remote_size_and_appends() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"hello").unwrap();
    let mut options = ftp_options(Vec::new());
    options.size = Some(2);
    let (url, rx) = spawn_ftp_server("/target.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE target.txt\r\nAPPE target.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"llo");
}

#[test]
fn ftp_upload_continue_at_auto_zero_size_uses_stor() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"hello").unwrap();
    let mut options = ftp_options(Vec::new());
    options.size = Some(0);
    let (url, rx) = spawn_ftp_server("/target.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE target.txt\r\nSTOR target.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"hello");
}

#[test]
fn ftp_upload_continue_at_zero_empty_file_still_sends_stor() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("empty.txt");
    std::fs::write(&upload, b"").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "0", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSTOR target.txt\r\nQUIT\r\n"
    );
    assert!(record.upload.is_empty());
    assert_eq!(record.data_connections, 1);
}

#[test]
fn ftp_upload_continue_at_complete_skips_stor() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"hello").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "5", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nQUIT\r\n"
    );
    assert!(record.upload.is_empty());
    assert_eq!(record.data_connections, 0);
}

#[test]
fn ftp_upload_stor_failure_returns_upload_failed() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"not sent").unwrap();
    let mut options = ftp_options(Vec::new());
    options.stor_denied = true;
    let (url, rx) = spawn_ftp_server("/target.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().failure().code(25).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSTOR target.txt\r\nQUIT\r\n"
    );
    assert!(record.upload.is_empty());
}

#[test]
fn ftp_upload_final_552_returns_remote_disk_full() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"full disk").unwrap();
    let mut options = ftp_options(Vec::new());
    options.stor_final = b"552 Disk full\r\n";
    let (url, rx) = spawn_ftp_server("/target.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().failure().code(70).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(record.upload, b"full disk");
}

#[test]
fn ftp_continue_at_fixed_offset_sends_rest_and_appends_output() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "hel").unwrap();
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"hello"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "3", "-o", output.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read_to_string(&output).unwrap(), "hello");
    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nREST 3\r\nRETR file.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 1);
}

#[test]
fn ftp_continue_at_auto_uses_existing_output_size() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "he").unwrap();
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"hello"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "-",
        "-o",
        output.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read_to_string(&output).unwrap(), "hello");
    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nREST 2\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_continue_at_fixed_offset_to_stdout_sends_rest() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"hello"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "2", &url]);
    command.assert().success().stdout("llo");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nREST 2\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_continue_at_auto_to_stdout_uses_zero_offset() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"hello"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", &url]);
    command.assert().success().stdout("hello");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_continue_at_without_size_still_sends_rest() {
    let mut options = ftp_options(b"hello");
    options.size = None;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "2", &url]);
    command.assert().success().stdout("llo");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nREST 2\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_continue_at_complete_skips_retr() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "hello").unwrap();
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"hello"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", "-o", output.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read_to_string(&output).unwrap(), "hello");
    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 0);
}

#[test]
fn ftp_continue_at_rest_failure_returns_rest_error() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "he").unwrap();
    let mut options = ftp_options(b"hello");
    options.rest_denied = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "2", "-o", output.to_str().unwrap(), &url]);
    command.assert().failure().code(31).stdout("");

    assert_eq!(std::fs::read_to_string(&output).unwrap(), "he");
    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nREST 2\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 0);
}

#[test]
fn ftp_continue_at_beyond_size_returns_bad_resume() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"hello"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "10", &url]);
    command.assert().failure().code(36).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 0);
}

#[test]
fn ftp_max_filesize_rejects_after_size_before_retr() {
    let (url, rx) = spawn_ftp_server("/large.bin", ftp_options(b"abcdef"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--max-filesize", "3", &url]);
    command.assert().failure().code(63).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE large.bin\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 0);
}

#[test]
fn ftp_dump_header_writes_control_replies_and_include_adds_no_bytes() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("ftp.headers");
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"body"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-i", "-D", dump.to_str().unwrap(), &url]);
    command.assert().success().stdout("body");

    let headers = String::from_utf8(std::fs::read(dump).unwrap()).unwrap();
    assert!(headers.contains("220 curl FTP test server\r\n"));
    assert!(headers.contains("226 Transfer complete\r\n"));
    rx.recv().unwrap();
}

#[test]
fn ftp_login_failure_returns_login_denied() {
    let mut options = ftp_options(Vec::new());
    options.login_denied = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(67).stdout("");

    assert_eq!(rx.recv().unwrap().commands, b"USER anonymous\r\n");
}

#[test]
fn ftp_cwd_failure_returns_remote_access_denied() {
    let mut options = ftp_options(Vec::new());
    options.cwd_denied = true;
    let (url, rx) = spawn_ftp_server("/private/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(9).stdout("");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD private\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_create_dirs_makes_missing_directory_and_retries_cwd() {
    let mut options = ftp_options(b"created path");
    options.missing_directories = vec!["first"];
    let (url, rx) = spawn_ftp_server("/first/dir/here/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--ftp-create-dirs", &url]);
    command.assert().success().stdout("created path");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD first\r\nMKD first\r\nCWD first\r\nCWD dir\r\nCWD here\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_create_dirs_retries_cwd_after_failed_mkd_then_returns_9() {
    let mut options = ftp_options(Vec::new());
    options.missing_directories = vec!["attempt"];
    options.mkd_denied = true;
    let (url, rx) = spawn_ftp_server("/attempt/to/get/this/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--ftp-create-dirs", &url]);
    command.assert().failure().code(9).stdout("");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD attempt\r\nMKD attempt\r\nCWD attempt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_upload_create_dirs_makes_missing_directory_before_stor() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"upload into created path").unwrap();
    let mut options = ftp_options(Vec::new());
    options.missing_directories = vec!["incoming"];
    let (url, rx) = spawn_ftp_server("/incoming/nested/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ftp-create-dirs",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD incoming\r\nMKD incoming\r\nCWD incoming\r\nCWD nested\r\nEPSV\r\nTYPE I\r\nSTOR file.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"upload into created path");
}

#[test]
fn ftp_quote_prequote_postquote_order_and_ignored_failures() {
    let mut options = ftp_options(b"quoted body");
    options.epsv_fails = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-Q",
        "NOOP 1",
        "-Q",
        "+NOOP 2",
        "-Q",
        "-NOOP 3",
        "-Q",
        "*FAIL",
        "-Q",
        "+*FAIL HARD",
        &url,
    ]);
    command.assert().success().stdout("quoted body");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nNOOP 1\r\nFAIL\r\nEPSV\r\nPASV\r\nTYPE I\r\nNOOP 2\r\nFAIL HARD\r\nSIZE file.txt\r\nRETR file.txt\r\nNOOP 3\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_quote_order_for_directory_listing() {
    let (url, rx) = spawn_ftp_server("/path/", ftp_options(b"listing\r\n"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q", "-sS", "--quote", "NOOP 1", "--quote", "+NOOP 2", "--quote", "-NOOP 3", &url,
    ]);
    command.assert().success().stdout("listing\r\n");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nNOOP 1\r\nCWD path\r\nEPSV\r\nTYPE A\r\nNOOP 2\r\nLIST\r\nNOOP 3\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_quote_failure_returns_quote_error_and_quits() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"not downloaded"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-Q", "FAIL HARD", &url]);
    command.assert().failure().code(21).stdout("");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nFAIL HARD\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_postquote_failure_returns_quote_error_after_writing_body() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"downloaded first"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-Q", "-FAIL after", &url]);
    command
        .assert()
        .failure()
        .code(21)
        .stdout("downloaded first");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nFAIL after\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_postquote_is_skipped_after_output_write_failure() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("missing").join("download.txt");
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"downloaded first"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-o",
        output.to_str().unwrap(),
        "-Q",
        "-DELE after",
        &url,
    ]);
    command.assert().failure().code(23).stdout("");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_postquote_is_skipped_after_buffered_max_filesize_failure() {
    let mut options = ftp_options(b"abcdef");
    options.size = None;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--max-filesize",
        "3",
        "-Q",
        "-DELE after",
        &url,
    ]);
    command.assert().failure().code(63).stdout("abc");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.data_connections, 1);
}

#[test]
fn ftp_postquote_is_skipped_after_failed_transfer() {
    let mut options = ftp_options(b"not downloaded");
    options.retr_denied = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-Q", "-DELE after", &url]);
    command.assert().failure().code(78).stdout("");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_upload_prequote_runs_before_stor() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"upload with quote").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-Q",
        "+NOOP before-stor",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nNOOP before-stor\r\nSTOR target.txt\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"upload with quote");
}

#[test]
fn ftp_upload_postquote_runs_after_successful_stor() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"upload before postquote").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-Q",
        "-DELE uploaded",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSTOR target.txt\r\nDELE uploaded\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"upload before postquote");
}

#[test]
fn ftp_head_prequote_runs_before_size() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args(["-q", "-sS", "-I", "-Q", "+NOOP before-size", &url])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("content-length: 0\r\n"));

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nMDTM file.txt\r\nTYPE I\r\nNOOP before-size\r\nSIZE file.txt\r\nREST 0\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_pwd_failure_is_ignored_before_download() {
    let mut options = ftp_options(b"downloaded after bad pwd\n".to_vec());
    options.pwd_denied = true;
    options.epsv_fails = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command
        .assert()
        .success()
        .stdout("downloaded after bad pwd\n");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nPASV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_passive_failure_returns_13() {
    let mut options = ftp_options(Vec::new());
    options.epsv_fails = true;
    options.pasv_denied = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(13).stdout("");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nPASV\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_malformed_pasv_reply_returns_14() {
    let mut options = ftp_options(Vec::new());
    options.epsv_fails = true;
    options.pasv_reply = Some(b"227 Entering Passive Mode (1216,256,2,127,127,127)\r\n");
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(14).stdout("");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nPASV\r\n"
    );
}

#[test]
fn ftp_default_skips_pasv_ip() {
    let mut options = ftp_options(b"downloaded");
    options.epsv_fails = true;
    options.pasv_host = [203, 0, 113, 1];
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("downloaded");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nPASV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_epsv_connect_failure_falls_back_to_pasv() {
    let mut options = ftp_options(b"downloaded");
    options.epsv_bad_port = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("downloaded");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nPASV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_disable_epsv_uses_pasv_directly() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"downloaded"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--disable-epsv", &url]);
    command.assert().success().stdout("downloaded");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nPASV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_epsv_reenables_after_disable_epsv() {
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"downloaded"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--disable-epsv", "--epsv", &url]);
    command.assert().success().stdout("downloaded");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_ipv6_disable_epsv_still_uses_epsv() {
    let Some((url, rx)) = spawn_ftp_server_ipv6("/", ftp_options(b"listing\n")) else {
        return;
    };

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--disable-epsv", "-g", &url]);
    command.assert().success().stdout("listing\n");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE A\r\nLIST\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_skip_pasv_ip_uses_control_host() {
    let mut options = ftp_options(b"downloaded");
    options.epsv_fails = true;
    options.pasv_host = [203, 0, 113, 1];
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--ftp-skip-pasv-ip", &url]);
    command.assert().success().stdout("downloaded");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nPASV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_type_failure_returns_17() {
    let mut options = ftp_options(Vec::new());
    options.type_denied = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(17).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_retr_550_returns_remote_file_not_found() {
    let mut options = ftp_options(Vec::new());
    options.retr_denied = true;
    let (url, rx) = spawn_ftp_server("/missing.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(78).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE missing.txt\r\nRETR missing.txt\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_list_failure_returns_19() {
    let mut options = ftp_options(Vec::new());
    options.retr_denied = true;
    let (url, rx) = spawn_ftp_server("/dir/", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(19).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD dir\r\nEPSV\r\nTYPE A\r\nLIST\r\nQUIT\r\n"
    );
}

#[test]
fn ftp_rejects_decoded_control_path() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "ftp://example.invalid/file%0dname"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn version_lists_ftp_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("FTP"));
}

#[test]
fn pop3_retr_downloads_message_and_unstuffs_dot_lines() {
    let (url, rx) = spawn_pop3_server("/42", b"+OK message follows\r\nFrom: me\r\n..body\r\n.\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().success().stdout("From: me\r\n.body\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nRETR 42\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_skips_initial_banner_before_greeting() {
    let greeting = b"        _   _ ____  _\r\n    ___| | | |  _ \\| |\r\n   / __| | | | |_) | |\r\n  | (__| |_| |  _ {| |___\r\n   \\___|\\___/|_| \\_\\_____|\r\n+OK curl POP3 server ready to serve\r\n";
    let (url, rx) =
        spawn_pop3_server_with_greeting("/850", greeting, b"+OK message follows\r\nhello\r\n.\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().success().stdout("hello\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nRETR 850\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_uses_url_userinfo_when_user_option_is_absent() {
    let (url, rx) = spawn_pop3_server("/42", b"+OK message follows\r\nhello\r\n.\r\n");
    let url = url.replacen("pop3://", "pop3://alice:secret@", 1);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("hello\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER alice\r\nPASS secret\r\nRETR 42\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_empty_path_lists_messages() {
    let (url, rx) = spawn_pop3_server("/", b"+OK scan listing follows\r\n1 100\r\n.\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().success().stdout("1 100\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nLIST\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_list_only_sends_list_for_message_id_without_body() {
    let (url, rx) = spawn_pop3_server("/42", b"+OK 42 100\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-l", "-u", "user:secret", &url]);
    command.assert().success().stdout("");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nLIST 42\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_command_error_returns_weird_server_reply() {
    let (url, rx) = spawn_pop3_server("/42", b"-ERR no such message\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-l", "-u", "user:secret", &url]);
    command.assert().failure().code(8).stdout("");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nLIST 42\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_retr_command_error_sends_quit_and_returns_weird_server_reply() {
    let (url, rx) = spawn_pop3_server("/42", b"-ERR no such message\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().failure().code(8).stdout("");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nRETR 42\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_custom_top_outputs_multiline_body() {
    let (url, rx) = spawn_pop3_server("", b"+OK top follows\r\nSubject: hi\r\n\r\n.\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", "-X", "TOP 42 0", &url]);
    command.assert().success().stdout("Subject: hi\r\n\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nTOP 42 0\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_head_custom_stat_suppresses_body_and_keeps_zero_http_code() {
    let (url, rx) = spawn_pop3_server("", b"+OK 2 200\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-I",
        "-u",
        "user:secret",
        "-X",
        "STAT",
        "-w",
        "%{http_code} %{size_download} %{header_json}",
        &url,
    ]);
    command.assert().success().stdout("000 0 {}");

    assert_eq!(
        rx.recv().unwrap(),
        b"CAPA\r\nUSER user\r\nPASS secret\r\nSTAT\r\nQUIT\r\n"
    );
}

#[test]
fn pop3_rejects_decoded_control_path() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "pop3://example.invalid/%0d%0a/42"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn pop3_login_failure_returns_login_denied() {
    let (url, rx) = spawn_pop3_login_denied_server("/42");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:wrong", &url]);
    command.assert().failure().code(67).stdout("");

    assert_eq!(rx.recv().unwrap(), b"CAPA\r\nUSER user\r\nPASS wrong\r\n");
}

#[test]
fn version_lists_pop3_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("POP3"));
}

#[test]
fn imap_fetch_mailindex_outputs_literal_and_quotes_login_atoms() {
    let (url, rx) = spawn_imap_server(
        "/inbox/;MAILINDEX=1",
        vec![(
            "FETCH 1 BODY[]",
            b"* 1 FETCH (BODY[] {7}\r\nhello\r\n{tag} OK FETCH completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "\"user:sec\"ret{", &url]);
    command.assert().success().stdout("hello\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN \"\\\"user\" \"sec\\\"ret{\"\r\nA003 SELECT inbox\r\nA004 FETCH 1 BODY[]\r\nA005 LOGOUT\r\n"
    );
}

#[test]
fn imap_uses_url_userinfo_and_uid_section_fetch() {
    let (url, rx) = spawn_imap_server(
        "/mailbox/;UID=42/;SECTION=TEXT",
        vec![(
            "UID FETCH 42 BODY[TEXT]",
            b"* 42 FETCH (BODY[TEXT] {4}\r\nbody{tag} OK FETCH completed\r\n",
        )],
    );
    let url = url.replacen("imap://", "imap://alice:secret@", 1);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("body");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN alice secret\r\nA003 SELECT mailbox\r\nA004 UID FETCH 42 BODY[TEXT]\r\nA005 LOGOUT\r\n"
    );
}

#[test]
fn imap_lists_mailbox_without_select() {
    let (url, rx) = spawn_imap_server(
        "/mailbox",
        vec![(
            "LIST \"mailbox\" *",
            b"* LIST () \"/\" /mailbox/one\r\n* LIST (\\Noselect) \"/\" /mailbox/two\r\n{tag} OK LIST completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command
        .assert()
        .success()
        .stdout("* LIST () \"/\" /mailbox/one\r\n* LIST (\\Noselect) \"/\" /mailbox/two\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 LIST \"mailbox\" *\r\nA004 LOGOUT\r\n"
    );
}

#[test]
fn imap_skips_initial_banner_before_greeting() {
    let greeting = b"        _   _ ____  _\r\n    ___| | | |  _ \\| |\r\n   / __| | | | |_) | |\r\n  | (__| |_| |  _ {| |___\r\n   \\___|\\___/|_| \\_\\_____|\r\n* OK curl IMAP server ready to serve\r\n";
    let (url, rx) = spawn_imap_server_with_greeting(
        "/806",
        greeting,
        vec![(
            "LIST \"806\" *",
            b"* LIST () \"/\" /806/blurdybloop\r\n{tag} OK LIST completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command
        .assert()
        .success()
        .stdout("* LIST () \"/\" /806/blurdybloop\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 LIST \"806\" *\r\nA004 LOGOUT\r\n"
    );
}

#[test]
fn imap_search_uses_url_query_after_select() {
    let (url, rx) = spawn_imap_server(
        "/mailbox?NEW",
        vec![(
            "SEARCH NEW",
            b"* SEARCH 1 123 456\r\n{tag} OK SEARCH completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().success().stdout("* SEARCH 1 123 456\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 SELECT mailbox\r\nA004 SEARCH NEW\r\nA005 LOGOUT\r\n"
    );
}

#[test]
fn imap_custom_noop_without_mailbox_outputs_untagged_lines() {
    let (url, rx) = spawn_imap_server(
        "/",
        vec![(
            "NOOP",
            b"* 22 EXPUNGE\r\n* 23 EXISTS\r\n{tag} OK NOOP completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", "-X", "NOOP", &url]);
    command
        .assert()
        .success()
        .stdout("* 22 EXPUNGE\r\n* 23 EXISTS\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 NOOP\r\nA004 LOGOUT\r\n"
    );
}

#[test]
fn imap_without_credentials_skips_login() {
    let (url, rx) = spawn_imap_server(
        "/mailbox",
        vec![(
            "LIST \"mailbox\" *",
            b"* LIST () \"/\" /mailbox/one\r\n{tag} OK LIST completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command
        .assert()
        .success()
        .stdout("* LIST () \"/\" /mailbox/one\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LIST \"mailbox\" *\r\nA003 LOGOUT\r\n"
    );
}

#[test]
fn imap_custom_fetch_outputs_envelope_and_literal() {
    let (url, rx) = spawn_imap_server(
        "/mailbox",
        vec![(
            "UID FETCH 1 BODY[]",
            b"* 1 FETCH (BODY[] {4}\r\nbody{tag} OK FETCH completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-u",
        "user:secret",
        "-X",
        "UID FETCH 1 BODY[]",
        &url,
    ]);
    command
        .assert()
        .success()
        .stdout("* 1 FETCH (BODY[] {4}\r\nbody");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 SELECT mailbox\r\nA004 UID FETCH 1 BODY[]\r\nA005 LOGOUT\r\n"
    );
}

#[test]
fn imap_custom_fetch_suppresses_literal_trailer_and_ignores_quoted_braces() {
    let (url, rx) = spawn_imap_server(
        "/mailbox/",
        vec![(
            "FETCH 456 (\"fake {50}\" BODY[TEXT])",
            b"* 456 FETCH ((\"fake {50}\" BODY[TEXT]) {5}\r\nhello)\r\n{tag} OK FETCH completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-u",
        "user:secret",
        "-X",
        "FETCH 456 (\"fake {50}\" BODY[TEXT])",
        &url,
    ]);
    command
        .assert()
        .success()
        .stdout("* 456 FETCH ((\"fake {50}\" BODY[TEXT]) {5}\r\nhello");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 SELECT mailbox\r\nA004 FETCH 456 (\"fake {50}\" BODY[TEXT])\r\nA005 LOGOUT\r\n"
    );
}

#[test]
fn imap_custom_command_failure_exits_quote_error() {
    let (url, rx) = spawn_imap_server("/", vec![("NOOP", b"{tag} NO command rejected\r\n")]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", "-X", "NOOP", &url]);
    command.assert().failure().code(21).stdout("");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 NOOP\r\nA004 LOGOUT\r\n"
    );
}

#[test]
fn imap_uidvalidity_mismatch_exits_remote_file_not_found() {
    let (url, rx) = spawn_imap_server(
        "/mailbox;UIDVALIDITY=123/;MAILINDEX=1",
        vec![(
            "SELECT mailbox",
            b"* OK [UIDVALIDITY 456] UIDs valid\r\n{tag} OK SELECT completed\r\n",
        )],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().failure().code(78).stdout("");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user secret\r\nA003 SELECT mailbox\r\nA004 LOGOUT\r\n"
    );
}

#[test]
fn imap_login_failure_returns_login_denied() {
    let (url, rx) = spawn_imap_login_denied_server("/mailbox/;MAILINDEX=1");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:wrong", &url]);
    command.assert().failure().code(67).stdout("");

    assert_eq!(
        rx.recv().unwrap(),
        b"A001 CAPABILITY\r\nA002 LOGIN user wrong\r\n"
    );
}

#[test]
fn imap_rejects_decoded_control_path() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "imap://example.invalid/%0d%0a/mailbox"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn version_lists_imap_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("IMAP"));
}

#[test]
fn smtp_upload_sends_mail_transaction_and_dot_stuffs_body() {
    let (url, rx) = spawn_smtp_server("/mail.example", b"250 mail.example\r\n", b"250 ok\r\n");
    let upload = b"From: sender\r\n\r\n.body\r\n";

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .args([
            "-q",
            "-sS",
            "--mail-from",
            "sender@example.com",
            "--mail-rcpt",
            "recipient@example.com",
            "-T",
            "-",
            &url,
        ])
        .write_stdin(upload.as_slice());
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO mail.example\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<recipient@example.com>\r\nDATA\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"From: sender\r\n\r\n..body\r\n.\r\n");
}

#[test]
fn smtp_upload_file_adds_size_when_server_advertises_size() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("mail.txt");
    std::fs::write(&upload, b"Subject: hi\r\n\r\nbody\r\n").unwrap();
    let (url, rx) = spawn_smtp_server(
        "/size.example",
        b"250-size.example\r\n250 SIZE\r\n",
        b"250 ok\r\n",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--mail-from",
        "<sender@example.com> RET=HDRS",
        "--mail-rcpt",
        "<recipient@example.com> NOTIFY=SUCCESS,FAILURE",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO size.example\r\nMAIL FROM:<sender@example.com> RET=HDRS SIZE=21\r\nRCPT TO:<recipient@example.com> NOTIFY=SUCCESS,FAILURE\r\nDATA\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"Subject: hi\r\n\r\nbody\r\n.\r\n");
}

#[test]
fn smtp_default_vrfy_outputs_response_and_code() {
    let (url, rx) = spawn_smtp_server("/vrfy.example", b"250 vrfy.example\r\n", b"252 maybe\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--mail-rcpt",
        "user@example.com",
        "-w",
        " %{http_code} %{size_download}",
        &url,
    ]);
    command.assert().success().stdout("252 maybe\r\n 252 11");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO vrfy.example\r\nVRFY user@example.com\r\nQUIT\r\n"
    );
    assert!(record.upload.is_empty());
}

#[test]
fn smtp_custom_expn_uses_mail_recipient() {
    let (url, rx) = spawn_smtp_server(
        "/expn.example",
        b"250 expn.example\r\n",
        b"250 Friend <friend@example.com>\r\n",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--mail-rcpt", "Friends", "-X", "EXPN", &url]);
    command
        .assert()
        .success()
        .stdout("250 Friend <friend@example.com>\r\n");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO expn.example\r\nEXPN Friends\r\nQUIT\r\n"
    );
    assert!(record.upload.is_empty());
}

#[test]
fn smtp_custom_expn_adds_smtputf8_when_advertised() {
    let (url, rx) = spawn_smtp_server(
        "/expn.example",
        b"250-expn.example\r\n250 SMTPUTF8\r\n",
        b"250 Friend <friend@example.com>\r\n",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--mail-rcpt", "Friends", "-X", "EXPN", &url]);
    command
        .assert()
        .success()
        .stdout("250 Friend <friend@example.com>\r\n");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO expn.example\r\nEXPN Friends SMTPUTF8\r\nQUIT\r\n"
    );
    assert!(record.upload.is_empty());
}

#[test]
fn smtp_recipient_failure_returns_send_error() {
    let (url, rx) = spawn_smtp_server_with_rcpt_responses(
        "/send.example",
        b"250 send.example\r\n",
        b"250 ok\r\n",
        vec![b"550 rejected\r\n"],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .args([
            "-q",
            "-sS",
            "--mail-from",
            "sender@example.com",
            "--mail-rcpt",
            "bad@example.com",
            "-T",
            "-",
            &url,
        ])
        .write_stdin("body\r\n");
    command.assert().failure().code(55).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO send.example\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<bad@example.com>\r\nQUIT\r\n"
    );
    assert!(record.upload.is_empty());
}

#[test]
fn smtp_rcpt_allowfails_continues_when_one_recipient_succeeds() {
    let (url, rx) = spawn_smtp_server_with_rcpt_responses(
        "/allow.example",
        b"250 allow.example\r\n",
        b"250 ok\r\n",
        vec![b"550 rejected\r\n", b"250 accepted\r\n"],
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .args([
            "-q",
            "-sS",
            "--mail-rcpt-allowfails",
            "--mail-from",
            "sender@example.com",
            "--mail-rcpt",
            "bad@example.com",
            "--mail-rcpt",
            "good@example.com",
            "-T",
            "-",
            &url,
        ])
        .write_stdin("body\r\n");
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO allow.example\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<bad@example.com>\r\nRCPT TO:<good@example.com>\r\nDATA\r\nQUIT\r\n"
    );
    assert_eq!(record.upload, b"body\r\n.\r\n");
}

#[test]
fn smtp_rejects_decoded_control_path() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "smtp://example.invalid/%0d%0a/name"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn version_lists_smtp_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("SMTP"));
}

#[test]
fn tftp_get_downloads_file_and_sends_default_options() {
    let (url, rx) = spawn_tftp_server(vec![b"hello from tftp".to_vec()]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("hello from tftp");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.request,
        b"\x00\x01file.txt\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x005\x00"
    );
    assert_eq!(record.acknowledgements, [b"\0\x04\0\x01".to_vec()]);
}

#[test]
fn tftp_local_port_binds_udp_socket() {
    let local_port = unused_local_udp_port();
    let (url, rx) = spawn_tftp_server(vec![b"bound".to_vec()]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--local-port", &local_port.to_string(), &url]);
    command.assert().success().stdout("bound");

    let record = rx.recv().unwrap();
    assert_eq!(record.peer.port(), local_port);
    assert_eq!(
        record.request,
        b"\x00\x01file.txt\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x005\x00"
    );
}

#[test]
fn tftp_interface_binds_udp_socket_to_host() {
    let (url, rx) = spawn_tftp_server(vec![b"bound".to_vec()]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--interface", "host!127.0.0.1", &url]);
    command.assert().success().stdout("bound");

    let record = rx.recv().unwrap();
    assert_eq!(record.peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        record.request,
        b"\x00\x01file.txt\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x005\x00"
    );
}

#[test]
fn tftp_interface_name_failure_returns_45() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--interface",
        "if!curl-rust-missing-interface",
        "tftp://127.0.0.1:9/file.txt",
    ]);
    command.assert().code(45).stdout("");
}

#[test]
fn tftp_low_speed_timeout_returns_28() {
    let (url, rx) = spawn_slow_tftp_server(Duration::from_millis(1200));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-Y1000", "-y1", &url]);
    command.assert().failure().code(28).stdout("").stderr(
        "curl: (28) Operation too slow. Less than 1000 bytes/sec transferred the last 1 seconds\n",
    );

    let record = rx.recv().unwrap();
    assert_eq!(record.acknowledgements.len(), 2);
    assert_eq!(
        record.request,
        b"\x00\x01file.txt\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x005\x00"
    );
}

#[test]
fn tftp_get_acks_oack_and_each_data_block() {
    let first = vec![b'a'; 8];
    let second = b"tail".to_vec();
    let (url, rx) = spawn_tftp_server_with_oack(
        vec![first.clone(), second.clone()],
        Some(tftp_oack(&[("blksize", "8"), ("tsize", "12")])),
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-blksize", "8", &url]);
    command.assert().success().stdout("aaaaaaaatail");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.request,
        b"\x00\x01file.txt\x00octet\x00tsize\x000\x00blksize\x008\x00timeout\x005\x00"
    );
    assert_eq!(
        record.acknowledgements,
        [
            b"\0\x04\0\0".to_vec(),
            b"\0\x04\0\x01".to_vec(),
            b"\0\x04\0\x02".to_vec()
        ]
    );
}

#[test]
fn tftp_exact_block_requires_final_empty_block() {
    let (url, rx) = spawn_tftp_server_with_oack(
        vec![vec![b'x'; 8], Vec::new()],
        Some(tftp_oack(&[("blksize", "8")])),
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-blksize", "8", &url]);
    command.assert().success().stdout("xxxxxxxx");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.acknowledgements,
        [
            b"\0\x04\0\0".to_vec(),
            b"\0\x04\0\x01".to_vec(),
            b"\0\x04\0\x02".to_vec()
        ]
    );
}

#[test]
fn tftp_oack_without_blksize_falls_back_to_default_block_size() {
    let first = vec![b'a'; 512];
    let second = b"tail".to_vec();
    let (url, rx) =
        spawn_tftp_server_with_oack(vec![first, second], Some(tftp_oack(&[("tsize", "516")])));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-blksize", "1024", &url]);
    command
        .assert()
        .success()
        .stdout(format!("{}tail", "a".repeat(512)));

    let record = rx.recv().unwrap();
    assert_eq!(
        record.acknowledgements,
        [
            b"\0\x04\0\0".to_vec(),
            b"\0\x04\0\x01".to_vec(),
            b"\0\x04\0\x02".to_vec()
        ]
    );
}

#[test]
fn tftp_oack_rejects_malformed_option_pair() {
    let mut oack = Vec::from(&6_u16.to_be_bytes()[..]);
    oack.extend_from_slice(b"blksize\0");
    let (url, rx) = spawn_tftp_oack_once(oack);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(71).stdout("");

    assert!(rx.recv().unwrap().starts_with(b"\0\x01file.txt\0octet\0"));
}

#[test]
fn tftp_oack_rejects_block_size_larger_than_requested() {
    let (url, rx) = spawn_tftp_oack_once(tftp_oack(&[("blksize", "16")]));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-blksize", "8", &url]);
    command.assert().failure().code(71).stdout("");

    assert!(rx.recv().unwrap().starts_with(b"\0\x01file.txt\0octet\0"));
}

#[test]
fn tftp_oack_rejects_invalid_block_size_values() {
    for value in ["", "abc", "0", "7", "65465"] {
        let (url, rx) = spawn_tftp_oack_once(tftp_oack(&[("blksize", value)]));

        let mut command = Command::cargo_bin("curl").unwrap();
        command.args(["-q", "-sS", &url]);
        command.assert().failure().code(71).stdout("");

        assert!(
            rx.recv().unwrap().starts_with(b"\0\x01file.txt\0octet\0"),
            "request was not captured for blksize={value:?}"
        );
    }
}

#[test]
fn tftp_oack_accepts_case_insensitive_numeric_prefix_block_size() {
    let (url, rx) = spawn_tftp_server_with_oack(
        vec![vec![b'a'; 8], b"tail".to_vec()],
        Some(tftp_oack(&[("BLKSIZE", "0008junk")])),
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-blksize", "8", &url]);
    command.assert().success().stdout("aaaaaaaatail");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.acknowledgements,
        [
            b"\0\x04\0\0".to_vec(),
            b"\0\x04\0\x01".to_vec(),
            b"\0\x04\0\x02".to_vec()
        ]
    );
}

#[test]
fn tftp_oack_rejects_zero_download_tsize() {
    let (url, rx) = spawn_tftp_oack_once(tftp_oack(&[("tsize", "0")]));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(71).stdout("");

    assert!(rx.recv().unwrap().starts_with(b"\0\x01file.txt\0octet\0"));
}

#[test]
fn tftp_no_options_sends_plain_rrq() {
    let (url, rx) = spawn_tftp_server(vec![b"plain".to_vec()]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", &url]);
    command.assert().success().stdout("plain");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x01file.txt\0octet\0");
}

#[test]
fn tftp_url_double_slash_preserves_leading_filename_slash() {
    let (url, rx) = spawn_tftp_server(vec![b"path".to_vec()]);
    let url = url.replace("/file.txt", "//dir/file.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", &url]);
    command.assert().success().stdout("path");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x01/dir/file.txt\0octet\0");
}

#[test]
fn tftp_use_ascii_sends_netascii_mode() {
    let (url, rx) = spawn_tftp_server(vec![b"ascii".to_vec()]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", "--use-ascii", &url]);
    command.assert().success().stdout("ascii");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x01file.txt\0netascii\0");
}

#[test]
fn tftp_mode_octet_suffix_overrides_use_ascii() {
    let (url, rx) = spawn_tftp_server(vec![b"octet".to_vec()]);
    let url = url.replace("/file.txt", "/file.txt;mode=octet");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", "--use-ascii", &url]);
    command.assert().success().stdout("octet");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x01file.txt\0octet\0");
}

#[test]
fn tftp_mode_netascii_suffix_sends_netascii() {
    let (url, rx) = spawn_tftp_server(vec![b"suffix".to_vec()]);
    let url = url.replace("/file.txt", "/file.txt;mode=netascii");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", &url]);
    command.assert().success().stdout("suffix");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x01file.txt\0netascii\0");
}

#[test]
fn tftp_encoded_mode_suffix_is_part_of_filename() {
    let (url, rx) = spawn_tftp_server(vec![b"encoded".to_vec()]);
    let url = url.replace("/file.txt", "/file%3Bmode%3Doctet");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", "--use-ascii", &url]);
    command.assert().success().stdout("encoded");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x01file;mode=octet\0netascii\0");
}

#[test]
fn tftp_mixed_case_mode_suffix_is_part_of_filename() {
    let (url, rx) = spawn_tftp_server(vec![b"mixed".to_vec()]);
    let url = url.replace("/file.txt", "/file.txt;mode=OCTET");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", "--use-ascii", &url]);
    command.assert().success().stdout("mixed");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x01file.txt;mode=OCTET\0netascii\0");
}

#[test]
fn tftp_writeout_reports_zero_http_code_and_download_size() {
    let (url, rx) = spawn_tftp_server(vec![b"abcdef".to_vec()]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-w", " %{http_code} %{size_download}", &url]);
    command.assert().success().stdout("abcdef 000 6");

    assert_eq!(
        rx.recv().unwrap().acknowledgements,
        [b"\0\x04\0\x01".to_vec()]
    );
}

#[test]
fn tftp_error_packet_maps_not_found() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = vec![0; 2048];
        let (read, peer) = socket.recv_from(&mut buffer).unwrap();
        tx.send(buffer[..read].to_vec()).unwrap();
        let mut packet = Vec::from(&5_u16.to_be_bytes()[..]);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(b"missing");
        packet.push(0);
        socket.send_to(&packet, peer).unwrap();
    });

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &format!("tftp://{addr}/missing.txt")]);
    command.assert().failure().code(68).stdout("");

    assert!(
        rx.recv()
            .unwrap()
            .starts_with(b"\0\x01missing.txt\0octet\0")
    );
}

#[test]
fn tftp_missing_first_url_does_not_override_later_success() {
    let (base_url, rx) = spawn_tftp_missing_then_success_server(vec![b"found".to_vec()]);
    let missing_url = format!("{base_url}/missing.txt");
    let found_url = format!("{base_url}/found.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &missing_url, &found_url]);
    command
        .assert()
        .success()
        .stdout("found")
        .stderr("curl: (68) TFTP: File Not Found\n");

    let record = rx.recv().unwrap();
    assert_eq!(record.requests.len(), 2);
    assert!(record.requests[0].starts_with(b"\0\x01missing.txt\0octet\0"));
    assert!(record.requests[1].starts_with(b"\0\x01found.txt\0octet\0"));
    assert_eq!(record.acknowledgements, [b"\0\x04\0\x01".to_vec()]);
}

#[test]
fn tftp_rejects_decoded_nul_path() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "tftp://example.invalid/%00"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn tftp_rejects_initial_request_packet_over_default_block_size() {
    let filename = "a".repeat(504);
    let url = format!("tftp://127.0.0.1:9/{filename}");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--max-time", "1", &url]);
    command.assert().failure().code(71).stdout("");
}

#[test]
fn tftp_requested_block_size_does_not_expand_initial_request_limit() {
    let filename = "a".repeat(504);
    let url = format!("tftp://127.0.0.1:9/{filename}");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--max-time",
        "1",
        "--tftp-blksize",
        "1024",
        &url,
    ]);
    command.assert().failure().code(71).stdout("");
}

#[test]
fn tftp_no_options_allows_initial_request_at_default_block_size() {
    let filename = "a".repeat(503);
    let path = format!("/{filename}");
    let (url, rx) = spawn_tftp_server(vec![b"fits".to_vec()]);
    let url = url.replace("/file.txt", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--tftp-no-options", &url]);
    command.assert().success().stdout("fits");

    let record = rx.recv().unwrap();
    assert_eq!(record.request.len(), 512);
    assert_eq!(&record.request[..2], b"\0\x01");
    assert_eq!(&record.request[2..2 + filename.len()], filename.as_bytes());
    assert_eq!(&record.request[2 + filename.len()..], b"\0octet\0");
}

#[test]
fn tftp_upload_file_sends_wrq_and_data() {
    let (url, rx) = spawn_tftp_upload_server(tftp_ack(0), 512);
    let url = url.replace("/upload.bin", "//");
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.bin");
    let body = b"a chunk\nof upload\n";
    std::fs::write(&upload, body).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    let mut expected = b"\x00\x02/payload.bin\x00octet\x00tsize\x00".to_vec();
    expected.extend_from_slice(body.len().to_string().as_bytes());
    expected.extend_from_slice(b"\x00blksize\x00512\x00timeout\x005\x00");
    assert_eq!(record.request, expected);
    assert_eq!(record.data_blocks, [(1, body.to_vec())]);
}

#[test]
fn tftp_upload_low_speed_timeout_returns_28() {
    let (url, rx) = spawn_delayed_tftp_upload_ack_server(Duration::from_millis(1200));
    let temp = tempdir().unwrap();
    let upload = temp.path().join("slow.bin");
    let body = b"slow upload";
    std::fs::write(&upload, body).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-Y1000",
        "-y1",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().failure().code(28).stdout("").stderr(
        "curl: (28) Operation too slow. Less than 1000 bytes/sec transferred the last 1 seconds\n",
    );

    let record = rx.recv().unwrap();
    let mut expected = b"\x00\x02upload.bin\x00octet\x00tsize\x00".to_vec();
    expected.extend_from_slice(body.len().to_string().as_bytes());
    expected.extend_from_slice(b"\x00blksize\x00512\x00timeout\x005\x00");
    assert_eq!(record.request, expected);
    assert_eq!(record.data_blocks, [(1, body.to_vec())]);
}

#[test]
fn tftp_upload_timeout_option_uses_connect_deadline() {
    let (url, rx) = spawn_tftp_upload_server(tftp_ack(0), 512);
    let url = url.replace("/upload.bin", "//");
    let temp = tempdir().unwrap();
    let upload = temp.path().join("test285.txt");
    let body = b"a chunk of\ndata\nsent\n to server\n";
    std::fs::write(&upload, body).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-T",
        upload.to_str().unwrap(),
        &url,
        "--connect-timeout",
        "549",
        "--max-time",
        "599",
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    let mut expected = b"\x00\x02/test285.txt\x00octet\x00tsize\x00".to_vec();
    expected.extend_from_slice(body.len().to_string().as_bytes());
    expected.extend_from_slice(b"\x00blksize\x00512\x00timeout\x0010\x00");
    assert_eq!(record.request, expected);
    assert_eq!(record.data_blocks, [(1, body.to_vec())]);
}

#[test]
fn tftp_upload_oack_exact_block_sends_final_empty_block() {
    let body = b"12345678";
    let (url, rx) = spawn_tftp_upload_server(tftp_oack(&[("blksize", "8")]), 8);
    let temp = tempdir().unwrap();
    let upload = temp.path().join("exact.bin");
    std::fs::write(&upload, body).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--tftp-blksize",
        "8",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    let mut expected = b"\x00\x02upload.bin\x00octet\x00tsize\x00".to_vec();
    expected.extend_from_slice(body.len().to_string().as_bytes());
    expected.extend_from_slice(b"\x00blksize\x008\x00timeout\x005\x00");
    assert_eq!(record.request, expected);
    assert_eq!(record.data_blocks, [(1, body.to_vec()), (2, Vec::new())]);
}

#[test]
fn tftp_upload_oack_without_blksize_falls_back_to_default_block_size() {
    let body = b"larger than eight bytes";
    let (url, rx) = spawn_tftp_upload_server(tftp_oack(&[("tsize", "999")]), 512);
    let temp = tempdir().unwrap();
    let upload = temp.path().join("fallback.bin");
    std::fs::write(&upload, body).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--tftp-blksize",
        "8",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    let mut expected = b"\x00\x02upload.bin\x00octet\x00tsize\x00".to_vec();
    expected.extend_from_slice(body.len().to_string().as_bytes());
    expected.extend_from_slice(b"\x00blksize\x008\x00timeout\x005\x00");
    assert_eq!(record.request, expected);
    assert_eq!(record.data_blocks, [(1, body.to_vec())]);
}

#[test]
fn tftp_upload_no_options_sends_plain_wrq() {
    let (url, rx) = spawn_tftp_upload_server(tftp_ack(0), 512);
    let temp = tempdir().unwrap();
    let upload = temp.path().join("plain.bin");
    std::fs::write(&upload, b"plain").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--tftp-no-options",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x02upload.bin\0octet\0");
    assert_eq!(record.data_blocks, [(1, b"plain".to_vec())]);
}

#[test]
fn tftp_upload_no_options_ignores_requested_block_size() {
    let (url, rx) = spawn_tftp_upload_server(tftp_ack(0), 512);
    let temp = tempdir().unwrap();
    let upload = temp.path().join("default-blocks.bin");
    let body = vec![b'x'; 600];
    std::fs::write(&upload, &body).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--max-time",
        "2",
        "--tftp-no-options",
        "--tftp-blksize",
        "8",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(record.request, b"\0\x02upload.bin\0octet\0");
    assert_eq!(
        record.data_blocks,
        [(1, body[..512].to_vec()), (2, body[512..].to_vec())]
    );
}

#[test]
fn tftp_upload_stdin_uses_zero_tsize() {
    let (url, rx) = spawn_tftp_upload_server(tftp_ack(0), 512);

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .args(["-q", "-sS", "-T", "-", &url])
        .write_stdin("from stdin");
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.request,
        b"\x00\x02upload.bin\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x005\x00"
    );
    assert_eq!(record.data_blocks, [(1, b"from stdin".to_vec())]);
}

#[test]
fn tftp_upload_error_packet_maps_permission() {
    let (url, rx) = spawn_tftp_upload_error_server(2);
    let temp = tempdir().unwrap();
    let upload = temp.path().join("denied.bin");
    std::fs::write(&upload, b"do not send").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command
        .assert()
        .failure()
        .code(69)
        .stdout("")
        .stderr("curl: (69) TFTP: Access Violation\n");

    assert!(rx.recv().unwrap().starts_with(b"\0\x02upload.bin\0octet\0"));
}

#[test]
fn mqtt_subscribe_outputs_publish_packet_and_sends_subscribe() {
    let (url, rx) = spawn_mqtt_subscribe_server(b"sensor".to_vec(), b"hello\n".to_vec());

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-sS", &url]).output().unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"\0\x06sensorhello\n");
    let record = rx.recv().unwrap();
    assert_eq!(
        record.connect,
        b"\0\x04MQTT\x04\x02\0\x3c\0\x0ccurlrust0000"
    );
    assert_eq!(record.subscribe, Some(b"\0\x01\0\x06sensor\0".to_vec()));
}

#[test]
fn mqtt_publish_sends_data_payload_and_disconnects() {
    let (url, rx) = spawn_mqtt_publish_server();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-d", "something", &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(record.publish, Some(b"\0\x06sensorsomething".to_vec()));
    assert_eq!(record.disconnect, Some(Vec::new()));
}

#[test]
fn mqtt_publish_empty_payload_to_space_topic() {
    let (url, rx) = spawn_mqtt_publish_server();
    let url = url.replace("/sensor", "/%20");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-d", "", &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(record.publish, Some(b"\0\x01 ".to_vec()));
}

#[test]
fn mqtt_connect_includes_user_and_password() {
    let (url, rx) = spawn_mqtt_publish_server();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-u",
        "testuser:testpasswd",
        "-d",
        "something",
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.connect,
        b"\0\x04MQTT\x04\xc2\0\x3c\0\x0ccurlrust0000\0\x08testuser\0\x0atestpasswd"
    );
}

#[test]
fn mqtt_rejects_missing_topic_after_connack() {
    let (url, rx) = spawn_mqtt_connack_server(0);
    let url = url.replace("/sensor", "");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-d", "", &url]);
    command.assert().failure().code(3).stdout("");

    assert_eq!(
        rx.recv().unwrap().connect,
        b"\0\x04MQTT\x04\x02\0\x3c\0\x0ccurlrust0000"
    );
}

#[test]
fn mqtt_connack_error_returns_weird_server_reply() {
    let (url, rx) = spawn_mqtt_connack_server(1);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(8).stdout("");

    assert_eq!(
        rx.recv().unwrap().connect,
        b"\0\x04MQTT\x04\x02\0\x3c\0\x0ccurlrust0000"
    );
}

#[test]
fn mqtt_max_filesize_rejects_large_publish_before_output() {
    let (url, _rx) = spawn_mqtt_subscribe_server(b"sensor".to_vec(), b"hello\n".to_vec());

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--max-filesize", "11", &url]);
    command.assert().failure().code(63).stdout("");
}

#[test]
fn rtsp_default_options_sends_star_uri_and_cseq() {
    let (url, rx) = spawn_rtsp_server(
        b"RTSP/1.0 200 OK\r\nServer: RTSPD/libcurl-test\r\nCSeq: 1\r\nPublic: DESCRIBE, OPTIONS\r\n\r\n",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "OPTIONS * RTSP/1.0");
    assert_eq!(header(&request, "cseq"), Some("1"));
    assert!(header(&request, "user-agent").unwrap().starts_with("curl/"));
    assert_eq!(header(&request, "session"), None);
    assert_eq!(header(&request, "transport"), None);
    assert!(request.body.is_empty());
}

#[test]
fn rtsp_include_and_head_output_response_headers() {
    const RESPONSE: &[u8] =
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";
    for flag in ["-i", "-I"] {
        let (url, rx) = spawn_rtsp_server(RESPONSE);
        let mut command = Command::cargo_bin("curl").unwrap();
        let output = command.args(["-q", "-sS", flag, &url]).output().unwrap();

        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\n"
        );
        assert_eq!(rx.recv().unwrap().start_line, "OPTIONS * RTSP/1.0");
    }
}

#[test]
fn rtsp_writeout_reports_response_code_and_zero_download_size() {
    let (url, _rx) =
        spawn_rtsp_server(b"RTSP/1.0 404 Not Found\r\nCSeq: 1\r\nContent-Length: 5\r\n\r\nhello");

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args([
            "-q",
            "-sS",
            "-w",
            "code=%{response_code} size=%{size_download}",
            &url,
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"code=404 size=0");
}

#[test]
fn rtsp_custom_request_is_ignored_for_default_cli() {
    let (url, rx) = spawn_rtsp_server(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-X", "DESCRIBE", &url]);
    command.assert().success().stdout("");

    assert_eq!(rx.recv().unwrap().start_line, "OPTIONS * RTSP/1.0");
}

#[test]
fn rtsp_bad_status_line_exits_weird_server_reply() {
    let (url, _rx) = spawn_rtsp_server(
        b"RTSP/1.1234567 200 OK\r\nServer: RTSPD/libcurl-test\r\nCSeq: 1\r\n\r\n",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(8).stdout("");
}

#[test]
fn rtsp_missing_cseq_exits_85_after_parsing_response_code() {
    let (url, _rx) = spawn_rtsp_server(b"RTSP/1.0 786          \n \nRTSP/          \n");

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command
        .args([
            "-q",
            "-sS",
            "-w",
            "code=%{response_code} exit=%{exitcode}",
            &url,
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(85));
    assert_eq!(output.stdout, b"code=786 exit=85");
}

#[test]
fn rtsp_rejects_custom_cseq_header() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-H", "CSeq: 2", "rtsp://127.0.0.1:9/media"]);
    command.assert().failure().code(85).stdout("");
}

#[test]
fn version_lists_mqtt_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("MQTT"));
}

#[test]
fn version_lists_rtsp_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("RTSP"));
}

#[test]
fn version_lists_tftp_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("TFTP"));
}

#[test]
fn telnet_upload_file_sends_file_and_outputs_response() {
    const REQUEST: &[u8] = b"GET /from-file HTTP/1.0\r\n\r\n";

    let temp = tempdir().unwrap();
    let upload = temp.path().join("request.txt");
    std::fs::write(&upload, REQUEST).unwrap();
    let (url, rx) = spawn_telnet_server(b"server response", b"", b"\r\n\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("server response");

    assert_eq!(rx.recv().unwrap(), REQUEST);
}

#[test]
fn telnet_sends_stdin_without_upload_file() {
    let (url, rx) = spawn_telnet_server(b"pong", b"", b"ping");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]).write_stdin("ping");
    command.assert().success().stdout("pong");

    assert_eq!(rx.recv().unwrap(), b"ping");
}

#[test]
fn telnet_upload_dash_reads_stdin_and_escapes_iac() {
    let (url, rx) = spawn_telnet_server(b"ok", b"", b"tail");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .args(["-q", "-sS", "-T", "-", &url])
        .write_stdin(b"head\xfftail".as_slice());
    command.assert().success().stdout("ok");

    assert_eq!(rx.recv().unwrap(), b"head\xff\xfftail");
}

#[test]
fn telnet_filters_negotiation_and_replies_to_peer() {
    let (url, rx) = spawn_telnet_echo_server(TELNET_NEGOTIATION_GREETING, b"test1452");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .args(["-q", "-sS", "-T", "-", &url])
        .write_stdin("test1452");
    command.assert().success().stdout("test1452");

    let received = rx.recv().unwrap();
    assert_eq!(strip_telnet_client_negotiation(&received), b"test1452");
    assert!(
        received
            .windows(3)
            .any(|window| window == [TELNET_IAC, TELNET_WONT, TELNET_NEW_ENVIRON])
    );
    assert!(
        received
            .windows(3)
            .any(|window| window == [TELNET_IAC, TELNET_DONT, TELNET_NEW_ENVIRON])
    );
}

#[test]
fn telnet_writeout_reports_zero_http_code_and_download_size() {
    let (url, rx) = spawn_telnet_server(b"abcdef", b"", b"");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-w",
        " %{http_code} %{size_download} %{header_json}",
        &url,
    ]);
    command.assert().success().stdout("abcdef 000 6 {}");

    assert_eq!(rx.recv().unwrap(), b"");
}

#[test]
fn telnet_dump_header_creates_empty_file_and_include_adds_nothing() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("telnet.headers");
    let (url, rx) = spawn_telnet_server(b"body", b"", b"");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-i", "-D", dump.to_str().unwrap(), &url]);
    command.assert().success().stdout("body");

    assert_eq!(rx.recv().unwrap(), b"");
    assert_eq!(std::fs::read(dump).unwrap(), b"");
}

#[test]
fn telnet_options_fail_explicitly_until_negotiation_options_are_supported() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-tTTYPE=vt100", "telnet://example.invalid"]);
    command.assert().failure().code(2).stdout("");
}

#[test]
fn ldap_anonymous_search_outputs_entry() {
    let entry = ldap_search_entry(
        b"cn=Alice,dc=example",
        &[
            ldap_attribute(b"cn", &[&b"Alice"[..]]),
            ldap_attribute(b"mail", &[&b"alice@example.com"[..]]),
        ],
    );
    let (url, rx) = spawn_ldap_server("/dc=example", 0, vec![entry], 0);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command
        .assert()
        .success()
        .stdout("DN: cn=Alice,dc=example\n\tcn: Alice\n\n\tmail: alice@example.com\n\n\n");

    let record = rx.recv().unwrap();
    assert!(contains_bytes(&record.bind, &ldap_tlv(0x80, b"")));
    assert!(contains_bytes(&record.search, &ldap_octet(b"dc=example")));
    assert!(contains_bytes(
        &record.search,
        &ldap_tlv(0x87, b"objectClass")
    ));
    assert!(contains_bytes(&record.unbind, &ldap_tlv(0x42, &[])));
}

#[test]
fn ldap_url_parses_base_attrs_scope_and_filter() {
    let (url, rx) = spawn_ldap_server("/dc=example?cn,sn?sub?(uid=alice)", 0, vec![], 0);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    let mut equality = Vec::new();
    equality.extend_from_slice(&ldap_octet(b"uid"));
    equality.extend_from_slice(&ldap_octet(b"alice"));
    assert!(contains_bytes(&record.search, &ldap_octet(b"dc=example")));
    assert!(contains_bytes(&record.search, &ldap_enumerated(2)));
    assert!(contains_bytes(&record.search, &ldap_tlv(0xa3, &equality)));
    assert!(contains_bytes(&record.search, &ldap_octet(b"cn")));
    assert!(contains_bytes(&record.search, &ldap_octet(b"sn")));
}

#[test]
fn ldap_simple_bind_uses_user_option() {
    let (url, rx) = spawn_ldap_server("/dc=example", 0, vec![], 0);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "cn=admin:secret", &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert!(contains_bytes(&record.bind, &ldap_octet(b"cn=admin")));
    assert!(contains_bytes(&record.bind, &ldap_tlv(0x80, b"secret")));
}

#[test]
fn ldap_search_failure_returns_39_and_writeout_code() {
    let (url, rx) = spawn_ldap_server("/missing", 0, vec![], 32);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-w", "%{response_code}", &url]);
    command.assert().failure().code(39).stdout("032");

    let _ = rx.recv().unwrap();
}

#[test]
fn ldap_bind_failure_returns_38() {
    let (url, rx) = spawn_ldap_server("/dc=example", 1, vec![], 0);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(38).stdout("");

    let _ = rx.recv().unwrap();
}

#[test]
fn ldap_head_suppresses_body() {
    let entry = ldap_search_entry(
        b"cn=Alice,dc=example",
        &[ldap_attribute(b"cn", &[&b"Alice"[..]])],
    );
    let (url, rx) = spawn_ldap_server("/dc=example", 0, vec![entry], 0);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-I",
        "-w",
        "%{size_download} %{http_code}",
        &url,
    ]);
    command.assert().success().stdout("0 000");

    let record = rx.recv().unwrap();
    assert!(contains_bytes(&record.search, &ldap_octet(b"dc=example")));
}

#[test]
fn ldap_dump_header_is_empty_and_include_adds_no_headers() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("ldap.headers");
    let entry = ldap_search_entry(
        b"cn=Alice,dc=example",
        &[ldap_attribute(b"cn", &[&b"Alice"[..]])],
    );
    let (url, rx) = spawn_ldap_server("/dc=example", 0, vec![entry], 0);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-i", "-D", dump.to_str().unwrap(), &url]);
    command
        .assert()
        .success()
        .stdout("DN: cn=Alice,dc=example\n\tcn: Alice\n\n\n");

    let _ = rx.recv().unwrap();
    assert_eq!(std::fs::read(dump).unwrap(), b"");
}

#[test]
fn version_lists_ldap_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("LDAP"));
}

#[test]
fn smb_download_outputs_body_and_sends_expected_sequence() {
    let body = b"Basic SMB test complete\n";
    let (url, rx) = spawn_smb_server("/TESTS/1451", SmbFixture::body(body));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "curltest:curltest", &url]);
    command
        .assert()
        .success()
        .stdout("Basic SMB test complete\n");

    let record = rx.recv().unwrap();
    let commands = record
        .packets
        .iter()
        .map(|packet| smb_packet_command(packet))
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        vec![
            TEST_SMB_COM_NEGOTIATE,
            TEST_SMB_COM_SETUP_ANDX,
            TEST_SMB_COM_TREE_CONNECT_ANDX,
            TEST_SMB_COM_NT_CREATE_ANDX,
            TEST_SMB_COM_READ_ANDX,
            TEST_SMB_COM_CLOSE,
            TEST_SMB_COM_TREE_DISCONNECT,
        ]
    );
    assert!(contains_bytes(&record.packets[1], b"curltest"));
    assert!(contains_bytes(&record.packets[2], b"\\\\127.0.0.1\\TESTS"));
    assert!(contains_bytes(&record.packets[3], b"1451"));
}

#[test]
fn smb_url_userinfo_splits_domain_and_decodes_path() {
    let (base_url, rx) = spawn_smb_server("/SHARE/dir/file%20x", SmbFixture::body(b"body"));
    let addr = base_url
        .strip_prefix("smb://")
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let url = format!("smb://DOMAIN%2Fuser:secret@{addr}/SHARE/dir/file%20x");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("body");

    let record = rx.recv().unwrap();
    assert!(contains_bytes(&record.packets[1], b"user"));
    assert!(contains_bytes(&record.packets[1], b"DOMAIN"));
    assert!(contains_bytes(&record.packets[3], b"dir\\file x"));
}

#[test]
fn smb_requires_credentials_returns_67() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "smb://127.0.0.1:1/SHARE/file"]);
    command.assert().failure().code(67).stdout("");
}

#[test]
fn smb_missing_share_path_returns_url_error() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", "smb://127.0.0.1/SHARE"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn smb_tree_noaccess_returns_9() {
    let mut fixture = SmbFixture::body(b"");
    fixture.tree_status = TEST_SMB_ERR_NOACCESS;
    let (url, rx) = spawn_smb_server("/SHARE/file", fixture);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().failure().code(9).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        smb_packet_command(&record.packets[2]),
        TEST_SMB_COM_TREE_CONNECT_ANDX
    );
}

#[test]
fn smb_open_missing_returns_78() {
    let mut fixture = SmbFixture::body(b"");
    fixture.open_status = 0x0002_0001;
    let (url, rx) = spawn_smb_server("/SHARE/missing", fixture);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().failure().code(78).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        smb_packet_command(&record.packets[3]),
        TEST_SMB_COM_NT_CREATE_ANDX
    );
}

#[test]
fn smb_malformed_read_frame_returns_56() {
    let mut fixture = SmbFixture::body(b"body");
    fixture.malformed_read = true;
    let (url, rx) = spawn_smb_server("/SHARE/file", fixture);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "user:secret", &url]);
    command.assert().failure().code(56).stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        smb_packet_command(&record.packets[4]),
        TEST_SMB_COM_READ_ANDX
    );
}

#[test]
fn smb_head_suppresses_body_and_keeps_zero_code() {
    let (url, rx) = spawn_smb_server("/SHARE/file", SmbFixture::body(b"body"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-I",
        "-w",
        "%{size_download} %{http_code}",
        "-u",
        "user:secret",
        &url,
    ]);
    command.assert().success().stdout("0 000");

    let record = rx.recv().unwrap();
    let commands = record
        .packets
        .iter()
        .map(|packet| smb_packet_command(packet))
        .collect::<Vec<_>>();
    assert!(!commands.contains(&TEST_SMB_COM_READ_ANDX));
}

#[test]
fn smb_dump_header_is_empty_and_include_adds_no_headers() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("smb.headers");
    let (url, rx) = spawn_smb_server("/SHARE/file", SmbFixture::body(b"body"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-i",
        "-D",
        dump.to_str().unwrap(),
        "-u",
        "user:secret",
        &url,
    ]);
    command.assert().success().stdout("body");

    let _ = rx.recv().unwrap();
    assert_eq!(std::fs::read(dump).unwrap(), b"");
}

#[test]
fn smb_max_filesize_truncates_and_returns_63() {
    let (url, rx) = spawn_smb_server("/SHARE/file", SmbFixture::body(b"abcdef"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--max-filesize",
        "3",
        "-u",
        "user:secret",
        &url,
    ]);
    command.assert().failure().code(63).stdout("abc");

    let _ = rx.recv().unwrap();
}

#[test]
fn smbs_is_explicitly_unsupported() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "smbs://example.com/SHARE/file"]);
    command.assert().failure().code(2).stdout("");
}

#[test]
fn unknown_url_scheme_exits_unsupported_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "htfp://127.0.0.1:9/none.htfml"]);
    command.assert().failure().code(1).stdout("");
}

#[test]
fn version_lists_smb_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("SMB"));
}

#[test]
fn sftp_downloads_file_with_known_hosts() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");
}

#[test]
fn scp_downloads_file_with_known_hosts() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let url = fixture.url_for("scp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");
}

fn sftp_range_fixture_file(fixture: &SshdFixture) -> PathBuf {
    let path = fixture.root.join("range-data.txt");
    std::fs::write(&path, b"Test data\nfor ssh test\n").unwrap();
    path
}

#[test]
fn scp_download_range_is_ignored_and_outputs_full_file() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("scp", &path);

    for range in ["5-9", "99-"] {
        let mut command = Command::cargo_bin("curl").unwrap();
        command.args(["-q", "-sS", "--range", range]);
        command.args(fixture.auth_args());
        command.arg(&url);
        command
            .assert()
            .success()
            .stdout("Test data\nfor ssh test\n");
    }
}

#[test]
fn scp_download_continue_at_fixed_to_stdout_is_ignored() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("scp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--continue-at", "5"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command
        .assert()
        .success()
        .stdout("Test data\nfor ssh test\n");
}

#[test]
fn scp_download_continue_at_fixed_appends_full_file_to_output() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let output = temp.path().join("out.txt");
    std::fs::write(&output, b"local prefix\n").unwrap();
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("scp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "13",
        "-o",
        output.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(
        std::fs::read(output).unwrap(),
        b"local prefix\nTest data\nfor ssh test\n"
    );
}

#[test]
fn scp_download_continue_at_auto_appends_full_file_to_output() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let output = temp.path().join("out.txt");
    std::fs::write(&output, b"local prefix\n").unwrap();
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("scp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "-",
        "-o",
        output.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(
        std::fs::read(output).unwrap(),
        b"local prefix\nTest data\nfor ssh test\n"
    );
}

#[test]
fn sftp_download_range_fixed_outputs_requested_bytes() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("sftp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--range", "5-9"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("data\n");
}

#[test]
fn sftp_download_range_end_past_eof_clamps_to_file_size() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("sftp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--range", "5-99"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("data\nfor ssh test\n");
}

#[test]
fn sftp_download_range_suffix_outputs_tail() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("sftp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--range", "-9"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh test\n");
}

#[test]
fn sftp_download_range_open_ended_outputs_to_eof() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("sftp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--range", "5-"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("data\nfor ssh test\n");
}

#[test]
fn sftp_download_range_start_past_eof_returns_33() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let path = sftp_range_fixture_file(&fixture);
    let url = fixture.url_for("sftp", &path);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--range", "99-"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(33).stdout("");
}

#[test]
fn sftp_download_continue_at_fixed_to_stdout_outputs_tail() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--continue-at", "4"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("fixture body\n");
}

#[test]
fn sftp_download_continue_at_fixed_appends_to_output() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let output = temp.path().join("out.txt");
    std::fs::write(&output, b"ssh ").unwrap();
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "4",
        "-o",
        output.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(output).unwrap(), b"ssh fixture body\n");
}

#[test]
fn sftp_download_continue_at_auto_uses_existing_output_size() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let output = temp.path().join("out.txt");
    std::fs::write(&output, b"ssh ").unwrap();
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "-",
        "-o",
        output.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(output).unwrap(), b"ssh fixture body\n");
}

#[test]
fn sftp_download_continue_at_complete_skips_body() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let output = temp.path().join("out.txt");
    std::fs::write(&output, b"ssh fixture body\n").unwrap();
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "-",
        "-o",
        output.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(output).unwrap(), b"ssh fixture body\n");
}

#[test]
fn sftp_download_continue_at_beyond_remote_size_returns_36() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let output = temp.path().join("out.txt");
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "100",
        "-o",
        output.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(36).stdout("");
}

#[test]
fn scp_quote_options_are_ignored() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let source = fixture.root.join("data.txt");
    let created_dir = fixture.root.join("scp-prequote-dir");
    let normal_quote = format!("rm {}", source.display());
    let prequote = format!("+mkdir {}", created_dir.display());
    let postquote = format!("-rm {}", source.display());
    let url = fixture.url_for("scp", &source);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--quote",
        &normal_quote,
        "--quote",
        &prequote,
        "--quote",
        &postquote,
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");

    assert_eq!(std::fs::read(source).unwrap(), b"ssh fixture body\n");
    assert!(!created_dir.exists());
}

#[test]
fn scp_unknown_quote_is_ignored() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let url = fixture.url_for("scp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", "unknown command with trailing junk"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");
}

#[test]
fn scp_upload_file_writes_remote_file() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"uploaded over scp\n").unwrap();
    let remote = fixture.root.join("scp-uploaded.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"uploaded over scp\n");
}

#[test]
fn scp_upload_dash_returns_upload_failed() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let remote = fixture.root.join("scp-stdin-upload.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", "-"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(25).stdout("");

    assert!(!remote.exists());
}

#[test]
fn scp_upload_to_directory_url_appends_local_filename() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("scp-client-name.txt");
    std::fs::write(&upload, b"scp directory upload\n").unwrap();
    let mut directory = fixture.root.join("dir").to_str().unwrap().to_string();
    directory.push('/');
    let url = fixture.url_for("scp", Path::new(&directory));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(
        std::fs::read(fixture.root.join("dir").join("scp-client-name.txt")).unwrap(),
        b"scp directory upload\n"
    );
}

#[test]
fn scp_upload_missing_local_file_returns_read_error() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing.txt");
    let remote = fixture.root.join("scp-should-not-exist.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", missing.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(26).stdout("");

    assert!(!remote.exists());
}

#[test]
fn scp_upload_missing_remote_directory_returns_25() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"not written\n").unwrap();
    let remote = fixture.root.join("missing-dir").join("payload.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(25).stdout("");

    assert!(!remote.exists());
}

#[test]
fn scp_upload_dump_header_and_include_emit_no_bytes() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    let dump = temp.path().join("headers.txt");
    std::fs::write(&upload, b"scp headerless upload\n").unwrap();
    let remote = fixture.root.join("scp-headerless-upload.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-i",
        "-D",
        dump.to_str().unwrap(),
        "-w",
        "%{size_download} %{http_code} %{header_json}",
        "-T",
        upload.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("0 000 {}");

    assert_eq!(std::fs::read(dump).unwrap(), b"");
    assert_eq!(std::fs::read(remote).unwrap(), b"scp headerless upload\n");
}

#[test]
fn scp_upload_dot_returns_upload_failed() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let remote = fixture.root.join("scp-dot-upload.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", "."]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(25).stdout("");

    assert!(!remote.exists());
}

#[test]
fn scp_upload_with_head_still_uploads_file() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"head still uploads\n").unwrap();
    let remote = fixture.root.join("scp-head-upload.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-I", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"head still uploads\n");
}

#[test]
fn scp_upload_range_continue_and_append_are_ignored() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"new scp bytes\n").unwrap();

    for (name, args) in [
        ("range", vec!["--range", "4-"]),
        ("continue", vec!["--continue-at", "4"]),
        ("append", vec!["--append"]),
    ] {
        let remote = fixture.root.join(format!("scp-{name}-ignored.txt"));
        std::fs::write(&remote, b"old prefix").unwrap();
        let url = fixture.url_for("scp", &remote);

        let mut command = Command::cargo_bin("curl").unwrap();
        command.args(["-q", "-sS"]);
        command.args(args);
        command.args(["-T", upload.to_str().unwrap()]);
        command.args(fixture.auth_args());
        command.arg(url);
        command.assert().success().stdout("");

        assert_eq!(std::fs::read(remote).unwrap(), b"new scp bytes\n");
    }
}

#[test]
fn scp_upload_create_dirs_is_ignored() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"not written\n").unwrap();
    let remote = fixture.root.join("scp-created").join("payload.txt");
    let url = fixture.url_for("scp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ftp-create-dirs",
        "-T",
        upload.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(25).stdout("");

    assert!(!remote.exists());
}

#[test]
fn sftp_missing_file_returns_78() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let url = fixture.url_for("sftp", &fixture.root.join("missing.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(78).stdout("");
}

#[test]
fn sftp_bad_key_returns_login_denied() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));
    let bad_public_key = fixture.bad_private_key.with_extension("pub");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--knownhosts",
        fixture.known_hosts.to_str().unwrap(),
        "--key",
        fixture.bad_private_key.to_str().unwrap(),
        "--pubkey",
        bad_public_key.to_str().unwrap(),
        "--user",
        &fixture.user,
        &url,
    ]);
    command.assert().failure().code(67).stdout("");
}

#[test]
fn sftp_head_writes_headers_without_body() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-I"]);
    command.args(fixture.auth_args());
    command.arg(url);
    let output = command.output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("content-length: 17\r\n"));
    assert!(!stdout.contains("ssh fixture body"));
}

#[test]
fn sftp_list_only_outputs_directory_names() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let mut directory = fixture.root.join("dir").to_str().unwrap().to_string();
    directory.push('/');
    let url = fixture.url_for("sftp", Path::new(&directory));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--list-only"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("alpha.txt\nbeta.txt\n");
}

#[test]
fn sftp_url_path_expands_remote_home() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let remote_home_dir = tempdir_in(home).unwrap();
    let remote_dirname = remote_home_dir
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let remote_file = remote_home_dir.path().join("url-home.txt");
    std::fs::write(&remote_file, b"sftp home url\n").unwrap();
    let url = format!(
        "sftp://127.0.0.1:{}/~/{remote_dirname}/url-home.txt",
        fixture.port
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("sftp home url\n");
}

#[test]
fn sftp_quote_mkdir_runs_before_download() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let remote_dir = fixture.root.join("quote created");
    let quote = format!("mkdir \"{}\"", remote_dir.display());
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");

    assert!(remote_dir.is_dir());
}

#[test]
fn sftp_quote_path_expands_remote_home() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let remote_home_dir = tempdir_in(home).unwrap();
    let remote_dirname = remote_home_dir
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let remote_file = remote_home_dir.path().join("quote-home.txt");
    std::fs::write(&remote_file, b"remove through quote\n").unwrap();
    let quote = format!("rm /~/{remote_dirname}/quote-home.txt");
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");

    assert!(!remote_file.exists());
}

#[test]
#[cfg(unix)]
fn sftp_quote_mtime_accepts_curl_getdate_formats() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };

    for (name, date, expected_mtime) in [
        ("asctime", "Sun Nov  6 08:49:37 1994", 784_111_777),
        ("named-tz", "Sun, 06 Nov 1994 08:49:37 CET", 784_108_177),
        ("compact-tz", "20040912 15:05:58 -0700", 1_095_026_758),
    ] {
        let remote_file = fixture.root.join(format!("mtime-{name}.txt"));
        std::fs::write(&remote_file, b"date quote\n").unwrap();
        let quote = format!("mtime \"{date}\" {}", remote_file.display());
        let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

        let mut command = Command::cargo_bin("curl").unwrap();
        command.args(["-q", "-sS", "--quote", &quote]);
        command.args(fixture.auth_args());
        command.arg(url);
        command.assert().success().stdout("ssh fixture body\n");

        assert_eq!(
            std::fs::metadata(remote_file).unwrap().mtime(),
            expected_mtime
        );
    }
}

#[test]
fn sftp_quote_mtime_rejects_bad_date() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let remote_file = fixture.root.join("mtime-bad-date.txt");
    std::fs::write(&remote_file, b"bad date quote\n").unwrap();
    let quote = format!("mtime \"1994-11-06T08:49:37Z\" {}", remote_file.display());
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(21).stdout("");
}

#[test]
fn sftp_quote_failure_returns_21_before_transfer() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let missing = fixture.root.join("missing-for-quote.txt");
    let quote = format!("rm {}", missing.display());
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(21).stdout("");
}

#[test]
fn sftp_quote_acceptfail_continues() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let missing = fixture.root.join("missing-for-accepted-quote.txt");
    let quote = format!("*rm {}", missing.display());
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");
}

#[test]
fn sftp_quote_statvfs_writes_header_data() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let quote = format!("statvfs {}", fixture.root.display());
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-i", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    let output = command.output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("statvfs:\nf_bsize: "));
    assert!(stdout.contains("\nf_namemax: "));
    assert!(stdout.ends_with("ssh fixture body\n"));
}

#[test]
fn sftp_quote_rejects_trailing_junk() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let remote_dir = fixture.root.join("junk-dir");
    let quote = format!("mkdir {} trailing", remote_dir.display());
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(21).stdout("");

    assert!(!remote_dir.exists());
}

#[test]
fn sftp_prequote_prefix_is_ignored() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let remote_dir = fixture.root.join("sftp-prequote-ignored");
    let quote = format!("+mkdir {}", remote_dir.display());
    let url = fixture.url_for("sftp", &fixture.root.join("data.txt"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");

    assert!(!remote_dir.exists());
}

#[test]
fn sftp_postquote_rename_runs_after_download() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let source = fixture.root.join("data.txt");
    let renamed = fixture.root.join("data-renamed.txt");
    let quote = format!("-rename {} {}", source.display(), renamed.display());
    let url = fixture.url_for("sftp", &source);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("ssh fixture body\n");

    assert!(!source.exists());
    assert_eq!(std::fs::read(renamed).unwrap(), b"ssh fixture body\n");
}

#[test]
fn sftp_postquote_failure_returns_21_after_body() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let source = fixture.root.join("data.txt");
    let quote = format!("-mkdir {}", source.display());
    let url = fixture.url_for("sftp", &source);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--quote", &quote]);
    command.args(fixture.auth_args());
    command.arg(url);
    command
        .assert()
        .failure()
        .code(21)
        .stdout("ssh fixture body\n");
}

#[test]
fn sftp_postquote_is_skipped_after_output_write_failure() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let source = fixture.root.join("data.txt");
    let output = temp.path().join("missing-parent").join("out.txt");
    let quote = format!("-rm {}", source.display());
    let url = fixture.url_for("sftp", &source);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--quote",
        &quote,
        "-o",
        output.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(23).stdout("");

    assert!(source.exists());
}

#[test]
fn sftp_upload_file_writes_remote_file() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"uploaded over sftp\n").unwrap();
    let remote = fixture.root.join("uploaded.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"uploaded over sftp\n");
}

#[test]
fn sftp_upload_create_dirs_makes_missing_parent_directories() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"created parents\n").unwrap();
    let remote = fixture
        .root
        .join("missing-parent")
        .join("nested")
        .join("payload.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ftp-create-dirs",
        "-T",
        upload.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"created parents\n");
}

#[test]
fn sftp_upload_append_preserves_existing_remote_bytes() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"new").unwrap();
    let remote = fixture.root.join("append-target.txt");
    std::fs::write(&remote, b"old ").unwrap();
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--append", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"old new");
}

#[test]
fn sftp_upload_continue_at_fixed_offset_skips_local_bytes() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"hello").unwrap();
    let remote = fixture.root.join("resume-fixed.txt");
    std::fs::write(&remote, b"he").unwrap();
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "2",
        "-T",
        upload.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"hello");
}

#[test]
fn sftp_upload_continue_at_auto_uses_remote_size() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"hello").unwrap();
    let remote = fixture.root.join("resume-auto.txt");
    std::fs::write(&remote, b"he").unwrap();
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"hello");
}

#[test]
fn sftp_upload_continue_at_auto_missing_remote_uploads_full_file() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"fresh upload\n").unwrap();
    let remote = fixture.root.join("resume-auto-missing.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"fresh upload\n");
}

#[test]
fn sftp_upload_continue_at_complete_skips_write() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"complete").unwrap();
    let remote = fixture.root.join("resume-complete.txt");
    std::fs::write(&remote, b"complete").unwrap();
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"complete");
}

#[test]
fn sftp_upload_postquote_removes_uploaded_file() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"upload then delete\n").unwrap();
    let remote = fixture.root.join("upload-postquote.txt");
    let quote = format!("-rm {}", remote.display());
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-T",
        upload.to_str().unwrap(),
        "--quote",
        &quote,
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert!(!remote.exists());
}

#[test]
fn sftp_upload_to_directory_url_appends_local_filename() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("client-name.txt");
    std::fs::write(&upload, b"directory upload\n").unwrap();
    let mut directory = fixture.root.join("dir").to_str().unwrap().to_string();
    directory.push('/');
    let url = fixture.url_for("sftp", Path::new(&directory));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(
        std::fs::read(fixture.root.join("dir").join("client-name.txt")).unwrap(),
        b"directory upload\n"
    );
}

#[test]
fn sftp_upload_missing_local_file_returns_read_error() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing.txt");
    let remote = fixture.root.join("should-not-exist.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", missing.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(26).stdout("");

    assert!(!remote.exists());
}

#[test]
fn sftp_upload_missing_remote_directory_returns_78() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"not written\n").unwrap();
    let remote = fixture.root.join("missing-dir").join("payload.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(78).stdout("");

    assert!(!remote.exists());
}

#[test]
fn sftp_upload_dash_reads_stdin() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let remote = fixture.root.join("stdin-upload.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", "-"]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.write_stdin("stdin upload\n");
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"stdin upload\n");
}

#[test]
fn sftp_upload_with_list_only_still_uploads() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"list-only upload\n").unwrap();
    let remote = fixture.root.join("list-only-upload.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--list-only", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"list-only upload\n");
}

#[test]
fn sftp_upload_dump_header_and_include_emit_no_bytes() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    let dump = temp.path().join("headers.txt");
    std::fs::write(&upload, b"headerless upload\n").unwrap();
    let remote = fixture.root.join("headerless-upload.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-i",
        "-D",
        dump.to_str().unwrap(),
        "-T",
        upload.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(dump).unwrap(), b"");
    assert_eq!(std::fs::read(remote).unwrap(), b"headerless upload\n");
}

#[test]
fn sftp_upload_ignores_max_filesize_and_reports_zero_download() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"larger than one byte\n").unwrap();
    let remote = fixture.root.join("max-filesize-upload.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--max-filesize",
        "1",
        "-w",
        "%{size_download} %{http_code} %{header_json}",
        "-T",
        upload.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("0 000 {}");

    assert_eq!(std::fs::read(remote).unwrap(), b"larger than one byte\n");
}

#[test]
fn sftp_upload_with_head_is_rejected() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    std::fs::write(&upload, b"not uploaded\n").unwrap();
    let remote = fixture.root.join("head-upload.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-I", "-T", upload.to_str().unwrap()]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().failure().code(2).stdout("");

    assert!(!remote.exists());
}

#[test]
fn sftp_upload_output_option_does_not_create_local_file() {
    let Some(fixture) = SshdFixture::new() else {
        return;
    };
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    let output = temp.path().join("local.out");
    std::fs::write(&upload, b"remote only\n").unwrap();
    let remote = fixture.root.join("remote-only.txt");
    let url = fixture.url_for("sftp", &remote);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-o",
        output.to_str().unwrap(),
        "-T",
        upload.to_str().unwrap(),
    ]);
    command.args(fixture.auth_args());
    command.arg(url);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read(remote).unwrap(), b"remote only\n");
    assert!(!output.exists());
}

#[test]
fn version_lists_scp_and_sftp_protocols() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.contains("SCP"));
    assert!(stdout.contains("SFTP"));
}

#[test]
fn http_upload_file_sends_put_body() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    std::fs::write(&upload, "body").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PUT /resource HTTP/1.1"));
    assert_eq!(header(&request, "content-length"), Some("4"));
    assert_eq!(request.body, b"body");
}

#[test]
fn http_upload_dash_reads_stdin() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", "-", &url]);
    command.write_stdin("from stdin");
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PUT /resource HTTP/1.1"));
    assert_eq!(header(&request, "content-length"), Some("10"));
    assert_eq!(request.body, b"from stdin");
}

#[test]
fn http_upload_to_directory_url_appends_local_filename() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    std::fs::write(&upload, "body").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let base_url = format!("{}/", gateway_origin(&url));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &base_url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PUT /upload.txt HTTP/1.1"));
    assert_eq!(request.body, b"body");
}

#[test]
fn http_upload_to_query_url_does_not_append_local_filename() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    std::fs::write(&upload, "body").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let query_url = format!("{}/?name=server", gateway_origin(&url));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &query_url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PUT /?name=server HTTP/1.1"));
    assert_eq!(request.body, b"body");
}

#[test]
fn http_upload_respects_custom_request_method() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    std::fs::write(&upload, "body").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-X",
        "PATCH",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PATCH /resource HTTP/1.1"));
    assert_eq!(request.body, b"body");
}

#[test]
fn http_upload_rejects_data_body_combination() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    std::fs::write(&upload, "body").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-T",
        upload.to_str().unwrap(),
        "-d",
        "a=b",
        "http://example.invalid/",
    ]);
    command.assert().failure().code(2).stdout("").stderr(
        "Warning: You can only select one HTTP request method! You asked for both PUT \n\
         Warning: (-T, --upload-file) and POST (-d, --data).\n",
    );
}

#[test]
fn http_upload_data_conflict_precedes_upload_file_read() {
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-T",
        missing.to_str().unwrap(),
        "-d",
        "a=b",
        "http://never-accessed/",
    ]);
    command.assert().failure().code(2).stdout("").stderr(
        "Warning: You can only select one HTTP request method! You asked for both PUT \n\
         Warning: (-T, --upload-file) and POST (-d, --data).\n",
    );
}

#[test]
fn http_data_rejects_continue_at_combination() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-d",
        "a=b",
        "--continue-at",
        "3",
        "http://example.invalid/",
    ]);
    command.assert().failure().code(2).stdout("");
}

#[test]
fn http_upload_missing_file_exits_read_error() {
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-T",
        missing.to_str().unwrap(),
        "http://example.invalid/",
    ]);
    command.assert().failure().code(26).stdout("");
}

#[test]
fn version_lists_telnet_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("TELNET"));
}

#[test]
fn ws_handshake_sends_upgrade_request() {
    let (url, rx) = spawn_ws_server(vec![ws_server_frame(0x8, &[])]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(record.request.start_line, "GET /chat?room=rust HTTP/1.1");
    assert!(header(&record.request, "host").is_some());
    assert!(
        header(&record.request, "user-agent")
            .unwrap()
            .starts_with("curl/")
    );
    assert_eq!(header(&record.request, "accept"), Some("*/*"));
    assert_eq!(header(&record.request, "upgrade"), Some("websocket"));
    assert_eq!(header(&record.request, "sec-websocket-version"), Some("13"));
    assert_eq!(
        header(&record.request, "sec-websocket-key"),
        Some("NDMyMTUzMjE2MzIxNzMyMQ==")
    );
    assert_eq!(header(&record.request, "connection"), Some("Upgrade"));
}

#[test]
fn ws_non_101_response_returns_http_error() {
    let (url, rx) = spawn_ws_raw_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(22).stdout("");

    assert_eq!(rx.recv().unwrap().start_line, "GET /chat HTTP/1.1");
}

#[test]
fn ws_text_frame_outputs_payload() {
    let (url, rx) = spawn_ws_server(vec![
        ws_server_frame(0x1, b"hello websocket"),
        ws_server_frame(0x8, &[]),
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("hello websocket");

    let _ = rx.recv().unwrap();
}

#[test]
fn ws_binary_frame_preserves_raw_payload() {
    let payload = b"\0bin\xffpayload".to_vec();
    let (url, rx) = spawn_ws_server(vec![
        ws_server_frame(0x2, &payload),
        ws_server_frame(0x8, &[]),
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-sS", &url]).output().unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, payload);
    let _ = rx.recv().unwrap();
}

#[test]
fn ws_ping_is_auto_ponged_without_output() {
    let (url, rx) = spawn_ws_server(vec![
        ws_server_frame(0x9, b"ping"),
        ws_server_frame(0x8, &[]),
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert!(
        record
            .frames
            .iter()
            .any(|(opcode, payload)| *opcode == 0xA && payload == b"ping")
    );
}

#[test]
fn ws_upload_file_sends_masked_binary_frame_after_get_upgrade() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.bin");
    std::fs::write(&upload, b"ws upload").unwrap();
    let (url, rx) = spawn_ws_upload_server();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(record.request.start_line, "GET /upload HTTP/1.1");
    assert!(
        record
            .frames
            .iter()
            .any(|(opcode, payload)| *opcode == 0x2 && payload == b"ws upload")
    );
}

#[test]
fn ws_upload_stdin_sends_masked_binary_frame() {
    let (url, rx) = spawn_ws_upload_server();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", "-", &url]);
    command.write_stdin("stdin websocket");
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert!(
        record
            .frames
            .iter()
            .any(|(opcode, payload)| *opcode == 0x2 && payload == b"stdin websocket")
    );
}

#[test]
fn ws_invalid_opcode_returns_recv_error() {
    let (url, rx) = spawn_ws_server(vec![vec![0x83, 0x00]]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(56).stdout("");

    let _ = rx.recv().unwrap();
}

#[test]
fn ws_include_dump_header_and_writeout_use_handshake_headers() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("ws.headers");
    let (url, rx) = spawn_ws_server(vec![
        ws_server_frame(0x1, b"payload"),
        ws_server_frame(0x8, &[]),
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-i",
        "-D",
        dump.to_str().unwrap(),
        "-w",
        " %{response_code} %{size_download}",
        &url,
    ]);
    let output = command.output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(stdout.contains("\r\n\r\npayload 101 7"));
    let headers = std::fs::read_to_string(dump).unwrap();
    assert!(headers.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(headers.contains("Sec-WebSocket-Accept: HkPsVga7+8LuxM4RGQ5p9tZHeYs=\r\n"));
    let _ = rx.recv().unwrap();
}

#[test]
fn version_lists_ws_protocol() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("WS"));
}

#[test]
fn ipfs_gateway_rewrites_to_http_path() {
    let (url, rx) = spawn_server(IPFS_RESPONSE);
    let gateway = gateway_origin(&url);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ipfs-gateway",
        &gateway,
        &format!("ipfs://{IPFS_CID}"),
    ]);
    command.assert().success().stdout("Hello curl from IPFS\n");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, format!("GET /ipfs/{IPFS_CID} HTTP/1.1"));
    assert_eq!(
        header(&request, "host"),
        Some(gateway.trim_start_matches("http://"))
    );
}

#[test]
fn ipfs_path_and_query_with_gateway_path() {
    let (url, rx) = spawn_server(IPFS_RESPONSE);
    let gateway = format!("{}/some/path", gateway_origin(&url));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ipfs-gateway",
        &gateway,
        &format!("ipfs://{IPFS_CID}/a/b?foo=bar&aaa=bbb"),
    ]);
    command.assert().success().stdout("Hello curl from IPFS\n");

    assert_eq!(
        rx.recv().unwrap().start_line,
        format!("GET /some/path/ipfs/{IPFS_CID}/a/b?foo=bar&aaa=bbb HTTP/1.1")
    );
}

#[test]
fn ipns_path_and_query_with_gateway_path() {
    let (url, rx) = spawn_server(IPFS_RESPONSE);
    let gateway = format!("{}/some/path", gateway_origin(&url));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ipfs-gateway",
        &gateway,
        "ipns://fancy.tld/a/b?foo=bar&aaa=bbb",
    ]);
    command.assert().success().stdout("Hello curl from IPFS\n");

    assert_eq!(
        rx.recv().unwrap().start_line,
        "GET /some/path/ipns/fancy.tld/a/b?foo=bar&aaa=bbb HTTP/1.1"
    );
}

#[test]
fn ipfs_gateway_env_overrides_gateway_file() {
    let temp = tempdir().unwrap();
    let file_dir = temp.path().join(".ipfs");
    std::fs::create_dir(&file_dir).unwrap();
    std::fs::write(file_dir.join("gateway"), "http://127.0.0.1:1\n").unwrap();
    let (url, rx) = spawn_server(IPFS_RESPONSE);
    let gateway = gateway_origin(&url);

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env("IPFS_GATEWAY", &gateway)
        .env("HOME", temp.path())
        .args(["-q", "-sS", &format!("ipfs://{IPFS_CID}")]);
    command.assert().success().stdout("Hello curl from IPFS\n");

    assert_eq!(
        rx.recv().unwrap().start_line,
        format!("GET /ipfs/{IPFS_CID} HTTP/1.1")
    );
}

#[test]
fn ipfs_gateway_file_discovery_uses_first_line() {
    let temp = tempdir().unwrap();
    let ipfs_dir = temp.path().join(".ipfs");
    std::fs::create_dir(&ipfs_dir).unwrap();
    let (url, rx) = spawn_server(IPFS_RESPONSE);
    let gateway = gateway_origin(&url);
    std::fs::write(ipfs_dir.join("gateway"), format!("{gateway}\nignored\n")).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("IPFS_GATEWAY")
        .env("HOME", temp.path())
        .args(["-q", "-sS", &format!("ipfs://{IPFS_CID}")]);
    command.assert().success().stdout("Hello curl from IPFS\n");

    assert_eq!(
        rx.recv().unwrap().start_line,
        format!("GET /ipfs/{IPFS_CID} HTTP/1.1")
    );
}

#[test]
fn ipfs_path_env_discovery_accepts_no_trailing_slash() {
    let temp = tempdir().unwrap();
    let ipfs_dir = temp.path().join("ipfs-data");
    std::fs::create_dir(&ipfs_dir).unwrap();
    let (url, rx) = spawn_server(IPFS_RESPONSE);
    let gateway = gateway_origin(&url);
    std::fs::write(ipfs_dir.join("gateway"), format!("{gateway}\n")).unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("IPFS_GATEWAY")
        .env("IPFS_PATH", &ipfs_dir)
        .args(["-q", "-sS", &format!("ipfs://{IPFS_CID}")]);
    command.assert().success().stdout("Hello curl from IPFS\n");

    assert_eq!(
        rx.recv().unwrap().start_line,
        format!("GET /ipfs/{IPFS_CID} HTTP/1.1")
    );
}

#[test]
fn ipfs_gateway_query_is_malformed_exit_3() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ipfs-gateway",
        "http://127.0.0.1:1/some/path?biz=baz",
        "ipns://fancy.tld/a/b?foo=bar&aaa=bbb",
    ]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn ipfs_auto_gateway_missing_exits_37() {
    let temp = tempdir().unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("IPFS_GATEWAY")
        .env_remove("IPFS_PATH")
        .env("HOME", temp.path())
        .args(["-q", "-sS", &format!("ipfs://{IPFS_CID}")]);
    command.assert().failure().code(37).stdout("");
}

#[test]
fn ipfs_auto_gateway_malformed_file_host_exits_3() {
    let temp = tempdir().unwrap();
    let ipfs_dir = temp.path().join(".ipfs");
    std::fs::create_dir(&ipfs_dir).unwrap();
    std::fs::write(ipfs_dir.join("gateway"), "http://nonexisting,local:8080\n").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .env_remove("IPFS_GATEWAY")
        .env_remove("IPFS_PATH")
        .env("HOME", temp.path())
        .args(["-q", "-sS", &format!("ipfs://{IPFS_CID}")]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn ipfs_malformed_explicit_gateway_exits_43() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ipfs-gateway",
        "http://",
        &format!("ipfs://{IPFS_CID}"),
    ]);
    command.assert().failure().code(43).stdout("");
}

#[test]
fn ipfs_malformed_explicit_gateway_host_exits_43() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--ipfs-gateway",
        "http://nonexisting,local:8080",
        &format!("ipfs://{IPFS_CID}"),
    ]);
    command.assert().failure().code(43).stdout("");
}

#[test]
fn version_lists_ipfs_and_ipns_protocols() {
    let mut command = Command::cargo_bin("curl").unwrap();
    let output = command.args(["-q", "-V"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.contains("IPFS"));
    assert!(stdout.contains("IPNS"));
}

#[test]
fn downloads_gopher_selector() {
    let (url, rx) = spawn_gopher_server(b"iMenu results\t\terror.host\t1\r\n.\r\n");
    let url = url.replace("/1/resource", "/1/selector/SELECTOR/1201");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command
        .assert()
        .success()
        .stdout("iMenu results\t\terror.host\t1\r\n.\r\n");

    assert_eq!(rx.recv().unwrap(), b"/selector/SELECTOR/1201\r\n");
}

#[test]
fn gopher_decodes_selector_before_sending() {
    let (url, rx) = spawn_gopher_server(b"search result\r\n");
    let url = url.replace(
        "/1/resource",
        "/7/the/search/engine%09query%20succeeded/1202",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("search result\r\n");

    assert_eq!(
        rx.recv().unwrap(),
        b"/the/search/engine\tquery succeeded/1202\r\n"
    );
}

#[test]
fn gopher_degenerate_selector_sends_only_crlf() {
    let (url, rx) = spawn_gopher_server(b"root\r\n");
    let url = url.replace("/1/resource", "/1");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("root\r\n");

    assert_eq!(rx.recv().unwrap(), b"\r\n");
}

#[test]
fn gopher_ipv6_literal_sends_selector() {
    let Some((url, rx)) = spawn_gopher_ipv6_server(b"ipv6\r\n") else {
        return;
    };

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-g", &url]);
    command.assert().success().stdout("ipv6\r\n");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
}

#[test]
fn gopher_appends_and_decodes_query_component() {
    let (url, rx) = spawn_gopher_server(b"query\r\n");
    let url = url.replace("/1/resource", "/7/search?term%20ok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().success().stdout("query\r\n");

    assert_eq!(rx.recv().unwrap(), b"/search?term ok\r\n");
}

#[test]
fn gopher_writeout_reports_zero_http_code_and_download_size() {
    let (url, rx) = spawn_gopher_server(b"abcdef");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-w", " %{http_code} %{size_download}", &url]);
    command.assert().success().stdout("abcdef 000 6");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
}

#[test]
fn gopher_remote_name_writes_url_filename() {
    let temp = tempdir().unwrap();
    let (url, rx) = spawn_gopher_server(b"saved");
    let url = url.replace("/1/resource", "/1/nested/result.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .current_dir(temp.path())
        .args(["-q", "-sS", "-O", &url]);
    command.assert().success().stdout("");

    assert_eq!(rx.recv().unwrap(), b"/nested/result.txt\r\n");
    assert_eq!(
        std::fs::read_to_string(temp.path().join("result.txt")).unwrap(),
        "saved"
    );
}

#[test]
fn gopher_rejects_decoded_nul_selector() {
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "gopher://example.invalid/1/%00"]);
    command.assert().failure().code(3).stdout("");
}

#[test]
fn gopher_include_does_not_echo_selector_header_data() {
    let (url, rx) = spawn_gopher_server(b"body\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-i", &url]);
    command.assert().success().stdout("body\r\n");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
}

#[test]
fn gopher_dump_header_writes_selector_as_header_data() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("gopher.headers");
    let (url, rx) = spawn_gopher_server(b"body\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-D", dump.to_str().unwrap(), &url]);
    command.assert().success().stdout("body\r\n");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
    assert_eq!(std::fs::read(dump).unwrap(), b"/resource\r\n");
}

#[test]
fn gopher_dump_header_dash_writes_selector_before_body() {
    let (url, rx) = spawn_gopher_server(b"body\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-D", "-", &url]);
    command.assert().success().stdout("/resource\r\nbody\r\n");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
}

#[test]
fn gopher_head_sends_selector_without_output_body() {
    let (url, rx) = spawn_gopher_server(b"body\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-I", &url]);
    command.assert().success().stdout("");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
}

#[test]
fn gopher_head_dump_header_writes_selector_without_body() {
    let temp = tempdir().unwrap();
    let dump = temp.path().join("gopher.headers");
    let (url, rx) = spawn_gopher_server(b"body\r\n");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-I", "-D", dump.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
    assert_eq!(std::fs::read(dump).unwrap(), b"/resource\r\n");
}

#[test]
fn gopher_header_json_remains_empty() {
    let (url, rx) = spawn_gopher_server(b"body");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-w", " %{header_json}", &url]);
    command.assert().success().stdout("body {}");

    assert_eq!(rx.recv().unwrap(), b"/resource\r\n");
}

#[test]
fn username_only_basic_auth_encodes_empty_password() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "alice", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "authorization"), Some("Basic YWxpY2U6"));
}

#[test]
fn basic_auth_selector_keeps_basic_http_auth() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--basic", "-u", "alice:secret", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(
        header(&request, "authorization"),
        Some("Basic YWxpY2U6c2VjcmV0")
    );
}

#[test]
fn unsupported_http_auth_selector_fails_before_basic_fallback() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--digest", "-u", "alice:secret", &url]);
    command.assert().failure().code(2).stdout("");

    assert!(rx.try_recv().is_err());
}

#[test]
fn sends_oauth2_bearer_authorization_header() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--oauth2-bearer", "token123", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "authorization"), Some("Bearer token123"));
}

#[test]
fn proxy_user_sets_proxy_authorization_header() {
    let (proxy_url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-x",
        &proxy_url,
        "-U",
        "aladdin:opensesame",
        "http://example.test/resource",
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(
        request
            .start_line
            .starts_with("GET http://example.test/resource HTTP/1.1")
    );
    assert!(header(&request, "user-agent").unwrap().starts_with("curl/"));
    assert_eq!(header(&request, "accept"), Some("*/*"));
    assert_eq!(header(&request, "proxy-connection"), Some("Keep-Alive"));
    assert_eq!(
        header(&request, "proxy-authorization"),
        Some("Basic YWxhZGRpbjpvcGVuc2VzYW1l")
    );
}

#[test]
fn unsupported_proxy_auth_selector_fails_before_basic_fallback() {
    let (proxy_url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-x",
        &proxy_url,
        "--proxy-digest",
        "-U",
        "aladdin:opensesame",
        "http://example.test/resource",
    ]);
    command.assert().failure().code(2).stdout("");

    assert!(rx.try_recv().is_err());
}

#[test]
fn unsupported_proxy_auth_selector_rejects_proxy_url_credentials() {
    let (proxy_url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let proxy = proxy_url.replacen("http://", "http://aladdin:opensesame@", 1);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-x",
        &proxy,
        "--proxy-digest",
        "http://example.test/resource",
    ]);
    command.assert().failure().code(2).stdout("");

    assert!(rx.try_recv().is_err());
}

#[test]
fn request_target_sets_http_proxy_request_line() {
    let (proxy_url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--request-target",
        "*",
        "-X",
        "OPTIONS",
        "-x",
        &proxy_url,
        "http://www.example.org/",
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "OPTIONS * HTTP/1.1");
    assert_eq!(header(&request, "host"), Some("www.example.org"));
    assert_eq!(header(&request, "proxy-connection"), Some("Keep-Alive"));
}

#[test]
fn raw_proxy_uses_user_agent_option_and_empty_value_suppresses_default() {
    let (custom_proxy_url, custom_rx) =
        spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ncustom");

    let mut custom = Command::cargo_bin("curl").unwrap();
    custom.args([
        "-q",
        "-sS",
        "-x",
        &custom_proxy_url,
        "-A",
        "proxy-agent",
        "http://example.test/resource",
    ]);
    custom.assert().success().stdout("custom");
    let custom_request = custom_rx.recv().unwrap();
    assert!(
        custom_request
            .start_line
            .starts_with("GET http://example.test/resource HTTP/1.1")
    );
    assert_eq!(header(&custom_request, "user-agent"), Some("proxy-agent"));
    assert_eq!(header_count(&custom_request, "user-agent"), 1);
    assert_eq!(header(&custom_request, "accept"), Some("*/*"));

    let (empty_proxy_url, empty_rx) =
        spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nempty");

    let mut empty = Command::cargo_bin("curl").unwrap();
    empty.args([
        "-q",
        "-sS",
        "-x",
        &empty_proxy_url,
        "-A",
        "",
        "http://example.test/resource",
    ]);
    empty.assert().success().stdout("empty");
    let empty_request = empty_rx.recv().unwrap();
    assert_eq!(header(&empty_request, "user-agent"), None);
    assert_eq!(header(&empty_request, "accept"), Some("*/*"));
}

#[test]
fn raw_proxy_empty_custom_headers_suppress_defaults_and_semicolon_sends_blank() {
    let (proxy_url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-x",
        &proxy_url,
        "-H",
        "Accept:",
        "-H",
        "User-Agent:",
        "-H",
        "X-Blank;",
        "http://example.test/resource",
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(
        request
            .start_line
            .starts_with("GET http://example.test/resource HTTP/1.1")
    );
    assert_eq!(header(&request, "accept"), None);
    assert_eq!(header(&request, "user-agent"), None);
    assert_eq!(header(&request, "x-blank"), Some(""));
}

#[test]
fn noproxy_bypasses_configured_proxy() {
    let (target_url, target_rx) =
        spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ntarget");
    let (proxy_url, proxy_rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nproxy");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-x", &proxy_url, "--noproxy", "*", &target_url]);
    command.assert().success().stdout("target");

    target_rx.recv().unwrap();
    assert!(proxy_rx.recv_timeout(Duration::from_millis(100)).is_err());
}

#[test]
fn etag_compare_sends_if_none_match() {
    let temp = tempdir().unwrap();
    let etag = temp.path().join("etag.txt");
    std::fs::write(&etag, "\"abc123\"\n").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--etag-compare", etag.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "if-none-match"), Some("\"abc123\""));
}

#[test]
fn etag_compare_missing_file_sends_empty_etag() {
    let temp = tempdir().unwrap();
    let etag = temp.path().join("missing.txt");
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--etag-compare", etag.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "if-none-match"), Some("\"\""));
}

#[test]
fn etag_save_writes_response_etag() {
    let temp = tempdir().unwrap();
    let etag = temp.path().join("nested").join("etag.txt");
    let (url, rx) =
        spawn_server(b"HTTP/1.1 200 OK\r\nETag: \"saved\"\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--create-dirs",
        "--etag-save",
        etag.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("ok");

    rx.recv().unwrap();
    assert_eq!(std::fs::read_to_string(etag).unwrap(), "\"saved\"\n");
}

#[test]
fn etag_save_creates_empty_file_when_header_missing() {
    let temp = tempdir().unwrap();
    let etag = temp.path().join("etag.txt");
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--etag-save", etag.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    rx.recv().unwrap();
    assert_eq!(std::fs::read_to_string(etag).unwrap(), "");
}

#[test]
fn cookie_jar_saves_response_cookies() {
    let response = b"HTTP/1.1 200 OK\r\n\
        Set-Cookie: sid=abc; Path=/; HttpOnly\r\n\
        Set-Cookie: theme=light; Path=/resource; Secure\r\n\
        Content-Length: 2\r\n\r\nok";
    let (url, rx) = spawn_server(response);
    let temp = tempdir().unwrap();
    let jar = temp.path().join("cookies.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-c", jar.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    rx.recv().unwrap();
    let text = std::fs::read_to_string(jar).unwrap();
    assert!(text.starts_with("# Netscape HTTP Cookie File\n"));
    assert!(text.contains("#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t0\tsid\tabc\n"));
    assert!(text.contains("127.0.0.1\tFALSE\t/resource\tTRUE\t0\ttheme\tlight\n"));
}

#[test]
fn cookie_jar_creates_header_only_file_without_cookies() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let temp = tempdir().unwrap();
    let jar = temp.path().join("cookies.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--cookie-jar", jar.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    rx.recv().unwrap();
    assert_eq!(
        std::fs::read_to_string(jar).unwrap(),
        "# Netscape HTTP Cookie File\n\
         # https://curl.se/docs/http-cookies.html\n\
         # This file was generated by libcurl! Edit at your own risk.\n\n"
    );
}

#[test]
fn cookie_jar_sends_cookie_on_later_url_in_group() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        tx.send(read_request(&mut stream)).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/\r\nConnection: close\r\nContent-Length: 3\r\n\r\none",
            )
            .unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        tx.send(read_request(&mut stream)).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
            .unwrap();
    });
    let first = format!("http://{addr}/one");
    let second = format!("http://{addr}/two");
    let temp = tempdir().unwrap();
    let jar = temp.path().join("cookies.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-c", jar.to_str().unwrap(), &first, &second]);
    command.assert().success().stdout("onetwo");

    rx.recv().unwrap();
    let second_request = rx.recv().unwrap();
    assert_eq!(header(&second_request, "cookie"), Some("sid=abc"));
}

#[test]
fn cookie_jar_sends_redirect_cookie_on_followup() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nSet-Cookie: sid=abc; Path=/\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let temp = tempdir().unwrap();
    let jar = temp.path().join("cookies.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "-c", jar.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    rx.recv().unwrap();
    let second_request = rx.recv().unwrap();
    assert_eq!(header(&second_request, "cookie"), Some("sid=abc"));
}

#[test]
fn empty_cookie_input_activates_cookie_engine() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        tx.send(read_request(&mut stream)).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/\r\nConnection: close\r\nContent-Length: 3\r\n\r\none",
            )
            .unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        tx.send(read_request(&mut stream)).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
            .unwrap();
    });
    let first = format!("http://{addr}/one");
    let second = format!("http://{addr}/two");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-b", "", &first, &second]);
    command.assert().success().stdout("onetwo");

    rx.recv().unwrap();
    let second_request = rx.recv().unwrap();
    assert_eq!(header(&second_request, "cookie"), Some("sid=abc"));
}

#[test]
fn cookie_header_appends_repeated_literals() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-b",
        "name=contents;name2=content2",
        "-b",
        "name3=content3",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(
        header(&request, "cookie"),
        Some("name=contents;name2=content2; name3=content3")
    );

    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-b",
        "name=contents",
        "-b",
        " name2=content2",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(
        header(&request, "cookie"),
        Some("name=contents; name2=content2")
    );
}

#[test]
fn cookie_file_sends_netscape_cookie() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let host = Url::parse(&url).unwrap().host_str().unwrap().to_string();
    let temp = tempdir().unwrap();
    let cookie_file = temp.path().join("cookies.txt");
    std::fs::write(
        &cookie_file,
        format!("{host}\tFALSE\t/\tFALSE\t0\tsid\tfrom-file\n"),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-b", cookie_file.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "cookie"), Some("sid=from-file"));
}

#[test]
fn junk_session_cookies_ignores_file_session_cookies() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let host = Url::parse(&url).unwrap().host_str().unwrap().to_string();
    let temp = tempdir().unwrap();
    let cookie_file = temp.path().join("cookies.txt");
    std::fs::write(
        &cookie_file,
        format!(
            "{host}\tFALSE\t/\tFALSE\t2000000000\tpersist\tyes\n\
             {host}\tFALSE\t/\tFALSE\t0\tsession\tno\n"
        ),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-j", "-b", cookie_file.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "cookie"), Some("persist=yes"));
}

#[test]
fn cookie_file_and_literal_cookie_are_combined() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let host = Url::parse(&url).unwrap().host_str().unwrap().to_string();
    let temp = tempdir().unwrap();
    let cookie_file = temp.path().join("cookies.txt");
    std::fs::write(
        &cookie_file,
        format!("{host}\tFALSE\t/\tFALSE\t0\tsid\tfrom-file\n"),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-b",
        cookie_file.to_str().unwrap(),
        "-b",
        "tool=curl",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "cookie"), Some("sid=from-file; tool=curl"));
}

#[test]
fn libcurl_writes_source_file_for_supported_options() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let temp = tempdir().unwrap();
    let source = temp.path().join("client.c");
    let parsed_url = Url::parse(&url).unwrap();
    let host = parsed_url.host_str().unwrap().to_string();
    let resolve_entry = format!("{}:{}:127.0.0.1", host, parsed_url.port().unwrap());
    let connect_to_entry = "nomatch.test:80:127.0.0.1:80";
    let cookie_file = temp.path().join("cookies.txt");
    std::fs::write(
        &cookie_file,
        format!("{host}\tFALSE\t/\tFALSE\t2000000000\tpersist\tyes\n"),
    )
    .unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "-X",
        "PUT",
        "-H",
        "X-Test: yes",
        "--list-only",
        "-d",
        "a=b",
        "-u",
        "alice:secret",
        "-A",
        "MyUA",
        "--oauth2-bearer",
        "token123",
        "--resolve",
        &resolve_entry,
        "--connect-to",
        connect_to_entry,
        "--disallow-username-in-url",
        "--max-filesize",
        "2M",
        "--http1.1",
        "--tlsv1.2",
        "--tls-max",
        "1.3",
        "--ipv4",
        "-e",
        "firstone.html;auto",
        "-j",
        "-b",
        cookie_file.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PUT /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-test"), Some("yes"));
    assert_eq!(header(&request, "referer"), Some("firstone.html"));
    assert_eq!(header(&request, "cookie"), Some("persist=yes"));
    assert_eq!(request.body, b"a=b");

    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("Sample code generated by the curl command line tool"));
    assert!(text.contains(&format!("CURLOPT_URL, \"{url}\"")));
    assert!(text.contains("curl_slist_append(slist1, \"X-Test: yes\");"));
    assert!(text.contains("CURLOPT_CUSTOMREQUEST, \"PUT\""));
    assert!(text.contains("CURLOPT_DIRLISTONLY, 1"));
    assert!(text.contains("CURLOPT_POSTFIELDS, \"a=b\""));
    assert!(text.contains("CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)3"));
    assert!(text.contains("CURLOPT_USERPWD, \"alice:secret\""));
    assert!(text.contains("CURLOPT_XOAUTH2_BEARER, \"token123\""));
    assert!(text.contains("CURLOPT_USERAGENT, \"MyUA\""));
    assert!(text.contains(&format!("curl_slist_append(slist2, \"{resolve_entry}\");")));
    assert!(text.contains("CURLOPT_RESOLVE, slist2"));
    assert!(text.contains(&format!(
        "curl_slist_append(slist3, \"{connect_to_entry}\");"
    )));
    assert!(text.contains("CURLOPT_CONNECT_TO, slist3"));
    assert!(text.contains("CURLOPT_DISALLOW_USERNAME_IN_URL, 1"));
    assert!(text.contains("CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)2097152"));
    assert!(text.contains("CURLOPT_REFERER, \"firstone.html\""));
    assert!(text.contains("CURLOPT_AUTOREFERER, 1"));
    assert!(text.contains("CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1"));
    assert!(text.contains(
        "CURLOPT_SSLVERSION, (long)(CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_3)"
    ));
    assert!(text.contains("CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4"));
    assert!(text.contains(&format!(
        "CURLOPT_COOKIEFILE, \"{}\"",
        cookie_file.display()
    )));
    assert!(text.contains("CURLOPT_COOKIESESSION, 1"));
    assert!(text.contains("curl_easy_perform(curl);"));
}

#[test]
fn libcurl_writes_request_target_option() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let temp = tempdir().unwrap();
    let source = temp.path().join("client.c");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "--http0.9",
        "--request-target",
        "*",
        "-X",
        "OPTIONS",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(request.start_line, "OPTIONS * HTTP/1.1");

    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("CURLOPT_CUSTOMREQUEST, \"OPTIONS\""));
    assert!(text.contains("CURLOPT_HTTP09_ALLOWED, 1"));
    assert!(text.contains("CURLOPT_REQUEST_TARGET, \"*\""));
}

#[test]
fn libcurl_writes_curl_compatible_default_user_agent() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let temp = tempdir().unwrap();
    let source = temp.path().join("client.c");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "--libcurl", source.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(header(&request, "user-agent").unwrap().starts_with("curl/"));
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("CURLOPT_USERAGENT, \"curl/"));
    assert!(!text.contains("CURLOPT_USERAGENT, \"curl-rust/"));
}

#[test]
fn libcurl_writes_smtp_mail_options() {
    let (url, rx) = spawn_smtp_server(
        "/libcurl.example",
        b"250 libcurl.example\r\n",
        b"250 ok\r\n",
    );
    let temp = tempdir().unwrap();
    let source = temp.path().join("smtp-client.c");

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .args([
            "-q",
            "-sS",
            "--libcurl",
            source.to_str().unwrap(),
            "--mail-from",
            "sender@example.com",
            "--mail-rcpt",
            "one@example.com",
            "--mail-rcpt",
            "two@example.com",
            "--mail-rcpt-allowfails",
            "-T",
            "-",
            &url,
        ])
        .write_stdin("body\r\n");
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"EHLO libcurl.example\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<one@example.com>\r\nRCPT TO:<two@example.com>\r\nDATA\r\nQUIT\r\n"
    );

    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("CURLOPT_MAIL_FROM, \"sender@example.com\""));
    assert!(text.contains("curl_slist_append(slist1, \"one@example.com\");"));
    assert!(text.contains("curl_slist_append(slist1, \"two@example.com\");"));
    assert!(text.contains("CURLOPT_MAIL_RCPT, slist1"));
    assert!(text.contains("CURLOPT_MAIL_RCPT_ALLOWFAILS, 1"));
}

#[test]
fn libcurl_writes_tftp_options() {
    let (url, rx) = spawn_tftp_server(vec![b"ok".to_vec()]);
    let temp = tempdir().unwrap();
    let source = temp.path().join("tftp-client.c");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "--tftp-blksize",
        "1024",
        "--tftp-no-options",
        "--use-ascii",
        &url,
    ]);
    command.assert().success().stdout("ok");

    assert_eq!(rx.recv().unwrap().request, b"\0\x01file.txt\0netascii\0");
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("CURLOPT_TFTP_BLKSIZE, 1024"));
    assert!(text.contains("CURLOPT_TFTP_NO_OPTIONS, 1"));
    assert!(text.contains("CURLOPT_TRANSFERTEXT, 1"));
}

#[test]
fn libcurl_writes_tftp_upload_directory_url() {
    let (url, rx) = spawn_tftp_upload_server(tftp_ack(0), 512);
    let url = url.replace("/upload.bin", "//");
    let temp = tempdir().unwrap();
    let upload = temp.path().join("client.bin");
    let source = temp.path().join("tftp-upload-client.c");
    std::fs::write(&upload, b"upload").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    assert!(
        rx.recv()
            .unwrap()
            .request
            .starts_with(b"\0\x02/client.bin\0octet\0")
    );
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains(&format!("CURLOPT_URL, \"{}client.bin\"", url)));
}

#[test]
fn libcurl_writes_ftp_upload_append_options() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("payload.txt");
    let source = temp.path().join("ftp-upload-client.c");
    std::fs::write(&upload, b"append").unwrap();
    let (url, rx) = spawn_ftp_server("/target.txt", ftp_options(Vec::new()));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "--append",
        "-T",
        upload.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let record = rx.recv().unwrap();
    assert_eq!(
        record.commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\nAPPE target.txt\r\nQUIT\r\n"
    );
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("CURLOPT_UPLOAD, 1L"));
    assert!(text.contains("CURLOPT_APPEND, 1L"));
}

#[test]
fn libcurl_writes_ftp_passive_options() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("ftp-passive-client.c");
    let (url, rx) = spawn_ftp_server("/file.txt", ftp_options(b"downloaded"));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "--disable-epsv",
        "--ftp-skip-pasv-ip",
        &url,
    ]);
    command.assert().success().stdout("downloaded");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nPASV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("CURLOPT_FTP_USE_EPSV, 0L"));
    assert!(text.contains("CURLOPT_FTP_SKIP_PASV_IP, 1L"));
}

#[test]
fn libcurl_writes_ftp_create_dirs_option() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("ftp-create-dirs-client.c");
    let mut options = ftp_options(b"downloaded");
    options.missing_directories = vec!["first"];
    let (url, rx) = spawn_ftp_server("/first/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "--ftp-create-dirs",
        &url,
    ]);
    command.assert().success().stdout("downloaded");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD first\r\nMKD first\r\nCWD first\r\nEPSV\r\nTYPE I\r\nSIZE file.txt\r\nRETR file.txt\r\nQUIT\r\n"
    );
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR_RETRY"));
}

#[test]
fn libcurl_writes_ftp_quote_options() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("ftp-quote-client.c");
    let mut options = ftp_options(b"quoted");
    options.epsv_fails = true;
    let (url, rx) = spawn_ftp_server("/file.txt", options);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "-Q",
        "NOOP 1",
        "-Q",
        "+NOOP 2",
        "-Q",
        "-NOOP 3",
        "-Q",
        "*FAIL",
        "-Q",
        "+*FAIL HARD",
        &url,
    ]);
    command.assert().success().stdout("quoted");

    assert_eq!(
        rx.recv().unwrap().commands,
        b"USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nNOOP 1\r\nFAIL\r\nEPSV\r\nPASV\r\nTYPE I\r\nNOOP 2\r\nFAIL HARD\r\nSIZE file.txt\r\nRETR file.txt\r\nNOOP 3\r\nQUIT\r\n"
    );
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("struct curl_slist *slist1;"));
    assert!(text.contains("struct curl_slist *slist2;"));
    assert!(text.contains("struct curl_slist *slist3;"));
    assert!(text.contains("curl_slist_append(slist1, \"NOOP 1\");"));
    assert!(text.contains("curl_slist_append(slist1, \"*FAIL\");"));
    assert!(text.contains("curl_slist_append(slist2, \"NOOP 3\");"));
    assert!(text.contains("curl_slist_append(slist3, \"NOOP 2\");"));
    assert!(text.contains("curl_slist_append(slist3, \"*FAIL HARD\");"));
    assert!(text.contains("CURLOPT_QUOTE, slist1"));
    assert!(text.contains("CURLOPT_POSTQUOTE, slist2"));
    assert!(text.contains("CURLOPT_PREQUOTE, slist3"));
}

#[test]
fn libcurl_rewrites_ipfs_url_to_gateway_url() {
    let (url, rx) = spawn_server(IPFS_RESPONSE);
    let gateway = gateway_origin(&url);
    let temp = tempdir().unwrap();
    let source = temp.path().join("client.c");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "--ipfs-gateway",
        &gateway,
        &format!("ipfs://{IPFS_CID}"),
    ]);
    command.assert().success().stdout("Hello curl from IPFS\n");

    assert_eq!(
        rx.recv().unwrap().start_line,
        format!("GET /ipfs/{IPFS_CID} HTTP/1.1")
    );
    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains(&format!("CURLOPT_URL, \"{gateway}/ipfs/{IPFS_CID}\"")));
}

#[test]
fn libcurl_writes_http_upload_options() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    let source = temp.path().join("upload-client.c");
    std::fs::write(&upload, "body").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let base_url = format!("{}/", gateway_origin(&url));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--libcurl",
        source.to_str().unwrap(),
        "-T",
        upload.to_str().unwrap(),
        &base_url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PUT /upload.txt HTTP/1.1"));

    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains(&format!("CURLOPT_URL, \"{base_url}upload.txt\"")));
    assert!(text.contains("CURLOPT_UPLOAD, 1L"));
    assert!(text.contains("CURLOPT_INFILESIZE_LARGE, (curl_off_t)4"));
}

#[test]
fn parallel_runs_transfers_concurrently_to_files() {
    let (slow_url, slow_rx) = spawn_timed_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow",
        Duration::from_millis(900),
    );
    let (fast_url, fast_rx) = spawn_timed_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfast",
        Duration::ZERO,
    );
    let temp = tempdir().unwrap();
    let slow_out = temp.path().join("slow.txt");
    let fast_out = temp.path().join("fast.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--parallel",
        "--parallel-max",
        "2",
        "-o",
        slow_out.to_str().unwrap(),
        &slow_url,
        "--next",
        "-o",
        fast_out.to_str().unwrap(),
        &fast_url,
    ]);
    command.assert().success().stdout("");

    let slow_started = slow_rx.recv().unwrap();
    let fast_started = fast_rx.recv().unwrap();
    let delta = if fast_started >= slow_started {
        fast_started.duration_since(slow_started)
    } else {
        slow_started.duration_since(fast_started)
    };

    assert!(
        delta < Duration::from_millis(700),
        "expected concurrent request starts, got {delta:?}"
    );
    assert_eq!(std::fs::read_to_string(slow_out).unwrap(), "slow");
    assert_eq!(std::fs::read_to_string(fast_out).unwrap(), "fast");
}

#[test]
fn time_cond_sends_if_modified_since() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-z", "Wed, 21 Oct 2015 07:28:00 GMT", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(
        header(&request, "if-modified-since"),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
}

#[test]
fn negative_time_cond_sends_if_unmodified_since() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--time-cond",
        "-Wed, 21 Oct 2015 07:28:00 GMT",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(
        header(&request, "if-unmodified-since"),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
}

#[test]
fn file_head_outputs_file_headers() {
    let temp = tempdir().unwrap();
    let file = temp.path().join("plain.txt");
    std::fs::write(&file, "hello").unwrap();
    let url = Url::from_file_path(&file).unwrap().to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-I", &url]);
    let output = command.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("content-length: 5\r\n"));
    assert!(!stdout.contains("HTTP/"));
}

#[test]
fn file_range_outputs_slice() {
    let temp = tempdir().unwrap();
    let file = temp.path().join("plain.txt");
    std::fs::write(&file, "hello").unwrap();
    let url = Url::from_file_path(&file).unwrap().to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-r", "1-3", &url]);
    command.assert().success().stdout("ell");
}

#[test]
fn file_missing_source_returns_file_read_error() {
    let temp = tempdir().unwrap();
    let url = Url::from_file_path(temp.path().join("missing.txt"))
        .unwrap()
        .to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &url]);
    command.assert().failure().code(37).stdout("");
}

#[test]
fn file_upload_writes_local_target() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    let target = temp.path().join("written.txt");
    std::fs::write(&upload, "data\nin\nfile\n").unwrap();
    let url = Url::from_file_path(&target).unwrap().to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read_to_string(target).unwrap(), "data\nin\nfile\n");
}

#[test]
fn file_upload_missing_parent_returns_write_error() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    let target = temp.path().join("missing").join("written.txt");
    std::fs::write(&upload, "data").unwrap();
    let url = Url::from_file_path(&target).unwrap().to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-T", upload.to_str().unwrap(), &url]);
    command.assert().failure().code(23).stdout("");
}

#[test]
fn file_urls_accept_uppercase_scheme_and_single_slash() {
    let temp = tempdir().unwrap();
    let file = temp.path().join("plain.txt");
    std::fs::write(&file, "hello").unwrap();
    let url = Url::from_file_path(&file).unwrap().to_string();
    let uppercase_url = url.replacen("file://", "FILE://", 1);
    let single_slash_url = format!("file:{}", file.display());

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", &uppercase_url, &single_slash_url]);
    command.assert().success().stdout("hellohello");
}

#[test]
fn continue_at_fixed_offset_sends_range_and_appends_output() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 2-4/5\r\nContent-Length: 3\r\n\r\nllo",
    );
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "he").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "2", "-o", output.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=2-"));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "hello");
}

#[test]
fn continue_at_fixed_offset_to_stdout_sends_range() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-4/5\r\nContent-Length: 2\r\n\r\nlo",
    );

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C3", &url]);
    command.assert().success().stdout("lo");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=3-"));
}

#[test]
fn continue_at_auto_uses_existing_output_size() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-4/5\r\nContent-Length: 2\r\n\r\nlo",
    );
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "hel").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--continue-at",
        "-",
        "-o",
        output.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=3-"));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "hello");
}

#[test]
fn continue_at_http_200_without_content_range_fails_without_appending() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "he").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-C",
        "2",
        "-o",
        output.to_str().unwrap(),
        "-w",
        " %{exitcode} %{errormsg} %{size_download}",
        &url,
    ]);
    command
        .assert()
        .failure()
        .code(33)
        .stdout(" 33 HTTP server does not seem to support byte ranges. Cannot resume. 0");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=2-"));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "he");
}

#[test]
fn continue_at_http_200_matching_existing_length_is_already_complete() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhe");
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "he").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "2", "-o", output.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=2-"));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "he");
}

#[test]
fn continue_at_http_416_with_fail_is_already_complete() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 416 Invalid range\r\nContent-Range: */2\r\nContent-Length: 5\r\n\r\nerror",
    );
    let temp = tempdir().unwrap();
    let output = temp.path().join("download.txt");
    std::fs::write(&output, "he").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-f",
        "-C",
        "2",
        "-o",
        output.to_str().unwrap(),
        "-w",
        " %{exitcode} %{http_code} %{size_download}",
        &url,
    ]);
    command.assert().success().stdout(" 0 416 0");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=2-"));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "he");
}

#[test]
fn continue_at_auto_to_stdout_uses_zero_offset() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "-", &url]);
    command.assert().success().stdout("hello");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), None);
}

#[test]
fn continue_at_resumes_file_url_output() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("plain.txt");
    let output = temp.path().join("copy.txt");
    std::fs::write(&source, "hello").unwrap();
    std::fs::write(&output, "he").unwrap();
    let url = Url::from_file_path(&source).unwrap().to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C", "2", "-o", output.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    assert_eq!(std::fs::read_to_string(output).unwrap(), "hello");
}

#[test]
fn sends_referer_range_and_url_query() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-e",
        "https://refer.example/source",
        "-r",
        "2-5",
        "--url-query",
        "q=hello world",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(
        request
            .start_line
            .starts_with("GET /resource?q=hello+world ")
    );
    assert_eq!(
        header(&request, "referer"),
        Some("https://refer.example/source")
    );
    assert_eq!(header(&request, "range"), Some("bytes=2-5"));
}

#[test]
fn location_does_not_auto_referer_without_referer_auto() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", &url]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "referer"), None);
    assert_eq!(header(&second, "referer"), None);
}

#[test]
fn location_unlimited_max_redirs_follows_more_than_default_limit() {
    const REDIRECT: &[u8] =
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    let mut responses = vec![REDIRECT; 51];
    responses.push(OK);
    let (url, rx) = spawn_sequence_server(responses);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--max-redirs", "-1", &url]);
    command.assert().success().stdout("ok");

    for _ in 0..52 {
        rx.recv().unwrap();
    }
}

#[test]
fn redirect_strips_oauth2_bearer_on_cross_origin_by_default() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--oauth2-bearer", "token123", &url]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "authorization"), Some("Bearer token123"));
    assert_eq!(header(&second, "authorization"), None);
}

#[test]
fn location_trusted_keeps_oauth2_bearer_on_cross_origin_redirect() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--location-trusted",
        "--oauth2-bearer",
        "token123",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "authorization"), Some("Bearer token123"));
    assert_eq!(header(&second, "authorization"), Some("Bearer token123"));
}

#[test]
fn redirect_strips_basic_auth_on_cross_origin_by_default() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--user", "user:pass", &url]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "authorization"), Some("Basic dXNlcjpwYXNz"));
    assert_eq!(header(&second, "authorization"), None);
}

#[test]
fn redirect_keeps_basic_auth_on_same_origin() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--user", "user:pass", &url]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "authorization"), Some("Basic dXNlcjpwYXNz"));
    assert_eq!(header(&second, "authorization"), Some("Basic dXNlcjpwYXNz"));
}

#[test]
fn redirect_strips_sensitive_custom_headers_on_cross_origin_by_default() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "-H",
        "Authorization: Custom auth",
        "-H",
        "Cookie: sid=abc",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "authorization"), Some("Custom auth"));
    assert_eq!(header(&first, "cookie"), Some("sid=abc"));
    assert_eq!(header(&second, "authorization"), None);
    assert_eq!(header(&second, "cookie"), None);
}

#[test]
fn location_trusted_keeps_sensitive_custom_headers_on_cross_origin_redirect() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--location-trusted",
        "-H",
        "Authorization: Custom auth",
        "-H",
        "Cookie: sid=abc",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "authorization"), Some("Custom auth"));
    assert_eq!(header(&first, "cookie"), Some("sid=abc"));
    assert_eq!(header(&second, "authorization"), Some("Custom auth"));
    assert_eq!(header(&second, "cookie"), Some("sid=abc"));
}

#[test]
fn redirect_strips_literal_cookie_on_cross_origin_by_default() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "-b", "sid=abc", &url]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "cookie"), Some("sid=abc"));
    assert_eq!(header(&second, "cookie"), None);
}

#[test]
fn cookie_engine_strips_literal_cookie_on_cross_origin_redirect_by_default() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let temp = tempdir().unwrap();
    let jar = temp.path().join("cookies.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "-c",
        jar.to_str().unwrap(),
        "-b",
        "sid=abc",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "cookie"), Some("sid=abc"));
    assert_eq!(header(&second, "cookie"), None);
}

#[test]
fn location_trusted_keeps_cookie_engine_literal_cookie_on_cross_origin_redirect() {
    let (url, first_rx, second_rx) =
        spawn_cross_origin_redirect(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let temp = tempdir().unwrap();
    let jar = temp.path().join("cookies.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "--location-trusted",
        "-c",
        jar.to_str().unwrap(),
        "-b",
        "sid=abc",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let first = first_rx.recv().unwrap();
    let second = second_rx.recv().unwrap();
    assert_eq!(header(&first, "cookie"), Some("sid=abc"));
    assert_eq!(header(&second, "cookie"), Some("sid=abc"));
}

#[test]
fn fixed_referer_is_reused_across_redirects_without_auto() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "-e", "fixed", "-w", " %{referer}", &url]);
    command.assert().success().stdout("ok fixed");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "referer"), Some("fixed"));
    assert_eq!(header(&second, "referer"), Some("fixed"));
}

#[test]
fn auto_referer_strips_credentials_and_fragment_on_redirect() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let auth_url = format!("{}#anchor", url.replacen("http://", "http://user:pass@", 1));

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "-e",
        ";auto",
        "-w",
        " %{referer}",
        &auth_url,
    ]);
    command.assert().success().stdout(format!("ok {url}"));

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "referer"), None);
    assert_eq!(header(&second, "referer"), Some(url.as_str()));
}

#[test]
fn auto_referer_tracks_immediately_previous_redirect_url() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: /two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let first_hop = Url::parse(&url).unwrap().join("/one").unwrap().to_string();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "-e", ";auto", "-w", " %{referer}", &url]);
    command.assert().success().stdout(format!("ok {first_hop}"));

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    let third = rx.recv().unwrap();
    assert_eq!(header(&first, "referer"), None);
    assert_eq!(header(&second, "referer"), Some(url.as_str()));
    assert_eq!(header(&third, "referer"), Some(first_hop.as_str()));
}

#[test]
fn auto_referer_redirect_rewrites_post_to_get() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "-e",
        ";auto",
        "-d",
        "body",
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok GET");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("GET /next HTTP/1.1"));
    assert!(second.body.is_empty());
    assert_eq!(header(&second, "referer"), Some(url.as_str()));
}

fn assert_plain_post_redirect_rewrites_to_get(first_response: &'static [u8]) {
    let (url, rx) = spawn_sequence_server(vec![
        first_response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "-d", "body", "-w", " %{method}", &url]);
    command.assert().success().stdout("ok GET");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("GET /next HTTP/1.1"));
    assert!(second.body.is_empty());
    assert_eq!(header(&second, "content-length"), None);
}

#[test]
fn plain_location_post301_rewrites_post_to_get() {
    assert_plain_post_redirect_rewrites_to_get(
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn plain_location_post302_rewrites_post_to_get() {
    assert_plain_post_redirect_rewrites_to_get(
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn plain_location_post303_rewrites_post_to_get() {
    assert_plain_post_redirect_rewrites_to_get(
        b"HTTP/1.1 303 See Other\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn assert_plain_post_redirect_preserves_body(first_response: &'static [u8]) {
    let (url, rx) = spawn_sequence_server(vec![
        first_response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "-d", "body", "-w", " %{method}", &url]);
    command.assert().success().stdout("ok POST");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("POST /next HTTP/1.1"));
    assert_eq!(second.body, b"body");
}

#[test]
fn plain_location_post307_preserves_body() {
    assert_plain_post_redirect_preserves_body(
        b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn plain_location_post308_preserves_body() {
    assert_plain_post_redirect_preserves_body(
        b"HTTP/1.1 308 Permanent Redirect\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn assert_post_redirect_preserves_method(first_response: &'static [u8], option: &str) {
    let (url, rx) = spawn_sequence_server(vec![
        first_response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "-d",
        "moo",
        option,
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok POST");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(first.body, b"moo");
    assert_eq!(header(&first, "referer"), None);
    assert!(second.start_line.starts_with("POST /next HTTP/1.1"));
    assert_eq!(second.body, b"moo");
    assert_eq!(header(&second, "referer"), None);
}

#[test]
fn post301_preserves_post_on_redirect() {
    assert_post_redirect_preserves_method(
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "--post301",
    );
}

#[test]
fn post302_preserves_post_on_redirect() {
    assert_post_redirect_preserves_method(
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "--post302",
    );
}

#[test]
fn post303_preserves_post_on_redirect() {
    assert_post_redirect_preserves_method(
        b"HTTP/1.1 303 See Other\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "--post303",
    );
}

#[test]
fn post301_follows_300_redirect_and_replays_post_body() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 300 Multiple Choices\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post301",
        "-d",
        "body",
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok POST");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("POST /next HTTP/1.1"));
    assert_eq!(second.body, b"body");
}

#[test]
fn custom_method_post_redirect_drops_body_when_post_flag_does_not_apply() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post302",
        "-X",
        "PUT",
        "-d",
        "body",
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok PUT");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("PUT /resource HTTP/1.1"));
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("PUT /next HTTP/1.1"));
    assert_eq!(second.body, b"");
    assert_eq!(header(&second, "content-length"), None);
}

#[test]
fn mismatched_post_redirect_flag_rewrites_post_to_get() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post301",
        "-d",
        "body",
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok GET");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("GET /next HTTP/1.1"));
    assert!(second.body.is_empty());
    assert_eq!(header(&second, "content-length"), None);
}

#[test]
fn post301_auto_referer_preserves_body_and_updates_referer() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post301",
        "-e",
        ";auto",
        "-d",
        "body",
        "-w",
        " %{method} %{referer}",
        &url,
    ]);
    command.assert().success().stdout(format!("ok POST {url}"));

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(header(&first, "referer"), None);
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("POST /next HTTP/1.1"));
    assert_eq!(header(&second, "referer"), Some(url.as_str()));
    assert_eq!(second.body, b"body");
}

#[test]
fn post301_file_data_redirect_replays_body() {
    let temp = tempdir().unwrap();
    let data = temp.path().join("data.txt");
    std::fs::write(&data, "from file").unwrap();
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post301",
        "-d",
        &format!("@{}", data.display()),
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok POST");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert_eq!(first.body, b"from file");
    assert!(second.start_line.starts_with("POST /next HTTP/1.1"));
    assert_eq!(second.body, b"from file");
}

#[test]
fn post301_multipart_redirect_replays_body() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post301",
        "-F",
        "field=value",
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok POST");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert!(second.start_line.starts_with("POST /next HTTP/1.1"));
    assert!(
        header(&first, "content-type")
            .unwrap()
            .starts_with("multipart/form-data; boundary=")
    );
    assert!(
        header(&second, "content-type")
            .unwrap()
            .starts_with("multipart/form-data; boundary=")
    );
    let body = String::from_utf8_lossy(&second.body);
    assert!(body.contains("name=\"field\""));
    assert!(body.contains("value"));
}

#[test]
fn upload_file_post303_redirect_switches_to_get_without_body() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    std::fs::write(&upload, "body").unwrap();
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 303 See Other\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post303",
        "-T",
        upload.to_str().unwrap(),
        "-w",
        " %{method}",
        &url,
    ]);
    command.assert().success().stdout("ok GET");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("PUT /resource HTTP/1.1"));
    assert_eq!(first.body, b"body");
    assert!(second.start_line.starts_with("GET /next HTTP/1.1"));
    assert!(second.body.is_empty());
    assert_eq!(header(&second, "content-length"), None);
}

#[test]
fn auto_referer_respects_max_redirs_limit() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--max-redirs", "0", "-e", ";auto", &url]);
    command.assert().failure().code(47).stdout("");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "referer"), None);
}

#[test]
fn plain_location_respects_max_redirs_zero() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "--max-redirs", "0", &url]);
    command.assert().failure().code(47).stdout("");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("GET /resource HTTP/1.1"));
    assert!(rx.try_recv().is_err());
}

#[test]
fn initial_referer_auto_replaces_referer_after_redirect() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "-e",
        "firstone.html;auto",
        "-w",
        " %{referer}",
        &url,
    ]);
    command.assert().success().stdout(format!("ok {url}"));

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "referer"), Some("firstone.html"));
    assert_eq!(header(&second, "referer"), Some(url.as_str()));
}

#[test]
fn custom_referer_header_suppresses_generated_referer() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "-e",
        ";auto",
        "-H",
        "Referer: custom",
        "-w",
        " %{referer}",
        &url,
    ]);
    command.assert().success().stdout("ok custom");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert_eq!(header(&first, "referer"), Some("custom"));
    assert_eq!(header(&second, "referer"), Some("custom"));
}

#[test]
fn sends_multipart_form_body() {
    let temp = tempdir().unwrap();
    let upload = temp.path().join("upload.txt");
    std::fs::write(&upload, "file body").unwrap();
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let file_arg = format!("upload=@{}", upload.display());

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-F", "field=value", "-F", &file_arg, &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("POST /resource HTTP/1.1"));
    assert!(
        header(&request, "content-type")
            .unwrap()
            .starts_with("multipart/form-data; boundary=")
    );
    let body = String::from_utf8_lossy(&request.body);
    assert!(body.contains("name=\"field\""));
    assert!(body.contains("value"));
    assert!(body.contains("name=\"upload\""));
    assert!(body.contains("filename=\"upload.txt\""));
    assert!(body.contains("file body"));
}

#[test]
fn dump_header_dash_writes_headers_to_stdout() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nX-Test: yes\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-D", "-", &url]);
    command
        .assert()
        .success()
        .stdout("HTTP/1.1 200 OK\r\nx-test: yes\r\ncontent-length: 2\r\n\r\nok");
    rx.recv().unwrap();
}

#[test]
fn dump_header_percent_writes_headers_to_stderr() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nX-Test: yes\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-D", "%", &url]);
    command
        .assert()
        .success()
        .stdout("ok")
        .stderr("HTTP/1.1 200 OK\r\nx-test: yes\r\ncontent-length: 2\r\n\r\n");
    rx.recv().unwrap();
}

#[test]
fn dump_header_records_manual_redirect_history() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nX-Hop: one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Hop: two\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("headers.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-L",
        "--post301",
        "-d",
        "moo",
        "-D",
        dump_path.to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("POST /resource HTTP/1.1"));
    assert!(second.start_line.starts_with("POST /next HTTP/1.1"));

    let headers = std::fs::read_to_string(dump_path).unwrap();
    assert!(headers.contains("HTTP/1.1 301 Moved Permanently\r\n"));
    assert!(headers.contains("x-hop: one\r\n"));
    assert!(headers.contains("HTTP/1.1 200 OK\r\n"));
    assert!(headers.contains("x-hop: two\r\n"));
}

#[test]
fn dump_header_records_plain_location_redirect_history() {
    let (url, rx) = spawn_sequence_server(vec![
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nX-Hop: one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Hop: two\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("headers.txt");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-L", "-D", dump_path.to_str().unwrap(), &url]);
    command.assert().success().stdout("ok");

    let first = rx.recv().unwrap();
    let second = rx.recv().unwrap();
    assert!(first.start_line.starts_with("GET /resource HTTP/1.1"));
    assert!(second.start_line.starts_with("GET /next HTTP/1.1"));

    let headers = std::fs::read_to_string(dump_path).unwrap();
    assert!(headers.contains("HTTP/1.1 301 Moved Permanently\r\n"));
    assert!(headers.contains("x-hop: one\r\n"));
    assert!(headers.contains("HTTP/1.1 200 OK\r\n"));
    assert!(headers.contains("x-hop: two\r\n"));
}

#[test]
fn dump_header_missing_parent_exits_write_error() {
    let temp = tempdir().unwrap();
    let dump_path = temp.path().join("missing").join("headers.txt");
    let url = "http://127.0.0.1:9/resource";

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-D", dump_path.to_str().unwrap(), url]);
    command.assert().failure().code(23).stdout("");

    assert!(!dump_path.exists());
}

#[test]
fn remote_header_name_requires_remote_name() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"server.bin\"\r\nContent-Length: 2\r\n\r\nok",
    );
    let temp = tempdir().unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .current_dir(temp.path())
        .args(["-q", "-sS", "-J", &url]);
    command.assert().success().stdout("ok");

    rx.recv().unwrap();
    assert!(!temp.path().join("server.bin").exists());
}

#[test]
fn remote_header_name_with_remote_name_writes_header_filename() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"server.bin\"\r\nContent-Length: 2\r\n\r\nok",
    );
    let temp = tempdir().unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command
        .current_dir(temp.path())
        .args(["-q", "-sS", "-O", "-J", &url]);
    command.assert().success().stdout("");

    rx.recv().unwrap();
    assert_eq!(
        std::fs::read_to_string(temp.path().join("server.bin")).unwrap(),
        "ok"
    );
}

#[test]
fn remote_header_name_with_remote_name_refuses_to_overwrite_header_filename() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nContent-Disposition: filename=name1460; charset=funny\r\nContent-Length: 4\r\n\r\nhej\n",
    );
    let temp = tempdir().unwrap();
    let output = temp.path().join("name1460");
    std::fs::write(&output, "initial content\n").unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-J",
        "-i",
        "-O",
        "--output-dir",
        temp.path().to_str().unwrap(),
        &url,
    ]);
    command.assert().failure().code(23).stdout("");

    rx.recv().unwrap();
    assert_eq!(
        std::fs::read_to_string(output).unwrap(),
        "initial content\n"
    );
}

#[test]
fn remote_header_name_with_remote_name_strips_header_filename_path() {
    let (url, rx) = spawn_server(
        b"HTTP/1.1 200 OK\r\nContent-Disposition: filename=log/server/server.bin\r\nContent-Length: 2\r\n\r\nok",
    );
    let temp = tempdir().unwrap();

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args([
        "-q",
        "-sS",
        "-J",
        "-O",
        "--output-dir",
        temp.path().to_str().unwrap(),
        &url,
    ]);
    command.assert().success().stdout("");

    rx.recv().unwrap();
    assert_eq!(
        std::fs::read_to_string(temp.path().join("server.bin")).unwrap(),
        "ok"
    );
    assert!(!temp.path().join("log").exists());
}

#[test]
fn writes_file_urls_with_globbed_output_markers() {
    let temp = tempdir().unwrap();
    std::fs::write(temp.path().join("file01.txt"), "one").unwrap();
    std::fs::write(temp.path().join("file02.txt"), "two").unwrap();
    let mut url = Url::from_file_path(temp.path().join("file[01-02].txt"))
        .unwrap()
        .to_string();
    url = url.replace("%5B01-02%5D", "[01-02]");

    let output = temp.path().join("copy-#1.txt");
    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-o", output.to_str().unwrap(), &url]);
    command.assert().success().stdout("");

    assert_eq!(
        std::fs::read_to_string(temp.path().join("copy-01.txt")).unwrap(),
        "one"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("copy-02.txt")).unwrap(),
        "two"
    );
}
