use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use tempfile::tempdir;
use url::Url;

#[derive(Debug)]
struct RequestRecord {
    start_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn spawn_server(response: &'static [u8]) -> (String, Receiver<RequestRecord>) {
    spawn_sequence_server(vec![response])
}

fn spawn_sequence_server(responses: Vec<&'static [u8]>) -> (String, Receiver<RequestRecord>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            tx.send(read_request(&mut stream)).unwrap();
            stream.write_all(response).unwrap();
        }
    });

    (format!("http://{addr}/resource"), rx)
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
    assert!(
        header(&request, "user-agent")
            .unwrap()
            .starts_with("curl-rust/")
    );
    assert_eq!(header(&request, "accept-encoding"), None);
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
fn username_only_basic_auth_encodes_empty_password() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-u", "alice", &url]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "authorization"), Some("Basic YWxpY2U6"));
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
    assert_eq!(
        header(&request, "proxy-authorization"),
        Some("Basic YWxhZGRpbjpvcGVuc2VzYW1l")
    );
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
fn libcurl_writes_source_file_for_supported_options() {
    let (url, rx) = spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let temp = tempdir().unwrap();
    let source = temp.path().join("client.c");

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
        "-d",
        "a=b",
        "-u",
        "alice:secret",
        "-A",
        "MyUA",
        "--http1.1",
        &url,
    ]);
    command.assert().success().stdout("ok");

    let request = rx.recv().unwrap();
    assert!(request.start_line.starts_with("PUT /resource HTTP/1.1"));
    assert_eq!(header(&request, "x-test"), Some("yes"));
    assert_eq!(request.body, b"a=b");

    let text = std::fs::read_to_string(source).unwrap();
    assert!(text.contains("Sample code generated by the curl command line tool"));
    assert!(text.contains(&format!("CURLOPT_URL, \"{url}\"")));
    assert!(text.contains("curl_slist_append(slist1, \"X-Test: yes\");"));
    assert!(text.contains("CURLOPT_CUSTOMREQUEST, \"PUT\""));
    assert!(text.contains("CURLOPT_POSTFIELDS, \"a=b\""));
    assert!(text.contains("CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)3"));
    assert!(text.contains("CURLOPT_USERPWD, \"alice:secret\""));
    assert!(text.contains("CURLOPT_USERAGENT, \"MyUA\""));
    assert!(text.contains("CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1"));
    assert!(text.contains("curl_easy_perform(curl);"));
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
fn continue_at_fixed_offset_sends_range_and_appends_output() {
    let (url, rx) = spawn_server(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\n\r\nllo");
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
    let (url, rx) = spawn_server(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\n\r\nlo");

    let mut command = Command::cargo_bin("curl").unwrap();
    command.args(["-q", "-sS", "-C3", &url]);
    command.assert().success().stdout("lo");

    let request = rx.recv().unwrap();
    assert_eq!(header(&request, "range"), Some("bytes=3-"));
}

#[test]
fn continue_at_auto_uses_existing_output_size() {
    let (url, rx) = spawn_server(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\n\r\nlo");
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
