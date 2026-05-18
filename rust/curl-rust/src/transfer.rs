use std::io::{self, Read, Write};
use std::net::{TcpStream as StdTcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use percent_encoding::percent_decode;
use ssh2::{
    CheckResult, ErrorCode as SshErrorCode, HashType, KnownHostFileKind, MethodType, Session,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_RANGES, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE,
    ETAG, HeaderName, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE,
    LAST_MODIFIED, LOCATION, RANGE, REFERER, RETRY_AFTER, USER_AGENT,
};
use reqwest::{Client, Method, StatusCode, Url, Version};

use crate::cli::{Config, ContinueAt, HttpVersionPreference, TransferConfig};
use crate::cookie::CookieJar;
use crate::data::{self, PreparedBody};
use crate::error::{CurlError, Result, ResultExt};
use crate::{glob, ipfs, output, writeout};

const TELNET_IAC: u8 = 255;
const TELNET_DONT: u8 = 254;
const TELNET_DO: u8 = 253;
const TELNET_WONT: u8 = 252;
const TELNET_WILL: u8 = 251;
const TELNET_SB: u8 = 250;
const TELNET_SE: u8 = 240;
const TFTP_DEFAULT_BLKSIZE: u16 = 512;
const TFTP_MAX_PACKET_SIZE: usize = 65_468;
const FTP_DEFAULT_PORT: u16 = 21;
const IMAP_DEFAULT_PORT: u16 = 143;
const MQTT_DEFAULT_PORT: u16 = 1883;
const RTSP_DEFAULT_PORT: u16 = 554;
const SMB_DEFAULT_PORT: u16 = 445;
const WS_DEFAULT_PORT: u16 = 80;
const LDAP_DEFAULT_PORT: u16 = 389;
const SSH_DEFAULT_PORT: u16 = 22;
const MQTT_CLIENT_ID: &[u8; 12] = b"curlrust0000";
const SMB_COM_CLOSE: u8 = 0x04;
const SMB_COM_READ_ANDX: u8 = 0x2e;
const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
const SMB_COM_NEGOTIATE: u8 = 0x72;
const SMB_COM_SETUP_ANDX: u8 = 0x73;
const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
const SMB_COM_NT_CREATE_ANDX: u8 = 0xa2;
const SMB_COM_NO_ANDX_COMMAND: u8 = 0xff;
const SMB_ERR_NOACCESS: u32 = 0x0005_0001;
const SMB_FILE_OPEN: u32 = 0x01;
const SMB_FILE_SHARE_ALL: u32 = 0x07;
const SMB_GENERIC_READ: u32 = 0x8000_0000;
const SMB_CAP_LARGE_FILES: u32 = 0x08;
const SMB_MAX_PAYLOAD_SIZE: usize = 0x8000;
const SMB_MAX_MESSAGE_SIZE: usize = SMB_MAX_PAYLOAD_SIZE + 0x1000;
const SMB_HEADER_START: usize = 4;
const SMB_HEADER_LEN: usize = 32;
const SMB_FULL_HEADER_LEN: usize = SMB_HEADER_START + SMB_HEADER_LEN;
const WS_KEY: &str = "NDMyMTUzMjE2MzIxNzMyMQ==";
const WS_ACCEPT: &str = "HkPsVga7+8LuxM4RGQ5p9tZHeYs=";
const WS_BINARY: u8 = 0x2;
const WS_CLOSE: u8 = 0x8;
const WS_PING: u8 = 0x9;
const WS_PONG: u8 = 0xA;
const MQTT_CONNECT: u8 = 0x10;
const MQTT_CONNACK: u8 = 0x20;
const MQTT_PUBLISH: u8 = 0x30;
const MQTT_SUBSCRIBE: u8 = 0x82;
const MQTT_SUBACK: u8 = 0x90;
const MQTT_PINGRESP: u8 = 0xd0;
const MQTT_DISCONNECT: u8 = 0xe0;

struct HttpAttempt {
    status: StatusCode,
    version: Version,
    final_url: Url,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
    retry_after: Option<Duration>,
    resume_from: u64,
}

pub async fn run(config: Config) -> Result<i32> {
    if config.parallel {
        return run_parallel(config).await;
    }

    let mut final_code = 0;

    for transfer in &config.transfers {
        let cookie_jar = build_cookie_jar(transfer)?;
        let client = build_client(transfer, cookie_jar.clone())?;
        let expanded_urls = expand_urls(transfer)?;

        for expanded in expanded_urls {
            let code = run_expanded_url(transfer, &client, expanded).await?;
            if code != 0 {
                final_code = code;
            }
        }

        if let (Some(path), Some(cookie_jar)) = (&transfer.cookie_jar, &cookie_jar) {
            cookie_jar.save_to_path(path, transfer.create_dirs, transfer.verbose);
        }
    }

    Ok(final_code)
}

struct ParallelJob {
    index: usize,
    transfer: TransferConfig,
    client: Client,
    expanded: glob::ExpandedUrl,
}

struct CookieSave {
    path: std::path::PathBuf,
    jar: Arc<CookieJar>,
    create_dirs: bool,
    verbose: bool,
}

async fn run_parallel(config: Config) -> Result<i32> {
    let (jobs, cookie_saves) = parallel_jobs(&config)?;
    let mut results = vec![0; jobs.len()];
    let mut pending = jobs.into_iter();
    let mut active = JoinSet::new();

    while active.len() < config.parallel_max {
        let Some(job) = pending.next() else {
            break;
        };
        spawn_parallel_job(&mut active, job);
    }

    while let Some(joined) = active.join_next().await {
        let (index, code) = joined.map_err(|error| {
            CurlError::Transfer(format!("parallel transfer task failed: {error}"))
        })??;
        results[index] = code;

        if let Some(job) = pending.next() {
            spawn_parallel_job(&mut active, job);
        }
    }

    for save in cookie_saves {
        save.jar
            .save_to_path(&save.path, save.create_dirs, save.verbose);
    }

    Ok(results
        .into_iter()
        .rev()
        .find(|code| *code != 0)
        .unwrap_or(0))
}

fn parallel_jobs(config: &Config) -> Result<(Vec<ParallelJob>, Vec<CookieSave>)> {
    let mut jobs = Vec::new();
    let mut cookie_saves = Vec::new();

    for transfer in &config.transfers {
        let cookie_jar = build_cookie_jar(transfer)?;
        let client = build_client(transfer, cookie_jar.clone())?;
        let expanded_urls = expand_urls(transfer)?;

        if let (Some(path), Some(cookie_jar)) = (&transfer.cookie_jar, &cookie_jar) {
            cookie_saves.push(CookieSave {
                path: path.clone(),
                jar: cookie_jar.clone(),
                create_dirs: transfer.create_dirs,
                verbose: transfer.verbose,
            });
        }

        for expanded in expanded_urls {
            jobs.push(ParallelJob {
                index: jobs.len(),
                transfer: transfer.clone(),
                client: client.clone(),
                expanded,
            });
        }
    }

    Ok((jobs, cookie_saves))
}

fn build_cookie_jar(transfer: &TransferConfig) -> Result<Option<Arc<CookieJar>>> {
    if !cookie_engine_active(transfer) {
        return Ok(None);
    }

    let jar = Arc::new(CookieJar::default());
    jar.set_explicit_cookie(transfer.cookie.as_deref());
    jar.load_from_inputs(&transfer.cookie_files, transfer.junk_session_cookies)?;
    Ok(Some(jar))
}

fn cookie_engine_active(transfer: &TransferConfig) -> bool {
    transfer.cookie_jar.is_some() || !transfer.cookie_files.is_empty()
}

fn spawn_parallel_job(active: &mut JoinSet<Result<(usize, i32)>>, job: ParallelJob) {
    active.spawn(async move {
        let code = run_expanded_url(&job.transfer, &job.client, job.expanded).await?;
        Ok((job.index, code))
    });
}

fn expand_urls(transfer: &TransferConfig) -> Result<Vec<glob::ExpandedUrl>> {
    let mut expanded = Vec::new();
    for url in &transfer.urls {
        expanded.extend(glob::expand_url(url, transfer.globoff)?);
    }
    Ok(expanded)
}

fn build_client(transfer: &TransferConfig, cookie_jar: Option<Arc<CookieJar>>) -> Result<Client> {
    let redirect = if transfer.follow_location && !transfer.auto_referer {
        reqwest::redirect::Policy::limited(transfer.max_redirs)
    } else {
        reqwest::redirect::Policy::none()
    };

    let mut builder = Client::builder()
        .redirect(redirect)
        .referer(false)
        .danger_accept_invalid_certs(transfer.insecure);

    if !transfer.compressed {
        builder = builder.no_gzip().no_brotli().no_deflate();
    }

    if let Some(cookie_jar) = cookie_jar {
        builder = builder.cookie_provider(cookie_jar);
    }

    if let Some(timeout) = transfer.max_time {
        builder = builder.timeout(timeout);
    }

    if let Some(timeout) = transfer.connect_timeout {
        builder = builder.connect_timeout(timeout);
    }

    if let Some(proxy) = &transfer.proxy
        && !transfer.noproxy.as_deref().is_some_and(is_global_noproxy)
    {
        let mut proxy = reqwest::Proxy::all(proxy).transfer_err()?;
        if let Some(proxy_user) = &transfer.proxy_user {
            let (login, password) = split_user_password(proxy_user);
            proxy = proxy.basic_auth(login, password);
        }
        if let Some(noproxy) = &transfer.noproxy {
            proxy = proxy.no_proxy(reqwest::NoProxy::from_string(noproxy));
        }
        builder = builder.proxy(proxy);
    }

    if matches!(
        transfer.http_version,
        HttpVersionPreference::Http2PriorKnowledge
    ) {
        builder = builder.http2_prior_knowledge();
    }

    builder.build().transfer_err()
}

fn is_global_noproxy(value: &str) -> bool {
    value.split(',').any(|entry| entry.trim() == "*")
}

async fn run_expanded_url(
    transfer: &TransferConfig,
    client: &Client,
    expanded: glob::ExpandedUrl,
) -> Result<i32> {
    let mut method_label = effective_method_label(transfer);
    let mut metrics = writeout::Metrics::empty(&expanded.url, &method_label);
    let started = Instant::now();
    let expanded = match ipfs::maybe_rewrite_url(&expanded.url, transfer.ipfs_gateway.as_deref()) {
        Ok(Some(url)) => glob::ExpandedUrl {
            url,
            variables: expanded.variables,
        },
        Ok(None) => expanded,
        Err(error) => {
            metrics.time_total = started.elapsed();
            metrics.exit_code = error.exit_code();
            metrics.errormsg = error.to_string();
            report_error(transfer, &error);
            write_writeout(transfer, &metrics)?;
            return Ok(metrics.exit_code);
        }
    };
    if transfer.upload_file.is_some()
        && transfer.method.is_none()
        && !transfer.head
        && is_http_url(&expanded.url)
    {
        method_label = Method::PUT.as_str().to_string();
        metrics.method = method_label.clone();
    }

    let result = if expanded.url.starts_with("file://") {
        run_file_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("dict://") {
        run_dict_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("ftp://") {
        run_ftp_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("ftps://") {
        Err(CurlError::Unsupported(
            "ftps:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("gopher://") {
        run_gopher_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("gophers://") {
        Err(CurlError::Unsupported(
            "gophers:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("telnet://") {
        run_telnet_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("pop3://") {
        run_pop3_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("pop3s://") {
        Err(CurlError::Unsupported(
            "pop3s:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("imap://") {
        run_imap_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("imaps://") {
        Err(CurlError::Unsupported(
            "imaps:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("ldap://") {
        run_ldap_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("ldaps://") {
        Err(CurlError::Unsupported(
            "ldaps:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("smb://") {
        run_smb_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("smbs://") {
        Err(CurlError::Unsupported(
            "smbs:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("scp://") {
        run_scp_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("sftp://") {
        run_sftp_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("smtp://") {
        run_smtp_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("smtps://") {
        Err(CurlError::Unsupported(
            "smtps:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("tftp://") {
        run_tftp_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("mqtt://") {
        run_mqtt_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("mqtts://") {
        Err(CurlError::Unsupported(
            "mqtts:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("rtsp://") {
        run_rtsp_transfer(transfer, &expanded, &mut metrics).await
    } else if expanded.url.starts_with("ws://") {
        run_ws_transfer(transfer, &expanded, &method_label, &mut metrics).await
    } else if expanded.url.starts_with("wss://") {
        Err(CurlError::Unsupported(
            "wss:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else {
        let mut method = effective_http_method(transfer)?;
        if method_label == Method::PUT.as_str() && transfer.method.is_none() {
            method = Method::PUT;
        }
        run_http_with_retries(transfer, client, &expanded, method, &mut metrics, started).await
    };

    metrics.time_total = started.elapsed();
    match result {
        Ok(()) => {
            write_writeout(transfer, &metrics)?;
            Ok(metrics.exit_code)
        }
        Err(error) => {
            metrics.exit_code = error.exit_code();
            metrics.errormsg = error.to_string();
            report_error(transfer, &error);
            write_writeout(transfer, &metrics)?;
            Ok(metrics.exit_code)
        }
    }
}

async fn run_file_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for file:// URLs"
        )));
    }
    reject_upload_file_for_scheme(transfer, "file://")?;

    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    let path = url
        .to_file_path()
        .map_err(|_| CurlError::Url("file URL cannot be converted to a local path".to_string()))?;
    let metadata_size = std::fs::metadata(&path)?.len();
    let output_url =
        Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &output_url)?;
    let resume_from = resume_offset(
        transfer,
        &output_url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
    )?;

    let body = if method == "HEAD" {
        Vec::new()
    } else {
        std::fs::read(path)?
    };
    let body = if method == "HEAD" {
        body
    } else {
        apply_file_range(body, effective_range(transfer, resume_from).as_deref())?
    };
    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    let modified = url
        .to_file_path()
        .ok()
        .and_then(|path| std::fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok());
    let header_size = if method == "HEAD" {
        metadata_size
    } else {
        body_bytes.len() as u64
    };
    let headers = output::file_headers(header_size, modified);
    let header_bytes = output::render_file_headers(&headers);
    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &header_bytes, transfer.create_dirs)?;
    }
    metrics.url_effective = expanded.url.clone();
    metrics.response_code = Some(200);
    metrics.size_download = body_bytes.len() as u64;
    metrics.headers = headers.clone();

    let mut bytes = Vec::new();
    if transfer.include_headers || method == "HEAD" {
        bytes.extend_from_slice(&header_bytes);
    }
    if method != "HEAD" {
        bytes.extend_from_slice(body_bytes);
    }
    let filename = output::write_response(
        transfer,
        &output_url,
        &headers,
        &expanded.variables,
        &bytes,
        resume_from > 0,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

async fn run_dict_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for dict:// URLs"
        )));
    }
    reject_upload_file_for_scheme(transfer, "dict://")?;

    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("DICT URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(2628);
    let request = dict_request(&url)?;

    let mut stream = connect_tcp(host, port, transfer).await?;
    stream.write_all(&request).await.map_err(tcp_io_error)?;

    let mut body = Vec::new();
    if method != "HEAD" {
        stream.read_to_end(&mut body).await.map_err(tcp_io_error)?;
    }
    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.url_effective = url.to_string();
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let mut bytes = Vec::new();
    if method != "HEAD" {
        bytes.extend_from_slice(body_bytes);
    }

    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        &bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

async fn run_ftp_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if transfer.method.is_some() {
        return Err(CurlError::Unsupported(
            "custom FTP requests in the Rust sidecar".to_string(),
        ));
    }
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for ftp:// URLs"
        )));
    }
    if !transfer.data.is_empty() || !transfer.url_query.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "data/form/query request bodies for ftp:// URLs".to_string(),
        ));
    }
    reject_upload_file_for_scheme(transfer, "ftp://")?;
    if transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(
            "--oauth2-bearer for ftp:// URLs".to_string(),
        ));
    }
    if transfer.range.is_some() || transfer.continue_at.is_some() {
        return Err(CurlError::Unsupported(
            "FTP range/resume in the Rust sidecar".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_ftp_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_ftp_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_ftp_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("FTP URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(FTP_DEFAULT_PORT);
    let path = ftp_path(&url)?;
    let (user, password) = ftp_credentials(transfer, &url)?;

    let mut stream = connect_tcp(host, port, transfer).await?;
    let mut control_headers = Vec::new();
    let greeting = ftp_read_response(&mut stream, metrics, &mut control_headers).await?;
    ftp_require_positive(&greeting, CurlError::WeirdServerReply)?;

    let mut user_command = Vec::from(&b"USER "[..]);
    user_command.extend_from_slice(&user);
    let response = ftp_command(&mut stream, &user_command, metrics, &mut control_headers).await?;
    match response.code {
        230 => {}
        331 => {
            let mut pass_command = Vec::from(&b"PASS "[..]);
            pass_command.extend_from_slice(&password);
            let response =
                ftp_command(&mut stream, &pass_command, metrics, &mut control_headers).await?;
            if response.code != 230 {
                return Err(CurlError::LoginDenied);
            }
        }
        _ => return Err(CurlError::LoginDenied),
    }

    let response = ftp_command(&mut stream, b"PWD", metrics, &mut control_headers).await?;
    ftp_require_positive(&response, CurlError::WeirdServerReply)?;

    for directory in &path.directories {
        let mut command = Vec::from(&b"CWD "[..]);
        command.extend_from_slice(directory);
        let response = ftp_command(&mut stream, &command, metrics, &mut control_headers).await?;
        ftp_require_positive(&response, CurlError::RemoteAccessDenied)?;
    }

    let mut synthetic_headers = reqwest::header::HeaderMap::new();
    let mut body = Vec::new();
    let transfer_result = if method == "HEAD" || transfer.head {
        ftp_head_file(
            &mut stream,
            &path,
            metrics,
            &mut control_headers,
            &mut synthetic_headers,
        )
        .await
    } else {
        match ftp_download_body(
            transfer,
            &mut stream,
            host,
            &path,
            metrics,
            &mut control_headers,
        )
        .await
        {
            Ok(downloaded) => {
                body = downloaded;
                Ok(())
            }
            Err(error) => Err(error),
        }
    };

    let response_code_before_quit = metrics.response_code;
    let _ = ftp_command(&mut stream, b"QUIT", metrics, &mut control_headers).await;
    metrics.response_code = response_code_before_quit;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &control_headers, transfer.create_dirs)?;
    }

    transfer_result?;

    metrics.url_effective = url.to_string();
    if method == "HEAD" || transfer.head {
        metrics.headers = synthetic_headers.clone();
        let header_bytes = if synthetic_headers.is_empty() {
            Vec::new()
        } else {
            output::render_file_headers(&synthetic_headers)
        };
        let filename = output::write_response(
            transfer,
            &url,
            &synthetic_headers,
            &expanded.variables,
            &header_bytes,
            false,
        )?;
        metrics.filename_effective = filename.map(|path| path.display().to_string());
        metrics.size_download = 0;
        return Ok(());
    }

    let (body_bytes, max_filesize_exceeded) = limit_body_for_max_filesize(transfer, &body);
    metrics.size_download = body_bytes.len() as u64;
    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        body_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

struct FtpPath {
    directories: Vec<Vec<u8>>,
    file: Option<Vec<u8>>,
}

struct FtpResponse {
    code: u16,
    lines: Vec<Vec<u8>>,
}

async fn ftp_head_file(
    stream: &mut TcpStream,
    path: &FtpPath,
    metrics: &mut writeout::Metrics,
    control_headers: &mut Vec<u8>,
    synthetic_headers: &mut reqwest::header::HeaderMap,
) -> Result<()> {
    let Some(file) = &path.file else {
        return Ok(());
    };

    let mut mdtm = Vec::from(&b"MDTM "[..]);
    mdtm.extend_from_slice(file);
    let response = ftp_command(stream, &mdtm, metrics, control_headers).await?;
    if response.code == 213
        && let Some(modified) = ftp_mdtm_time(&response)
        && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(modified))
    {
        synthetic_headers.insert(LAST_MODIFIED, value);
    }

    ftp_set_type(stream, b'I', metrics, control_headers).await?;

    let mut size_command = Vec::from(&b"SIZE "[..]);
    size_command.extend_from_slice(file);
    let response = ftp_command(stream, &size_command, metrics, control_headers).await?;
    if response.code == 213
        && let Some(size) = ftp_size_value(&response)
        && let Ok(value) = HeaderValue::from_str(&size.to_string())
    {
        synthetic_headers.insert(CONTENT_LENGTH, value);
    }

    let response = ftp_command(stream, b"REST 0", metrics, control_headers).await?;
    ftp_require_code(&response, &[350], CurlError::FtpCouldntRetrFile)?;
    synthetic_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    Ok(())
}

async fn ftp_download_body(
    transfer: &TransferConfig,
    stream: &mut TcpStream,
    host: &str,
    path: &FtpPath,
    metrics: &mut writeout::Metrics,
    control_headers: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    let (data_host, data_port) = ftp_enter_passive(stream, host, metrics, control_headers).await?;
    let mut data_stream = connect_tcp(&data_host, data_port, transfer).await?;
    let ascii = transfer.list_only || path.file.is_none();
    ftp_set_type(
        stream,
        if ascii { b'A' } else { b'I' },
        metrics,
        control_headers,
    )
    .await?;

    if let Some(file) = path.file.as_ref().filter(|_| !transfer.list_only) {
        let mut size_command = Vec::from(&b"SIZE "[..]);
        size_command.extend_from_slice(file);
        let response = ftp_command(stream, &size_command, metrics, control_headers).await?;
        if response.code == 213
            && let (Some(max), Some(size)) = (transfer.max_filesize, ftp_size_value(&response))
            && max > 0
            && size > max
        {
            return Err(CurlError::FileSizeExceeded);
        }
    }

    let command = ftp_transfer_command(path, transfer.list_only);
    let response = ftp_command(stream, &command, metrics, control_headers).await?;
    if response.code / 100 != 1 {
        return if command.starts_with(b"RETR ") && response.code == 550 {
            Err(CurlError::RemoteFileNotFound)
        } else {
            Err(CurlError::FtpCouldntRetrFile)
        };
    }

    let mut body = Vec::new();
    data_stream
        .read_to_end(&mut body)
        .await
        .map_err(tcp_io_error)?;
    let response = ftp_read_response(stream, metrics, control_headers).await?;
    ftp_require_positive(&response, CurlError::FtpCouldntRetrFile)?;
    Ok(body)
}

async fn ftp_enter_passive(
    stream: &mut TcpStream,
    host: &str,
    metrics: &mut writeout::Metrics,
    control_headers: &mut Vec<u8>,
) -> Result<(String, u16)> {
    let response = ftp_command(stream, b"EPSV", metrics, control_headers).await?;
    if response.code == 229 {
        let port = ftp_epsv_port(&response)?;
        return Ok((host.to_string(), port));
    }

    let response = ftp_command(stream, b"PASV", metrics, control_headers).await?;
    if response.code != 227 {
        return Err(CurlError::FtpWeirdPasvReply);
    }
    ftp_pasv_addr(&response)
}

async fn ftp_set_type(
    stream: &mut TcpStream,
    mode: u8,
    metrics: &mut writeout::Metrics,
    control_headers: &mut Vec<u8>,
) -> Result<()> {
    let command = [b'T', b'Y', b'P', b'E', b' ', mode];
    let response = ftp_command(stream, &command, metrics, control_headers).await?;
    ftp_require_positive(&response, CurlError::FtpCouldntSetType)
}

fn ftp_transfer_command(path: &FtpPath, list_only: bool) -> Vec<u8> {
    if list_only {
        Vec::from(&b"NLST"[..])
    } else if let Some(file) = &path.file {
        let mut command = Vec::from(&b"RETR "[..]);
        command.extend_from_slice(file);
        command
    } else {
        Vec::from(&b"LIST"[..])
    }
}

async fn ftp_command(
    stream: &mut TcpStream,
    command: &[u8],
    metrics: &mut writeout::Metrics,
    control_headers: &mut Vec<u8>,
) -> Result<FtpResponse> {
    ftp_send_line(stream, command).await?;
    ftp_read_response(stream, metrics, control_headers).await
}

async fn ftp_send_line(stream: &mut TcpStream, line: &[u8]) -> Result<()> {
    stream.write_all(line).await.map_err(tcp_io_error)?;
    stream.write_all(b"\r\n").await.map_err(tcp_io_error)
}

async fn ftp_read_response(
    stream: &mut TcpStream,
    metrics: &mut writeout::Metrics,
    control_headers: &mut Vec<u8>,
) -> Result<FtpResponse> {
    let first = ftp_read_line(stream).await?;
    let code = ftp_response_code(&first)?;
    let continued = first.get(3) == Some(&b'-');
    control_headers.extend_from_slice(&first);
    let mut lines = vec![first];

    if continued {
        loop {
            let line = ftp_read_line(stream).await?;
            let done = line.starts_with(format!("{code:03} ").as_bytes());
            control_headers.extend_from_slice(&line);
            lines.push(line);
            if done {
                break;
            }
        }
    }

    metrics.response_code = Some(code);
    Ok(FtpResponse { code, lines })
}

async fn ftp_read_line(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0; 1];
    loop {
        let read = stream.read(&mut byte).await.map_err(tcp_io_error)?;
        if read == 0 {
            if line.is_empty() {
                return Err(CurlError::WeirdServerReply);
            }
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(line)
}

fn ftp_response_code(line: &[u8]) -> Result<u16> {
    if line.len() < 3 || !line[..3].iter().all(u8::is_ascii_digit) {
        return Err(CurlError::WeirdServerReply);
    }
    Ok(
        u16::from(line[0] - b'0') * 100
            + u16::from(line[1] - b'0') * 10
            + u16::from(line[2] - b'0'),
    )
}

fn ftp_require_positive(response: &FtpResponse, error: CurlError) -> Result<()> {
    if response.code / 100 == 2 {
        Ok(())
    } else {
        Err(error)
    }
}

fn ftp_require_code(response: &FtpResponse, expected: &[u16], error: CurlError) -> Result<()> {
    if expected.contains(&response.code) {
        Ok(())
    } else {
        Err(error)
    }
}

fn ftp_epsv_port(response: &FtpResponse) -> Result<u16> {
    for line in &response.lines {
        if let Some(open) = line.iter().position(|byte| *byte == b'(') {
            let payload = &line[open + 1..];
            if payload.len() < 5 {
                continue;
            }
            let sep = payload[0];
            if payload.get(1) != Some(&sep) || payload.get(2) != Some(&sep) {
                continue;
            }
            let mut index = 3;
            let start = index;
            while payload.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if index == start || payload.get(index) != Some(&sep) {
                continue;
            }
            let port = std::str::from_utf8(&payload[start..index])
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or(CurlError::FtpWeirdPasvReply)?;
            return Ok(port);
        }
    }
    Err(CurlError::FtpWeirdPasvReply)
}

fn ftp_pasv_addr(response: &FtpResponse) -> Result<(String, u16)> {
    for line in &response.lines {
        for start in 0..line.len() {
            if !line[start].is_ascii_digit() {
                continue;
            }
            if let Some(numbers) = ftp_parse_pasv_numbers(&line[start..]) {
                let host = format!(
                    "{}.{}.{}.{}",
                    numbers[0], numbers[1], numbers[2], numbers[3]
                );
                let port = u16::from(numbers[4]) * 256 + u16::from(numbers[5]);
                return Ok((host, port));
            }
        }
    }
    Err(CurlError::FtpWeirdPasvReply)
}

fn ftp_parse_pasv_numbers(bytes: &[u8]) -> Option<[u8; 6]> {
    let mut numbers = [0_u8; 6];
    let mut index = 0;
    for (slot, number) in numbers.iter_mut().enumerate() {
        let start = index;
        let mut value = 0_u16;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            value = value
                .checked_mul(10)?
                .checked_add(u16::from(bytes[index] - b'0'))?;
            if value > u16::from(u8::MAX) {
                return None;
            }
            index += 1;
        }
        if index == start {
            return None;
        }
        *number = value as u8;
        if slot < 5 {
            if bytes.get(index) != Some(&b',') {
                return None;
            }
            index += 1;
        }
    }
    Some(numbers)
}

fn ftp_path(url: &Url) -> Result<FtpPath> {
    let encoded = url.path().strip_prefix('/').unwrap_or(url.path());
    let decoded = percent_decode(encoded.as_bytes()).collect::<Vec<_>>();
    if has_control_byte(&decoded) {
        return Err(CurlError::Url(
            "FTP path contains a decoded control byte".to_string(),
        ));
    }

    let (directory_bytes, file) = if decoded.is_empty() || decoded.ends_with(b"/") {
        let directory = decoded.strip_suffix(b"/").unwrap_or(&decoded);
        (directory, None)
    } else if let Some(slash) = decoded.iter().rposition(|byte| *byte == b'/') {
        let file = decoded[slash + 1..].to_vec();
        let directory = if slash == 0 && decoded.starts_with(b"/") {
            &decoded[..1]
        } else {
            &decoded[..slash]
        };
        (directory, Some(file))
    } else {
        (&[][..], Some(decoded.clone()))
    };

    Ok(FtpPath {
        directories: ftp_directory_components(directory_bytes),
        file,
    })
}

fn ftp_directory_components(path: &[u8]) -> Vec<Vec<u8>> {
    if path.is_empty() {
        return Vec::new();
    }

    let mut components = Vec::new();
    let mut rest = path;
    if rest.starts_with(b"/") {
        components.push(Vec::from(&b"/"[..]));
        rest = &rest[1..];
    }

    for component in rest.split(|byte| *byte == b'/') {
        if !component.is_empty() {
            components.push(component.to_vec());
        }
    }
    components
}

fn ftp_credentials(transfer: &TransferConfig, url: &Url) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(user) = &transfer.user {
        let (login, password) = split_user_password(user);
        let login = login.as_bytes().to_vec();
        let password = password.as_bytes().to_vec();
        if has_control_byte(&login) || has_control_byte(&password) {
            return Err(CurlError::Url(
                "FTP credentials contain a decoded control byte".to_string(),
            ));
        }
        return Ok((login, password));
    }

    if !url.username().is_empty() || url.password().is_some() {
        let login = percent_decode(url.username().as_bytes()).collect::<Vec<_>>();
        let password = url
            .password()
            .map(|password| percent_decode(password.as_bytes()).collect::<Vec<_>>())
            .unwrap_or_default();
        if has_control_byte(&login) || has_control_byte(&password) {
            return Err(CurlError::Url(
                "FTP credentials contain a decoded control byte".to_string(),
            ));
        }
        return Ok((login, password));
    }

    Ok((b"anonymous".to_vec(), b"ftp@example.com".to_vec()))
}

fn ftp_size_value(response: &FtpResponse) -> Option<u64> {
    let line = response.lines.first()?;
    let text = std::str::from_utf8(line).ok()?;
    text.get(4..)?.trim().parse::<u64>().ok()
}

fn ftp_mdtm_time(response: &FtpResponse) -> Option<SystemTime> {
    let line = response.lines.first()?;
    let text = std::str::from_utf8(line).ok()?;
    let timestamp = text.get(4..)?.trim();
    if timestamp.len() < 14 {
        return None;
    }
    let year = timestamp.get(0..4)?.parse::<i32>().ok()?;
    let month = timestamp.get(4..6)?.parse::<u32>().ok()?;
    let day = timestamp.get(6..8)?.parse::<u32>().ok()?;
    let hour = timestamp.get(8..10)?.parse::<u32>().ok()?;
    let minute = timestamp.get(10..12)?.parse::<u32>().ok()?;
    let second = timestamp.get(12..14)?.parse::<u32>().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    if seconds < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month as i32;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64::from(era * 146_097 + doe - 719_468)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SshProtocol {
    Scp,
    Sftp,
}

struct SshDownload {
    body: Vec<u8>,
    headers: reqwest::header::HeaderMap,
}

enum SshTransferResult {
    Download(SshDownload),
    Upload,
}

async fn run_scp_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    run_ssh_transfer(transfer, expanded, method, metrics, SshProtocol::Scp).await
}

async fn run_sftp_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    run_ssh_transfer(transfer, expanded, method, metrics, SshProtocol::Sftp).await
}

async fn run_ssh_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
    protocol: SshProtocol,
) -> Result<()> {
    validate_ssh_transfer(transfer, method, protocol)?;

    let mut url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    if transfer.upload_file.is_some() {
        data::append_upload_filename_to_url(&mut url, transfer.upload_file.as_deref());
    } else {
        output::validate_output_target(transfer, &url)?;
    }
    let upload_body = transfer
        .upload_file
        .as_deref()
        .map(data::read_upload_body)
        .transpose()?;

    let transfer_for_task = transfer.clone();
    let url_for_task = url.to_string();
    let method_for_task = method.to_string();
    let task = tokio::task::spawn_blocking(move || {
        run_ssh_blocking(
            &transfer_for_task,
            &url_for_task,
            &method_for_task,
            protocol,
            upload_body,
        )
    });
    let download = if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(timeout, task)
            .await
            .map_err(|_| CurlError::Timeout)?
    } else {
        task.await
    }
    .map_err(|error| CurlError::Transfer(format!("SSH transfer task failed: {error}")))??;

    if matches!(download, SshTransferResult::Upload) {
        if let Some(path) = &transfer.dump_header {
            output::dump_headers(path, &[], transfer.create_dirs)?;
        }
        metrics.url_effective = url.to_string();
        metrics.size_download = 0;
        metrics.headers = reqwest::header::HeaderMap::new();
        return Ok(());
    }

    let SshTransferResult::Download(download) = download else {
        unreachable!();
    };

    let is_head = method == "HEAD" || transfer.head;
    let (body_bytes, max_filesize_exceeded) = if is_head {
        (&[][..], false)
    } else {
        limit_body_for_max_filesize(transfer, &download.body)
    };
    let header_bytes = if is_head && !download.headers.is_empty() {
        output::render_file_headers(&download.headers)
    } else {
        Vec::new()
    };

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &header_bytes, transfer.create_dirs)?;
    }

    let mut bytes = Vec::new();
    if is_head {
        bytes.extend_from_slice(&header_bytes);
    } else {
        bytes.extend_from_slice(body_bytes);
    }

    metrics.url_effective = url.to_string();
    metrics.size_download = body_bytes.len() as u64;
    metrics.headers = download.headers.clone();

    let filename = output::write_response(
        transfer,
        &url,
        &download.headers,
        &expanded.variables,
        &bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

fn validate_ssh_transfer(
    transfer: &TransferConfig,
    method: &str,
    protocol: SshProtocol,
) -> Result<()> {
    let scheme = match protocol {
        SshProtocol::Scp => "scp://",
        SshProtocol::Sftp => "sftp://",
    };
    if transfer.method.is_some() {
        return Err(CurlError::Unsupported(format!(
            "custom requests for {scheme} URLs"
        )));
    }
    if transfer.upload_file.is_some() {
        if protocol == SshProtocol::Scp {
            return Err(CurlError::Unsupported(
                "SCP uploads in the Rust sidecar".to_string(),
            ));
        }
        if method != "GET" {
            return Err(CurlError::Unsupported(format!(
                "{method} requests for {scheme} uploads"
            )));
        }
        if transfer.head {
            return Err(CurlError::Unsupported(format!(
                "--upload-file combined with --head for {scheme} URLs"
            )));
        }
    } else if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for {scheme} URLs"
        )));
    }
    if !transfer.data.is_empty() || !transfer.url_query.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(format!(
            "data/form/query request bodies for {scheme} URLs"
        )));
    }
    if transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(format!(
            "--oauth2-bearer for {scheme} URLs"
        )));
    }
    if transfer.range.is_some() || transfer.continue_at.is_some() {
        return Err(CurlError::Unsupported(format!(
            "range/resume for {scheme} URLs"
        )));
    }
    if transfer.proxy.is_some() {
        return Err(CurlError::Unsupported(format!(
            "proxying for {scheme} URLs"
        )));
    }
    Ok(())
}

fn run_ssh_blocking(
    transfer: &TransferConfig,
    url: &str,
    method: &str,
    protocol: SshProtocol,
    upload_body: Option<Vec<u8>>,
) -> Result<SshTransferResult> {
    let url = Url::parse(url).map_err(|error| CurlError::Url(error.to_string()))?;
    let path = ssh_url_path(&url, protocol)?;
    let session = ssh_connect(transfer, &url)?;

    if let Some(upload_body) = upload_body {
        if protocol == SshProtocol::Sftp {
            ssh_sftp_upload(&session, &path, &upload_body)?;
            return Ok(SshTransferResult::Upload);
        }
        return Err(CurlError::Unsupported(
            "SCP uploads in the Rust sidecar".to_string(),
        ));
    }

    match protocol {
        SshProtocol::Scp => {
            ssh_scp_download(&session, &path, method).map(SshTransferResult::Download)
        }
        SshProtocol::Sftp => {
            ssh_sftp_download(transfer, &session, &path, method).map(SshTransferResult::Download)
        }
    }
}

fn ssh_scp_download(session: &Session, path: &str, method: &str) -> Result<SshDownload> {
    let (mut channel, stat) = session
        .scp_recv(Path::new(path))
        .map_err(ssh_error_to_curl)?;
    if stat.is_dir() {
        return Err(CurlError::RemoteAccessDenied);
    }

    let headers = output::file_headers(stat.size(), None);
    let mut body = Vec::new();
    if method != "HEAD" {
        channel
            .read_to_end(&mut body)
            .map_err(|error| CurlError::Transfer(error.to_string()))?;
    }
    Ok(SshDownload { body, headers })
}

fn ssh_sftp_download(
    transfer: &TransferConfig,
    session: &Session,
    path: &str,
    method: &str,
) -> Result<SshDownload> {
    let sftp = session.sftp().map_err(ssh_error_to_curl)?;
    if path.ends_with('/') {
        let entries = sftp.readdir(Path::new(path)).map_err(ssh_error_to_curl)?;
        let body = if method == "HEAD" {
            Vec::new()
        } else {
            sftp_directory_listing(entries, transfer.list_only)
        };
        return Ok(SshDownload {
            body,
            headers: reqwest::header::HeaderMap::new(),
        });
    }

    let stat = sftp.stat(Path::new(path)).map_err(ssh_error_to_curl)?;
    let headers = sftp_file_headers(&stat);
    let mut body = Vec::new();
    if method != "HEAD" {
        let mut file = sftp.open(Path::new(path)).map_err(ssh_error_to_curl)?;
        file.read_to_end(&mut body)
            .map_err(|error| CurlError::Transfer(error.to_string()))?;
    }
    Ok(SshDownload { body, headers })
}

fn ssh_sftp_upload(session: &Session, path: &str, body: &[u8]) -> Result<()> {
    let sftp = session.sftp().map_err(ssh_error_to_curl)?;
    let mut file = sftp.create(Path::new(path)).map_err(ssh_error_to_curl)?;
    file.write_all(body).map_err(|_| CurlError::SendError)?;
    file.close().map_err(ssh_error_to_curl)?;
    Ok(())
}

fn ssh_connect(transfer: &TransferConfig, url: &Url) -> Result<Session> {
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("SSH URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(SSH_DEFAULT_PORT);
    let stream = ssh_tcp_connect(host, port, transfer)?;
    let mut session = Session::new().map_err(ssh_error_to_curl)?;

    if transfer.compressed_ssh {
        session
            .method_pref(MethodType::CompCs, "zlib@openssh.com,zlib,none")
            .map_err(ssh_error_to_curl)?;
        session
            .method_pref(MethodType::CompSc, "zlib@openssh.com,zlib,none")
            .map_err(ssh_error_to_curl)?;
    }
    if let Some(timeout) = ssh_timeout_ms(transfer) {
        session.set_timeout(timeout);
    }

    session.set_tcp_stream(stream);
    session.handshake().map_err(ssh_error_to_curl)?;
    verify_ssh_host_key(transfer, &session, host, port)?;
    ssh_authenticate(transfer, &session, url)?;
    Ok(session)
}

fn ssh_tcp_connect(host: &str, port: u16, transfer: &TransferConfig) -> Result<StdTcpStream> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| CurlError::Transfer(error.to_string()))?;
    let mut last_error = None;
    for address in addresses {
        let stream = if let Some(timeout) = transfer.connect_timeout {
            StdTcpStream::connect_timeout(&address, timeout)
        } else {
            StdTcpStream::connect(address)
        };
        match stream {
            Ok(stream) => {
                if let Some(timeout) = transfer.max_time {
                    let _ = stream.set_read_timeout(Some(timeout));
                    let _ = stream.set_write_timeout(Some(timeout));
                }
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(CurlError::Transfer(
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "could not resolve SSH host".to_string()),
    ))
}

fn verify_ssh_host_key(
    transfer: &TransferConfig,
    session: &Session,
    host: &str,
    port: u16,
) -> Result<()> {
    if transfer.insecure {
        return Ok(());
    }

    let mut checked_hostpub = false;
    if let Some(expected) = &transfer.ssh_hostpubmd5 {
        checked_hostpub = true;
        let actual = session
            .host_key_hash(HashType::Md5)
            .ok_or(CurlError::PeerVerificationFailed)?;
        if normalize_md5(expected) != hex_lower(actual) {
            return Err(CurlError::PeerVerificationFailed);
        }
    }
    if let Some(expected) = &transfer.ssh_hostpubsha256 {
        checked_hostpub = true;
        let actual = session
            .host_key_hash(HashType::Sha256)
            .ok_or(CurlError::PeerVerificationFailed)?;
        if normalize_sha256(expected) != base64_no_padding(actual) {
            return Err(CurlError::PeerVerificationFailed);
        }
    }
    if checked_hostpub {
        return Ok(());
    }

    let (key, _) = session
        .host_key()
        .ok_or(CurlError::PeerVerificationFailed)?;
    let mut known_hosts = session.known_hosts().map_err(ssh_error_to_curl)?;
    let known_hosts_file = ssh_known_hosts_file(transfer)?;
    known_hosts
        .read_file(&known_hosts_file, KnownHostFileKind::OpenSSH)
        .map_err(|_| CurlError::PeerVerificationFailed)?;
    match known_hosts.check_port(host, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch | CheckResult::NotFound | CheckResult::Failure => {
            Err(CurlError::PeerVerificationFailed)
        }
    }
}

fn ssh_authenticate(transfer: &TransferConfig, session: &Session, url: &Url) -> Result<()> {
    let credentials = ssh_credentials(transfer, url)?;
    if let Some(private_key) = &transfer.ssh_private_key {
        let passphrase =
            (!credentials.password.is_empty()).then_some(credentials.password.as_str());
        session
            .userauth_pubkey_file(
                &credentials.username,
                transfer.ssh_public_key.as_deref(),
                private_key,
                passphrase,
            )
            .map_err(|_| CurlError::LoginDenied)?;
    } else if credentials.has_password {
        session
            .userauth_password(&credentials.username, &credentials.password)
            .map_err(|_| CurlError::LoginDenied)?;
    } else {
        session
            .userauth_agent(&credentials.username)
            .map_err(|_| CurlError::LoginDenied)?;
    }

    if session.authenticated() {
        Ok(())
    } else {
        Err(CurlError::LoginDenied)
    }
}

struct SshCredentials {
    username: String,
    password: String,
    has_password: bool,
}

fn ssh_credentials(transfer: &TransferConfig, url: &Url) -> Result<SshCredentials> {
    if let Some(user) = &transfer.user {
        let (username, password) = split_user_password(user);
        if has_control_byte(username.as_bytes()) || has_control_byte(password.as_bytes()) {
            return Err(CurlError::Url(
                "SSH credentials contain a decoded control byte".to_string(),
            ));
        }
        return Ok(SshCredentials {
            username: username.to_string(),
            password: password.to_string(),
            has_password: true,
        });
    }

    let url_has_user = !url.username().is_empty();
    let url_has_password = url.password().is_some();
    let username = if url_has_user {
        percent_decode(url.username().as_bytes()).collect::<Vec<_>>()
    } else {
        ssh_default_username().into_bytes()
    };
    let password = url
        .password()
        .map(|password| percent_decode(password.as_bytes()).collect::<Vec<_>>())
        .unwrap_or_default();
    if has_control_byte(&username) || has_control_byte(&password) {
        return Err(CurlError::Url(
            "SSH credentials contain a decoded control byte".to_string(),
        ));
    }

    Ok(SshCredentials {
        username: String::from_utf8(username)
            .map_err(|_| CurlError::Url("SSH username is not valid UTF-8".to_string()))?,
        password: String::from_utf8(password)
            .map_err(|_| CurlError::Url("SSH password is not valid UTF-8".to_string()))?,
        has_password: url_has_password,
    })
}

fn ssh_default_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "anonymous".to_string())
}

fn ssh_known_hosts_file(transfer: &TransferConfig) -> Result<PathBuf> {
    if let Some(path) = &transfer.ssh_known_hosts {
        return Ok(path.clone());
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(CurlError::PeerVerificationFailed)?;
    for filename in ["known_hosts", "known_hosts2"] {
        let path = home.join(".ssh").join(filename);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(CurlError::PeerVerificationFailed)
}

fn ssh_timeout_ms(transfer: &TransferConfig) -> Option<u32> {
    transfer.max_time.map(|timeout| {
        u32::try_from(timeout.as_millis())
            .unwrap_or(u32::MAX)
            .max(1)
    })
}

fn ssh_url_path(url: &Url, protocol: SshProtocol) -> Result<String> {
    let decoded = percent_decode(url.path().as_bytes()).collect::<Vec<_>>();
    if has_control_byte(&decoded) {
        return Err(CurlError::Url(
            "SSH path contains a decoded control byte".to_string(),
        ));
    }
    let mut path = String::from_utf8(decoded)
        .map_err(|_| CurlError::Url("SSH path is not valid UTF-8".to_string()))?;
    if path.is_empty() {
        path = ".".to_string();
    }
    if protocol == SshProtocol::Scp {
        if path == "/~" {
            path = ".".to_string();
        } else if let Some(stripped) = path.strip_prefix("/~/") {
            path = stripped.to_string();
        }
    }
    Ok(path)
}

fn sftp_file_headers(stat: &ssh2::FileStat) -> reqwest::header::HeaderMap {
    let size = stat.size.unwrap_or(0);
    let modified = stat
        .mtime
        .map(|mtime| UNIX_EPOCH + Duration::from_secs(mtime));
    output::file_headers(size, modified)
}

fn sftp_directory_listing(mut entries: Vec<(PathBuf, ssh2::FileStat)>, list_only: bool) -> Vec<u8> {
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    let mut body = Vec::new();
    for (path, stat) in entries {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_else(|| path.to_string_lossy());
        if list_only {
            body.extend_from_slice(name.as_bytes());
            body.push(b'\n');
        } else {
            body.extend_from_slice(format!("{:>12} {name}\n", stat.size.unwrap_or(0)).as_bytes());
        }
    }
    body
}

fn normalize_md5(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

fn normalize_sha256(value: &str) -> String {
    value
        .strip_prefix("SHA256:")
        .or_else(|| value.strip_prefix("sha256//"))
        .unwrap_or(value)
        .trim_end_matches('=')
        .to_string()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn base64_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(b0 >> 2) as usize] as char);
        output.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        }
    }
    output
}

fn ssh_error_to_curl(error: ssh2::Error) -> CurlError {
    match error.code() {
        SshErrorCode::SFTP(2 | 10) | SshErrorCode::Session(-28) => CurlError::RemoteFileNotFound,
        SshErrorCode::SFTP(3) => CurlError::RemoteAccessDenied,
        SshErrorCode::Session(-18 | -48) => CurlError::LoginDenied,
        SshErrorCode::Session(-9) => CurlError::Timeout,
        _ => CurlError::Transfer(error.to_string()),
    }
}

async fn run_pop3_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if transfer.method.is_none() && method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for pop3:// URLs"
        )));
    }
    reject_upload_file_for_scheme(transfer, "pop3://")?;
    if transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(
            "--oauth2-bearer for pop3:// URLs".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_pop3_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_pop3_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_pop3_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("POP3 URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(110);
    let message_id = pop3_message_id(&url)?;
    let (user, password) = pop3_credentials(transfer, &url)?;
    let command = pop3_command(transfer, &message_id)?;
    let command_has_body = pop3_command_has_body(&command);

    let mut stream = connect_tcp(host, port, transfer).await?;
    pop3_expect_ok(pop3_read_line(&mut stream).await?, false)?;

    pop3_send_line(&mut stream, b"CAPA").await?;
    pop3_read_capa(&mut stream).await?;

    let mut user_command = Vec::from(&b"USER "[..]);
    user_command.extend_from_slice(&user);
    pop3_send_line(&mut stream, &user_command).await?;
    pop3_expect_ok(pop3_read_line(&mut stream).await?, true)?;

    let mut pass_command = Vec::from(&b"PASS "[..]);
    pass_command.extend_from_slice(&password);
    pop3_send_line(&mut stream, &pass_command).await?;
    pop3_expect_ok(pop3_read_line(&mut stream).await?, true)?;

    pop3_send_line(&mut stream, &command).await?;
    pop3_expect_ok(pop3_read_line(&mut stream).await?, false)?;

    let mut body = if command_has_body {
        pop3_read_multiline_body(&mut stream).await?
    } else {
        Vec::new()
    };

    let _ = pop3_send_line(&mut stream, b"QUIT").await;
    let _ = pop3_read_line(&mut stream).await;

    metrics.url_effective = url.to_string();
    if transfer.head || method == "HEAD" {
        body.clear();
    }
    let (body_bytes, max_filesize_exceeded) = if transfer.head || method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        body_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

async fn run_smtp_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if transfer.method.is_none() && method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for smtp:// URLs"
        )));
    }
    if !transfer.data.is_empty() || !transfer.url_query.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "data/form request bodies for smtp:// URLs".to_string(),
        ));
    }
    if transfer.user.is_some() || transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(
            "SMTP authentication in the Rust sidecar".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_smtp_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_smtp_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_smtp_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("SMTP URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(25);
    let ehlo_domain = smtp_ehlo_domain(&url)?;
    let upload = transfer
        .upload_file
        .as_deref()
        .map(data::read_upload_body)
        .transpose()?;

    if upload.is_some() && transfer.mail_rcpt.is_empty() {
        return Err(CurlError::Usage(
            "--mail-rcpt is required for smtp:// uploads".to_string(),
        ));
    }

    let mut stream = connect_tcp(host, port, transfer).await?;
    let greeting = smtp_read_response(&mut stream).await?;
    metrics.response_code = Some(greeting.code);
    smtp_require_code(&greeting, &[220], CurlError::WeirdServerReply)?;

    let capabilities = smtp_greet(&mut stream, &ehlo_domain, metrics).await?;

    let body = if let Some(upload) = upload {
        smtp_send_mail(transfer, &mut stream, &capabilities, &upload, metrics).await?;
        Vec::new()
    } else {
        let command = smtp_command(transfer)?;
        smtp_send_line(&mut stream, &command).await?;
        let response = smtp_read_response(&mut stream).await?;
        metrics.response_code = Some(response.code);
        if !smtp_success(response.code) {
            return Err(CurlError::WeirdServerReply);
        }
        if transfer.head || method == "HEAD" {
            Vec::new()
        } else {
            response.lines.concat()
        }
    };

    let _ = smtp_send_line(&mut stream, b"QUIT").await;
    let _ = smtp_read_response(&mut stream).await;

    metrics.url_effective = url.to_string();
    let (body_bytes, max_filesize_exceeded) = if transfer.head || method == "HEAD" {
        (&body[..0], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        body_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

async fn run_tftp_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if transfer.upload_file.is_some() {
        if method == "HEAD" || (transfer.method.is_some() && method != "GET") {
            return Err(CurlError::Unsupported(format!(
                "{method} requests for tftp:// uploads"
            )));
        }
    } else if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for tftp:// URLs"
        )));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_tftp_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_tftp_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_tftp_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let upload = transfer
        .upload_file
        .as_deref()
        .map(data::read_upload_body)
        .transpose()?;
    let mut url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    if upload.is_some() {
        data::append_upload_filename_to_url(&mut url, transfer.upload_file.as_deref());
    }
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("TFTP URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(69);
    let (filename, mode) = tftp_filename_and_mode(&url)?;
    let requested_blksize = transfer.tftp_blksize.unwrap_or(TFTP_DEFAULT_BLKSIZE);
    let initial_blksize = if transfer.tftp_no_options {
        TFTP_DEFAULT_BLKSIZE
    } else {
        requested_blksize
    };
    let upload_tsize = match (upload.as_ref(), transfer.upload_file.as_deref()) {
        (Some(bytes), Some(path)) if path != "-" => bytes.len() as u64,
        _ => 0,
    };
    let request = if upload.is_some() {
        tftp_wrq_packet(
            &filename,
            mode,
            requested_blksize,
            transfer.tftp_no_options,
            upload_tsize,
        )
    } else {
        tftp_rrq_packet(&filename, mode, requested_blksize, transfer.tftp_no_options)
    };

    let bind_addr = if url.has_host()
        && url
            .host()
            .is_some_and(|host| matches!(host, url::Host::Ipv6(_)))
    {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).await.map_err(tcp_io_error)?;
    socket
        .send_to(&request, (host, port))
        .await
        .map_err(tcp_io_error)?;

    if let Some(upload) = upload {
        run_tftp_upload(&socket, &upload, initial_blksize).await?;
        metrics.url_effective = url.to_string();
        metrics.size_download = 0;
        if let Some(path) = &transfer.dump_header {
            output::dump_headers(path, &[], transfer.create_dirs)?;
        }
        return Ok(());
    }

    let mut body = Vec::new();
    let mut expected_block = 1_u16;
    let mut block_size = usize::from(initial_blksize);
    let mut peer = None;
    let mut packet = vec![0; TFTP_MAX_PACKET_SIZE];

    loop {
        let (read, addr) = socket.recv_from(&mut packet).await.map_err(tcp_io_error)?;
        if let Some(peer) = peer {
            if addr != peer {
                let error = tftp_error_packet(5, b"Unknown transfer ID");
                let _ = socket.send_to(&error, addr).await;
                continue;
            }
        } else {
            peer = Some(addr);
        }

        let received = &packet[..read];
        match tftp_opcode(received)? {
            3 => {
                let block = tftp_block_number(received)?;
                if block == expected_block {
                    let data = &received[4..];
                    body.extend_from_slice(data);
                    let ack = tftp_ack_packet(block);
                    socket.send_to(&ack, addr).await.map_err(tcp_io_error)?;
                    if data.len() < block_size {
                        break;
                    }
                    expected_block = expected_block.wrapping_add(1);
                } else if block == expected_block.wrapping_sub(1) {
                    let ack = tftp_ack_packet(block);
                    socket.send_to(&ack, addr).await.map_err(tcp_io_error)?;
                } else {
                    return Err(CurlError::TftpIllegal);
                }
            }
            5 => return Err(tftp_error_response(received)),
            6 => {
                block_size = tftp_oack_blksize(received).unwrap_or(block_size);
                let ack = tftp_ack_packet(0);
                socket.send_to(&ack, addr).await.map_err(tcp_io_error)?;
            }
            _ => return Err(CurlError::TftpIllegal),
        }
    }

    metrics.url_effective = url.to_string();
    if method == "HEAD" {
        body.clear();
    }
    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        body_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

async fn run_tftp_upload(socket: &UdpSocket, body: &[u8], requested_blksize: u16) -> Result<()> {
    let mut block_size = usize::from(requested_blksize);
    let mut peer = None;
    let mut packet = vec![0; TFTP_MAX_PACKET_SIZE];
    let mut offset = 0_usize;
    let mut next_block = 1_u16;
    let mut last_packet = Vec::new();
    let mut last_sent_block: Option<u16> = None;
    let mut last_sent_len = 0_usize;

    loop {
        let (read, addr) = socket.recv_from(&mut packet).await.map_err(tcp_io_error)?;
        if let Some(peer) = peer {
            if addr != peer {
                let error = tftp_error_packet(5, b"Unknown transfer ID");
                let _ = socket.send_to(&error, addr).await;
                continue;
            }
        } else {
            peer = Some(addr);
        }

        let received = &packet[..read];
        match tftp_opcode(received)? {
            4 => {
                let ack = tftp_block_number(received)?;
                if let Some(block) = last_sent_block {
                    if ack != block {
                        if ack == block.wrapping_sub(1) && !last_packet.is_empty() {
                            socket
                                .send_to(&last_packet, addr)
                                .await
                                .map_err(tcp_io_error)?;
                            continue;
                        }
                        return Err(CurlError::SendError);
                    }
                    if last_sent_len < block_size {
                        break;
                    }
                } else if ack != 0 {
                    return Err(CurlError::SendError);
                }

                let (data_packet, block, data_len) =
                    tftp_next_data_packet(body, block_size, &mut offset, &mut next_block);
                socket
                    .send_to(&data_packet, addr)
                    .await
                    .map_err(tcp_io_error)?;
                last_packet = data_packet;
                last_sent_block = Some(block);
                last_sent_len = data_len;
            }
            5 => return Err(tftp_error_response(received)),
            6 => {
                if last_sent_block.is_some() {
                    return Err(CurlError::TftpIllegal);
                }
                block_size = tftp_oack_blksize(received).unwrap_or(block_size);
                let (data_packet, block, data_len) =
                    tftp_next_data_packet(body, block_size, &mut offset, &mut next_block);
                socket
                    .send_to(&data_packet, addr)
                    .await
                    .map_err(tcp_io_error)?;
                last_packet = data_packet;
                last_sent_block = Some(block);
                last_sent_len = data_len;
            }
            _ => return Err(CurlError::TftpIllegal),
        }
    }

    Ok(())
}

async fn run_mqtt_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if method != "GET" && method != "POST" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for mqtt:// URLs"
        )));
    }
    if transfer.head {
        return Err(CurlError::Unsupported(
            "HEAD requests for mqtt:// URLs".to_string(),
        ));
    }
    if !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "--form for mqtt:// URLs".to_string(),
        ));
    }
    reject_upload_file_for_scheme(transfer, "mqtt://")?;
    if !transfer.url_query.is_empty() {
        return Err(CurlError::Unsupported(
            "--url-query for mqtt:// URLs".to_string(),
        ));
    }

    let body = data::prepare_body(&transfer.data)?;
    let publish = body.is_some() && !transfer.get;
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("MQTT URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(MQTT_DEFAULT_PORT);

    let mut stream = connect_tcp(host, port, transfer).await?;
    stream
        .write_all(&mqtt_connect_packet(transfer.user.as_deref())?)
        .await
        .map_err(tcp_io_error)?;
    mqtt_expect_connack(&mut stream).await?;
    let topic = mqtt_topic_from_url(&url)?;

    metrics.url_effective = url.to_string();
    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    if publish {
        let body = body.map_or_else(Vec::new, |body| body.bytes);
        stream
            .write_all(&mqtt_publish_packet(&topic, &body)?)
            .await
            .map_err(tcp_io_error)?;
        stream
            .write_all(&[MQTT_DISCONNECT, 0])
            .await
            .map_err(tcp_io_error)?;
        metrics.size_download = 0;
        return Ok(());
    }

    stream
        .write_all(&mqtt_subscribe_packet(&topic)?)
        .await
        .map_err(tcp_io_error)?;
    let body = mqtt_read_subscribe_body(&mut stream, transfer).await?;
    metrics.size_download = body.len() as u64;
    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        &body,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    Ok(())
}

async fn mqtt_expect_connack(stream: &mut TcpStream) -> Result<()> {
    let packet = mqtt_read_packet(stream).await?;
    if packet.packet_type != MQTT_CONNACK || packet.remaining_len != 2 || packet.body != [0, 0] {
        return Err(CurlError::WeirdServerReply);
    }
    Ok(())
}

async fn mqtt_read_subscribe_body(
    stream: &mut TcpStream,
    transfer: &TransferConfig,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut saw_suback = false;

    loop {
        let header = mqtt_read_packet_header(stream).await?;
        match header.packet_type & 0xf0 {
            MQTT_SUBACK => {
                let packet_body = mqtt_read_packet_body(stream, header.remaining_len).await?;
                if header.remaining_len != 3 || packet_body != [0, 1, 0] {
                    return Err(CurlError::WeirdServerReply);
                }
                saw_suback = true;
            }
            MQTT_PUBLISH => {
                if let Some(limit) = max_filesize_limit(transfer)
                    && header.remaining_len as u64 > limit
                {
                    return Err(CurlError::FileSizeExceeded);
                }
                let packet_body = mqtt_read_packet_body(stream, header.remaining_len).await?;
                body.extend_from_slice(&packet_body);
            }
            MQTT_DISCONNECT => {
                if header.remaining_len != 0 || (header.packet_type & 0x0f) != 0 {
                    return Err(CurlError::WeirdServerReply);
                }
                break;
            }
            MQTT_PINGRESP => {
                if header.remaining_len != 0 || (header.packet_type & 0x0f) != 0 {
                    return Err(CurlError::WeirdServerReply);
                }
            }
            _ => return Err(CurlError::WeirdServerReply),
        }
    }

    if !saw_suback {
        return Err(CurlError::WeirdServerReply);
    }
    Ok(body)
}

async fn run_rtsp_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if !transfer.data.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "request bodies for rtsp:// URLs".to_string(),
        ));
    }
    reject_upload_file_for_scheme(transfer, "rtsp://")?;
    if !transfer.url_query.is_empty() {
        return Err(CurlError::Unsupported(
            "--url-query for rtsp:// URLs".to_string(),
        ));
    }

    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("RTSP URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(RTSP_DEFAULT_PORT);

    let request = rtsp_options_request(transfer)?;
    let mut stream = connect_tcp(host, port, transfer).await?;
    stream.write_all(&request).await.map_err(tcp_io_error)?;

    let response = rtsp_read_response(&mut stream).await?;
    metrics.url_effective = url.to_string();
    metrics.method = "OPTIONS".to_string();
    metrics.response_code = Some(response.status);
    metrics.size_download = 0;
    metrics.content_type = response
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    metrics.headers = response.headers.clone();

    if response.cseq != Some(1) {
        return Err(CurlError::RtspCseqError);
    }

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &response.header_bytes, transfer.create_dirs)?;
    }

    let mut output_bytes = Vec::new();
    if transfer.include_headers || transfer.head {
        output_bytes.extend_from_slice(&response.header_bytes);
    }
    let filename = output::write_response(
        transfer,
        &url,
        &response.headers,
        &expanded.variables,
        &output_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    Ok(())
}

struct RtspResponse {
    status: u16,
    cseq: Option<u32>,
    headers: reqwest::header::HeaderMap,
    header_bytes: Vec<u8>,
}

fn rtsp_options_request(transfer: &TransferConfig) -> Result<Vec<u8>> {
    let parsed_headers = parse_headers(&transfer.headers)?;
    for (name, _) in &parsed_headers {
        if name.as_str().eq_ignore_ascii_case("cseq") {
            return Err(CurlError::RtspCseqError);
        }
        if name.as_str().eq_ignore_ascii_case("session") {
            return Err(CurlError::BadFunctionArgument(
                "Session ID cannot be set as a custom header".to_string(),
            ));
        }
    }

    let has_user_agent = parsed_headers
        .iter()
        .any(|(name, _)| name.as_str().eq_ignore_ascii_case("user-agent"));
    let has_referer = parsed_headers
        .iter()
        .any(|(name, _)| name.as_str().eq_ignore_ascii_case("referer"));

    let mut request = Vec::new();
    request.extend_from_slice(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n");
    if !has_user_agent {
        request.extend_from_slice(
            format!(
                "User-Agent: {}\r\n",
                transfer
                    .user_agent
                    .as_deref()
                    .unwrap_or(concat!("curl-rust/", env!("CARGO_PKG_VERSION")))
            )
            .as_bytes(),
        );
    }
    if let Some(referer) = &transfer.referer
        && !has_referer
    {
        request.extend_from_slice(format!("Referer: {referer}\r\n").as_bytes());
    }
    for (name, value) in parsed_headers {
        request.extend_from_slice(name.as_str().as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

async fn rtsp_read_response(stream: &mut TcpStream) -> Result<RtspResponse> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let mut header_end = None;
    loop {
        let read = stream.read(&mut buffer).await.map_err(tcp_io_error)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(end) = rtsp_header_end(&bytes) {
            header_end = Some(end);
            break;
        }
        if bytes.len() > 64 * 1024 {
            return Err(CurlError::WeirdServerReply);
        }
    }

    if bytes.is_empty() {
        return Err(CurlError::Transfer("empty RTSP reply".to_string()));
    }

    let header_end = header_end.unwrap_or(bytes.len());
    let header_bytes = bytes[..header_end].to_vec();
    let mut body = bytes[header_end..].to_vec();
    let (status, headers, cseq, content_length) = rtsp_parse_headers(&header_bytes)?;
    while body.len() < content_length {
        let read = stream.read(&mut buffer).await.map_err(tcp_io_error)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..read]);
    }

    Ok(RtspResponse {
        status,
        cseq,
        headers,
        header_bytes,
    })
}

fn rtsp_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}

fn rtsp_parse_headers(
    bytes: &[u8],
) -> Result<(u16, reqwest::header::HeaderMap, Option<u32>, usize)> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.lines();
    let status_line = lines.next().ok_or(CurlError::WeirdServerReply)?;
    let status = rtsp_parse_status(status_line)?;
    let mut headers = reqwest::header::HeaderMap::new();
    let mut cseq = None;
    let mut content_length = 0_usize;

    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let trimmed = value.trim();
        if name.eq_ignore_ascii_case("cseq") {
            cseq = trimmed.parse::<u32>().ok();
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = trimmed.parse::<usize>().unwrap_or(0);
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.trim().as_bytes()),
            HeaderValue::from_bytes(trimmed.as_bytes()),
        ) {
            headers.append(name, value);
        }
    }

    Ok((status, headers, cseq, content_length))
}

fn rtsp_parse_status(line: &str) -> Result<u16> {
    let mut parts = line.split_whitespace();
    let version = parts.next().ok_or(CurlError::WeirdServerReply)?;
    if version != "RTSP/1.0" {
        return Err(CurlError::WeirdServerReply);
    }
    let code = parts.next().ok_or(CurlError::WeirdServerReply)?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CurlError::WeirdServerReply);
    }
    code.parse::<u16>().map_err(|_| CurlError::WeirdServerReply)
}

async fn run_telnet_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for telnet:// URLs"
        )));
    }
    if !transfer.telnet_options.is_empty() {
        return Err(CurlError::Unsupported(
            "--telnet-option for telnet:// URLs".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_telnet_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_telnet_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_telnet_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("telnet URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(23);
    let input = telnet_input(transfer)?;

    let mut stream = connect_tcp(host, port, transfer).await?;
    if !input.is_empty() {
        stream
            .write_all(&telnet_escape_outgoing(&input))
            .await
            .map_err(tcp_io_error)?;
    }

    let mut state = TelnetRecvState::Data;
    let mut body = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let read = stream.read(&mut buffer).await.map_err(tcp_io_error)?;
        if read == 0 {
            break;
        }

        let replies = telnet_process_incoming(&buffer[..read], &mut state, &mut body);
        if !replies.is_empty() {
            stream.write_all(&replies).await.map_err(tcp_io_error)?;
        }
    }

    metrics.url_effective = url.to_string();
    if method == "HEAD" {
        body.clear();
    }
    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        body_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

struct WsResponse {
    status: u16,
    headers: reqwest::header::HeaderMap,
    header_bytes: Vec<u8>,
}

struct WsFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

async fn run_ws_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for ws:// URLs"
        )));
    }
    if !transfer.data.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "data/form request bodies for ws:// URLs".to_string(),
        ));
    }
    if !transfer.url_query.is_empty() {
        return Err(CurlError::Unsupported(
            "--url-query for ws:// URLs".to_string(),
        ));
    }
    if transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(
            "--oauth2-bearer for ws:// URLs".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_ws_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_ws_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_ws_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("WebSocket URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(WS_DEFAULT_PORT);
    let upload = ws_upload_body(transfer)?;

    let mut stream = connect_tcp(host, port, transfer).await?;
    let request = ws_handshake_request(transfer, &url)?;
    stream.write_all(&request).await.map_err(tcp_io_error)?;

    let response = ws_read_response(&mut stream).await?;
    metrics.url_effective = url.to_string();
    metrics.response_code = Some(response.status);
    metrics.headers = response.headers.clone();

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &response.header_bytes, transfer.create_dirs)?;
    }

    if response.status != 101 {
        return Err(CurlError::HttpStatus {
            status: response.status,
        });
    }
    ws_validate_accept(&response.headers)?;

    if !upload.is_empty() {
        stream
            .write_all(&ws_masked_frame(WS_BINARY, &upload))
            .await
            .map_err(tcp_io_error)?;
    }

    let (body, saw_close) = if method == "HEAD" {
        (Vec::new(), true)
    } else {
        ws_read_body(&mut stream).await?
    };
    if !saw_close && body.is_empty() {
        return Err(CurlError::GotNothing);
    }

    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" {
        (&[][..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    let write_headers = transfer.include_headers || method == "HEAD";
    let mut output_bytes = Vec::new();
    if write_headers {
        output_bytes.extend_from_slice(&response.header_bytes);
    }
    if method != "HEAD" {
        output_bytes.extend_from_slice(body_bytes);
    }

    if write_headers || method != "HEAD" {
        let filename = output::write_response(
            transfer,
            &url,
            &response.headers,
            &expanded.variables,
            &output_bytes,
            false,
        )?;
        metrics.filename_effective = filename.map(|path| path.display().to_string());
    }
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

fn ws_upload_body(transfer: &TransferConfig) -> Result<Vec<u8>> {
    match transfer.upload_file.as_deref() {
        Some(".") | None => Ok(Vec::new()),
        Some(path) => data::read_upload_body(path),
    }
}

fn ws_handshake_request(transfer: &TransferConfig, url: &Url) -> Result<Vec<u8>> {
    let parsed_headers = parse_headers(&transfer.headers)?;
    let has_header = |name: &str| {
        parsed_headers
            .iter()
            .any(|(header_name, _)| header_name.as_str().eq_ignore_ascii_case(name))
    };
    let mut request = Vec::new();
    request.extend_from_slice(format!("GET {} HTTP/1.1\r\n", ws_request_target(url)).as_bytes());

    if !has_header("host") {
        request.extend_from_slice(format!("Host: {}\r\n", ws_host_header(url)).as_bytes());
    }
    if !has_header("user-agent") {
        request.extend_from_slice(
            format!(
                "User-Agent: {}\r\n",
                transfer
                    .user_agent
                    .as_deref()
                    .unwrap_or(concat!("curl-rust/", env!("CARGO_PKG_VERSION")))
            )
            .as_bytes(),
        );
    }
    if !has_header("accept") {
        request.extend_from_slice(b"Accept: */*\r\n");
    }
    request.extend_from_slice(b"Upgrade: websocket\r\n");
    request.extend_from_slice(b"Sec-WebSocket-Version: 13\r\n");
    request.extend_from_slice(format!("Sec-WebSocket-Key: {WS_KEY}\r\n").as_bytes());
    request.extend_from_slice(b"Connection: Upgrade\r\n");
    for (name, value) in parsed_headers {
        request.extend_from_slice(name.as_str().as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

fn ws_request_target(url: &Url) -> String {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    if let Some(query) = url.query() {
        format!("{path}?{query}")
    } else {
        path.to_string()
    }
}

fn ws_host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

async fn ws_read_response(stream: &mut TcpStream) -> Result<WsResponse> {
    let mut header_bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await.map_err(tcp_io_error)?;
        if read == 0 {
            return Err(CurlError::GotNothing);
        }
        header_bytes.push(byte[0]);
        if header_bytes.ends_with(b"\r\n\r\n") || header_bytes.ends_with(b"\n\n") {
            break;
        }
        if header_bytes.len() > 64 * 1024 {
            return Err(CurlError::WeirdServerReply);
        }
    }

    let text = String::from_utf8_lossy(&header_bytes);
    let mut lines = text.lines();
    let status_line = lines.next().ok_or(CurlError::WeirdServerReply)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or(CurlError::WeirdServerReply)?
        .parse::<u16>()
        .map_err(|_| CurlError::WeirdServerReply)?;
    let mut headers = reqwest::header::HeaderMap::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(CurlError::WeirdServerReply);
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| CurlError::WeirdServerReply)?;
        let value =
            HeaderValue::from_str(value.trim_start()).map_err(|_| CurlError::WeirdServerReply)?;
        headers.append(name, value);
    }

    Ok(WsResponse {
        status,
        headers,
        header_bytes,
    })
}

fn ws_validate_accept(headers: &reqwest::header::HeaderMap) -> Result<()> {
    let accept = headers
        .get("sec-websocket-accept")
        .and_then(|value| value.to_str().ok())
        .ok_or(CurlError::WeirdServerReply)?;
    if accept.trim() == WS_ACCEPT {
        Ok(())
    } else {
        Err(CurlError::WeirdServerReply)
    }
}

async fn ws_read_body(stream: &mut TcpStream) -> Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    let mut continuation = Vec::new();
    let mut continuation_opcode = 0_u8;

    loop {
        let Some(frame) = ws_read_frame(stream).await? else {
            return Ok((body, false));
        };

        match frame.opcode {
            0x0 => {
                if continuation_opcode == 0 {
                    return Err(CurlError::RecvError);
                }
                continuation.extend_from_slice(&frame.payload);
                if frame.fin {
                    body.extend_from_slice(&continuation);
                    continuation.clear();
                    continuation_opcode = 0;
                }
            }
            0x1 | WS_BINARY => {
                if continuation_opcode != 0 {
                    return Err(CurlError::RecvError);
                }
                if frame.fin {
                    body.extend_from_slice(&frame.payload);
                } else {
                    continuation = frame.payload;
                    continuation_opcode = frame.opcode;
                }
            }
            WS_CLOSE => {
                stream
                    .write_all(&ws_masked_frame(WS_CLOSE, &frame.payload))
                    .await
                    .map_err(tcp_io_error)?;
                return Ok((body, true));
            }
            WS_PING => {
                stream
                    .write_all(&ws_masked_frame(WS_PONG, &frame.payload))
                    .await
                    .map_err(tcp_io_error)?;
            }
            WS_PONG => {}
            _ => return Err(CurlError::RecvError),
        }
    }
}

async fn ws_read_frame(stream: &mut TcpStream) -> Result<Option<WsFrame>> {
    let mut head = [0_u8; 2];
    match stream.read_exact(&mut head).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(tcp_io_error(error)),
    }

    let fin = head[0] & 0x80 != 0;
    let rsv = head[0] & 0x70;
    let opcode = head[0] & 0x0f;
    if rsv != 0 {
        return Err(CurlError::RecvError);
    }

    let masked = head[1] & 0x80 != 0;
    if masked {
        return Err(CurlError::RecvError);
    }
    let mut length = u64::from(head[1] & 0x7f);
    if length == 126 {
        let mut bytes = [0_u8; 2];
        stream.read_exact(&mut bytes).await.map_err(tcp_io_error)?;
        length = u64::from(u16::from_be_bytes(bytes));
    } else if length == 127 {
        let mut bytes = [0_u8; 8];
        stream.read_exact(&mut bytes).await.map_err(tcp_io_error)?;
        length = u64::from_be_bytes(bytes);
        if length > usize::MAX as u64 {
            return Err(CurlError::RecvError);
        }
    }

    if matches!(opcode, WS_CLOSE | WS_PING | WS_PONG) && (!fin || length > 125) {
        return Err(CurlError::RecvError);
    }
    if matches!(opcode, 0x3..=0x7 | 0xB..=0xF) {
        return Err(CurlError::RecvError);
    }

    let mut payload = vec![0_u8; length as usize];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(tcp_io_error)?;
    Ok(Some(WsFrame {
        fin,
        opcode,
        payload,
    }))
}

fn ws_masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    if payload.len() <= 125 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    frame
}

async fn run_smb_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if transfer.method.is_some() {
        return Err(CurlError::Unsupported(
            "custom SMB requests in the Rust sidecar".to_string(),
        ));
    }
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for smb:// URLs"
        )));
    }
    if !transfer.data.is_empty() || !transfer.url_query.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "data/form/query request bodies for smb:// URLs".to_string(),
        ));
    }
    reject_upload_file_for_scheme(transfer, "smb://")?;
    if transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(
            "--oauth2-bearer for smb:// URLs".to_string(),
        ));
    }
    if transfer.range.is_some() || transfer.continue_at.is_some() {
        return Err(CurlError::Unsupported(
            "SMB range/resume in the Rust sidecar".to_string(),
        ));
    }
    if transfer.list_only {
        return Err(CurlError::Unsupported(
            "SMB directory listing in the Rust sidecar".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_smb_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_smb_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_smb_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("SMB URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(SMB_DEFAULT_PORT);
    let path = smb_url_path(&url)?;
    let credentials = smb_credentials(transfer, &url, host)?;
    let mut stream = connect_tcp(host, port, transfer).await?;
    let mut state = SmbConnection::default();

    smb_send_command(
        &mut stream,
        &mut state,
        SMB_COM_NEGOTIATE,
        &smb_negotiate_body(),
    )
    .await?;
    let packet = smb_read_packet(&mut stream).await?;
    let response = smb_response(&packet, SMB_COM_NEGOTIATE)?;
    if response.status != 0 {
        return Err(CurlError::Transfer("SMB negotiate failed".to_string()));
    }

    smb_send_command(
        &mut stream,
        &mut state,
        SMB_COM_SETUP_ANDX,
        &smb_setup_body(&credentials)?,
    )
    .await?;
    let packet = smb_read_packet(&mut stream).await?;
    let response = smb_response(&packet, SMB_COM_SETUP_ANDX)?;
    if response.status != 0 {
        return Err(CurlError::LoginDenied);
    }
    state.uid = response.uid;

    smb_send_command(
        &mut stream,
        &mut state,
        SMB_COM_TREE_CONNECT_ANDX,
        &smb_tree_connect_body(host, &path)?,
    )
    .await?;
    let packet = smb_read_packet(&mut stream).await?;
    let response = smb_response(&packet, SMB_COM_TREE_CONNECT_ANDX)?;
    if response.status != 0 {
        return Err(smb_file_error(response.status));
    }
    state.tid = response.tid;

    smb_send_command(
        &mut stream,
        &mut state,
        SMB_COM_NT_CREATE_ANDX,
        &smb_open_body(&path)?,
    )
    .await?;
    let packet = smb_read_packet(&mut stream).await?;
    let response = smb_response(&packet, SMB_COM_NT_CREATE_ANDX)?;
    if response.status != 0 {
        let error = smb_file_error(response.status);
        let _ = smb_tree_disconnect(&mut stream, &mut state).await;
        return Err(error);
    }
    let fid = smb_read_u16_at(response.body, 6)?;
    let eof = smb_read_u64_at(response.body, 56)?;

    let mut body = Vec::new();
    let transfer_result = if method == "HEAD" || transfer.head {
        Ok(())
    } else {
        smb_download_body(&mut stream, &mut state, fid, eof, &mut body).await
    };

    let _ = smb_close(&mut stream, &mut state, fid).await;
    let _ = smb_tree_disconnect(&mut stream, &mut state).await;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    transfer_result?;

    metrics.url_effective = url.to_string();
    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" || transfer.head {
        (&[][..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;
    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        body_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

struct SmbPath {
    share: Vec<u8>,
    file: Vec<u8>,
}

struct SmbCredentials {
    user: Vec<u8>,
    domain: Vec<u8>,
}

#[derive(Default)]
struct SmbConnection {
    uid: u16,
    tid: u16,
    mid: u16,
}

struct SmbResponse<'a> {
    status: u32,
    tid: u16,
    uid: u16,
    body: &'a [u8],
}

impl SmbConnection {
    fn next_mid(&mut self) -> u16 {
        let mid = self.mid;
        self.mid = self.mid.wrapping_add(1);
        mid
    }
}

fn smb_url_path(url: &Url) -> Result<SmbPath> {
    let decoded = percent_decode(url.path().as_bytes()).collect::<Vec<_>>();
    if has_control_byte(&decoded) {
        return Err(CurlError::Url(
            "SMB path contains a decoded control byte".to_string(),
        ));
    }

    let start = decoded
        .iter()
        .position(|byte| *byte != b'/' && *byte != b'\\')
        .unwrap_or(decoded.len());
    let path = &decoded[start..];
    let separator = path
        .iter()
        .position(|byte| *byte == b'/' || *byte == b'\\')
        .ok_or_else(|| CurlError::Url("SMB URL is missing a share path".to_string()))?;
    if separator == 0 || separator + 1 >= path.len() {
        return Err(CurlError::Url(
            "SMB URL is missing a share path".to_string(),
        ));
    }

    let share = path[..separator].to_vec();
    let mut file = path[separator + 1..].to_vec();
    for byte in &mut file {
        if *byte == b'/' {
            *byte = b'\\';
        }
    }
    Ok(SmbPath { share, file })
}

fn smb_credentials(transfer: &TransferConfig, url: &Url, host: &str) -> Result<SmbCredentials> {
    let (login, password) = if let Some(user) = &transfer.user {
        let (login, password) = split_user_password(user);
        (login.as_bytes().to_vec(), password.as_bytes().to_vec())
    } else {
        let login = percent_decode(url.username().as_bytes()).collect::<Vec<_>>();
        let password = url
            .password()
            .map(|password| percent_decode(password.as_bytes()).collect::<Vec<_>>())
            .unwrap_or_default();
        (login, password)
    };

    if login.is_empty() {
        return Err(CurlError::LoginDenied);
    }
    if has_control_byte(&login) || has_control_byte(&password) {
        return Err(CurlError::Url(
            "SMB credentials contain a decoded control byte".to_string(),
        ));
    }

    let separator = login
        .iter()
        .position(|byte| *byte == b'/' || *byte == b'\\');
    let (domain, user) = if let Some(separator) = separator {
        if separator == 0 || separator + 1 >= login.len() {
            return Err(CurlError::LoginDenied);
        }
        (login[..separator].to_vec(), login[separator + 1..].to_vec())
    } else {
        (host.as_bytes().to_vec(), login)
    };

    Ok(SmbCredentials { user, domain })
}

async fn smb_download_body(
    stream: &mut TcpStream,
    state: &mut SmbConnection,
    fid: u16,
    eof: u64,
    body: &mut Vec<u8>,
) -> Result<()> {
    let mut offset = 0_u64;
    while offset < eof {
        let remaining = eof.saturating_sub(offset);
        let max_bytes = remaining.min(SMB_MAX_PAYLOAD_SIZE as u64) as u16;
        smb_send_command(
            stream,
            state,
            SMB_COM_READ_ANDX,
            &smb_read_body(fid, offset, max_bytes),
        )
        .await?;
        let packet = smb_read_packet(stream).await?;
        let response = smb_response(&packet, SMB_COM_READ_ANDX)?;
        if response.status != 0 {
            return Err(CurlError::RecvError);
        }
        let chunk = smb_read_response_data(&packet, response.body)?;
        if chunk.is_empty() {
            break;
        }
        body.extend_from_slice(chunk);
        offset = offset.saturating_add(chunk.len() as u64);
        if chunk.len() < SMB_MAX_PAYLOAD_SIZE {
            break;
        }
    }
    Ok(())
}

async fn smb_close(stream: &mut TcpStream, state: &mut SmbConnection, fid: u16) -> Result<()> {
    smb_send_command(stream, state, SMB_COM_CLOSE, &smb_close_body(fid)).await?;
    let packet = smb_read_packet(stream).await?;
    let _ = smb_response(&packet, SMB_COM_CLOSE)?;
    Ok(())
}

async fn smb_tree_disconnect(stream: &mut TcpStream, state: &mut SmbConnection) -> Result<()> {
    smb_send_command(
        stream,
        state,
        SMB_COM_TREE_DISCONNECT,
        &smb_tree_disconnect_body(),
    )
    .await?;
    let packet = smb_read_packet(stream).await?;
    let _ = smb_response(&packet, SMB_COM_TREE_DISCONNECT)?;
    Ok(())
}

async fn smb_send_command(
    stream: &mut TcpStream,
    state: &mut SmbConnection,
    command: u8,
    body: &[u8],
) -> Result<()> {
    let packet = smb_message(command, state.tid, state.uid, state.next_mid(), body)?;
    stream
        .write_all(&packet)
        .await
        .map_err(|_| CurlError::SendError)
}

fn smb_message(command: u8, tid: u16, uid: u16, mid: u16, body: &[u8]) -> Result<Vec<u8>> {
    let length = SMB_HEADER_LEN
        .checked_add(body.len())
        .filter(|length| *length <= u16::MAX as usize)
        .ok_or(CurlError::SendError)?;
    let mut packet = Vec::with_capacity(SMB_HEADER_START + length);
    packet.push(0);
    packet.push(0);
    packet.push((length >> 8) as u8);
    packet.push(length as u8);
    packet.extend_from_slice(b"\xffSMB");
    packet.push(command);
    push_le_u32(&mut packet, 0);
    packet.push(0x18);
    push_le_u16(&mut packet, 0x0041);
    push_le_u16(&mut packet, 0);
    packet.extend_from_slice(&[0; 8]);
    push_le_u16(&mut packet, 0);
    push_le_u16(&mut packet, tid);
    push_le_u16(&mut packet, 0x4242);
    push_le_u16(&mut packet, uid);
    push_le_u16(&mut packet, mid);
    packet.extend_from_slice(body);
    Ok(packet)
}

fn smb_negotiate_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0);
    push_le_u16(&mut body, 12);
    body.push(0x02);
    body.extend_from_slice(b"NT LM 0.12");
    body.push(0);
    body
}

fn smb_setup_body(credentials: &SmbCredentials) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&credentials.user);
    bytes.push(0);
    bytes.extend_from_slice(&credentials.domain);
    bytes.push(0);
    bytes.extend_from_slice(b"Unix\0curl\0");

    let byte_count = u16::try_from(bytes.len()).map_err(|_| CurlError::FileSizeExceeded)?;
    let mut body = Vec::new();
    body.push(0x0d);
    body.extend_from_slice(&[SMB_COM_NO_ANDX_COMMAND, 0]);
    push_le_u16(&mut body, 0);
    push_le_u16(&mut body, 0x9000);
    push_le_u16(&mut body, 1);
    push_le_u16(&mut body, 1);
    push_le_u32(&mut body, 0);
    push_le_u16(&mut body, 0);
    push_le_u16(&mut body, 0);
    push_le_u32(&mut body, 0);
    push_le_u32(&mut body, SMB_CAP_LARGE_FILES);
    push_le_u16(&mut body, byte_count);
    body.extend_from_slice(&bytes);
    Ok(body)
}

fn smb_tree_connect_body(host: &str, path: &SmbPath) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\\\\");
    bytes.extend_from_slice(host.as_bytes());
    bytes.push(b'\\');
    bytes.extend_from_slice(&path.share);
    bytes.push(0);
    bytes.extend_from_slice(b"?????\0");

    let byte_count = u16::try_from(bytes.len()).map_err(|_| CurlError::FileSizeExceeded)?;
    let mut body = Vec::new();
    body.push(0x04);
    body.extend_from_slice(&[SMB_COM_NO_ANDX_COMMAND, 0]);
    push_le_u16(&mut body, 0);
    push_le_u16(&mut body, 0);
    push_le_u16(&mut body, 0);
    push_le_u16(&mut body, byte_count);
    body.extend_from_slice(&bytes);
    Ok(body)
}

fn smb_open_body(path: &SmbPath) -> Result<Vec<u8>> {
    let name_length = u16::try_from(path.file.len()).map_err(|_| CurlError::FileSizeExceeded)?;
    let byte_count = name_length
        .checked_add(1)
        .ok_or(CurlError::FileSizeExceeded)?;
    let mut body = Vec::new();
    body.push(0x18);
    body.extend_from_slice(&[SMB_COM_NO_ANDX_COMMAND, 0]);
    push_le_u16(&mut body, 0);
    body.push(0);
    push_le_u16(&mut body, name_length);
    push_le_u32(&mut body, 0);
    push_le_u32(&mut body, 0);
    push_le_u32(&mut body, SMB_GENERIC_READ);
    push_le_u64(&mut body, 0);
    push_le_u32(&mut body, 0);
    push_le_u32(&mut body, SMB_FILE_SHARE_ALL);
    push_le_u32(&mut body, SMB_FILE_OPEN);
    push_le_u32(&mut body, 0);
    push_le_u32(&mut body, 0);
    body.push(0);
    push_le_u16(&mut body, byte_count);
    body.extend_from_slice(&path.file);
    body.push(0);
    Ok(body)
}

fn smb_read_body(fid: u16, offset: u64, max_bytes: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x0c);
    body.extend_from_slice(&[SMB_COM_NO_ANDX_COMMAND, 0]);
    push_le_u16(&mut body, 0);
    push_le_u16(&mut body, fid);
    push_le_u32(&mut body, offset as u32);
    push_le_u16(&mut body, max_bytes);
    push_le_u16(&mut body, max_bytes);
    push_le_u32(&mut body, 0);
    push_le_u16(&mut body, 0);
    push_le_u32(&mut body, (offset >> 32) as u32);
    push_le_u16(&mut body, 0);
    body
}

fn smb_close_body(fid: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x03);
    push_le_u16(&mut body, fid);
    push_le_u32(&mut body, 0);
    push_le_u16(&mut body, 0);
    body
}

fn smb_tree_disconnect_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0);
    push_le_u16(&mut body, 0);
    body
}

async fn smb_read_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut nbt = [0; SMB_HEADER_START];
    stream.read_exact(&mut nbt).await.map_err(smb_read_error)?;
    let length = (((nbt[1] & 0x01) as usize) << 16) | ((nbt[2] as usize) << 8) | nbt[3] as usize;
    if nbt[0] != 0 || !(SMB_HEADER_LEN..=SMB_MAX_MESSAGE_SIZE).contains(&length) {
        return Err(CurlError::RecvError);
    }

    let mut packet = Vec::with_capacity(SMB_HEADER_START + length);
    packet.extend_from_slice(&nbt);
    packet.resize(SMB_HEADER_START + length, 0);
    stream
        .read_exact(&mut packet[SMB_HEADER_START..])
        .await
        .map_err(smb_read_error)?;
    if &packet[SMB_HEADER_START..SMB_HEADER_START + 4] != b"\xffSMB" {
        return Err(CurlError::RecvError);
    }
    Ok(packet)
}

fn smb_read_error(error: io::Error) -> CurlError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        CurlError::RecvError
    } else {
        tcp_io_error(error)
    }
}

fn smb_response<'a>(packet: &'a [u8], command: u8) -> Result<SmbResponse<'a>> {
    if packet.len() < SMB_FULL_HEADER_LEN
        || &packet[SMB_HEADER_START..SMB_HEADER_START + 4] != b"\xffSMB"
    {
        return Err(CurlError::RecvError);
    }
    if packet[8] != command {
        return Err(CurlError::WeirdServerReply);
    }
    Ok(SmbResponse {
        status: smb_read_u32_at(packet, 9)?,
        tid: smb_read_u16_at(packet, 28)?,
        uid: smb_read_u16_at(packet, 32)?,
        body: &packet[SMB_FULL_HEADER_LEN..],
    })
}

fn smb_read_response_data<'a>(packet: &'a [u8], body: &[u8]) -> Result<&'a [u8]> {
    if body.len() < 15 {
        return Err(CurlError::RecvError);
    }
    let length = smb_read_u16_at(body, 11)? as usize;
    let offset = smb_read_u16_at(body, 13)? as usize;
    let data_start = SMB_HEADER_START
        .checked_add(offset)
        .ok_or(CurlError::RecvError)?;
    let data_end = data_start
        .checked_add(length)
        .filter(|end| *end <= packet.len())
        .ok_or(CurlError::RecvError)?;
    Ok(&packet[data_start..data_end])
}

fn smb_file_error(status: u32) -> CurlError {
    if status == SMB_ERR_NOACCESS {
        CurlError::RemoteAccessDenied
    } else {
        CurlError::RemoteFileNotFound
    }
}

fn push_le_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_le_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_le_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn smb_read_u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).ok_or(CurlError::RecvError)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn smb_read_u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or(CurlError::RecvError)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn smb_read_u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or(CurlError::RecvError)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

async fn run_ldap_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for ldap:// URLs"
        )));
    }
    if !transfer.data.is_empty() || !transfer.url_query.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "data/form/query request bodies for ldap:// URLs".to_string(),
        ));
    }
    reject_upload_file_for_scheme(transfer, "ldap://")?;
    if transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(
            "--oauth2-bearer for ldap:// URLs".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_ldap_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_ldap_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_ldap_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("LDAP URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(LDAP_DEFAULT_PORT);
    let request = ldap_url_request(&url)?;
    let (login, password) = ldap_credentials(transfer, &url)?;
    let mut stream = connect_tcp(host, port, transfer).await?;

    stream
        .write_all(&ldap_message(1, &ldap_bind_request(&login, &password)))
        .await
        .map_err(tcp_io_error)?;
    let bind_response = ldap_read_message(&mut stream).await?;
    let bind_response = ldap_parse_message(&bind_response)?;
    if bind_response.protocol_tag != 0x61 {
        return Err(CurlError::WeirdServerReply);
    }
    let bind_code = ldap_result_code(bind_response.protocol_value)?;
    if bind_code != 0 {
        return Err(ldap_bind_error(bind_code));
    }

    stream
        .write_all(&ldap_message(2, &ldap_search_request(&request)))
        .await
        .map_err(tcp_io_error)?;

    let mut body = Vec::new();
    loop {
        let message = ldap_read_message(&mut stream).await?;
        let message = ldap_parse_message(&message)?;
        match message.protocol_tag {
            0x64 => ldap_append_search_entry(&mut body, message.protocol_value)?,
            0x65 => {
                let code = ldap_result_code(message.protocol_value)?;
                metrics.response_code = Some(u16::try_from(code).unwrap_or(0));
                if code != 0 && code != 4 {
                    return Err(CurlError::LdapSearchFailed);
                }
                break;
            }
            0x73 => {}
            _ => return Err(CurlError::RecvError),
        }
    }

    let _ = stream
        .write_all(&ldap_message(3, &ldap_tlv(0x42, &[])))
        .await;

    metrics.url_effective = url.to_string();
    if method == "HEAD" {
        body.clear();
    }
    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let mut bytes = Vec::new();
    if method != "HEAD" {
        bytes.extend_from_slice(body_bytes);
    }
    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        &bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

struct LdapUrlRequest {
    dn: Vec<u8>,
    attributes: Vec<Vec<u8>>,
    scope: u8,
    filter: LdapFilter,
}

enum LdapFilter {
    Present(Vec<u8>),
    Equality(Vec<u8>, Vec<u8>),
}

struct LdapMessage<'a> {
    protocol_tag: u8,
    protocol_value: &'a [u8],
}

struct BerTlv<'a> {
    tag: u8,
    value: &'a [u8],
}

struct BerReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_tlv(&mut self) -> Result<BerTlv<'a>> {
        if self.position >= self.bytes.len() {
            return Err(CurlError::RecvError);
        }
        let tag = self.bytes[self.position];
        self.position += 1;
        let length = ber_read_length(self.bytes, &mut self.position)?;
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(CurlError::RecvError)?;
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(BerTlv { tag, value })
    }

    fn read_tag(&mut self, tag: u8) -> Result<&'a [u8]> {
        let tlv = self.read_tlv()?;
        if tlv.tag != tag {
            return Err(CurlError::RecvError);
        }
        Ok(tlv.value)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn ldap_url_request(url: &Url) -> Result<LdapUrlRequest> {
    let dn = ldap_percent_decode(
        "LDAP DN",
        url.path().strip_prefix('/').unwrap_or(url.path()),
    )?;
    let mut attributes = Vec::new();
    let mut scope = 0;
    let mut filter = LdapFilter::Present(b"objectClass".to_vec());

    if let Some(query) = url.query() {
        let mut fields = query.split('?');
        if let Some(raw_attributes) = fields.next()
            && !raw_attributes.is_empty()
        {
            for attribute in raw_attributes.split(',') {
                attributes.push(ldap_percent_decode("LDAP attribute", attribute)?);
            }
        }
        if let Some(raw_scope) = fields.next()
            && !raw_scope.is_empty()
        {
            scope = ldap_scope(raw_scope)?;
        }
        if let Some(raw_filter) = fields.next()
            && !raw_filter.is_empty()
        {
            let decoded = ldap_percent_decode("LDAP filter", raw_filter)?;
            filter = ldap_filter(&decoded)?;
        }
        if fields.any(|field| !field.is_empty()) {
            return Err(CurlError::Unsupported(
                "LDAP URL extensions in the Rust sidecar".to_string(),
            ));
        }
    }

    Ok(LdapUrlRequest {
        dn,
        attributes,
        scope,
        filter,
    })
}

fn ldap_scope(scope: &str) -> Result<u8> {
    if scope.eq_ignore_ascii_case("base") {
        Ok(0)
    } else if scope.eq_ignore_ascii_case("one") || scope.eq_ignore_ascii_case("onetree") {
        Ok(1)
    } else if scope.eq_ignore_ascii_case("sub") || scope.eq_ignore_ascii_case("subtree") {
        Ok(2)
    } else {
        Err(CurlError::Url("bad LDAP URL scope".to_string()))
    }
}

fn ldap_filter(filter: &[u8]) -> Result<LdapFilter> {
    let inner = filter
        .strip_prefix(b"(")
        .and_then(|filter| filter.strip_suffix(b")"))
        .unwrap_or(filter);
    let Some(index) = inner.iter().position(|byte| *byte == b'=') else {
        return Err(CurlError::Url("bad LDAP URL filter".to_string()));
    };
    let (attribute, value) = inner.split_at(index);
    let value = &value[1..];
    if attribute.is_empty() {
        return Err(CurlError::Url("bad LDAP URL filter".to_string()));
    }
    if value == b"*" {
        Ok(LdapFilter::Present(attribute.to_vec()))
    } else {
        Ok(LdapFilter::Equality(attribute.to_vec(), value.to_vec()))
    }
}

fn ldap_percent_decode(label: &str, text: &str) -> Result<Vec<u8>> {
    let decoded = percent_decode(text.as_bytes()).collect::<Vec<_>>();
    if decoded.contains(&0) {
        return Err(CurlError::Url(format!(
            "{label} contains a decoded NUL byte"
        )));
    }
    Ok(decoded)
}

fn ldap_credentials(transfer: &TransferConfig, url: &Url) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(user) = &transfer.user {
        let (login, password) = split_user_password(user);
        return Ok((login.as_bytes().to_vec(), password.as_bytes().to_vec()));
    }

    if url.username().is_empty() && url.password().is_none() {
        return Ok((Vec::new(), Vec::new()));
    }

    let login = percent_decode(url.username().as_bytes()).collect::<Vec<_>>();
    let password = url
        .password()
        .map(|password| percent_decode(password.as_bytes()).collect::<Vec<_>>())
        .unwrap_or_default();
    if login.contains(&0) || password.contains(&0) {
        return Err(CurlError::Url(
            "LDAP credentials contain a decoded NUL byte".to_string(),
        ));
    }
    Ok((login, password))
}

fn ldap_bind_request(login: &[u8], password: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&ldap_integer(3));
    body.extend_from_slice(&ldap_octet_string(login));
    body.extend_from_slice(&ldap_tlv(0x80, password));
    ldap_tlv(0x60, &body)
}

fn ldap_search_request(request: &LdapUrlRequest) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&ldap_octet_string(&request.dn));
    body.extend_from_slice(&ldap_enumerated(request.scope as i32));
    body.extend_from_slice(&ldap_enumerated(0));
    body.extend_from_slice(&ldap_integer(0));
    body.extend_from_slice(&ldap_integer(0));
    body.extend_from_slice(&ldap_boolean(false));
    body.extend_from_slice(&ldap_filter_tlv(&request.filter));

    let mut attributes = Vec::new();
    for attribute in &request.attributes {
        attributes.extend_from_slice(&ldap_octet_string(attribute));
    }
    body.extend_from_slice(&ldap_sequence(&attributes));
    ldap_tlv(0x63, &body)
}

fn ldap_filter_tlv(filter: &LdapFilter) -> Vec<u8> {
    match filter {
        LdapFilter::Present(attribute) => ldap_tlv(0x87, attribute),
        LdapFilter::Equality(attribute, value) => {
            let mut assertion = Vec::new();
            assertion.extend_from_slice(&ldap_octet_string(attribute));
            assertion.extend_from_slice(&ldap_octet_string(value));
            ldap_tlv(0xa3, &assertion)
        }
    }
}

fn ldap_message(id: i32, protocol_op: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&ldap_integer(id));
    body.extend_from_slice(protocol_op);
    ldap_sequence(&body)
}

fn ldap_sequence(content: &[u8]) -> Vec<u8> {
    ldap_tlv(0x30, content)
}

fn ldap_integer(value: i32) -> Vec<u8> {
    ldap_tlv(0x02, &ber_integer_content(value))
}

fn ldap_enumerated(value: i32) -> Vec<u8> {
    ldap_tlv(0x0a, &ber_integer_content(value))
}

fn ldap_boolean(value: bool) -> Vec<u8> {
    ldap_tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

fn ldap_octet_string(value: &[u8]) -> Vec<u8> {
    ldap_tlv(0x04, value)
}

fn ldap_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(tag);
    bytes.extend_from_slice(&ber_length(content.len()));
    bytes.extend_from_slice(content);
    bytes
}

fn ber_integer_content(value: i32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
            || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    bytes
}

fn ber_length(length: usize) -> Vec<u8> {
    if length < 128 {
        return vec![length as u8];
    }

    let mut bytes = Vec::new();
    let mut remaining = length;
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    bytes.reverse();

    let mut encoded = Vec::with_capacity(bytes.len() + 1);
    encoded.push(0x80 | bytes.len() as u8);
    encoded.extend_from_slice(&bytes);
    encoded
}

async fn ldap_read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut tag = [0; 1];
    stream.read_exact(&mut tag).await.map_err(ldap_read_error)?;
    if tag[0] != 0x30 {
        return Err(CurlError::RecvError);
    }

    let mut length_first = [0; 1];
    stream
        .read_exact(&mut length_first)
        .await
        .map_err(ldap_read_error)?;
    let length = if length_first[0] & 0x80 == 0 {
        length_first[0] as usize
    } else {
        let count = (length_first[0] & 0x7f) as usize;
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(CurlError::RecvError);
        }
        let mut bytes = vec![0; count];
        stream
            .read_exact(&mut bytes)
            .await
            .map_err(ldap_read_error)?;
        bytes
            .into_iter()
            .fold(0_usize, |length, byte| (length << 8) | byte as usize)
    };

    let mut content = vec![0; length];
    stream
        .read_exact(&mut content)
        .await
        .map_err(ldap_read_error)?;
    Ok(content)
}

fn ldap_read_error(error: io::Error) -> CurlError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        CurlError::GotNothing
    } else {
        tcp_io_error(error)
    }
}

fn ldap_parse_message(content: &[u8]) -> Result<LdapMessage<'_>> {
    let mut reader = BerReader::new(content);
    let message_id = reader.read_tag(0x02)?;
    let _ = ber_parse_integer(message_id)?;
    let protocol = reader.read_tlv()?;
    if !reader.is_empty() {
        return Err(CurlError::RecvError);
    }
    Ok(LdapMessage {
        protocol_tag: protocol.tag,
        protocol_value: protocol.value,
    })
}

fn ldap_result_code(content: &[u8]) -> Result<i32> {
    let mut reader = BerReader::new(content);
    ber_parse_integer(reader.read_tag(0x0a)?)
}

fn ldap_bind_error(code: i32) -> CurlError {
    match code {
        49 => CurlError::LoginDenied,
        50 => CurlError::RemoteAccessDenied,
        _ => CurlError::LdapCannotBind,
    }
}

fn ldap_append_search_entry(body: &mut Vec<u8>, content: &[u8]) -> Result<()> {
    let mut reader = BerReader::new(content);
    let dn = reader.read_tag(0x04)?;
    let attributes = reader.read_tag(0x30)?;
    body.extend_from_slice(b"DN: ");
    body.extend_from_slice(dn);
    body.push(b'\n');

    let mut attributes = BerReader::new(attributes);
    while !attributes.is_empty() {
        let attribute = attributes.read_tag(0x30)?;
        let mut attribute = BerReader::new(attribute);
        let name = attribute.read_tag(0x04)?;
        let values = attribute.read_tag(0x31)?;
        let mut values = BerReader::new(values);
        if values.is_empty() {
            body.push(b'\t');
            body.extend_from_slice(name);
            body.extend_from_slice(b":\n\n");
            continue;
        }
        while !values.is_empty() {
            let value = values.read_tag(0x04)?;
            body.push(b'\t');
            body.extend_from_slice(name);
            body.extend_from_slice(b": ");
            body.extend_from_slice(value);
            body.push(b'\n');
        }
        body.push(b'\n');
    }
    body.push(b'\n');
    Ok(())
}

fn ber_read_length(bytes: &[u8], position: &mut usize) -> Result<usize> {
    if *position >= bytes.len() {
        return Err(CurlError::RecvError);
    }
    let first = bytes[*position];
    *position += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }

    let count = (first & 0x7f) as usize;
    if count == 0 || count > std::mem::size_of::<usize>() || *position + count > bytes.len() {
        return Err(CurlError::RecvError);
    }
    let mut length = 0_usize;
    for byte in &bytes[*position..*position + count] {
        length = (length << 8) | *byte as usize;
    }
    *position += count;
    Ok(length)
}

fn ber_parse_integer(bytes: &[u8]) -> Result<i32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(CurlError::RecvError);
    }
    let mut value = if bytes[0] & 0x80 != 0 { -1_i32 } else { 0 };
    for byte in bytes {
        value = (value << 8) | *byte as i32;
    }
    Ok(value)
}

async fn run_gopher_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for gopher:// URLs"
        )));
    }
    reject_upload_file_for_scheme(transfer, "gopher://")?;

    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("gopher URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(70);
    let selector = gopher_selector(&url)?;
    let mut header_bytes = selector.clone();
    header_bytes.extend_from_slice(b"\r\n");

    let mut stream = connect_tcp(host, port, transfer).await?;
    stream
        .write_all(&header_bytes)
        .await
        .map_err(tcp_io_error)?;

    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.map_err(tcp_io_error)?;
    metrics.url_effective = url.to_string();

    if method == "HEAD" {
        body.clear();
    }
    let (body_bytes, max_filesize_exceeded) = if method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &header_bytes, transfer.create_dirs)?;
    }

    let mut bytes = Vec::new();
    if method != "HEAD" {
        bytes.extend_from_slice(body_bytes);
    }

    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        &bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

async fn connect_tcp(host: &str, port: u16, transfer: &TransferConfig) -> Result<TcpStream> {
    let connect = TcpStream::connect((host, port));
    if let Some(timeout) = transfer.connect_timeout {
        tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| CurlError::Transfer("connection timed out".to_string()))?
            .map_err(tcp_io_error)
    } else {
        connect.await.map_err(tcp_io_error)
    }
}

fn tcp_io_error(error: io::Error) -> CurlError {
    CurlError::Transfer(error.to_string())
}

fn reject_upload_file_for_scheme(transfer: &TransferConfig, scheme: &str) -> Result<()> {
    if transfer.upload_file.is_some() {
        return Err(CurlError::Unsupported(format!(
            "--upload-file for {scheme}"
        )));
    }
    Ok(())
}

fn pop3_message_id(url: &Url) -> Result<Vec<u8>> {
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    let decoded = percent_decode(path.as_bytes()).collect::<Vec<_>>();
    if has_control_byte(&decoded) {
        return Err(CurlError::Url(
            "POP3 message id contains a decoded control byte".to_string(),
        ));
    }
    Ok(decoded)
}

fn pop3_credentials(transfer: &TransferConfig, url: &Url) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(user) = &transfer.user {
        let (login, password) = split_user_password(user);
        return Ok((login.as_bytes().to_vec(), password.as_bytes().to_vec()));
    }

    let login = percent_decode(url.username().as_bytes()).collect::<Vec<_>>();
    let password = url
        .password()
        .map(|password| percent_decode(password.as_bytes()).collect::<Vec<_>>())
        .unwrap_or_default();
    if has_control_byte(&login) || has_control_byte(&password) {
        return Err(CurlError::Url(
            "POP3 credentials contain a decoded control byte".to_string(),
        ));
    }
    Ok((login, password))
}

fn pop3_command(transfer: &TransferConfig, message_id: &[u8]) -> Result<Vec<u8>> {
    let mut command = if let Some(custom) = &transfer.method {
        let decoded = percent_decode(custom.as_bytes()).collect::<Vec<_>>();
        if has_control_byte(&decoded) {
            return Err(CurlError::Url(
                "POP3 custom request contains a decoded control byte".to_string(),
            ));
        }
        decoded
    } else if message_id.is_empty() || transfer.list_only {
        Vec::from(&b"LIST"[..])
    } else {
        Vec::from(&b"RETR"[..])
    };

    if !message_id.is_empty() {
        command.push(b' ');
        command.extend_from_slice(message_id);
    }
    Ok(command)
}

fn pop3_command_has_body(command: &[u8]) -> bool {
    let mut parts = command.splitn(2, |byte| byte.is_ascii_whitespace());
    let name = parts.next().unwrap_or_default();
    let has_args = parts
        .next()
        .is_some_and(|args| args.iter().any(|byte| !byte.is_ascii_whitespace()));

    if name.eq_ignore_ascii_case(b"LIST") || name.eq_ignore_ascii_case(b"UIDL") {
        return !has_args;
    }
    name.eq_ignore_ascii_case(b"RETR")
        || name.eq_ignore_ascii_case(b"TOP")
        || name.eq_ignore_ascii_case(b"CAPA")
        || name.eq_ignore_ascii_case(b"MSG")
        || name.eq_ignore_ascii_case(b"XTND")
}

fn has_control_byte(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte < 32 || *byte == 127)
}

async fn pop3_send_line(stream: &mut TcpStream, line: &[u8]) -> Result<()> {
    stream.write_all(line).await.map_err(tcp_io_error)?;
    stream.write_all(b"\r\n").await.map_err(tcp_io_error)
}

async fn pop3_read_line(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0; 1];
    loop {
        let read = stream.read(&mut byte).await.map_err(tcp_io_error)?;
        if read == 0 {
            if line.is_empty() {
                return Err(CurlError::WeirdServerReply);
            }
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(line)
}

async fn pop3_read_capa(stream: &mut TcpStream) -> Result<()> {
    let line = pop3_read_line(stream).await?;
    if line.starts_with(b"+OK") {
        loop {
            let line = pop3_read_line(stream).await?;
            if pop3_is_terminator_line(&line) {
                break;
            }
        }
        Ok(())
    } else if line.starts_with(b"-ERR") {
        Ok(())
    } else {
        Err(CurlError::WeirdServerReply)
    }
}

async fn pop3_read_multiline_body(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = pop3_read_line(stream).await?;
        if pop3_is_terminator_line(&line) {
            break;
        }
        if line.starts_with(b"..") {
            body.extend_from_slice(&line[1..]);
        } else {
            body.extend_from_slice(&line);
        }
    }
    Ok(body)
}

fn pop3_is_terminator_line(line: &[u8]) -> bool {
    matches!(line, b".\r\n" | b".\n" | b".")
}

fn pop3_expect_ok(line: Vec<u8>, login: bool) -> Result<()> {
    if line.starts_with(b"+OK") {
        Ok(())
    } else if line.starts_with(b"-ERR") && login {
        Err(CurlError::LoginDenied)
    } else {
        Err(CurlError::WeirdServerReply)
    }
}

async fn run_imap_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    if transfer.method.is_none() && method != "GET" && method != "HEAD" {
        return Err(CurlError::Unsupported(format!(
            "{method} requests for imap:// URLs"
        )));
    }
    if !transfer.data.is_empty() || !transfer.forms.is_empty() {
        return Err(CurlError::Unsupported(
            "data/form request bodies for imap:// URLs".to_string(),
        ));
    }
    reject_upload_file_for_scheme(transfer, "imap://")?;
    if !transfer.url_query.is_empty() {
        return Err(CurlError::Unsupported(
            "--url-query for imap:// URLs".to_string(),
        ));
    }
    if transfer.oauth2_bearer.is_some() {
        return Err(CurlError::Unsupported(
            "--oauth2-bearer for imap:// URLs".to_string(),
        ));
    }

    if let Some(timeout) = transfer.max_time {
        tokio::time::timeout(
            timeout,
            run_imap_exchange(transfer, expanded, method, metrics),
        )
        .await
        .map_err(|_| CurlError::Timeout)?
    } else {
        run_imap_exchange(transfer, expanded, method, metrics).await
    }
}

async fn run_imap_exchange(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &str,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;
    let host = url
        .host_str()
        .ok_or_else(|| CurlError::Url("IMAP URL is missing a host".to_string()))?;
    let port = url.port().unwrap_or(IMAP_DEFAULT_PORT);
    let request = imap_request(transfer, &url)?;
    let credentials = imap_credentials(transfer, &url)?;

    let mut stream = connect_tcp(host, port, transfer).await?;
    let preauth = imap_read_greeting(&mut stream).await?;
    let mut tag_id = 0_u16;

    let tag = imap_next_tag(&mut tag_id);
    imap_send_command(&mut stream, &tag, b"CAPABILITY").await?;
    let _ = imap_read_response(&mut stream, &tag, ImapReadMode::Quiet).await?;

    if let (false, Some((user, password))) = (preauth, credentials) {
        let tag = imap_next_tag(&mut tag_id);
        let mut login = Vec::from(&b"LOGIN "[..]);
        login.extend_from_slice(&imap_atom(&user, false));
        login.push(b' ');
        login.extend_from_slice(&imap_atom(&password, false));
        imap_send_command(&mut stream, &tag, &login).await?;
        let response = imap_read_response(&mut stream, &tag, ImapReadMode::Quiet).await?;
        if response.status != ImapStatus::Ok {
            return Err(CurlError::LoginDenied);
        }
    }

    let body = imap_run_selected_command(&mut stream, &mut tag_id, &request).await;
    let _ = imap_logout(&mut stream, &mut tag_id).await;
    let mut body = body?;

    metrics.url_effective = url.to_string();
    metrics.method = imap_method_label(&request);
    if transfer.head || method == "HEAD" {
        body.clear();
    }
    let (body_bytes, max_filesize_exceeded) = if transfer.head || method == "HEAD" {
        (&body[..], false)
    } else {
        limit_body_for_max_filesize(transfer, &body)
    };
    metrics.size_download = body_bytes.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        body_bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

struct ImapRequest {
    mailbox: Option<Vec<u8>>,
    uidvalidity: Option<u32>,
    uid: Option<Vec<u8>>,
    mail_index: Option<Vec<u8>>,
    section: Option<Vec<u8>>,
    partial: Option<Vec<u8>>,
    query: Option<Vec<u8>>,
    custom: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImapStatus {
    Ok,
    Preauth,
    No,
    Bad,
    Other,
}

enum ImapReadMode {
    Quiet,
    Lines,
    FetchBody,
}

struct ImapResponse {
    status: ImapStatus,
    output: Vec<u8>,
    uidvalidity: Option<u32>,
    saw_untagged: bool,
    saw_literal: bool,
}

async fn imap_run_selected_command(
    stream: &mut TcpStream,
    tag_id: &mut u16,
    request: &ImapRequest,
) -> Result<Vec<u8>> {
    if request.mailbox.is_some()
        && (request.custom.is_some()
            || request.uid.is_some()
            || request.mail_index.is_some()
            || request.query.is_some())
    {
        let tag = imap_next_tag(tag_id);
        let mailbox = imap_atom(request.mailbox.as_deref().unwrap_or_default(), false);
        let mut select = Vec::from(&b"SELECT "[..]);
        select.extend_from_slice(&mailbox);
        imap_send_command(stream, &tag, &select).await?;
        let response = imap_read_response(stream, &tag, ImapReadMode::Quiet).await?;
        if response.status != ImapStatus::Ok {
            return Err(CurlError::LoginDenied);
        }
        if let (Some(expected), Some(actual)) = (request.uidvalidity, response.uidvalidity)
            && expected != actual
        {
            return Err(CurlError::RemoteFileNotFound);
        }
    }

    if let Some(custom) = &request.custom {
        let mode = if imap_custom_fetch_listing(custom) {
            ImapReadMode::Quiet
        } else {
            ImapReadMode::Lines
        };
        return imap_send_body_command(stream, tag_id, custom, mode).await;
    }

    if request.uid.is_some() || request.mail_index.is_some() {
        let command = imap_fetch_command(request)?;
        let response =
            imap_send_response_command(stream, tag_id, &command, ImapReadMode::FetchBody).await?;
        if response.status != ImapStatus::Ok {
            return Err(CurlError::RemoteFileNotFound);
        }
        if !response.saw_literal {
            return if response.saw_untagged {
                Err(CurlError::WeirdServerReply)
            } else {
                Err(CurlError::RemoteFileNotFound)
            };
        }
        return Ok(response.output);
    }

    if let Some(query) = &request.query {
        let mut command = Vec::from(&b"SEARCH "[..]);
        command.extend_from_slice(query);
        return imap_send_body_command(stream, tag_id, &command, ImapReadMode::Lines).await;
    }

    let mailbox = request.mailbox.as_deref().unwrap_or_default();
    let mut command = Vec::from(&b"LIST \""[..]);
    command.extend_from_slice(&imap_atom(mailbox, true));
    command.extend_from_slice(b"\" *");
    imap_send_body_command(stream, tag_id, &command, ImapReadMode::Lines).await
}

async fn imap_send_body_command(
    stream: &mut TcpStream,
    tag_id: &mut u16,
    command: &[u8],
    mode: ImapReadMode,
) -> Result<Vec<u8>> {
    let response = imap_send_response_command(stream, tag_id, command, mode).await?;
    if response.status == ImapStatus::Ok {
        Ok(response.output)
    } else {
        Err(CurlError::QuoteError)
    }
}

async fn imap_send_response_command(
    stream: &mut TcpStream,
    tag_id: &mut u16,
    command: &[u8],
    mode: ImapReadMode,
) -> Result<ImapResponse> {
    let tag = imap_next_tag(tag_id);
    imap_send_command(stream, &tag, command).await?;
    imap_read_response(stream, &tag, mode).await
}

fn imap_request(transfer: &TransferConfig, url: &Url) -> Result<ImapRequest> {
    let mut request = imap_parse_url_path(url)?;
    if let Some(custom) = &transfer.method {
        let decoded = percent_decode(custom.as_bytes()).collect::<Vec<_>>();
        if has_control_byte(&decoded) {
            return Err(CurlError::Url(
                "IMAP custom request contains a decoded control byte".to_string(),
            ));
        }
        request.custom = Some(decoded);
    }
    Ok(request)
}

fn imap_parse_url_path(url: &Url) -> Result<ImapRequest> {
    let path = url.path().as_bytes();
    let mut index = usize::from(path.first() == Some(&b'/'));
    let begin = index;
    while index < path.len() && imap_is_bchar(path[index]) {
        index += 1;
    }

    let mailbox = if index != begin {
        let mut end = index;
        if end > begin && path[end - 1] == b'/' {
            end -= 1;
        }
        Some(imap_percent_decode("IMAP mailbox", &path[begin..end])?)
    } else {
        None
    };

    let mut request = ImapRequest {
        mailbox,
        uidvalidity: None,
        uid: None,
        mail_index: None,
        section: None,
        partial: None,
        query: None,
        custom: None,
    };

    while index < path.len() && path[index] == b';' {
        index += 1;
        let name_begin = index;
        while index < path.len() && path[index] != b'=' {
            index += 1;
        }
        if index >= path.len() {
            return Err(CurlError::Url("malformed IMAP URL parameter".to_string()));
        }
        let name = imap_percent_decode("IMAP URL parameter", &path[name_begin..index])?;
        index += 1;
        let value_begin = index;
        while index < path.len() && imap_is_bchar(path[index]) {
            index += 1;
        }
        let mut value = imap_percent_decode("IMAP URL parameter value", &path[value_begin..index])?;
        if value.last() == Some(&b'/') {
            value.pop();
        }
        if value.is_empty() {
            continue;
        }

        if name.eq_ignore_ascii_case(b"UIDVALIDITY") && request.uidvalidity.is_none() {
            let text = std::str::from_utf8(&value)
                .map_err(|_| CurlError::Url("bad IMAP UIDVALIDITY".to_string()))?;
            request.uidvalidity = text.parse::<u32>().ok();
        } else if name.eq_ignore_ascii_case(b"UID") && request.uid.is_none() {
            request.uid = Some(value);
        } else if name.eq_ignore_ascii_case(b"MAILINDEX") && request.mail_index.is_none() {
            request.mail_index = Some(value);
        } else if name.eq_ignore_ascii_case(b"SECTION") && request.section.is_none() {
            request.section = Some(value);
        } else if name.eq_ignore_ascii_case(b"PARTIAL") && request.partial.is_none() {
            request.partial = Some(value);
        } else {
            return Err(CurlError::Url("unsupported IMAP URL parameter".to_string()));
        }
    }

    if request.mailbox.is_some()
        && request.uid.is_none()
        && request.mail_index.is_none()
        && let Some(query) = url.query()
    {
        request.query = Some(imap_percent_decode("IMAP query", query.as_bytes())?);
    }

    if index != path.len() {
        return Err(CurlError::Url("malformed IMAP URL path".to_string()));
    }
    Ok(request)
}

fn imap_percent_decode(name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let decoded = percent_decode(bytes).collect::<Vec<_>>();
    if has_control_byte(&decoded) {
        return Err(CurlError::Url(format!(
            "{name} contains a decoded control byte"
        )));
    }
    Ok(decoded)
}

fn imap_fetch_command(request: &ImapRequest) -> Result<Vec<u8>> {
    let section = request.section.as_deref().unwrap_or_default();
    let mut command = if let Some(uid) = &request.uid {
        let mut command = Vec::from(&b"UID FETCH "[..]);
        command.extend_from_slice(uid);
        command
    } else if let Some(mail_index) = &request.mail_index {
        let mut command = Vec::from(&b"FETCH "[..]);
        command.extend_from_slice(mail_index);
        command
    } else {
        return Err(CurlError::Url("Cannot FETCH without a UID".to_string()));
    };
    command.extend_from_slice(b" BODY[");
    command.extend_from_slice(section);
    command.push(b']');
    if let Some(partial) = &request.partial {
        command.push(b'<');
        command.extend_from_slice(partial);
        command.push(b'>');
    }
    Ok(command)
}

fn imap_credentials(transfer: &TransferConfig, url: &Url) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    if let Some(user) = &transfer.user {
        let (login, password) = split_user_password(user);
        return Ok(Some((
            login.as_bytes().to_vec(),
            password.as_bytes().to_vec(),
        )));
    }

    if url.username().is_empty() && url.password().is_none() {
        return Ok(None);
    }

    let login = percent_decode(url.username().as_bytes()).collect::<Vec<_>>();
    let password = url
        .password()
        .map(|password| percent_decode(password.as_bytes()).collect::<Vec<_>>())
        .unwrap_or_default();
    if has_control_byte(&login) || has_control_byte(&password) {
        return Err(CurlError::Url(
            "IMAP credentials contain a decoded control byte".to_string(),
        ));
    }
    Ok(Some((login, password)))
}

fn imap_atom(input: &[u8], escape_only: bool) -> Vec<u8> {
    const SPECIALS: &[u8] = b"() {%*]\\\"";
    if !input.iter().any(|byte| SPECIALS.contains(byte)) {
        return input.to_vec();
    }

    let mut atom = Vec::new();
    if !escape_only {
        atom.push(b'"');
    }
    for byte in input {
        if matches!(*byte, b'\\' | b'"') {
            atom.push(b'\\');
        }
        atom.push(*byte);
    }
    if !escape_only {
        atom.push(b'"');
    }
    atom
}

fn imap_is_bchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b":@/&=-._~!$'()*+,%".contains(&byte)
}

fn imap_method_label(request: &ImapRequest) -> String {
    if let Some(custom) = &request.custom {
        let word = custom
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            .unwrap_or_default();
        return String::from_utf8_lossy(word).to_string();
    }
    if request.uid.is_some() || request.mail_index.is_some() {
        "FETCH".to_string()
    } else if request.query.is_some() {
        "SEARCH".to_string()
    } else {
        "LIST".to_string()
    }
}

async fn imap_read_greeting(stream: &mut TcpStream) -> Result<bool> {
    let line = pop3_read_line(stream).await?;
    match imap_untagged_status(&line) {
        ImapStatus::Ok => Ok(false),
        ImapStatus::Preauth => Ok(true),
        _ => Err(CurlError::WeirdServerReply),
    }
}

async fn imap_logout(stream: &mut TcpStream, tag_id: &mut u16) -> Result<()> {
    let tag = imap_next_tag(tag_id);
    imap_send_command(stream, &tag, b"LOGOUT").await?;
    let _ = imap_read_response(stream, &tag, ImapReadMode::Quiet).await?;
    Ok(())
}

fn imap_next_tag(tag_id: &mut u16) -> String {
    *tag_id += 1;
    format!("A{:03}", *tag_id)
}

async fn imap_send_command(stream: &mut TcpStream, tag: &str, command: &[u8]) -> Result<()> {
    stream
        .write_all(tag.as_bytes())
        .await
        .map_err(tcp_io_error)?;
    stream.write_all(b" ").await.map_err(tcp_io_error)?;
    stream.write_all(command).await.map_err(tcp_io_error)?;
    stream.write_all(b"\r\n").await.map_err(tcp_io_error)
}

async fn imap_read_response(
    stream: &mut TcpStream,
    tag: &str,
    mode: ImapReadMode,
) -> Result<ImapResponse> {
    let mut response = ImapResponse {
        status: ImapStatus::Other,
        output: Vec::new(),
        uidvalidity: None,
        saw_untagged: false,
        saw_literal: false,
    };

    loop {
        let line = pop3_read_line(stream).await?;
        if imap_is_empty_line(&line) {
            continue;
        }
        if imap_is_tagged_line(&line, tag) {
            response.status = imap_tagged_status(&line, tag);
            return Ok(response);
        }

        response.saw_untagged = true;
        if response.uidvalidity.is_none() {
            response.uidvalidity = imap_uidvalidity(&line);
        }
        let literal_size = imap_literal_size(&line)?;
        match mode {
            ImapReadMode::Quiet => {
                if let Some(size) = literal_size {
                    let _ = imap_read_literal(stream, size).await?;
                    response.saw_literal = true;
                }
            }
            ImapReadMode::FetchBody => {
                if let Some(size) = literal_size {
                    let literal = imap_read_literal(stream, size).await?;
                    response.output.extend_from_slice(&literal);
                    response.saw_literal = true;
                }
            }
            ImapReadMode::Lines => {
                response.output.extend_from_slice(&line);
                if let Some(size) = literal_size {
                    let literal = imap_read_literal(stream, size).await?;
                    response.output.extend_from_slice(&literal);
                    response.saw_literal = true;
                }
            }
        }
    }
}

async fn imap_read_literal(stream: &mut TcpStream, size: usize) -> Result<Vec<u8>> {
    let mut literal = vec![0; size];
    stream
        .read_exact(&mut literal)
        .await
        .map_err(tcp_io_error)?;
    Ok(literal)
}

fn imap_is_empty_line(line: &[u8]) -> bool {
    matches!(line, b"\r\n" | b"\n" | b"")
}

fn imap_is_tagged_line(line: &[u8], tag: &str) -> bool {
    let tag = tag.as_bytes();
    line.starts_with(tag)
        && line
            .get(tag.len())
            .is_some_and(|byte| byte.is_ascii_whitespace())
}

fn imap_tagged_status(line: &[u8], tag: &str) -> ImapStatus {
    imap_status_word(line.get(tag.len()..).unwrap_or_default())
}

fn imap_untagged_status(line: &[u8]) -> ImapStatus {
    if let Some(rest) = line.strip_prefix(b"*") {
        imap_status_word(rest)
    } else {
        ImapStatus::Other
    }
}

fn imap_status_word(bytes: &[u8]) -> ImapStatus {
    let mut index = 0;
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }
    let start = index;
    while bytes
        .get(index)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        index += 1;
    }
    match &bytes[start..index].to_ascii_uppercase()[..] {
        b"OK" => ImapStatus::Ok,
        b"PREAUTH" => ImapStatus::Preauth,
        b"NO" => ImapStatus::No,
        b"BAD" => ImapStatus::Bad,
        _ => ImapStatus::Other,
    }
}

fn imap_uidvalidity(line: &[u8]) -> Option<u32> {
    let upper = line.to_ascii_uppercase();
    let marker = b"[UIDVALIDITY ";
    let start = upper
        .windows(marker.len())
        .position(|window| window == marker)?
        + marker.len();
    let mut end = start;
    while upper.get(end).is_some_and(|byte| byte.is_ascii_digit()) {
        end += 1;
    }
    std::str::from_utf8(&upper[start..end]).ok()?.parse().ok()
}

fn imap_literal_size(line: &[u8]) -> Result<Option<usize>> {
    let mut in_quote = false;
    let mut escaped = false;
    let mut index = 0;
    while index < line.len() {
        let byte = line[index];
        if in_quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_quote = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_quote = true;
            index += 1;
            continue;
        }
        if byte == b'{' {
            let start = index + 1;
            let mut end = start;
            while line.get(end).is_some_and(|byte| byte.is_ascii_digit()) {
                end += 1;
            }
            if end > start && line.get(end) == Some(&b'}') {
                let size = std::str::from_utf8(&line[start..end])
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or(CurlError::WeirdServerReply)?;
                return Ok(Some(size));
            }
        }
        index += 1;
    }
    Ok(None)
}

fn imap_custom_fetch_listing(command: &[u8]) -> bool {
    let upper = command.to_ascii_uppercase();
    if upper.starts_with(b"FETCH ") {
        imap_custom_fetch_listing_match(&command[5..])
    } else if upper.starts_with(b"UID FETCH ") {
        imap_custom_fetch_listing_match(&command[9..])
    } else {
        false
    }
}

fn imap_custom_fetch_listing_match(params: &[u8]) -> bool {
    if params.first() != Some(&b' ') {
        return false;
    }
    let mut index = 1;
    while params.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
        index += 1;
    }
    index > 1 && matches!(params.get(index), Some(b':' | b','))
}

struct SmtpResponse {
    code: u16,
    lines: Vec<Vec<u8>>,
}

async fn smtp_greet(
    stream: &mut TcpStream,
    ehlo_domain: &[u8],
    metrics: &mut writeout::Metrics,
) -> Result<SmtpResponse> {
    let mut ehlo = Vec::from(&b"EHLO "[..]);
    ehlo.extend_from_slice(ehlo_domain);
    smtp_send_line(stream, &ehlo).await?;
    let response = smtp_read_response(stream).await?;
    metrics.response_code = Some(response.code);
    if response.code == 250 {
        return Ok(response);
    }

    let mut helo = Vec::from(&b"HELO "[..]);
    helo.extend_from_slice(ehlo_domain);
    smtp_send_line(stream, &helo).await?;
    let response = smtp_read_response(stream).await?;
    metrics.response_code = Some(response.code);
    smtp_require_code(&response, &[250], CurlError::RemoteAccessDenied)?;
    Ok(response)
}

async fn smtp_send_mail(
    transfer: &TransferConfig,
    stream: &mut TcpStream,
    capabilities: &SmtpResponse,
    upload: &[u8],
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let mail_from = smtp_path_address(transfer.mail_from.as_deref())?;
    let mut command = Vec::from(&b"MAIL FROM:"[..]);
    command.extend_from_slice(&mail_from);
    if smtp_response_has_keyword(capabilities, b"SIZE") {
        command.extend_from_slice(format!(" SIZE={}", upload.len()).as_bytes());
    }
    smtp_send_line(stream, &command).await?;
    let response = smtp_read_response(stream).await?;
    metrics.response_code = Some(response.code);
    smtp_require_success(&response, CurlError::SendError)?;

    let mut accepted_recipients = 0_usize;
    for recipient in &transfer.mail_rcpt {
        let recipient = smtp_path_address(Some(recipient.as_str()))?;
        let mut command = Vec::from(&b"RCPT TO:"[..]);
        command.extend_from_slice(&recipient);
        smtp_send_line(stream, &command).await?;
        let response = smtp_read_response(stream).await?;
        metrics.response_code = Some(response.code);
        if smtp_success(response.code) {
            accepted_recipients += 1;
        } else if !transfer.mail_rcpt_allowfails {
            return Err(CurlError::SendError);
        }
    }

    if accepted_recipients == 0 {
        return Err(CurlError::SendError);
    }

    smtp_send_line(stream, b"DATA").await?;
    let response = smtp_read_response(stream).await?;
    metrics.response_code = Some(response.code);
    smtp_require_code(&response, &[354], CurlError::SendError)?;

    let upload = smtp_dot_stuffed_body(upload);
    stream.write_all(&upload).await.map_err(tcp_io_error)?;
    let response = smtp_read_response(stream).await?;
    metrics.response_code = Some(response.code);
    smtp_require_code(&response, &[250], CurlError::WeirdServerReply)
}

fn smtp_command(transfer: &TransferConfig) -> Result<Vec<u8>> {
    let mut command = if let Some(custom) = &transfer.method {
        smtp_argument_bytes("--request", custom)?
    } else if transfer.mail_rcpt.is_empty() {
        Vec::from(&b"HELP"[..])
    } else {
        Vec::from(&b"VRFY"[..])
    };

    if let Some(recipient) = transfer.mail_rcpt.first() {
        command.push(b' ');
        command.extend_from_slice(&smtp_argument_bytes("--mail-rcpt", recipient)?);
    }
    Ok(command)
}

fn smtp_path_address(value: Option<&str>) -> Result<Vec<u8>> {
    let value = value.unwrap_or("");
    smtp_argument_bytes("SMTP address", &format_smtp_path_address(value))
}

fn format_smtp_path_address(value: &str) -> String {
    if value.starts_with('<') {
        return value.to_string();
    }
    if value.is_empty() {
        return "<>".to_string();
    }
    if let Some((address, suffix)) = value.split_once(' ') {
        return format!("<{}> {}", address, suffix.trim_start());
    }
    format!("<{value}>")
}

fn smtp_argument_bytes(name: &str, value: &str) -> Result<Vec<u8>> {
    let bytes = value.as_bytes().to_vec();
    if has_control_byte(&bytes) {
        return Err(CurlError::Url(format!(
            "{name} contains a decoded control byte"
        )));
    }
    Ok(bytes)
}

fn smtp_ehlo_domain(url: &Url) -> Result<Vec<u8>> {
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    let decoded = percent_decode(path.as_bytes()).collect::<Vec<_>>();
    if has_control_byte(&decoded) {
        return Err(CurlError::Url(
            "SMTP URL path contains a decoded control byte".to_string(),
        ));
    }
    if decoded.is_empty() {
        Ok(Vec::from(&b"localhost"[..]))
    } else {
        Ok(decoded)
    }
}

async fn smtp_send_line(stream: &mut TcpStream, line: &[u8]) -> Result<()> {
    stream.write_all(line).await.map_err(tcp_io_error)?;
    stream.write_all(b"\r\n").await.map_err(tcp_io_error)
}

async fn smtp_read_response(stream: &mut TcpStream) -> Result<SmtpResponse> {
    let mut lines = Vec::new();
    let mut response_code = None;
    loop {
        let line = smtp_read_line(stream).await?;
        let code = smtp_response_code(&line)?;
        if let Some(expected) = response_code {
            if expected != code {
                return Err(CurlError::WeirdServerReply);
            }
        } else {
            response_code = Some(code);
        }
        let continued = line.get(3) == Some(&b'-');
        lines.push(line);
        if !continued {
            break;
        }
    }

    Ok(SmtpResponse {
        code: response_code.ok_or(CurlError::WeirdServerReply)?,
        lines,
    })
}

async fn smtp_read_line(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0; 1];
    loop {
        let read = stream.read(&mut byte).await.map_err(tcp_io_error)?;
        if read == 0 {
            if line.is_empty() {
                return Err(CurlError::WeirdServerReply);
            }
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(line)
}

fn smtp_response_code(line: &[u8]) -> Result<u16> {
    if line.len() < 3 || !line[..3].iter().all(u8::is_ascii_digit) {
        return Err(CurlError::WeirdServerReply);
    }
    Ok(
        u16::from(line[0] - b'0') * 100
            + u16::from(line[1] - b'0') * 10
            + u16::from(line[2] - b'0'),
    )
}

fn smtp_require_success(response: &SmtpResponse, error: CurlError) -> Result<()> {
    if smtp_success(response.code) {
        Ok(())
    } else {
        Err(error)
    }
}

fn smtp_require_code(response: &SmtpResponse, accepted: &[u16], error: CurlError) -> Result<()> {
    if accepted.contains(&response.code) {
        Ok(())
    } else {
        Err(error)
    }
}

fn smtp_success(code: u16) -> bool {
    (200..300).contains(&code)
}

fn smtp_response_has_keyword(response: &SmtpResponse, keyword: &[u8]) -> bool {
    response.lines.iter().any(|line| {
        smtp_response_payload(line)
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case(keyword))
    })
}

fn smtp_response_payload(line: &[u8]) -> &[u8] {
    let mut payload = if line.len() > 4 { &line[4..] } else { &[] };
    while payload
        .last()
        .is_some_and(|byte| matches!(*byte, b'\r' | b'\n'))
    {
        payload = &payload[..payload.len() - 1];
    }
    payload
}

fn smtp_dot_stuffed_body(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() + 8);
    let mut at_line_start = true;
    for byte in input {
        if at_line_start && *byte == b'.' {
            output.push(b'.');
        }
        output.push(*byte);
        at_line_start = *byte == b'\n';
    }
    if !input.ends_with(b"\r\n") {
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b".\r\n");
    output
}

fn tftp_filename_and_mode(url: &Url) -> Result<(Vec<u8>, &'static str)> {
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    let mut decoded = percent_decode(path.as_bytes()).collect::<Vec<_>>();
    if decoded.contains(&0) {
        return Err(CurlError::Url(
            "TFTP filename contains a decoded NUL byte".to_string(),
        ));
    }

    let mode = if strip_tftp_mode_suffix(&mut decoded, b";mode=netascii") {
        "netascii"
    } else {
        strip_tftp_mode_suffix(&mut decoded, b";mode=octet");
        "octet"
    };

    if decoded.is_empty() {
        return Err(CurlError::TftpIllegal);
    }
    Ok((decoded, mode))
}

fn strip_tftp_mode_suffix(value: &mut Vec<u8>, suffix: &[u8]) -> bool {
    if value.len() < suffix.len() {
        return false;
    }
    let start = value.len() - suffix.len();
    if value[start..].eq_ignore_ascii_case(suffix) {
        value.truncate(start);
        true
    } else {
        false
    }
}

struct MqttPacket {
    packet_type: u8,
    remaining_len: usize,
    body: Vec<u8>,
}

struct MqttPacketHeader {
    packet_type: u8,
    remaining_len: usize,
}

fn mqtt_connect_packet(user: Option<&str>) -> Result<Vec<u8>> {
    let (username, password) = user.map(split_user_password).unwrap_or(("", ""));
    if username.len() > u16::MAX as usize || password.len() > u16::MAX as usize {
        return Err(CurlError::WeirdServerReply);
    }

    let mut body = Vec::new();
    mqtt_append_string(&mut body, b"MQTT")?;
    body.push(4);
    let mut flags = 0x02;
    if !username.is_empty() {
        flags |= 0x80;
    }
    if !password.is_empty() {
        flags |= 0x40;
    }
    body.push(flags);
    body.extend_from_slice(&60_u16.to_be_bytes());
    mqtt_append_string(&mut body, MQTT_CLIENT_ID)?;
    if !username.is_empty() {
        mqtt_append_string(&mut body, username.as_bytes())?;
    }
    if !password.is_empty() {
        mqtt_append_string(&mut body, password.as_bytes())?;
    }

    mqtt_packet(MQTT_CONNECT, &body)
}

fn mqtt_subscribe_packet(topic: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_u16.to_be_bytes());
    mqtt_append_string(&mut body, topic)?;
    body.push(0);
    mqtt_packet(MQTT_SUBSCRIBE, &body)
}

fn mqtt_publish_packet(topic: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(topic.len() + payload.len() + 2);
    mqtt_append_string(&mut body, topic)?;
    body.extend_from_slice(payload);
    mqtt_packet(MQTT_PUBLISH, &body)
}

fn mqtt_packet(packet_type: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(body.len() + 5);
    packet.push(packet_type);
    mqtt_encode_remaining_len(body.len(), &mut packet)?;
    packet.extend_from_slice(body);
    Ok(packet)
}

fn mqtt_append_string(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len())
        .map_err(|_| CurlError::Url("MQTT topic or field exceeds 65535 bytes".to_string()))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn mqtt_encode_remaining_len(mut len: usize, output: &mut Vec<u8>) -> Result<()> {
    if len > 0x0fff_ffff {
        return Err(CurlError::WeirdServerReply);
    }

    loop {
        let mut encoded = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            encoded |= 128;
        }
        output.push(encoded);
        if len == 0 {
            return Ok(());
        }
    }
}

async fn mqtt_read_packet(stream: &mut TcpStream) -> Result<MqttPacket> {
    let header = mqtt_read_packet_header(stream).await?;
    let body = mqtt_read_packet_body(stream, header.remaining_len).await?;
    Ok(MqttPacket {
        packet_type: header.packet_type,
        remaining_len: header.remaining_len,
        body,
    })
}

async fn mqtt_read_packet_header(stream: &mut TcpStream) -> Result<MqttPacketHeader> {
    let mut first = [0; 1];
    stream.read_exact(&mut first).await.map_err(tcp_io_error)?;

    let mut multiplier = 1_usize;
    let mut remaining_len = 0_usize;
    for _ in 0..4 {
        let mut byte = [0; 1];
        stream.read_exact(&mut byte).await.map_err(tcp_io_error)?;
        remaining_len += usize::from(byte[0] & 127) * multiplier;
        if byte[0] & 128 == 0 {
            return Ok(MqttPacketHeader {
                packet_type: first[0],
                remaining_len,
            });
        }
        multiplier *= 128;
    }

    Err(CurlError::WeirdServerReply)
}

async fn mqtt_read_packet_body(stream: &mut TcpStream, remaining_len: usize) -> Result<Vec<u8>> {
    let mut body = vec![0; remaining_len];
    if remaining_len > 0 {
        stream.read_exact(&mut body).await.map_err(tcp_io_error)?;
    }
    Ok(body)
}

fn mqtt_topic_from_url(url: &Url) -> Result<Vec<u8>> {
    let path = url.path();
    if path.len() <= 1 {
        return Err(CurlError::Url(
            "No MQTT topic found. Forgot to URL encode it?".to_string(),
        ));
    }

    let topic = percent_decode(&path.as_bytes()[1..]).collect::<Vec<_>>();
    if topic.len() > u16::MAX as usize {
        return Err(CurlError::Url("Too long MQTT topic".to_string()));
    }
    Ok(topic)
}

fn tftp_rrq_packet(filename: &[u8], mode: &str, blksize: u16, no_options: bool) -> Vec<u8> {
    tftp_request_packet(1, filename, mode, blksize, no_options, 0)
}

fn tftp_wrq_packet(
    filename: &[u8],
    mode: &str,
    blksize: u16,
    no_options: bool,
    upload_size: u64,
) -> Vec<u8> {
    tftp_request_packet(2, filename, mode, blksize, no_options, upload_size)
}

fn tftp_request_packet(
    opcode: u16,
    filename: &[u8],
    mode: &str,
    blksize: u16,
    no_options: bool,
    transfer_size: u64,
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&opcode.to_be_bytes());
    packet.extend_from_slice(filename);
    packet.push(0);
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0);
    if !no_options {
        packet.extend_from_slice(b"tsize\0");
        packet.extend_from_slice(transfer_size.to_string().as_bytes());
        packet.push(0);
        packet.extend_from_slice(b"blksize\0");
        packet.extend_from_slice(blksize.to_string().as_bytes());
        packet.push(0);
        packet.extend_from_slice(b"timeout\0");
        packet.extend_from_slice(b"5\0");
    }
    packet
}

fn tftp_next_data_packet(
    body: &[u8],
    block_size: usize,
    offset: &mut usize,
    block: &mut u16,
) -> (Vec<u8>, u16, usize) {
    let block_number = *block;
    let remaining = body.len().saturating_sub(*offset);
    let data_len = remaining.min(block_size);
    let end = *offset + data_len;
    let packet = tftp_data_packet(block_number, &body[*offset..end]);
    *offset = end;
    *block = block.wrapping_add(1);
    (packet, block_number, data_len)
}

fn tftp_data_packet(block: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(data.len() + 4);
    packet.extend_from_slice(&3_u16.to_be_bytes());
    packet.extend_from_slice(&block.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

fn tftp_ack_packet(block: u16) -> [u8; 4] {
    let mut packet = [0, 4, 0, 0];
    packet[2..].copy_from_slice(&block.to_be_bytes());
    packet
}

fn tftp_error_packet(code: u16, message: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&5_u16.to_be_bytes());
    packet.extend_from_slice(&code.to_be_bytes());
    packet.extend_from_slice(message);
    packet.push(0);
    packet
}

fn tftp_opcode(packet: &[u8]) -> Result<u16> {
    if packet.len() < 2 {
        return Err(CurlError::TftpIllegal);
    }
    Ok(u16::from_be_bytes([packet[0], packet[1]]))
}

fn tftp_block_number(packet: &[u8]) -> Result<u16> {
    if packet.len() < 4 {
        return Err(CurlError::TftpIllegal);
    }
    Ok(u16::from_be_bytes([packet[2], packet[3]]))
}

fn tftp_oack_blksize(packet: &[u8]) -> Option<usize> {
    let mut parts = packet.get(2..)?.split(|byte| *byte == 0);
    while let Some(option) = parts.next() {
        if option.is_empty() {
            break;
        }
        let value = parts.next()?;
        if option.eq_ignore_ascii_case(b"blksize")
            && let Ok(text) = std::str::from_utf8(value)
            && let Ok(blksize) = text.parse::<usize>()
            && blksize > 0
        {
            return Some(blksize);
        }
    }
    None
}

fn tftp_error_response(packet: &[u8]) -> CurlError {
    let code = packet
        .get(2..4)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .unwrap_or(0);
    match code {
        1 => CurlError::TftpNotFound,
        2 => CurlError::TftpPermission,
        3 => CurlError::TftpDiskFull,
        5 => CurlError::TftpUnknownId,
        6 => CurlError::TftpFileExists,
        7 => CurlError::TftpNoSuchUser,
        _ => CurlError::TftpIllegal,
    }
}

fn max_filesize_limit(transfer: &TransferConfig) -> Option<u64> {
    transfer.max_filesize.filter(|limit| *limit > 0)
}

fn limit_body_for_max_filesize<'a>(transfer: &TransferConfig, body: &'a [u8]) -> (&'a [u8], bool) {
    let Some(limit) = max_filesize_limit(transfer) else {
        return (body, false);
    };
    if body.len() as u64 <= limit {
        return (body, false);
    }

    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    (&body[..limit.min(body.len())], true)
}

fn check_http_content_length_max_filesize(
    transfer: &TransferConfig,
    headers: &reqwest::header::HeaderMap,
    ignore_body: bool,
) -> Result<()> {
    let Some(limit) = max_filesize_limit(transfer) else {
        return Ok(());
    };
    if ignore_body {
        return Ok(());
    }

    let Some(value) = headers.get(CONTENT_LENGTH) else {
        return Ok(());
    };
    let Ok(value) = value.to_str() else {
        return Ok(());
    };
    let Some(length) = parse_http_content_length_for_max_filesize(value) else {
        return Ok(());
    };
    if length > u128::from(limit) {
        return Err(CurlError::FileSizeExceeded);
    }
    Ok(())
}

fn parse_http_content_length_for_max_filesize(value: &str) -> Option<u128> {
    let value = value.trim();
    let value = value.split(',').next().unwrap_or(value).trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelnetRecvState {
    Data,
    Cr,
    Iac,
    Will,
    Wont,
    Do,
    Dont,
    Subnegotiation,
    SubnegotiationIac,
}

fn telnet_input(transfer: &TransferConfig) -> Result<Vec<u8>> {
    match transfer.upload_file.as_deref() {
        Some("-") | None => {
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes)?;
            Ok(bytes)
        }
        Some(path) => Ok(std::fs::read(path)?),
    }
}

fn telnet_escape_outgoing(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for byte in input {
        output.push(*byte);
        if *byte == TELNET_IAC {
            output.push(TELNET_IAC);
        }
    }
    output
}

fn telnet_process_incoming(
    input: &[u8],
    state: &mut TelnetRecvState,
    body: &mut Vec<u8>,
) -> Vec<u8> {
    let mut replies = Vec::new();

    for byte in input {
        match *state {
            TelnetRecvState::Data => match *byte {
                TELNET_IAC => *state = TelnetRecvState::Iac,
                b'\r' => {
                    body.push(*byte);
                    *state = TelnetRecvState::Cr;
                }
                _ => body.push(*byte),
            },
            TelnetRecvState::Cr => {
                *state = TelnetRecvState::Data;
                if *byte != 0 {
                    if *byte == TELNET_IAC {
                        *state = TelnetRecvState::Iac;
                    } else {
                        body.push(*byte);
                    }
                }
            }
            TelnetRecvState::Iac => match *byte {
                TELNET_WILL => *state = TelnetRecvState::Will,
                TELNET_WONT => *state = TelnetRecvState::Wont,
                TELNET_DO => *state = TelnetRecvState::Do,
                TELNET_DONT => *state = TelnetRecvState::Dont,
                TELNET_SB => *state = TelnetRecvState::Subnegotiation,
                TELNET_IAC => {
                    body.push(TELNET_IAC);
                    *state = TelnetRecvState::Data;
                }
                _ => *state = TelnetRecvState::Data,
            },
            TelnetRecvState::Will => {
                telnet_reply(&mut replies, TELNET_DONT, *byte);
                *state = TelnetRecvState::Data;
            }
            TelnetRecvState::Wont => {
                *state = TelnetRecvState::Data;
            }
            TelnetRecvState::Do => {
                telnet_reply(&mut replies, TELNET_WONT, *byte);
                *state = TelnetRecvState::Data;
            }
            TelnetRecvState::Dont => {
                *state = TelnetRecvState::Data;
            }
            TelnetRecvState::Subnegotiation => {
                if *byte == TELNET_IAC {
                    *state = TelnetRecvState::SubnegotiationIac;
                }
            }
            TelnetRecvState::SubnegotiationIac => {
                *state = if *byte == TELNET_SE {
                    TelnetRecvState::Data
                } else {
                    TelnetRecvState::Subnegotiation
                };
            }
        }
    }

    replies
}

fn telnet_reply(output: &mut Vec<u8>, command: u8, option: u8) {
    output.extend_from_slice(&[TELNET_IAC, command, option]);
}

fn dict_request(url: &Url) -> Result<Vec<u8>> {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let path = percent_decode(path.as_bytes()).collect::<Vec<_>>();
    if path.iter().any(|byte| *byte < 32) {
        return Err(CurlError::Url(
            "DICT path contains a decoded control byte".to_string(),
        ));
    }

    let command = if let Some(rest) = strip_dict_prefix(&path, &[b"/MATCH:", b"/M:", b"/FIND:"]) {
        dict_match_command(rest)
    } else if let Some(rest) = strip_dict_prefix(&path, &[b"/DEFINE:", b"/D:", b"/LOOKUP:"]) {
        dict_define_command(rest)
    } else {
        dict_generic_command(&path)
    };

    let mut request = Vec::new();
    request.extend_from_slice(
        format!("CLIENT curl-rust {}\r\n", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    request.extend_from_slice(&command);
    request.extend_from_slice(b"\r\nQUIT\r\n");
    Ok(request)
}

fn strip_dict_prefix<'a>(path: &'a [u8], prefixes: &[&[u8]]) -> Option<&'a [u8]> {
    prefixes.iter().find_map(|prefix| {
        path.get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
            .then_some(&path[prefix.len()..])
    })
}

fn dict_match_command(rest: &[u8]) -> Vec<u8> {
    let mut parts = rest.split(|byte| *byte == b':');
    let word = default_if_empty(parts.next(), b"default");
    let database = default_if_empty(parts.next(), b"!");
    let strategy = default_if_empty(parts.next(), b".");

    let mut command = Vec::from(&b"MATCH "[..]);
    command.extend_from_slice(database);
    command.push(b' ');
    command.extend_from_slice(strategy);
    command.push(b' ');
    command.extend_from_slice(&dict_escape_word(word));
    command
}

fn dict_define_command(rest: &[u8]) -> Vec<u8> {
    let mut parts = rest.split(|byte| *byte == b':');
    let word = default_if_empty(parts.next(), b"default");
    let database = default_if_empty(parts.next(), b"!");

    let mut command = Vec::from(&b"DEFINE "[..]);
    command.extend_from_slice(database);
    command.push(b' ');
    command.extend_from_slice(&dict_escape_word(word));
    command
}

fn dict_generic_command(path: &[u8]) -> Vec<u8> {
    let mut command = path.strip_prefix(b"/").unwrap_or(path).to_vec();
    for byte in &mut command {
        if *byte == b':' {
            *byte = b' ';
        }
    }
    command
}

fn default_if_empty<'a>(value: Option<&'a [u8]>, default: &'a [u8]) -> &'a [u8] {
    value.filter(|value| !value.is_empty()).unwrap_or(default)
}

fn dict_escape_word(word: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(word.len());
    for byte in word {
        if *byte <= 32 || *byte == 127 || matches!(*byte, b'\'' | b'"' | b'\\') {
            escaped.push(b'\\');
        }
        escaped.push(*byte);
    }
    escaped
}

fn gopher_selector(url: &Url) -> Result<Vec<u8>> {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let gopher_path = if let Some(query) = url.query() {
        format!("{path}?{query}")
    } else {
        path.to_string()
    };

    if gopher_path.len() <= 2 {
        return Ok(Vec::new());
    }

    let decoded = percent_decode(&gopher_path.as_bytes()[2..]).collect::<Vec<_>>();
    if decoded.contains(&0) {
        return Err(CurlError::Url(
            "gopher selector contains a decoded NUL byte".to_string(),
        ));
    }
    Ok(decoded)
}

async fn run_http_transfer(
    transfer: &TransferConfig,
    client: &Client,
    expanded: &glob::ExpandedUrl,
    method: Method,
    metrics: &mut writeout::Metrics,
) -> Result<HttpAttempt> {
    let prepared_query = data::prepare_body(&transfer.url_query)?;
    let prepared_body = data::prepare_body(&transfer.data)?;
    let upload_body = transfer
        .upload_file
        .as_deref()
        .map(data::read_upload_body)
        .transpose()?;
    let has_multipart = !transfer.forms.is_empty();
    if prepared_body.is_some() && has_multipart {
        return Err(CurlError::Usage(
            "--form cannot be combined with --data or --json".to_string(),
        ));
    }
    if prepared_body.is_some() && transfer.continue_at.is_some() {
        return Err(CurlError::Usage(
            "--continue-at cannot be combined with --data or --json".to_string(),
        ));
    }
    if upload_body.is_some() && prepared_body.is_some() {
        return Err(CurlError::Usage(
            "--upload-file cannot be combined with --data or --json".to_string(),
        ));
    }
    if upload_body.is_some() && has_multipart {
        return Err(CurlError::Usage(
            "--upload-file cannot be combined with --form".to_string(),
        ));
    }
    if transfer.get && has_multipart {
        return Err(CurlError::Usage(
            "--get cannot be combined with --form".to_string(),
        ));
    }
    if transfer.get && upload_body.is_some() {
        return Err(CurlError::Usage(
            "--get cannot be combined with --upload-file".to_string(),
        ));
    }
    let mut url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    data::append_upload_filename_to_url(&mut url, transfer.upload_file.as_deref());
    output::validate_output_target(transfer, &url)?;
    let resume_from = resume_offset(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
    )?;

    if let Some(query) = prepared_query.as_ref().filter(|query| !query.is_empty()) {
        append_query_body(&mut url, &query.bytes);
    }

    if transfer.get
        && let Some(body) = prepared_body.as_ref().filter(|body| !body.is_empty())
    {
        append_query_body(&mut url, &body.bytes);
    }

    let custom_referer = explicit_header_value(&transfer.headers, "referer")?;
    let mut current_referer = if custom_referer.is_some() {
        None
    } else {
        transfer.referer.clone()
    };
    let mut redirects = 0usize;

    loop {
        let multipart = data::prepare_multipart(&transfer.forms)?;
        let mut request = client.request(method.clone(), url.clone());
        request = apply_version(request, transfer, &url);
        request = apply_headers(
            request,
            transfer,
            prepared_body.as_ref(),
            resume_from,
            current_referer.as_deref(),
        )?;
        request = apply_auth(request, transfer);

        if let Some(form) = multipart {
            request = request.multipart(form);
        } else if let Some(body) = upload_body.as_ref() {
            request = request
                .header(CONTENT_LENGTH, body.len())
                .body(body.clone());
        } else if !transfer.get
            && let Some(body) = prepared_body.as_ref()
        {
            request = request
                .header(CONTENT_LENGTH, body.bytes.len())
                .body(body.bytes.clone());
        }

        if transfer.verbose {
            eprintln!("> {} {}", method.as_str(), url);
        }

        let response = request.send().await.transfer_err()?;
        let status = response.status();
        let version = response.version();
        let final_url = response.url().clone();
        let headers = response.headers().clone();

        if transfer.verbose {
            eprintln!("< {}", status_line(version, status));
            for (name, value) in &headers {
                eprintln!("< {}: {}", name, String::from_utf8_lossy(value.as_bytes()));
            }
        }

        if transfer.auto_referer
            && transfer.follow_location
            && is_followed_redirect(status)
            && let Some(next_url) = redirect_location(&final_url, &headers)?
        {
            if redirects >= transfer.max_redirs {
                metrics.url_effective = final_url.to_string();
                metrics.response_code = Some(status.as_u16());
                metrics.referer = custom_referer.clone().or_else(|| current_referer.clone());
                metrics.redirect_url = Some(next_url.to_string());
                metrics.headers = headers;
                return Err(CurlError::TooManyRedirects {
                    max: transfer.max_redirs,
                });
            }

            response.bytes().await.transfer_err()?;
            if custom_referer.is_none() {
                current_referer = Some(auto_referer_value(&final_url));
            }
            url = next_url;
            redirects += 1;
            continue;
        }

        metrics.url_effective = final_url.to_string();
        metrics.response_code = Some(status.as_u16());
        metrics.referer = custom_referer.clone().or_else(|| current_referer.clone());
        metrics.content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        metrics.redirect_url = headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        metrics.headers = headers.clone();

        check_http_content_length_max_filesize(transfer, &headers, method == Method::HEAD)?;

        let body = if method == Method::HEAD {
            Vec::new()
        } else {
            response.bytes().await.transfer_err()?.to_vec()
        };
        metrics.size_download = body.len() as u64;
        let retry_after = retry_after_delay(&headers);

        return Ok(HttpAttempt {
            status,
            version,
            final_url,
            headers,
            body,
            retry_after,
            resume_from,
        });
    }
}

async fn run_http_with_retries(
    transfer: &TransferConfig,
    client: &Client,
    expanded: &glob::ExpandedUrl,
    method: Method,
    metrics: &mut writeout::Metrics,
    retry_started: Instant,
) -> Result<()> {
    loop {
        reset_attempt_metrics(metrics);

        match run_http_transfer(transfer, client, expanded, method.clone(), metrics).await {
            Ok(attempt) => {
                if should_retry_http_attempt(transfer, &attempt)
                    && retry_delay_for_next(transfer, metrics, retry_started, attempt.retry_after)
                        .is_some()
                {
                    if transfer.fail_with_body && is_http_error_status(attempt.status) {
                        let _ = write_http_attempt_output(
                            transfer, expanded, &method, metrics, &attempt, false,
                        )?;
                    }
                    schedule_retry(transfer, metrics, retry_started, attempt.retry_after).await;
                    continue;
                }
                return finish_http_transfer(transfer, expanded, method, metrics, attempt);
            }
            Err(error) => {
                if should_retry_transfer_error(transfer, &error)
                    && schedule_retry(transfer, metrics, retry_started, None).await
                {
                    continue;
                }
                return Err(error);
            }
        }
    }
}

fn reset_attempt_metrics(metrics: &mut writeout::Metrics) {
    metrics.response_code = None;
    metrics.size_download = 0;
    metrics.content_type = None;
    metrics.filename_effective = None;
    metrics.exit_code = 0;
    metrics.errormsg.clear();
    metrics.redirect_url = None;
    metrics.referer = None;
    metrics.headers = reqwest::header::HeaderMap::new();
}

fn finish_http_transfer(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: Method,
    metrics: &mut writeout::Metrics,
    attempt: HttpAttempt,
) -> Result<()> {
    let max_filesize_exceeded =
        write_http_attempt_output(transfer, expanded, &method, metrics, &attempt, true)?;
    if max_filesize_exceeded {
        return Err(CurlError::FileSizeExceeded);
    }

    if transfer.fail && is_http_error_status(attempt.status) {
        return Err(CurlError::HttpStatus {
            status: attempt.status.as_u16(),
        });
    }

    Ok(())
}

fn write_http_attempt_output(
    transfer: &TransferConfig,
    expanded: &glob::ExpandedUrl,
    method: &Method,
    metrics: &mut writeout::Metrics,
    attempt: &HttpAttempt,
    persist_headers: bool,
) -> Result<bool> {
    let header_bytes = output::render_headers(attempt.version, attempt.status, &attempt.headers);
    if persist_headers && let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &header_bytes, transfer.create_dirs)?;
    }
    if persist_headers && let Some(path) = &transfer.etag_save {
        save_etag(path, &attempt.headers, transfer.create_dirs)?;
    }

    let is_error = is_http_error_status(attempt.status);
    let write_headers = transfer.include_headers || transfer.head;
    let write_body =
        method.as_str() != "HEAD" && (!is_error || !transfer.fail || transfer.fail_with_body);
    let (body_bytes, max_filesize_exceeded) = if write_body {
        limit_body_for_max_filesize(transfer, &attempt.body)
    } else {
        (&[][..], false)
    };
    metrics.size_download = body_bytes.len() as u64;

    if write_headers || write_body {
        let mut bytes = Vec::new();
        if write_headers {
            bytes.extend_from_slice(&header_bytes);
        }
        if write_body {
            bytes.extend_from_slice(body_bytes);
        }
        let filename = output::write_response(
            transfer,
            &attempt.final_url,
            &attempt.headers,
            &expanded.variables,
            &bytes,
            attempt.resume_from > 0,
        )?;
        metrics.filename_effective = filename.map(|path| path.display().to_string());
    }

    Ok(max_filesize_exceeded)
}

async fn schedule_retry(
    transfer: &TransferConfig,
    metrics: &mut writeout::Metrics,
    retry_started: Instant,
    retry_after: Option<Duration>,
) -> bool {
    let Some((next_retry, delay)) =
        retry_delay_for_next(transfer, metrics, retry_started, retry_after)
    else {
        return false;
    };

    metrics.num_retries = next_retry;
    if delay > Duration::ZERO {
        tokio::time::sleep(delay).await;
    }
    true
}

fn retry_delay_for_next(
    transfer: &TransferConfig,
    metrics: &writeout::Metrics,
    retry_started: Instant,
    retry_after: Option<Duration>,
) -> Option<(usize, Duration)> {
    if metrics.num_retries >= transfer.retry {
        return None;
    }

    let next_retry = metrics.num_retries + 1;
    let delay = retry_after.unwrap_or_else(|| retry_delay(transfer, next_retry));
    retry_within_max_time(transfer, retry_started, delay).then_some((next_retry, delay))
}

fn is_http_error_status(status: StatusCode) -> bool {
    status.is_client_error() || status.is_server_error()
}

fn should_retry_http_attempt(transfer: &TransferConfig, attempt: &HttpAttempt) -> bool {
    if is_retryable_http_status(attempt.status) {
        return true;
    }

    transfer.retry_all_errors
        && transfer.fail
        && (attempt.status.is_client_error() || attempt.status.is_server_error())
}

fn should_retry_transfer_error(transfer: &TransferConfig, error: &CurlError) -> bool {
    let CurlError::Transfer(message) = error else {
        return false;
    };

    if transfer.retry_all_errors {
        return true;
    }

    let message = message.to_ascii_lowercase();
    message.contains("timed out")
        || message.contains("timeout")
        || message.contains("resolve")
        || message.contains("dns")
        || message.contains("failed to lookup")
        || (transfer.retry_connrefused
            && (message.contains("connection refused")
                || message.contains("os error 111")
                || message.contains("refused")))
}

fn is_retryable_http_status(status: StatusCode) -> bool {
    matches!(
        status.as_u16(),
        408 | 429 | 500 | 502 | 503 | 504 | 522 | 524
    )
}

fn retry_delay(transfer: &TransferConfig, retry_number: usize) -> Duration {
    if transfer.retry_delay > Duration::ZERO {
        return transfer.retry_delay;
    }

    let exponent = retry_number.saturating_sub(1);
    Duration::from_secs((1_u64 << exponent.min(10)).min(600))
}

fn retry_within_max_time(
    transfer: &TransferConfig,
    retry_started: Instant,
    delay: Duration,
) -> bool {
    if transfer.retry_max_time == Duration::ZERO {
        return true;
    }

    retry_started
        .elapsed()
        .checked_add(delay)
        .is_some_and(|elapsed_after_delay| elapsed_after_delay <= transfer.retry_max_time)
}

fn retry_after_delay(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<f64>()
        && seconds.is_finite()
        && !seconds.is_sign_negative()
        && seconds <= u64::MAX as f64
    {
        return Some(Duration::from_secs_f64(seconds));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    retry_at.duration_since(std::time::SystemTime::now()).ok()
}

fn effective_method_label(transfer: &TransferConfig) -> String {
    if let Some(method) = &transfer.method {
        return method.clone();
    }

    if transfer.head {
        return Method::HEAD.as_str().to_string();
    }

    if (!transfer.data.is_empty() || !transfer.forms.is_empty()) && !transfer.get {
        return Method::POST.as_str().to_string();
    }

    Method::GET.as_str().to_string()
}

fn effective_http_method(transfer: &TransferConfig) -> Result<Method> {
    if let Some(method) = &transfer.method {
        return Method::from_bytes(method.as_bytes())
            .map_err(|error| CurlError::Usage(format!("invalid method {method:?}: {error}")));
    }

    if transfer.head {
        return Ok(Method::HEAD);
    }

    if (!transfer.data.is_empty() || !transfer.forms.is_empty()) && !transfer.get {
        return Ok(Method::POST);
    }

    Ok(Method::GET)
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn apply_version(
    request: reqwest::RequestBuilder,
    transfer: &TransferConfig,
    url: &Url,
) -> reqwest::RequestBuilder {
    match transfer.http_version {
        HttpVersionPreference::Http10 => request.version(Version::HTTP_10),
        HttpVersionPreference::Http11 => request.version(Version::HTTP_11),
        HttpVersionPreference::Http2 if url.scheme() == "https" => request.version(Version::HTTP_2),
        HttpVersionPreference::Http2PriorKnowledge => request.version(Version::HTTP_2),
        HttpVersionPreference::Http2 => request,
        HttpVersionPreference::Any => request,
    }
}

fn apply_headers(
    mut request: reqwest::RequestBuilder,
    transfer: &TransferConfig,
    body: Option<&PreparedBody>,
    resume_from: u64,
    referer: Option<&str>,
) -> Result<reqwest::RequestBuilder> {
    let parsed_headers = parse_headers(&transfer.headers)?;
    let has_accept = parsed_headers
        .iter()
        .any(|(name, _)| name.as_str().eq_ignore_ascii_case("accept"));
    let has_content_type = parsed_headers
        .iter()
        .any(|(name, _)| name.as_str().eq_ignore_ascii_case("content-type"));
    let has_referer = parsed_headers
        .iter()
        .any(|(name, _)| name.as_str().eq_ignore_ascii_case("referer"));

    request = request.header(
        USER_AGENT,
        transfer
            .user_agent
            .as_deref()
            .unwrap_or(concat!("curl-rust/", env!("CARGO_PKG_VERSION"))),
    );

    if transfer.compressed {
        request = request.header(ACCEPT_ENCODING, "deflate, gzip, br");
    }

    if let Some(cookie) = &transfer.cookie
        && !cookie_engine_active(transfer)
    {
        request = request.header(COOKIE, cookie);
    }

    if let Some(token) = &transfer.oauth2_bearer {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }

    if let Some(path) = &transfer.etag_compare {
        request = request.header(IF_NONE_MATCH, load_etag_compare(path)?);
    }

    if let Some(time_cond) = &transfer.time_cond {
        let (name, value) = time_condition_header(time_cond);
        request = request.header(name, value);
    }

    if let Some(referer) = referer
        && !has_referer
    {
        request = request.header(REFERER, referer);
    }

    if let Some(range) = effective_range(transfer, resume_from) {
        request = request.header(RANGE, range_header_value(&range));
    }

    if body.is_some_and(|body| body.is_json) {
        if !has_content_type {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        if !has_accept {
            request = request.header(ACCEPT, "application/json");
        }
    }

    for (name, value) in parsed_headers {
        request = request.header(name, value);
    }

    Ok(request)
}

fn is_followed_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn redirect_location(
    current_url: &Url,
    headers: &reqwest::header::HeaderMap,
) -> Result<Option<Url>> {
    let Some(location) = headers.get(LOCATION) else {
        return Ok(None);
    };
    let location = location
        .to_str()
        .map_err(|error| CurlError::Transfer(format!("redirect Location is not UTF-8: {error}")))?;
    current_url
        .join(location)
        .map(Some)
        .map_err(|error| CurlError::Url(error.to_string()))
}

fn auto_referer_value(previous: &Url) -> String {
    let mut referer = previous.clone();
    let _ = referer.set_username("");
    let _ = referer.set_password(None);
    referer.set_fragment(None);
    referer.to_string()
}

fn parse_headers(headers: &[String]) -> Result<Vec<(HeaderName, HeaderValue)>> {
    let mut parsed = Vec::new();
    for header in headers {
        if let Some(path) = header.strip_prefix('@') {
            let text = std::fs::read_to_string(path)?;
            for line in text.lines().filter(|line| !line.trim().is_empty()) {
                parsed.push(parse_header(line)?);
            }
        } else {
            parsed.push(parse_header(header)?);
        }
    }
    Ok(parsed)
}

fn explicit_header_value(headers: &[String], name: &str) -> Result<Option<String>> {
    Ok(parse_headers(headers)?
        .into_iter()
        .rev()
        .find(|(header_name, _)| header_name.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.to_str().ok().map(ToString::to_string)))
}

fn parse_header(header: &str) -> Result<(HeaderName, HeaderValue)> {
    let Some((name, value)) = header.split_once(':') else {
        return Err(CurlError::Usage(format!(
            "header {header:?} is missing ':'"
        )));
    };
    let name = HeaderName::from_bytes(name.trim().as_bytes())
        .map_err(|error| CurlError::Usage(format!("bad header name {name:?}: {error}")))?;
    let value = HeaderValue::from_str(value.trim_start())
        .map_err(|error| CurlError::Usage(format!("bad header value for {name}: {error}")))?;
    Ok((name, value))
}

fn apply_auth(
    request: reqwest::RequestBuilder,
    transfer: &TransferConfig,
) -> reqwest::RequestBuilder {
    let Some(user) = &transfer.user else {
        return request;
    };

    if transfer.oauth2_bearer.is_some() {
        return request;
    }

    let (login, password) = split_user_password(user);
    request.basic_auth(login.to_string(), Some(password.to_string()))
}

fn split_user_password(value: &str) -> (&str, &str) {
    value.split_once(':').unwrap_or((value, ""))
}

fn load_etag_compare(path: &Path) -> Result<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let etag = text.lines().next().unwrap_or("").trim();
    if etag.is_empty() {
        Ok("\"\"".to_string())
    } else {
        Ok(etag.to_string())
    }
}

fn time_condition_header(value: &str) -> (HeaderName, &str) {
    value
        .strip_prefix('-')
        .map_or((IF_MODIFIED_SINCE, value), |value| {
            (IF_UNMODIFIED_SINCE, value.trim_start())
        })
}

fn save_etag(path: &Path, headers: &reqwest::header::HeaderMap, create_dirs: bool) -> Result<()> {
    if create_dirs
        && let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut text = headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    if !text.is_empty() {
        text.push('\n');
    }
    std::fs::write(path, text)?;
    Ok(())
}

fn append_query_body(url: &mut Url, body: &[u8]) {
    let body = String::from_utf8_lossy(body);
    let mut query = url.query().unwrap_or("").to_string();
    if !query.is_empty() && !body.is_empty() {
        query.push('&');
    }
    query.push_str(&body);
    url.set_query(Some(&query));
}

fn resume_offset(
    transfer: &TransferConfig,
    url: &Url,
    headers: &reqwest::header::HeaderMap,
    variables: &[String],
) -> Result<u64> {
    let Some(continue_at) = transfer.continue_at else {
        return Ok(0);
    };

    match continue_at {
        ContinueAt::Offset(offset) => Ok(offset),
        ContinueAt::Auto => {
            let Some(path) = output::output_path(transfer, url, headers, variables)? else {
                return Ok(0);
            };
            match std::fs::metadata(path) {
                Ok(metadata) => Ok(metadata.len()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
                Err(error) => Err(error.into()),
            }
        }
    }
}

fn effective_range(transfer: &TransferConfig, resume_from: u64) -> Option<String> {
    if resume_from > 0 {
        Some(format!("{resume_from}-"))
    } else {
        transfer.range.clone()
    }
}

fn range_header_value(range: &str) -> String {
    if range
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bytes="))
    {
        range.to_string()
    } else {
        format!("bytes={range}")
    }
}

fn apply_file_range(bytes: Vec<u8>, range: Option<&str>) -> Result<Vec<u8>> {
    let Some(range) = range else {
        return Ok(bytes);
    };
    let range = range
        .strip_prefix("bytes=")
        .or_else(|| range.strip_prefix("BYTES="))
        .unwrap_or(range);
    if range.contains(',') {
        return Err(CurlError::Unsupported(
            "multipart ranges for file:// URLs".to_string(),
        ));
    }

    let Some((start, end)) = range.split_once('-') else {
        return Err(CurlError::Usage(format!("bad range {range:?}")));
    };
    let len = bytes.len();
    let (start, end_exclusive) = if start.is_empty() {
        let suffix = end
            .parse::<usize>()
            .map_err(|_| CurlError::Usage(format!("bad range {range:?}")))?;
        let start = len.saturating_sub(suffix);
        (start, len)
    } else {
        let start = start
            .parse::<usize>()
            .map_err(|_| CurlError::Usage(format!("bad range {range:?}")))?;
        let end_exclusive = if end.is_empty() {
            len
        } else {
            end.parse::<usize>()
                .map_err(|_| CurlError::Usage(format!("bad range {range:?}")))?
                .saturating_add(1)
                .min(len)
        };
        (start.min(len), end_exclusive)
    };

    if start >= end_exclusive {
        return Ok(Vec::new());
    }
    Ok(bytes[start..end_exclusive].to_vec())
}

fn report_error(transfer: &TransferConfig, error: &CurlError) {
    if !transfer.silent || transfer.show_error {
        eprintln!("curl: ({}) {error}", error.exit_code());
    }
}

fn write_writeout(transfer: &TransferConfig, metrics: &writeout::Metrics) -> Result<()> {
    if let Some(format) = &transfer.write_out {
        print!("{}", writeout::render(format, metrics));
    }
    Ok(())
}

fn status_line(version: Version, status: StatusCode) -> String {
    let version = match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    };
    format!(
        "{version} {} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
}
