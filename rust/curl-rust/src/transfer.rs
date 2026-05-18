use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use percent_encoding::percent_decode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ETAG, HeaderName,
    HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE, LOCATION, RANGE, REFERER,
    RETRY_AFTER, USER_AGENT,
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
    let mut method = effective_method(transfer)?;
    let mut metrics = writeout::Metrics::empty(&expanded.url, method.as_str());
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
        method = Method::PUT;
        metrics.method = method.as_str().to_string();
    }

    let result = if expanded.url.starts_with("file://") {
        run_file_transfer(transfer, &expanded, method.as_str(), &mut metrics).await
    } else if expanded.url.starts_with("dict://") {
        run_dict_transfer(transfer, &expanded, method.as_str(), &mut metrics).await
    } else if expanded.url.starts_with("gopher://") {
        run_gopher_transfer(transfer, &expanded, method.as_str(), &mut metrics).await
    } else if expanded.url.starts_with("gophers://") {
        Err(CurlError::Unsupported(
            "gophers:// URLs are not implemented in the Rust sidecar".to_string(),
        ))
    } else if expanded.url.starts_with("telnet://") {
        run_telnet_transfer(transfer, &expanded, method.as_str(), &mut metrics).await
    } else {
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
    let modified = url
        .to_file_path()
        .ok()
        .and_then(|path| std::fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok());
    let header_size = if method == "HEAD" {
        metadata_size
    } else {
        body.len() as u64
    };
    let headers = output::file_headers(header_size, modified);
    let header_bytes = output::render_file_headers(&headers);
    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &header_bytes, transfer.create_dirs)?;
    }
    metrics.url_effective = expanded.url.clone();
    metrics.response_code = Some(200);
    metrics.size_download = body.len() as u64;
    metrics.headers = headers.clone();

    let mut bytes = Vec::new();
    if transfer.include_headers || method == "HEAD" {
        bytes.extend_from_slice(&header_bytes);
    }
    if method != "HEAD" {
        bytes.extend_from_slice(&body);
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
    metrics.url_effective = url.to_string();
    metrics.size_download = body.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let mut bytes = Vec::new();
    if method != "HEAD" {
        bytes.extend_from_slice(&body);
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
    Ok(())
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
    metrics.size_download = body.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &[], transfer.create_dirs)?;
    }

    let bytes = if method == "HEAD" { &[][..] } else { &body };
    let filename = output::write_response(
        transfer,
        &url,
        &reqwest::header::HeaderMap::new(),
        &expanded.variables,
        bytes,
        false,
    )?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    Ok(())
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
    metrics.size_download = body.len() as u64;

    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &header_bytes, transfer.create_dirs)?;
    }

    let mut bytes = Vec::new();
    if method != "HEAD" {
        bytes.extend_from_slice(&body);
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
                        write_http_attempt_output(
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
    write_http_attempt_output(transfer, expanded, &method, metrics, &attempt, true)?;

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
) -> Result<()> {
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
    metrics.size_download = if write_body {
        attempt.body.len() as u64
    } else {
        0
    };

    if write_headers || write_body {
        let mut bytes = Vec::new();
        if write_headers {
            bytes.extend_from_slice(&header_bytes);
        }
        if write_body {
            bytes.extend_from_slice(&attempt.body);
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

    Ok(())
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

fn effective_method(transfer: &TransferConfig) -> Result<Method> {
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
