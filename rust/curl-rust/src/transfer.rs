use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use percent_encoding::percent_decode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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
const TFTP_DEFAULT_BLKSIZE: u16 = 512;
const TFTP_MAX_PACKET_SIZE: usize = 65_468;
const IMAP_DEFAULT_PORT: u16 = 143;
const MQTT_DEFAULT_PORT: u16 = 1883;
const RTSP_DEFAULT_PORT: u16 = 554;
const MQTT_CLIENT_ID: &[u8; 12] = b"curlrust0000";
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
