use std::path::Path;
use std::time::Instant;

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ETAG, HeaderName,
    HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE, LOCATION, RANGE, REFERER,
    USER_AGENT,
};
use reqwest::{Client, Method, StatusCode, Url, Version};

use crate::cli::{Config, HttpVersionPreference, TransferConfig};
use crate::data::{self, PreparedBody};
use crate::error::{CurlError, Result, ResultExt};
use crate::{glob, output, writeout};

pub async fn run(config: Config) -> Result<i32> {
    let mut final_code = 0;

    for transfer in &config.transfers {
        let client = build_client(transfer)?;
        let expanded_urls = expand_urls(transfer)?;

        for expanded in expanded_urls {
            let code = run_expanded_url(transfer, &client, expanded).await?;
            if code != 0 {
                final_code = code;
            }
        }
    }

    Ok(final_code)
}

fn expand_urls(transfer: &TransferConfig) -> Result<Vec<glob::ExpandedUrl>> {
    let mut expanded = Vec::new();
    for url in &transfer.urls {
        expanded.extend(glob::expand_url(url, transfer.globoff)?);
    }
    Ok(expanded)
}

fn build_client(transfer: &TransferConfig) -> Result<Client> {
    let redirect = if transfer.follow_location {
        reqwest::redirect::Policy::limited(transfer.max_redirs)
    } else {
        reqwest::redirect::Policy::none()
    };

    let mut builder = Client::builder()
        .redirect(redirect)
        .danger_accept_invalid_certs(transfer.insecure);

    if !transfer.compressed {
        builder = builder.no_gzip().no_brotli().no_deflate();
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
    let method = effective_method(transfer)?;
    let mut metrics = writeout::Metrics::empty(&expanded.url, method.as_str());
    let started = Instant::now();

    let result = if expanded.url.starts_with("file://") {
        run_file_transfer(transfer, &expanded, method.as_str(), &mut metrics).await
    } else {
        run_http_transfer(transfer, client, &expanded, method, &mut metrics).await
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

    let url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    let path = url
        .to_file_path()
        .map_err(|_| CurlError::Url("file URL cannot be converted to a local path".to_string()))?;
    let metadata_size = std::fs::metadata(&path)?.len();
    let body = if method == "HEAD" {
        Vec::new()
    } else {
        std::fs::read(path)?
    };
    let body = if method == "HEAD" {
        body
    } else {
        apply_file_range(body, transfer.range.as_deref())?
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

    let output_url =
        Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &output_url)?;
    let mut bytes = Vec::new();
    if transfer.include_headers || method == "HEAD" {
        bytes.extend_from_slice(&header_bytes);
    }
    if method != "HEAD" {
        bytes.extend_from_slice(&body);
    }
    let filename =
        output::write_response(transfer, &output_url, &headers, &expanded.variables, &bytes)?;
    metrics.filename_effective = filename.map(|path| path.display().to_string());
    Ok(())
}

async fn run_http_transfer(
    transfer: &TransferConfig,
    client: &Client,
    expanded: &glob::ExpandedUrl,
    method: Method,
    metrics: &mut writeout::Metrics,
) -> Result<()> {
    let prepared_query = data::prepare_body(&transfer.url_query)?;
    let prepared_body = data::prepare_body(&transfer.data)?;
    let multipart = data::prepare_multipart(&transfer.forms)?;
    if prepared_body.is_some() && multipart.is_some() {
        return Err(CurlError::Usage(
            "--form cannot be combined with --data or --json".to_string(),
        ));
    }
    if transfer.get && multipart.is_some() {
        return Err(CurlError::Usage(
            "--get cannot be combined with --form".to_string(),
        ));
    }
    let mut url = Url::parse(&expanded.url).map_err(|error| CurlError::Url(error.to_string()))?;
    output::validate_output_target(transfer, &url)?;

    if let Some(query) = prepared_query.as_ref().filter(|query| !query.is_empty()) {
        append_query_body(&mut url, &query.bytes);
    }

    if transfer.get
        && let Some(body) = prepared_body.as_ref().filter(|body| !body.is_empty())
    {
        append_query_body(&mut url, &body.bytes);
    }

    let mut request = client.request(method.clone(), url.clone());
    request = apply_version(request, transfer, &url);
    request = apply_headers(request, transfer, prepared_body.as_ref())?;
    request = apply_auth(request, transfer);

    if let Some(form) = multipart {
        request = request.multipart(form);
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
    metrics.url_effective = final_url.to_string();
    metrics.response_code = Some(status.as_u16());
    metrics.content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    metrics.redirect_url = headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    metrics.headers = headers.clone();

    if transfer.verbose {
        eprintln!("< {}", status_line(version, status));
        for (name, value) in &headers {
            eprintln!("< {}: {}", name, String::from_utf8_lossy(value.as_bytes()));
        }
    }

    let header_bytes = output::render_headers(version, status, &headers);
    if let Some(path) = &transfer.dump_header {
        output::dump_headers(path, &header_bytes, transfer.create_dirs)?;
    }
    if let Some(path) = &transfer.etag_save {
        save_etag(path, &headers, transfer.create_dirs)?;
    }

    let body = if method == Method::HEAD {
        Vec::new()
    } else {
        response.bytes().await.transfer_err()?.to_vec()
    };
    metrics.size_download = body.len() as u64;

    let should_write_body =
        !transfer.fail || !status.is_client_error() && !status.is_server_error();
    let should_write_fail_body =
        transfer.fail_with_body && (status.is_client_error() || status.is_server_error());

    if should_write_body || should_write_fail_body {
        let mut bytes = Vec::new();
        if transfer.include_headers || transfer.head {
            bytes.extend_from_slice(&header_bytes);
        }
        if method != Method::HEAD {
            bytes.extend_from_slice(&body);
        }
        let filename =
            output::write_response(transfer, &final_url, &headers, &expanded.variables, &bytes)?;
        metrics.filename_effective = filename.map(|path| path.display().to_string());
    }

    if transfer.fail && (status.is_client_error() || status.is_server_error()) {
        return Err(CurlError::HttpStatus {
            status: status.as_u16(),
        });
    }

    Ok(())
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
) -> Result<reqwest::RequestBuilder> {
    let parsed_headers = parse_headers(&transfer.headers)?;
    let has_accept = parsed_headers
        .iter()
        .any(|(name, _)| name.as_str().eq_ignore_ascii_case("accept"));
    let has_content_type = parsed_headers
        .iter()
        .any(|(name, _)| name.as_str().eq_ignore_ascii_case("content-type"));

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

    if let Some(cookie) = &transfer.cookie {
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

    if let Some(referer) = &transfer.referer {
        request = request.header(REFERER, referer);
    }

    if let Some(range) = &transfer.range {
        request = request.header(RANGE, range_header_value(range));
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
