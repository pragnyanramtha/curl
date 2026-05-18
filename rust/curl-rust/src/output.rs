use std::fs::OpenOptions;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use reqwest::header::{
    ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_LENGTH, HeaderMap, HeaderValue, LAST_MODIFIED,
};
use reqwest::{StatusCode, Version};
use url::Url;

use crate::cli::TransferConfig;
use crate::error::Result;
use crate::glob;

pub fn render_headers(version: Version, status: StatusCode, headers: &HeaderMap) -> Vec<u8> {
    let mut output = Vec::new();
    let version = match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    };
    let reason = status.canonical_reason().unwrap_or("");
    output.extend_from_slice(format!("{version} {} {reason}\r\n", status.as_u16()).as_bytes());
    for (name, value) in headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output
}

pub fn render_file_headers(headers: &HeaderMap) -> Vec<u8> {
    let mut output = Vec::new();
    for (name, value) in headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output
}

pub fn write_response(
    transfer: &TransferConfig,
    url: &Url,
    headers: &HeaderMap,
    variables: &[String],
    bytes: &[u8],
    append: bool,
) -> Result<Option<PathBuf>> {
    let path = output_path(transfer, url, headers, variables)?;
    match path {
        Some(path) => {
            let is_header_filename_output = transfer.remote_name
                && transfer.remote_header_name
                && remote_header_filename(headers).is_some();
            if transfer.create_dirs
                && let Some(parent) = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            if append {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?
                    .write_all(bytes)?;
            } else if is_header_filename_output {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?
                    .write_all(bytes)?;
            } else {
                std::fs::write(&path, bytes)?;
            }
            Ok(Some(path))
        }
        None => {
            io::stdout().write_all(bytes)?;
            Ok(None)
        }
    }
}

pub fn validate_output_target(transfer: &TransferConfig, url: &Url) -> Result<()> {
    if transfer.remote_name && !transfer.remote_header_name {
        remote_url_filename(url)?;
    }
    Ok(())
}

pub fn file_headers(size: u64, modified: Option<std::time::SystemTime>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&size.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(modified) = modified
        && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(modified))
    {
        headers.insert(LAST_MODIFIED, value);
    }
    headers
}

pub fn dump_headers(path: &Path, bytes: &[u8], create_dirs: bool) -> Result<()> {
    if path == Path::new("-") {
        io::stdout().write_all(bytes)?;
        return Ok(());
    }

    if create_dirs
        && let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

pub fn prepare_dump_header_target(path: &Path, create_dirs: bool) -> Result<()> {
    if path == Path::new("-") {
        return Ok(());
    }

    if create_dirs
        && let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    Ok(())
}

pub fn output_path(
    transfer: &TransferConfig,
    url: &Url,
    headers: &HeaderMap,
    variables: &[String],
) -> Result<Option<PathBuf>> {
    if let Some(output) = &transfer.output {
        if output == "-" {
            return Ok(None);
        }
        let expanded = glob::apply_output_variables(output, variables);
        return Ok(Some(apply_output_dir(transfer, PathBuf::from(expanded))));
    }

    if transfer.remote_name {
        let filename = if transfer.remote_header_name {
            match remote_header_filename(headers) {
                Some(filename) => filename,
                None => remote_url_filename(url)?,
            }
        } else {
            remote_url_filename(url)?
        };
        return Ok(Some(apply_output_dir(transfer, PathBuf::from(filename))));
    }

    Ok(None)
}

fn apply_output_dir(transfer: &TransferConfig, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }

    transfer
        .output_dir
        .as_ref()
        .map_or(path.clone(), |dir| dir.join(path))
}

fn remote_url_filename(url: &Url) -> Result<String> {
    let Some(filename) = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
    else {
        return Err(
            io::Error::new(ErrorKind::InvalidInput, "remote filename has no length").into(),
        );
    };
    Ok(filename)
}

fn remote_header_filename(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CONTENT_DISPOSITION)?.to_str().ok()?;
    parse_content_disposition_filename(value)
}

fn parse_content_disposition_filename(value: &str) -> Option<String> {
    for part in value.split(';').map(str::trim) {
        let Some(raw) = part.strip_prefix("filename=") else {
            continue;
        };
        let trimmed = raw.trim_matches('"');
        if !trimmed.is_empty() && !trimmed.contains('/') && !trimmed.contains('\\') {
            return Some(trimmed.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    #[test]
    fn renders_http_status_and_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", HeaderValue::from_static("ok"));
        let rendered = render_headers(Version::HTTP_11, StatusCode::OK, &headers);
        let rendered = String::from_utf8(rendered).unwrap();

        assert!(rendered.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(rendered.contains("x-test: ok\r\n"));
    }

    #[test]
    fn renders_file_headers_without_http_status_line() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
        let rendered = render_file_headers(&headers);
        let rendered = String::from_utf8(rendered).unwrap();

        assert_eq!(rendered, "content-length: 5\r\n\r\n");
    }

    #[test]
    fn parses_remote_header_filename() {
        assert_eq!(
            parse_content_disposition_filename("attachment; filename=\"archive.bin\""),
            Some("archive.bin".to_string())
        );
        assert_eq!(
            parse_content_disposition_filename("attachment; filename=\"../bad\""),
            None
        );
    }

    #[test]
    fn rejects_empty_remote_filename_for_remote_name() {
        let transfer = TransferConfig {
            remote_name: true,
            ..TransferConfig::default()
        };
        let url = Url::parse("http://example.com/").unwrap();

        let error = validate_output_target(&transfer, &url).unwrap_err();
        assert!(error.to_string().contains("remote filename has no length"));
    }
}
