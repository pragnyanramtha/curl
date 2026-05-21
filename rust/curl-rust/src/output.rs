use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use reqwest::header::{
    ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_LENGTH, HeaderMap, HeaderValue, LAST_MODIFIED,
};
use reqwest::{StatusCode, Version};
use url::Url;

use crate::cli::{FileClobberMode, TransferConfig};
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
    if transfer.out_null {
        return Ok(None);
    }

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
            let effective_path = if append {
                {
                    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
                    file.write_all(bytes)?;
                }
                path
            } else {
                let (mut file, effective_path) =
                    open_output_file(&path, transfer.file_clobber_mode, is_header_filename_output)?;
                if let Err(error) = file.write_all(bytes) {
                    remove_output_on_write_error(transfer, &effective_path);
                    return Err(error.into());
                }
                effective_path
            };
            Ok(Some(effective_path))
        }
        None => {
            io::stdout().write_all(bytes)?;
            Ok(None)
        }
    }
}

pub fn apply_remote_time(transfer: &TransferConfig, headers: &HeaderMap, path: Option<&Path>) {
    if !transfer.remote_time {
        return;
    }
    let Some(path) = path else {
        return;
    };
    let Some(remote_time) = remote_file_time(headers) else {
        return;
    };
    if let Err(error) = set_output_file_time(path, remote_time)
        && !transfer.silent
    {
        eprintln!(
            "Warning: Failed to set filetime {}: {error}",
            unix_timestamp(remote_time)
        );
    }
}

fn remote_file_time(headers: &HeaderMap) -> Option<SystemTime> {
    let value = headers.get(LAST_MODIFIED)?.to_str().ok()?;
    httpdate::parse_http_date(value)
        .ok()
        .or_else(|| parse_curl_http_date(value))
}

fn unix_timestamp(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::from(duration.as_secs()),
        Err(error) => -i128::from(error.duration().as_secs()),
    }
}

fn parse_curl_http_date(value: &str) -> Option<SystemTime> {
    let normalized = value.replace(',', " ");
    let mut parts = normalized.split_whitespace().collect::<Vec<_>>();
    if parts
        .first()
        .is_some_and(|part| parse_weekday_name(part).is_some())
    {
        parts.remove(0);
    }

    match parts.as_slice() {
        [month, day, time, year, zone] if time.contains(':') => {
            let month = parse_month_name(month)?;
            let day = day.parse().ok()?;
            let year = year.parse().ok()?;
            let (hour, minute, second) = parse_hms(time)?;
            let zone_offset = parse_zone_offset_seconds(zone)?;
            system_time_from_curl_date(year, month, day, hour, minute, second, zone_offset)
        }
        [day, month, year, time, zone] if time.contains(':') => {
            let month = parse_month_name(month)?;
            let day = day.parse().ok()?;
            let year = year.parse().ok()?;
            let (hour, minute, second) = parse_hms(time)?;
            let zone_offset = parse_zone_offset_seconds(zone)?;
            system_time_from_curl_date(year, month, day, hour, minute, second, zone_offset)
        }
        _ => None,
    }
}

fn parse_weekday_name(value: &str) -> Option<()> {
    matches!(
        value.get(..3)?.to_ascii_lowercase().as_str(),
        "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun"
    )
    .then_some(())
}

fn parse_month_name(value: &str) -> Option<u32> {
    match value.get(..3)?.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn parse_hms(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split(':');
    let hour: u32 = parts.next()?.parse().ok()?;
    let minute: u32 = parts.next()?.parse().ok()?;
    let second: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second.min(59)))
}

fn parse_zone_offset_seconds(value: &str) -> Option<i64> {
    if value.eq_ignore_ascii_case("gmt") || value.eq_ignore_ascii_case("utc") {
        return Some(0);
    }
    let bytes = value.as_bytes();
    if bytes.len() != 5 || !matches!(bytes[0], b'+' | b'-') {
        return None;
    }
    let hours: i64 = value[1..3].parse().ok()?;
    let minutes: i64 = value[3..5].parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    let seconds = hours.checked_mul(3_600)?.checked_add(minutes * 60)?;
    Some(if bytes[0] == b'-' { -seconds } else { seconds })
}

fn system_time_from_curl_date(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    zone_offset_seconds: i64,
) -> Option<SystemTime> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let seconds = days_from_civil(year, month, day)
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?
        .checked_sub(zone_offset_seconds)?;
    if seconds >= 0 {
        UNIX_EPOCH.checked_add(std::time::Duration::from_secs(seconds as u64))
    } else {
        UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(seconds.unsigned_abs()))
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    year -= i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_for_formula = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_for_formula + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(unix)]
fn set_output_file_time(path: &Path, remote_time: SystemTime) -> io::Result<()> {
    let times = [
        system_time_to_timespec(remote_time)?,
        system_time_to_timespec(remote_time)?,
    ];
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn set_output_file_time(_path: &Path, _remote_time: SystemTime) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn system_time_to_timespec(time: SystemTime) -> io::Result<libc::timespec> {
    let (seconds, nanos) = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (
            i128::from(duration.as_secs()),
            i128::from(duration.subsec_nanos()),
        ),
        Err(error) => {
            let duration = error.duration();
            if duration.subsec_nanos() == 0 {
                (-i128::from(duration.as_secs()), 0)
            } else {
                (
                    -i128::from(duration.as_secs()) - 1,
                    i128::from(1_000_000_000 - duration.subsec_nanos()),
                )
            }
        }
    };
    Ok(libc::timespec {
        tv_sec: seconds
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filetime out of range"))?,
        tv_nsec: nanos
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filetime out of range"))?,
    })
}

fn open_output_file(
    path: &Path,
    clobber_mode: FileClobberMode,
    is_header_filename_output: bool,
) -> io::Result<(std::fs::File, PathBuf)> {
    if clobber_mode == FileClobberMode::Always
        || (clobber_mode == FileClobberMode::Default && !is_header_filename_output)
    {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        return Ok((file, path.to_path_buf()));
    }

    if clobber_mode == FileClobberMode::Never {
        return open_numbered_output_file(path);
    }

    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    Ok((file, path.to_path_buf()))
}

fn open_numbered_output_file(path: &Path) -> io::Result<(std::fs::File, PathBuf)> {
    let mut last_error = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => return Ok((file, path.to_path_buf())),
        Err(error) if should_try_numbered_output(&error) => error,
        Err(error) => return Err(error),
    };

    for number in 1..100 {
        let candidate = numbered_output_path(path, number);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((file, candidate)),
            Err(error) if should_try_numbered_output(&error) => last_error = error,
            Err(error) => return Err(error),
        }
    }

    Err(last_error)
}

fn should_try_numbered_output(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AlreadyExists | io::ErrorKind::IsADirectory
    )
}

fn numbered_output_path(path: &Path, number: u8) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{number}"));
    PathBuf::from(name)
}

fn remove_output_on_write_error(transfer: &TransferConfig, path: &Path) {
    if !transfer.remove_on_error {
        return;
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if !metadata.is_file() {
        return;
    }
    if std::fs::remove_file(path).is_ok() && (transfer.verbose || transfer.trace_output) {
        eprintln!("Note: Removed output file: {}", path.display());
    }
}

pub fn validate_output_target(transfer: &TransferConfig, url: &Url) -> Result<()> {
    if transfer.out_null {
        return Ok(());
    }
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
    if path == Path::new("%") {
        io::stderr().write_all(bytes)?;
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

pub fn append_dump_headers(path: &Path, bytes: &[u8], create_dirs: bool) -> Result<()> {
    if path == Path::new("-") {
        io::stdout().write_all(bytes)?;
        return Ok(());
    }
    if path == Path::new("%") {
        io::stderr().write_all(bytes)?;
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
        .append(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

pub fn prepare_dump_header_target(path: &Path, create_dirs: bool) -> Result<()> {
    if path == Path::new("-") {
        return Ok(());
    }
    if path == Path::new("%") {
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
    if transfer.out_null {
        return Ok(None);
    }

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
    let filename = url
        .path_segments()
        .and_then(|segments| {
            segments
                .rev()
                .find(|segment| !segment.is_empty())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "curl_response".to_string());
    Ok(filename)
}

fn remote_header_filename(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CONTENT_DISPOSITION)?.to_str().ok()?;
    parse_content_disposition_filename(value)
}

fn parse_content_disposition_filename(value: &str) -> Option<String> {
    let mut index = 0;
    let bytes = value.as_bytes();

    while index < bytes.len() {
        while index < bytes.len() && !bytes[index].is_ascii_alphabetic() {
            index += 1;
        }
        if index + "filename=".len() > bytes.len() {
            break;
        }

        if !bytes[index..].starts_with(b"filename=") {
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            continue;
        }

        index += "filename=".len();
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
            index += 1;
        }

        let raw_filename = parse_content_disposition_filename_value(&value[index..]);
        let filename = raw_filename.rsplit(['/', '\\']).next().unwrap_or_default();
        if !matches!(filename, "" | "." | "..") {
            return Some(filename.to_string());
        }
        return None;
    }
    None
}

fn parse_content_disposition_filename_value(raw: &str) -> &str {
    let raw = raw.trim_start_matches([' ', '\t']);
    let Some(first) = raw.as_bytes().first().copied() else {
        return raw;
    };

    let value = if first == b'\'' || first == b'"' {
        let rest = &raw[1..];
        let quote = first as char;
        match rest.find(quote) {
            Some(end) => &rest[..end],
            None => rest,
        }
    } else {
        let end = raw.find(';').unwrap_or(raw.len());
        &raw[..end]
    };

    let end = value.find(['\r', '\n']).unwrap_or(value.len());
    &value[..end]
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
            Some("bad".to_string())
        );
        assert_eq!(
            parse_content_disposition_filename("attachment; filename=log\\server\\archive.bin"),
            Some("archive.bin".to_string())
        );
        assert_eq!(
            parse_content_disposition_filename("inline; filename=\"name1312;weird\""),
            Some("name1312;weird".to_string())
        );
        assert_eq!(
            parse_content_disposition_filename("inline; filename='name1313"),
            Some("name1313".to_string())
        );
    }

    #[test]
    fn parses_pre_epoch_remote_file_time_with_numeric_zone() {
        let remote_time = parse_curl_http_date("Wed, 09 Oct 1940 16:45:49 +0100").unwrap();

        assert_eq!(unix_timestamp(remote_time), -922_349_651);
    }

    #[test]
    fn root_remote_filename_uses_curl_response() {
        let transfer = TransferConfig {
            remote_name: true,
            ..TransferConfig::default()
        };
        let url = Url::parse("http://example.com/").unwrap();

        validate_output_target(&transfer, &url).unwrap();
        assert_eq!(remote_url_filename(&url).unwrap(), "curl_response");
    }

    #[test]
    fn trailing_slash_remote_filename_uses_previous_segment() {
        let url = Url::parse("http://example.com/path/to/here/").unwrap();

        assert_eq!(remote_url_filename(&url).unwrap(), "here");
    }
}
