use std::{collections::HashSet, time::Duration};

use reqwest::header::HeaderMap;

#[derive(Debug, Clone)]
pub struct Metrics {
    pub url: String,
    pub url_effective: String,
    pub response_code: Option<u16>,
    pub http_version: Option<String>,
    pub size_download: u64,
    pub size_delivered: u64,
    pub size_header: u64,
    pub size_request: u64,
    pub size_upload: u64,
    pub time_total: Duration,
    pub time_queue: Duration,
    pub time_namelookup: Duration,
    pub time_connect: Duration,
    pub time_appconnect: Duration,
    pub time_pretransfer: Duration,
    pub time_posttransfer: Duration,
    pub time_starttransfer: Duration,
    pub time_redirect: Duration,
    pub content_type: Option<String>,
    pub filename_effective: Option<String>,
    pub method: String,
    pub exit_code: i32,
    pub errormsg: String,
    pub redirect_url: Option<String>,
    pub referer: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub local_ip: Option<String>,
    pub local_port: Option<u16>,
    pub http_connect: Option<u16>,
    pub proxy_used: bool,
    pub num_connects: u64,
    pub num_redirects: usize,
    pub num_retries: usize,
    pub headers: HeaderMap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

impl Metrics {
    pub fn empty(url: &str, method: &str) -> Self {
        Self {
            url: url.to_string(),
            url_effective: url.to_string(),
            response_code: None,
            http_version: None,
            size_download: 0,
            size_delivered: 0,
            size_header: 0,
            size_request: 0,
            size_upload: 0,
            time_total: Duration::ZERO,
            time_queue: Duration::ZERO,
            time_namelookup: Duration::ZERO,
            time_connect: Duration::ZERO,
            time_appconnect: Duration::ZERO,
            time_pretransfer: Duration::ZERO,
            time_posttransfer: Duration::ZERO,
            time_starttransfer: Duration::ZERO,
            time_redirect: Duration::ZERO,
            content_type: None,
            filename_effective: None,
            method: method.to_string(),
            exit_code: 0,
            errormsg: String::new(),
            redirect_url: None,
            referer: None,
            remote_ip: None,
            remote_port: None,
            local_ip: None,
            local_port: None,
            http_connect: None,
            proxy_used: false,
            num_connects: 0,
            num_redirects: 0,
            num_retries: 0,
            headers: HeaderMap::new(),
        }
    }
}

pub fn render(format: &str, metrics: &Metrics) -> String {
    render_segments(format, metrics)
        .into_iter()
        .map(|(_, chunk)| chunk)
        .collect()
}

pub fn render_segments(format: &str, metrics: &Metrics) -> Vec<(OutputStream, String)> {
    let mut segments = Vec::new();
    let mut stream = OutputStream::Stdout;
    let mut output = String::new();
    let mut chars = format.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some('n') => output.push('\n'),
                Some('r') => output.push('\r'),
                Some('t') => output.push('\t'),
                Some(other) => {
                    output.push('\\');
                    output.push(other);
                }
                None => output.push('\\'),
            },
            '%' => {
                if chars.peek() == Some(&'%') {
                    chars.next();
                    output.push('%');
                    continue;
                }

                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut name = String::new();
                    let mut closed = false;
                    for next in chars.by_ref() {
                        if next == '}' {
                            closed = true;
                            break;
                        }
                        name.push(next);
                    }
                    if !closed {
                        output.push_str("%{");
                        output.push_str(&name);
                        continue;
                    }
                    match name.as_str() {
                        "stdout" => switch_stream(
                            &mut segments,
                            &mut output,
                            &mut stream,
                            OutputStream::Stdout,
                        ),
                        "stderr" => switch_stream(
                            &mut segments,
                            &mut output,
                            &mut stream,
                            OutputStream::Stderr,
                        ),
                        _ => output.push_str(&variable(&name, metrics)),
                    }
                } else {
                    output.push('%');
                }
            }
            other => output.push(other),
        }
    }

    if !output.is_empty() {
        segments.push((stream, output));
    }
    segments
}

fn switch_stream(
    segments: &mut Vec<(OutputStream, String)>,
    output: &mut String,
    stream: &mut OutputStream,
    next_stream: OutputStream,
) {
    if !output.is_empty() {
        segments.push((*stream, std::mem::take(output)));
    }
    *stream = next_stream;
}

fn variable(name: &str, metrics: &Metrics) -> String {
    match name {
        "url_effective" => metrics.url_effective.clone(),
        "http_code" | "response_code" => metrics
            .response_code
            .map(|code| format!("{code:03}"))
            .unwrap_or_else(|| "000".to_string()),
        "size_download" => metrics.size_download.to_string(),
        "size_delivered" => metrics.size_delivered.to_string(),
        "size_header" => metrics.size_header.to_string(),
        "size_request" => metrics.size_request.to_string(),
        "size_upload" => metrics.size_upload.to_string(),
        "time_total" => format_duration(time_value(metrics, TimeMetric::Total)),
        "time_queue" => format_duration(time_value(metrics, TimeMetric::Queue)),
        "time_namelookup" => format_duration(time_value(metrics, TimeMetric::NameLookup)),
        "time_connect" => format_duration(time_value(metrics, TimeMetric::Connect)),
        "time_appconnect" => format_duration(time_value(metrics, TimeMetric::AppConnect)),
        "time_pretransfer" => format_duration(time_value(metrics, TimeMetric::PreTransfer)),
        "time_posttransfer" => format_duration(time_value(metrics, TimeMetric::PostTransfer)),
        "time_starttransfer" => format_duration(time_value(metrics, TimeMetric::StartTransfer)),
        "time_redirect" => format_duration(time_value(metrics, TimeMetric::Redirect)),
        "content_type" => metrics.content_type.clone().unwrap_or_default(),
        "filename_effective" => metrics.filename_effective.clone().unwrap_or_default(),
        "method" => metrics.method.clone(),
        "http_version" => metrics.http_version.clone().unwrap_or_default(),
        "remote_ip" => metrics.remote_ip.clone().unwrap_or_default(),
        "remote_port" => metrics
            .remote_port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "0".to_string()),
        "local_ip" => metrics.local_ip.clone().unwrap_or_default(),
        "local_port" => metrics
            .local_port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "0".to_string()),
        "http_connect" => metrics
            .http_connect
            .map(|code| format!("{code:03}"))
            .unwrap_or_else(|| "000".to_string()),
        "proxy_used" => u8::from(metrics.proxy_used).to_string(),
        "num_connects" => metrics.num_connects.to_string(),
        "num_redirects" => metrics.num_redirects.to_string(),
        "exitcode" => metrics.exit_code.to_string(),
        "errormsg" => metrics.errormsg.clone(),
        "redirect_url" => metrics.redirect_url.clone().unwrap_or_default(),
        "referer" => metrics.referer.clone().unwrap_or_default(),
        "num_retries" => metrics.num_retries.to_string(),
        "scheme" => url_part(&metrics.url_effective, UrlPart::Scheme).unwrap_or_default(),
        "num_headers" => metrics.headers.len().to_string(),
        "json" => json(metrics),
        "header_json" => header_json(&metrics.headers),
        _ => String::new(),
    }
}

fn json(metrics: &Metrics) -> String {
    let scheme = url_part(&metrics.url_effective, UrlPart::Scheme);
    let speed_download = speed(metrics.size_download, metrics.time_total);
    let speed_upload = speed(metrics.size_upload, metrics.time_total);
    let fields = [
        json_string("certs", Some("")),
        json_number("conn_id", 0),
        json_optional("content_type", metrics.content_type.as_deref()),
        json_optional_nonempty("errormsg", &metrics.errormsg),
        json_number("exitcode", metrics.exit_code),
        json_optional("filename_effective", metrics.filename_effective.as_deref()),
        json_null("ftp_entry_path"),
        json_number("http_code", metrics.response_code.unwrap_or(0)),
        json_number("http_connect", metrics.http_connect.unwrap_or(0)),
        json_string("http_version", metrics.http_version.as_deref()),
        json_string("local_ip", metrics.local_ip.as_deref()),
        json_number("local_port", metrics.local_port.unwrap_or(0)),
        json_string("method", Some(&metrics.method)),
        json_number("num_certs", 0),
        json_number("num_connects", metrics.num_connects),
        json_number("num_headers", metrics.headers.len()),
        json_number("num_redirects", metrics.num_redirects),
        json_number("num_retries", metrics.num_retries),
        json_number("proxy_ssl_verify_result", 0),
        json_number("proxy_used", u8::from(metrics.proxy_used)),
        json_optional("redirect_url", metrics.redirect_url.as_deref()),
        json_optional("referer", metrics.referer.as_deref()),
        json_string("remote_ip", metrics.remote_ip.as_deref()),
        json_number("remote_port", metrics.remote_port.unwrap_or(0)),
        json_number("response_code", metrics.response_code.unwrap_or(0)),
        json_string("scheme", scheme.as_deref()),
        json_number("size_delivered", metrics.size_delivered),
        json_number("size_download", metrics.size_download),
        json_number("size_header", metrics.size_header),
        json_number("size_request", metrics.size_request),
        json_number("size_upload", metrics.size_upload),
        json_number("speed_download", speed_download),
        json_number("speed_upload", speed_upload),
        json_number("ssl_verify_result", 0),
        json_duration_field(
            "time_appconnect",
            time_value(metrics, TimeMetric::AppConnect),
        ),
        json_duration_field("time_connect", time_value(metrics, TimeMetric::Connect)),
        json_duration_field(
            "time_namelookup",
            time_value(metrics, TimeMetric::NameLookup),
        ),
        json_duration_field(
            "time_posttransfer",
            time_value(metrics, TimeMetric::PostTransfer),
        ),
        json_duration_field(
            "time_pretransfer",
            time_value(metrics, TimeMetric::PreTransfer),
        ),
        json_duration_field("time_queue", time_value(metrics, TimeMetric::Queue)),
        json_duration_field("time_redirect", time_value(metrics, TimeMetric::Redirect)),
        json_duration_field(
            "time_starttransfer",
            time_value(metrics, TimeMetric::StartTransfer),
        ),
        json_duration_field("time_total", time_value(metrics, TimeMetric::Total)),
        json_number("tls_earlydata", 0),
        json_string("url", Some(&metrics.url)),
        json_string("url_effective", Some(&metrics.url_effective)),
        json_number("urlnum", 0),
        json_number("xfer_id", 0),
        json_string("curl_version", Some(env!("CARGO_PKG_VERSION"))),
    ];
    format!("{{{}}}", fields.join(","))
}

fn json_string(name: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{name}\":\"{}\"", escape_json(value)),
        None => format!("\"{name}\":null"),
    }
}

fn json_optional(name: &str, value: Option<&str>) -> String {
    json_string(name, value)
}

fn json_optional_nonempty(name: &str, value: &str) -> String {
    if value.is_empty() {
        format!("\"{name}\":null")
    } else {
        json_string(name, Some(value))
    }
}

fn json_null(name: &str) -> String {
    format!("\"{name}\":null")
}

fn json_number<T: std::fmt::Display>(name: &str, value: T) -> String {
    format!("\"{name}\":{value}")
}

fn json_duration_field(name: &str, value: Duration) -> String {
    format!("\"{name}\":{}", format_duration(value))
}

fn format_duration(value: Duration) -> String {
    format!("{:.6}", value.as_secs_f64())
}

#[derive(Clone, Copy)]
enum TimeMetric {
    Queue,
    NameLookup,
    Connect,
    AppConnect,
    PreTransfer,
    PostTransfer,
    StartTransfer,
    Redirect,
    Total,
}

fn time_value(metrics: &Metrics, metric: TimeMetric) -> Duration {
    let total = positive_duration(metrics.time_total);
    let stored = match metric {
        TimeMetric::Queue => metrics.time_queue,
        TimeMetric::NameLookup => metrics.time_namelookup,
        TimeMetric::Connect => metrics.time_connect,
        TimeMetric::AppConnect => metrics.time_appconnect,
        TimeMetric::PreTransfer => metrics.time_pretransfer,
        TimeMetric::PostTransfer => metrics.time_posttransfer,
        TimeMetric::StartTransfer => metrics.time_starttransfer,
        TimeMetric::Redirect => metrics.time_redirect,
        TimeMetric::Total => metrics.time_total,
    };
    if !stored.is_zero() || matches!(metric, TimeMetric::Total) {
        return if matches!(metric, TimeMetric::Total) {
            total
        } else {
            stored
        };
    }

    match metric {
        TimeMetric::Queue => total,
        TimeMetric::NameLookup | TimeMetric::Connect if metrics.num_connects > 0 => total,
        TimeMetric::AppConnect
            if metrics.num_connects > 0 && metrics.url_effective.starts_with("https:") =>
        {
            total
        }
        TimeMetric::PreTransfer
            if metrics.size_download > 0
                || metrics.size_upload > 0
                || metrics.response_code.is_some() =>
        {
            total
        }
        TimeMetric::PostTransfer if metrics.size_request > 0 || metrics.size_upload > 0 => total,
        TimeMetric::StartTransfer if metrics.size_download > 0 => total,
        _ => Duration::ZERO,
    }
}

fn positive_duration(value: Duration) -> Duration {
    if value.is_zero() {
        Duration::from_micros(1)
    } else {
        value
    }
}

fn speed(size: u64, duration: Duration) -> u64 {
    let seconds = duration.as_secs_f64();
    if seconds <= 0.0 {
        0
    } else {
        (size as f64 / seconds) as u64
    }
}

enum UrlPart {
    Scheme,
}

fn url_part(url: &str, part: UrlPart) -> Option<String> {
    match part {
        UrlPart::Scheme => url.split_once(':').map(|(scheme, _)| scheme.to_string()),
    }
}

fn header_json(headers: &HeaderMap) -> String {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    for name in headers.keys() {
        if !seen.insert(name.clone()) {
            continue;
        }

        let values = headers
            .get_all(name)
            .iter()
            .map(|value| {
                let value = String::from_utf8_lossy(value.as_bytes());
                format!("\"{}\"", escape_json(&value))
            })
            .collect::<Vec<_>>()
            .join(",");
        entries.push(format!(
            "\"{}\":[{}]",
            escape_json(&name.as_str().to_ascii_lowercase()),
            values
        ));
    }
    format!("{{{}}}", entries.join(","))
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other if other.is_control() => escaped.push_str(&format!("\\u{:04x}", other as u32)),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_common_variables() {
        let mut metrics = Metrics::empty("https://example.com/", "GET");
        metrics.response_code = Some(200);
        metrics.size_download = 5;
        metrics.size_delivered = 5;
        metrics.num_retries = 2;
        metrics.referer = Some("https://refer.example/source".to_string());
        metrics.headers.insert(
            reqwest::header::DATE,
            "Tue, 09 Nov 2010 14:49:00 GMT".parse().unwrap(),
        );
        metrics
            .headers
            .insert(reqwest::header::CONTENT_TYPE, "text/plain".parse().unwrap());

        assert_eq!(
            render(
                "%{url_effective} %{http_code} %{size_download} %{referer} %{num_retries}\\n",
                &metrics
            ),
            "https://example.com/ 200 5 https://refer.example/source 2\n"
        );
        assert_eq!(render("%{size_delivered}", &metrics), "5");
        assert_eq!(render("%{scheme} %{num_headers}", &metrics), "https 2");
        metrics.http_version = Some("1.1".to_string());
        metrics.remote_ip = Some("127.0.0.1".to_string());
        metrics.remote_port = Some(8080);
        metrics.local_port = Some(49152);
        metrics.http_connect = Some(200);
        metrics.proxy_used = true;
        metrics.size_header = 42;
        metrics.size_request = 84;
        assert!(
            render("%{json}", &metrics).contains("\"referer\":\"https://refer.example/source\"")
        );
        let json = render("%{json}", &metrics);
        assert!(json.contains("\"http_version\":\"1.1\""));
        assert!(json.contains("\"remote_ip\":\"127.0.0.1\""));
        assert!(json.contains("\"remote_port\":8080"));
        assert!(json.contains("\"local_port\":49152"));
        assert!(json.contains("\"http_connect\":200"));
        assert!(json.contains("\"proxy_used\":1"));
        assert!(json.contains("\"size_header\":42"));
        assert!(json.contains("\"size_request\":84"));
        assert!(json.contains("\"time_queue\":"));
    }

    #[test]
    fn render_segments_switches_output_streams() {
        let metrics = Metrics::empty("https://example.com/", "GET");

        assert_eq!(
            render_segments("one%{stderr}two%{stdout}three", &metrics),
            vec![
                (OutputStream::Stdout, "one".to_string()),
                (OutputStream::Stderr, "two".to_string()),
                (OutputStream::Stdout, "three".to_string()),
            ]
        );
        assert_eq!(
            render("one%{stderr}two%{stdout}three", &metrics),
            "onetwothree"
        );
    }

    #[test]
    fn render_preserves_unclosed_variable_literal() {
        let metrics = Metrics::empty("file:///missing", "GET");

        assert_eq!(render("%{", &metrics), "%{");
        assert_eq!(render("prefix %{http_code", &metrics), "prefix %{http_code");
    }

    #[test]
    fn header_json_groups_repeated_headers() {
        let mut metrics = Metrics::empty("https://example.com/", "GET");
        metrics.headers.append(
            reqwest::header::SET_COOKIE,
            "first=1; path=/".parse().unwrap(),
        );
        metrics.headers.append(
            reqwest::header::SET_COOKIE,
            "second=2; path=/".parse().unwrap(),
        );
        metrics
            .headers
            .insert(reqwest::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        metrics.headers.insert(
            reqwest::header::HeaderName::from_static("x-escaped"),
            "quote \" slash \\".parse().unwrap(),
        );

        let rendered = render("%{header_json}", &metrics);

        assert_eq!(rendered.matches("\"set-cookie\":").count(), 1);
        assert!(rendered.contains("\"set-cookie\":[\"first=1; path=/\",\"second=2; path=/\"]"));
        assert!(rendered.contains("\"content-type\":[\"text/plain\"]"));
        assert!(rendered.contains("\"x-escaped\":[\"quote \\\" slash \\\\\"]"));
    }
}
