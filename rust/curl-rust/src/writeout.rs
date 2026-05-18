use std::time::Duration;

use reqwest::header::HeaderMap;

#[derive(Debug, Clone)]
pub struct Metrics {
    pub url_effective: String,
    pub response_code: Option<u16>,
    pub size_download: u64,
    pub time_total: Duration,
    pub content_type: Option<String>,
    pub filename_effective: Option<String>,
    pub method: String,
    pub exit_code: i32,
    pub errormsg: String,
    pub redirect_url: Option<String>,
    pub referer: Option<String>,
    pub num_retries: usize,
    pub headers: HeaderMap,
}

impl Metrics {
    pub fn empty(url: &str, method: &str) -> Self {
        Self {
            url_effective: url.to_string(),
            response_code: None,
            size_download: 0,
            time_total: Duration::ZERO,
            content_type: None,
            filename_effective: None,
            method: method.to_string(),
            exit_code: 0,
            errormsg: String::new(),
            redirect_url: None,
            referer: None,
            num_retries: 0,
            headers: HeaderMap::new(),
        }
    }
}

pub fn render(format: &str, metrics: &Metrics) -> String {
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
                    for next in chars.by_ref() {
                        if next == '}' {
                            break;
                        }
                        name.push(next);
                    }
                    output.push_str(&variable(&name, metrics));
                } else {
                    output.push('%');
                }
            }
            other => output.push(other),
        }
    }

    output
}

fn variable(name: &str, metrics: &Metrics) -> String {
    match name {
        "url_effective" => metrics.url_effective.clone(),
        "http_code" | "response_code" => metrics
            .response_code
            .map(|code| format!("{code:03}"))
            .unwrap_or_else(|| "000".to_string()),
        "size_download" => metrics.size_download.to_string(),
        "time_total" => format!("{:.6}", metrics.time_total.as_secs_f64()),
        "content_type" => metrics.content_type.clone().unwrap_or_default(),
        "filename_effective" => metrics.filename_effective.clone().unwrap_or_default(),
        "method" => metrics.method.clone(),
        "exitcode" => metrics.exit_code.to_string(),
        "errormsg" => metrics.errormsg.clone(),
        "redirect_url" => metrics.redirect_url.clone().unwrap_or_default(),
        "referer" => metrics.referer.clone().unwrap_or_default(),
        "num_retries" => metrics.num_retries.to_string(),
        "json" => json(metrics),
        "header_json" => header_json(&metrics.headers),
        "stdout" | "stderr" => String::new(),
        _ => String::new(),
    }
}

fn json(metrics: &Metrics) -> String {
    format!(
        "{{\"url_effective\":\"{}\",\"http_code\":{},\"response_code\":{},\"size_download\":{},\"time_total\":{:.6},\"method\":\"{}\",\"exitcode\":{},\"errormsg\":\"{}\",\"referer\":{},\"num_retries\":{}}}",
        escape_json(&metrics.url_effective),
        metrics.response_code.unwrap_or(0),
        metrics.response_code.unwrap_or(0),
        metrics.size_download,
        metrics.time_total.as_secs_f64(),
        escape_json(&metrics.method),
        metrics.exit_code,
        escape_json(&metrics.errormsg),
        json_optional_string(metrics.referer.as_deref()),
        metrics.num_retries
    )
}

fn json_optional_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn header_json(headers: &HeaderMap) -> String {
    let mut entries = Vec::new();
    for (name, value) in headers {
        let value = String::from_utf8_lossy(value.as_bytes());
        entries.push(format!(
            "\"{}\":[\"{}\"]",
            escape_json(name.as_str()),
            escape_json(&value)
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
        metrics.num_retries = 2;
        metrics.referer = Some("https://refer.example/source".to_string());

        assert_eq!(
            render(
                "%{url_effective} %{http_code} %{size_download} %{referer} %{num_retries}\\n",
                &metrics
            ),
            "https://example.com/ 200 5 https://refer.example/source 2\n"
        );
        assert!(
            render("%{json}", &metrics).contains("\"referer\":\"https://refer.example/source\"")
        );
    }
}
