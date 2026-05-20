use crate::error::{CurlError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedUrl {
    pub url: String,
    pub variables: Vec<String>,
    pub remote_name: bool,
}

pub fn expand_url(input: &str, globoff: bool) -> Result<Vec<ExpandedUrl>> {
    if globoff {
        return Ok(vec![ExpandedUrl {
            url: input.to_string(),
            variables: Vec::new(),
            remote_name: false,
        }]);
    }

    expand_recursive(input, Vec::new())
}

pub fn apply_default_protocol(input: &str, default_protocol: Option<&str>) -> String {
    if input.contains("://") {
        return input.to_string();
    }
    let Some(protocol) = default_protocol.or_else(|| guess_default_protocol(input)) else {
        return input.to_string();
    };
    format!("{protocol}://{input}")
}

fn guess_default_protocol(input: &str) -> Option<&'static str> {
    let colon = input.find(':')?;
    let first_path_separator = input.find('/').unwrap_or(input.len());
    if colon < first_path_separator && input[..colon].contains('.') {
        Some("http")
    } else {
        None
    }
}

fn expand_recursive(input: &str, variables: Vec<String>) -> Result<Vec<ExpandedUrl>> {
    let Some(token) = find_token(input)? else {
        return Ok(vec![ExpandedUrl {
            url: input.to_string(),
            variables,
            remote_name: false,
        }]);
    };

    let prefix = &input[..token.start];
    let suffix = &input[token.end..];
    let mut expanded = Vec::new();

    for replacement in token.values {
        let next = format!("{prefix}{replacement}{suffix}");
        let mut next_variables = variables.clone();
        next_variables.push(replacement);
        expanded.extend(expand_recursive(&next, next_variables)?);
    }

    Ok(expanded)
}

struct Token {
    start: usize,
    end: usize,
    values: Vec<String>,
}

fn find_token(input: &str) -> Result<Option<Token>> {
    let mut brace = input.find('{').map(TokenStart::Brace);
    let mut bracket = input.find('[').map(TokenStart::Bracket);

    let start = match (brace.take(), bracket.take()) {
        (Some(left), Some(right)) => Some(if left.index() <= right.index() {
            left
        } else {
            right
        }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    };

    match start {
        Some(TokenStart::Brace(start)) => brace_token(input, start),
        Some(TokenStart::Bracket(start)) => bracket_token(input, start),
        None => Ok(None),
    }
}

enum TokenStart {
    Brace(usize),
    Bracket(usize),
}

impl TokenStart {
    fn index(&self) -> usize {
        match *self {
            Self::Brace(index) | Self::Bracket(index) => index,
        }
    }
}

fn brace_token(input: &str, start: usize) -> Result<Option<Token>> {
    let Some(relative_end) = input[start + 1..].find('}') else {
        return Err(CurlError::Url("unmatched { in URL glob".to_string()));
    };
    let end = start + 1 + relative_end;
    let content = &input[start + 1..end];
    if !content.contains(',') {
        return Ok(None);
    }
    let values = content.split(',').map(ToString::to_string).collect();
    Ok(Some(Token {
        start,
        end: end + 1,
        values,
    }))
}

fn bracket_token(input: &str, start: usize) -> Result<Option<Token>> {
    let Some(relative_end) = input[start + 1..].find(']') else {
        return Err(CurlError::Url("unmatched [ in URL glob".to_string()));
    };
    let end = start + 1 + relative_end;
    let content = &input[start + 1..end];

    let Some((left, right)) = content.split_once('-') else {
        return Ok(None);
    };

    if left.is_empty() || right.is_empty() || content.contains(':') {
        return Ok(None);
    }

    let values = if left.chars().all(|ch| ch.is_ascii_digit())
        && right.chars().all(|ch| ch.is_ascii_digit())
    {
        numeric_range(left, right)?
    } else if left.len() == 1
        && right.len() == 1
        && left.chars().all(|ch| ch.is_ascii_alphabetic())
        && right.chars().all(|ch| ch.is_ascii_alphabetic())
    {
        alpha_range(left.as_bytes()[0], right.as_bytes()[0])?
    } else {
        return Ok(None);
    };

    Ok(Some(Token {
        start,
        end: end + 1,
        values,
    }))
}

fn numeric_range(left: &str, right: &str) -> Result<Vec<String>> {
    let start: i64 = left
        .parse()
        .map_err(|_| CurlError::Url("invalid numeric range".to_string()))?;
    let end: i64 = right
        .parse()
        .map_err(|_| CurlError::Url("invalid numeric range".to_string()))?;
    if start > end {
        return Err(CurlError::Url("bad numeric range".to_string()));
    }
    if end == i64::MAX {
        return Err(CurlError::Url("range end/step overflow".to_string()));
    }
    let width = left.len().max(right.len());
    let mut values = Vec::new();
    let mut current = start;
    loop {
        values.push(format!("{current:0width$}"));
        if current == end {
            break;
        }
        current += 1;
    }
    Ok(values)
}

fn alpha_range(start: u8, end: u8) -> Result<Vec<String>> {
    let step = if start <= end { 1_i16 } else { -1_i16 };
    let mut values = Vec::new();
    let mut current = i16::from(start);
    let end = i16::from(end);
    loop {
        values.push((current as u8 as char).to_string());
        if current == end {
            break;
        }
        current += step;
    }
    Ok(values)
}

pub fn apply_output_variables(pattern: &str, variables: &[String]) -> String {
    let mut output = pattern.to_string();
    for (index, variable) in variables.iter().enumerate() {
        output = output.replace(&format!("#{}", index + 1), variable);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_brace_and_numeric_ranges() {
        let expanded = expand_url("http://host/{a,b}/file[01-02]", false).unwrap();
        let urls: Vec<_> = expanded.iter().map(|item| item.url.as_str()).collect();

        assert_eq!(
            urls,
            [
                "http://host/a/file01",
                "http://host/a/file02",
                "http://host/b/file01",
                "http://host/b/file02"
            ]
        );
        assert_eq!(expanded[0].variables, ["a", "01"]);
    }

    #[test]
    fn leaves_ipv6_brackets_alone() {
        let expanded = expand_url("http://[::1]/", false).unwrap();
        assert_eq!(expanded[0].url, "http://[::1]/");
    }

    #[test]
    fn rejects_c_curl_numeric_range_edges() {
        assert!(
            expand_url("http://host/[2-1]", false)
                .unwrap_err()
                .to_string()
                .contains("bad numeric range")
        );
        assert!(
            expand_url(
                "http://host/[9223372036854775806-9223372036854775807]",
                false,
            )
            .unwrap_err()
            .to_string()
            .contains("range end/step overflow")
        );
    }

    #[test]
    fn applies_default_protocol_to_schemeless_urls() {
        assert_eq!(
            apply_default_protocol("/tmp/file.txt", Some("file")),
            "file:///tmp/file.txt"
        );
        assert_eq!(
            apply_default_protocol("example.com", Some("https")),
            "https://example.com"
        );
        assert_eq!(
            apply_default_protocol("http://example.com", Some("https")),
            "http://example.com"
        );
        assert_eq!(apply_default_protocol("example.com", None), "example.com");
        assert_eq!(
            apply_default_protocol("127.0.0.1:8080/file", None),
            "http://127.0.0.1:8080/file"
        );
    }

    #[test]
    fn applies_output_markers() {
        assert_eq!(
            apply_output_variables("file-#1-#2.txt", &["a".into(), "01".into()]),
            "file-a-01.txt"
        );
    }
}
