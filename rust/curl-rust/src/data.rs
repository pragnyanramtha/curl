use std::io::{self, Read};

use percent_encoding::percent_decode_str;
use reqwest::multipart::{Form, Part};
use url::form_urlencoded;

use crate::error::{CurlError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataKind {
    UrlEncoded,
    Raw,
    Binary,
    UrlEncodeField,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSpec {
    pub kind: DataKind,
    pub value: String,
}

impl DataSpec {
    pub fn new(kind: DataKind, value: String) -> Self {
        Self { kind, value }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBody {
    pub bytes: Vec<u8>,
    pub is_json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormKind {
    Form,
    FormString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormSpec {
    pub kind: FormKind,
    pub value: String,
}

impl FormSpec {
    pub fn new(kind: FormKind, value: String) -> Self {
        Self { kind, value }
    }
}

impl PreparedBody {
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

pub fn prepare_body(specs: &[DataSpec]) -> Result<Option<PreparedBody>> {
    if specs.is_empty() {
        return Ok(None);
    }

    let is_json = specs.iter().any(|spec| spec.kind == DataKind::Json);
    let mut parts = Vec::with_capacity(specs.len());
    for spec in specs {
        parts.push(load_part(spec)?);
    }

    let bytes = if is_json {
        parts.concat()
    } else {
        join_with_ampersand(parts)
    };

    Ok(Some(PreparedBody { bytes, is_json }))
}

pub fn prepare_multipart(specs: &[FormSpec]) -> Result<Option<Form>> {
    if specs.is_empty() {
        return Ok(None);
    }

    let mut form = Form::new();
    for spec in specs {
        form = add_form_part(form, spec)?;
    }
    Ok(Some(form))
}

fn load_part(spec: &DataSpec) -> Result<Vec<u8>> {
    match spec.kind {
        DataKind::UrlEncoded => {
            if let Some(path) = spec.value.strip_prefix('@') {
                let bytes = read_data_argument(path)?;
                Ok(bytes
                    .into_iter()
                    .filter(|byte| !matches!(byte, b'\r' | b'\n'))
                    .collect())
            } else {
                Ok(spec.value.as_bytes().to_vec())
            }
        }
        DataKind::Raw => Ok(spec.value.as_bytes().to_vec()),
        DataKind::Binary => {
            if let Some(path) = spec.value.strip_prefix('@') {
                read_data_argument(path)
            } else {
                Ok(spec.value.as_bytes().to_vec())
            }
        }
        DataKind::Json => {
            if let Some(path) = spec.value.strip_prefix('@') {
                read_data_argument(path)
            } else {
                Ok(spec.value.as_bytes().to_vec())
            }
        }
        DataKind::UrlEncodeField => data_urlencode(&spec.value).map(|value| value.into_bytes()),
    }
}

fn add_form_part(form: Form, spec: &FormSpec) -> Result<Form> {
    let Some((name, value)) = spec.value.split_once('=') else {
        return Err(CurlError::Usage(format!(
            "form argument {:?} is missing '='",
            spec.value
        )));
    };
    if name.is_empty() {
        return Err(CurlError::Usage(
            "form field name must not be empty".to_string(),
        ));
    }

    if spec.kind == FormKind::Form {
        if let Some(file) = value.strip_prefix('@') {
            let (path, options) = split_form_options(file);
            if path.is_empty() {
                return Err(CurlError::Usage("form file path is empty".to_string()));
            }
            let bytes = read_data_argument(path)?;
            let mut part = Part::bytes(bytes).file_name(
                form_option(options, "filename")
                    .unwrap_or_else(|| default_form_filename(path).to_string()),
            );
            if let Some(mime) = form_option(options, "type") {
                part = part
                    .mime_str(&mime)
                    .map_err(|error| CurlError::Usage(format!("bad form MIME type: {error}")))?;
            }
            return Ok(form.part(name.to_string(), part));
        }

        if let Some(file) = value.strip_prefix('<') {
            let (path, options) = split_form_options(file);
            if path.is_empty() {
                return Err(CurlError::Usage("form file path is empty".to_string()));
            }
            let text = read_text_argument(path)?;
            let mut part = Part::text(text);
            if let Some(mime) = form_option(options, "type") {
                part = part
                    .mime_str(&mime)
                    .map_err(|error| CurlError::Usage(format!("bad form MIME type: {error}")))?;
            }
            return Ok(form.part(name.to_string(), part));
        }
    }

    Ok(form.text(name.to_string(), value.to_string()))
}

fn split_form_options(value: &str) -> (&str, &str) {
    value
        .split_once(';')
        .map_or((value, ""), |(path, options)| (path, options))
}

fn form_option(options: &str, key: &str) -> Option<String> {
    for part in options.split(';') {
        let (name, value) = part.split_once('=')?;
        if name == key && !value.is_empty() {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn default_form_filename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("upload")
}

fn read_data_argument(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        Ok(std::fs::read(path)?)
    }
}

fn data_urlencode(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix('@') {
        let data = read_text_argument(path)?;
        return Ok(encode(&data));
    }

    if let Some((name, path)) = value.split_once('@')
        && !path.is_empty()
    {
        let data = read_text_argument(path)?;
        return Ok(format!("{name}={}", encode(&data)));
    }

    if let Some((name, data)) = value.split_once('=') {
        if name.is_empty() {
            return Ok(encode(data));
        }
        return Ok(format!("{name}={}", encode(data)));
    }

    Ok(encode(value))
}

fn read_text_argument(path: &str) -> Result<String> {
    let bytes = read_data_argument(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn join_with_ampersand(parts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = Vec::new();
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 {
            body.push(b'&');
        }
        body.extend(part);
    }
    body
}

pub fn decode_percent_file_url_path(path: &str) -> Result<String> {
    percent_decode_str(path)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|error| CurlError::Url(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_data_parts_like_form_body() {
        let body = prepare_body(&[
            DataSpec::new(DataKind::UrlEncoded, "a=b".to_string()),
            DataSpec::new(DataKind::UrlEncoded, "c=d".to_string()),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(body.bytes, b"a=b&c=d");
    }

    #[test]
    fn urlencodes_field_values() {
        let body = prepare_body(&[DataSpec::new(
            DataKind::UrlEncodeField,
            "name=hello world".to_string(),
        )])
        .unwrap()
        .unwrap();

        assert_eq!(body.bytes, b"name=hello+world");
    }

    #[test]
    fn json_parts_are_concatenated_without_separator() {
        let body = prepare_body(&[
            DataSpec::new(DataKind::Json, "{\"a\":".to_string()),
            DataSpec::new(DataKind::Json, "1}".to_string()),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(body.bytes, br#"{"a":1}"#);
        assert!(body.is_json);
    }

    #[test]
    fn builds_multipart_fields_and_files() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), "file body").unwrap();
        let spec = format!("upload=@{}", temp.path().display());

        let form = prepare_multipart(&[
            FormSpec::new(FormKind::Form, "field=value".to_string()),
            FormSpec::new(FormKind::Form, spec),
        ])
        .unwrap();

        assert!(form.is_some());
    }

    #[test]
    fn form_string_keeps_leading_at_literal() {
        let form = prepare_multipart(&[FormSpec::new(
            FormKind::FormString,
            "field=@literal".to_string(),
        )])
        .unwrap();

        assert!(form.is_some());
    }
}
