use std::io::{self, Read};
use std::path::Path;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use reqwest::multipart::{Form, Part};
use url::{Url, form_urlencoded};

use crate::error::{CurlError, Result};

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMultipart {
    pub bytes: Vec<u8>,
    pub content_type: String,
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

pub fn prepare_multipart_body(specs: &[FormSpec]) -> Result<Option<PreparedMultipart>> {
    if specs.is_empty() {
        return Ok(None);
    }

    let boundary = "----------------------------------9ef8d6205763";
    let mut bytes = Vec::new();
    for spec in specs {
        append_multipart_part(&mut bytes, boundary, spec)?;
    }
    bytes.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Ok(Some(PreparedMultipart {
        bytes,
        content_type: format!("multipart/form-data; boundary={boundary}"),
    }))
}

pub fn read_upload_body(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        read_data_argument(path)
    } else {
        read_local_file(path)
    }
}

pub fn append_upload_filename_to_url(url: &mut Url, upload_path: Option<&str>) {
    let Some(upload_path) = upload_path else {
        return;
    };
    if upload_path == "-" || url.query().is_some() || !url.path().ends_with('/') {
        return;
    }

    let Some(filename) = Path::new(upload_path)
        .file_name()
        .and_then(|filename| filename.to_str())
        .filter(|filename| !filename.is_empty())
    else {
        return;
    };

    let mut path = url.path().to_string();
    path.push_str(&utf8_percent_encode(filename, PATH_SEGMENT_ENCODE_SET).to_string());
    url.set_path(&path);
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
            if let Some(mime) = form_content_type_option(options) {
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
            if let Some(mime) = form_content_type_option(options) {
                part = part
                    .mime_str(&mime)
                    .map_err(|error| CurlError::Usage(format!("bad form MIME type: {error}")))?;
            }
            return Ok(form.part(name.to_string(), part));
        }
    }

    Ok(form.text(name.to_string(), value.to_string()))
}

fn append_multipart_part(bytes: &mut Vec<u8>, boundary: &str, spec: &FormSpec) -> Result<()> {
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

    bytes.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    if spec.kind == FormKind::Form {
        if let Some(file) = value.strip_prefix('@') {
            let (path, options) = split_form_options(file);
            if path.is_empty() {
                return Err(CurlError::Usage("form file path is empty".to_string()));
            }
            let body = read_data_argument(path)?;
            let filename = form_option(options, "filename")
                .unwrap_or_else(|| default_form_filename(path).to_string());
            append_content_disposition(bytes, name, Some(&filename));
            let content_type = form_content_type_option(options)
                .unwrap_or_else(|| default_multipart_file_content_type(path).to_string());
            bytes.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
            bytes.extend_from_slice(b"\r\n");
            bytes.extend_from_slice(&body);
            bytes.extend_from_slice(b"\r\n");
            return Ok(());
        }

        if let Some(file) = value.strip_prefix('<') {
            let (path, options) = split_form_options(file);
            if path.is_empty() {
                return Err(CurlError::Usage("form file path is empty".to_string()));
            }
            let body = read_data_argument(path)?;
            append_content_disposition(bytes, name, None);
            if let Some(content_type) = form_content_type_option(options) {
                bytes.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
            }
            bytes.extend_from_slice(b"\r\n");
            bytes.extend_from_slice(&body);
            bytes.extend_from_slice(b"\r\n");
            return Ok(());
        }
    }

    let (value, options) = if spec.kind == FormKind::Form {
        split_form_options(value)
    } else {
        (value, "")
    };
    let content_type = form_content_type_option(options);
    append_content_disposition(bytes, name, None);
    if let Some(content_type) = content_type.as_deref() {
        bytes.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    let value = if content_type.is_some() {
        value.trim_start()
    } else {
        value
    };
    bytes.extend_from_slice(value.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    Ok(())
}

fn append_content_disposition(bytes: &mut Vec<u8>, name: &str, filename: Option<&str>) {
    bytes.extend_from_slice(b"Content-Disposition: form-data; name=\"");
    bytes.extend_from_slice(escape_multipart_quoted(name).as_bytes());
    bytes.extend_from_slice(b"\"");
    if let Some(filename) = filename {
        bytes.extend_from_slice(b"; filename=\"");
        bytes.extend_from_slice(escape_multipart_quoted(filename).as_bytes());
        bytes.extend_from_slice(b"\"");
    }
    bytes.extend_from_slice(b"\r\n");
}

fn escape_multipart_quoted(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'\r' => escaped.push_str("%0D"),
            b'\n' => escaped.push_str("%0A"),
            b'"' => escaped.push_str("%22"),
            _ => escaped.push(byte as char),
        }
    }
    escaped
}

fn split_form_options(value: &str) -> (&str, &str) {
    value
        .split_once(';')
        .map_or((value, ""), |(path, options)| (path, options))
}

fn form_option(options: &str, key: &str) -> Option<String> {
    for part in options.split(';') {
        let (name, value) = part.split_once('=')?;
        let name = name.trim();
        let value = value.trim();
        if name == key && !value.is_empty() {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn form_content_type_option(options: &str) -> Option<String> {
    let mut parts = options.split(';').map(str::trim).peekable();
    while let Some(part) = parts.next() {
        let (name, value) = part.split_once('=')?;
        if name.trim() != "type" {
            continue;
        }

        let mut content_type = value.trim().trim_matches('"').to_string();
        while let Some(next) = parts.peek().copied() {
            let option_name = next.split_once('=').map(|(name, _)| name.trim());
            if matches!(option_name, Some("filename")) {
                break;
            }
            if !next.is_empty() {
                content_type.push(';');
                content_type.push_str(next);
            }
            parts.next();
        }
        return (!content_type.is_empty()).then_some(content_type);
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

fn default_multipart_file_content_type(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("txt" | "text" | "c" | "h" | "html" | "htm" | "css" | "csv" | "xml") => "text/plain",
        _ => "application/octet-stream",
    }
}

fn read_data_argument(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        read_local_file(path)
    }
}

fn read_local_file(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|_| CurlError::ReadError(format!("cannot open '{path}'")))
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

    #[test]
    fn missing_form_file_returns_read_error() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing.txt");
        let spec = format!("field=@{}", missing.display());

        let error = match prepare_multipart(&[FormSpec::new(FormKind::Form, spec)]) {
            Ok(_) => panic!("missing form file should fail"),
            Err(error) => error,
        };

        assert!(matches!(error, CurlError::ReadError(_)));
        assert_eq!(error.exit_code(), 26);
    }

    #[test]
    fn prepares_raw_multipart_fields_and_text_file() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("test9.txt");
        std::fs::write(&file, "foo-\nThis is a moo-\nbar\n").unwrap();

        let body = prepare_multipart_body(&[
            FormSpec::new(FormKind::Form, "name=daniel".to_string()),
            FormSpec::new(FormKind::Form, "tool=curl".to_string()),
            FormSpec::new(FormKind::Form, format!("file=@{}", file.display())),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(body.bytes.len(), 431);
        assert!(
            body.content_type
                .starts_with("multipart/form-data; boundary=")
        );
        let wire = String::from_utf8(body.bytes).unwrap();
        assert!(wire.contains(
            "Content-Disposition: form-data; name=\"file\"; filename=\"test9.txt\"\r\n\
             Content-Type: text/plain\r\n"
        ));
        assert!(wire.ends_with("--\r\n"));
    }

    #[test]
    fn raw_multipart_keeps_type_parameters_and_trims_typed_field_padding() {
        let body = prepare_multipart_body(&[FormSpec::new(
            FormKind::Form,
            "html= <body>hello</body>;type=text/html;charset=verymoo".to_string(),
        )])
        .unwrap()
        .unwrap();

        let wire = String::from_utf8(body.bytes).unwrap();
        assert!(wire.contains(
            "Content-Disposition: form-data; name=\"html\"\r\n\
             Content-Type: text/html;charset=verymoo\r\n\
             \r\n\
             <body>hello</body>\r\n"
        ));
    }
}
