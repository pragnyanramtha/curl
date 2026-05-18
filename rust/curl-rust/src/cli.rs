use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use crate::data::{DataKind, DataSpec, FormKind, FormSpec};
use crate::error::{CurlError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub show_help: bool,
    pub show_version: bool,
    pub transfers: Vec<TransferConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferConfig {
    pub urls: Vec<String>,
    pub method: Option<String>,
    pub head: bool,
    pub get: bool,
    pub include_headers: bool,
    pub headers: Vec<String>,
    pub data: Vec<DataSpec>,
    pub url_query: Vec<DataSpec>,
    pub forms: Vec<FormSpec>,
    pub output: Option<String>,
    pub output_dir: Option<PathBuf>,
    pub remote_name: bool,
    pub remote_header_name: bool,
    pub dump_header: Option<PathBuf>,
    pub etag_compare: Option<PathBuf>,
    pub etag_save: Option<PathBuf>,
    pub time_cond: Option<String>,
    pub write_out: Option<String>,
    pub follow_location: bool,
    pub max_redirs: usize,
    pub retry: usize,
    pub retry_all_errors: bool,
    pub retry_connrefused: bool,
    pub retry_delay: Duration,
    pub retry_max_time: Duration,
    pub fail: bool,
    pub fail_with_body: bool,
    pub user: Option<String>,
    pub oauth2_bearer: Option<String>,
    pub proxy: Option<String>,
    pub proxy_user: Option<String>,
    pub noproxy: Option<String>,
    pub insecure: bool,
    pub connect_timeout: Option<Duration>,
    pub max_time: Option<Duration>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub range: Option<String>,
    pub continue_at: Option<ContinueAt>,
    pub cookie: Option<String>,
    pub cookie_jar: Option<PathBuf>,
    pub compressed: bool,
    pub verbose: bool,
    pub silent: bool,
    pub show_error: bool,
    pub globoff: bool,
    pub create_dirs: bool,
    pub http_version: HttpVersionPreference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinueAt {
    Offset(u64),
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersionPreference {
    Any,
    Http10,
    Http11,
    Http2,
    Http2PriorKnowledge,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            show_help: false,
            show_version: false,
            transfers: vec![TransferConfig::default()],
        }
    }
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            method: None,
            head: false,
            get: false,
            include_headers: false,
            headers: Vec::new(),
            data: Vec::new(),
            url_query: Vec::new(),
            forms: Vec::new(),
            output: None,
            output_dir: None,
            remote_name: false,
            remote_header_name: false,
            dump_header: None,
            etag_compare: None,
            etag_save: None,
            time_cond: None,
            write_out: None,
            follow_location: false,
            max_redirs: 50,
            retry: 0,
            retry_all_errors: false,
            retry_connrefused: false,
            retry_delay: Duration::ZERO,
            retry_max_time: Duration::ZERO,
            fail: false,
            fail_with_body: false,
            user: None,
            oauth2_bearer: None,
            proxy: None,
            proxy_user: None,
            noproxy: None,
            insecure: false,
            connect_timeout: None,
            max_time: None,
            user_agent: None,
            referer: None,
            range: None,
            continue_at: None,
            cookie: None,
            cookie_jar: None,
            compressed: false,
            verbose: false,
            silent: false,
            show_error: false,
            globoff: false,
            create_dirs: false,
            http_version: HttpVersionPreference::Any,
        }
    }
}

pub fn parse_args<I, S>(args: I) -> Result<Config>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.into().to_string_lossy().into_owned())
        .collect();
    if should_load_default_config(&args)
        && let Some(path) = default_config_path()
        && path.is_file()
    {
        let mut config_args = read_config_tokens(&path)?;
        config_args.append(&mut args);
        args = config_args;
    }

    let mut parser = Parser {
        args,
        pos: 0,
        config: Config::default(),
        loaded_configs: 0,
    };
    parser.parse()
}

struct Parser {
    args: Vec<String>,
    pos: usize,
    config: Config,
    loaded_configs: usize,
}

impl Parser {
    fn parse(&mut self) -> Result<Config> {
        while let Some(arg) = self.next() {
            if arg == "--" {
                while let Some(url) = self.next() {
                    self.current().urls.push(url);
                }
                break;
            }

            if let Some(long) = arg.strip_prefix("--") {
                self.parse_long(long)?;
            } else if arg.starts_with('-') && arg.len() > 1 {
                self.parse_short(&arg[1..])?;
            } else {
                self.current().urls.push(arg);
            }
        }

        self.config.transfers.retain(TransferConfig::has_options);

        if self.config.transfers.is_empty() && !self.config.show_help && !self.config.show_version {
            return Err(CurlError::Usage("no URL specified".to_string()));
        }
        if !self.config.show_help
            && !self.config.show_version
            && self
                .config
                .transfers
                .iter()
                .any(|transfer| transfer.urls.is_empty())
        {
            return Err(CurlError::Usage("no URL specified".to_string()));
        }

        Ok(std::mem::take(&mut self.config))
    }

    fn parse_long(&mut self, raw: &str) -> Result<()> {
        let (name, inline_value) = raw
            .split_once('=')
            .map_or((raw, None), |(name, value)| (name, Some(value.to_string())));

        if let Some(name) = name.strip_prefix("no-") {
            if inline_value.is_some() {
                return Err(CurlError::Usage(format!(
                    "option --no-{name} does not take a value"
                )));
            }
            self.parse_no_long(name)?;
            return Ok(());
        }

        match name {
            "help" => self.config.show_help = true,
            "version" => self.config.show_version = true,
            "disable" => {}
            "config" => {
                let value = self.value_for(name, inline_value)?;
                self.insert_config_file(&value)?;
            }
            "url" => {
                let value = self.value_for(name, inline_value)?;
                self.current().urls.push(value);
            }
            "next" => {
                self.config.transfers.push(TransferConfig::default());
            }
            "request" => {
                let value = self.value_for(name, inline_value)?;
                self.current().method = Some(value);
            }
            "head" => self.current().head = true,
            "get" => self.current().get = true,
            "include" => self.current().include_headers = true,
            "header" => {
                let value = self.value_for(name, inline_value)?;
                self.current().headers.push(value);
            }
            "referer" => {
                let value = self.value_for(name, inline_value)?;
                self.current().referer = Some(value);
            }
            "range" => {
                let value = self.value_for(name, inline_value)?;
                if self.current().continue_at.is_some() {
                    return Err(CurlError::Usage(
                        "--range is mutually exclusive with --continue-at".to_string(),
                    ));
                }
                self.current().range = Some(value);
            }
            "continue-at" => {
                let value = self.value_for(name, inline_value)?;
                if self.current().range.is_some() {
                    return Err(CurlError::Usage(
                        "--continue-at is mutually exclusive with --range".to_string(),
                    ));
                }
                self.current().continue_at = Some(parse_continue_at(name, &value)?);
            }
            "data" | "data-ascii" => {
                let value = self.value_for(name, inline_value)?;
                self.current()
                    .data
                    .push(DataSpec::new(DataKind::UrlEncoded, value));
            }
            "data-raw" => {
                let value = self.value_for(name, inline_value)?;
                self.current()
                    .data
                    .push(DataSpec::new(DataKind::Raw, value));
            }
            "data-binary" => {
                let value = self.value_for(name, inline_value)?;
                self.current()
                    .data
                    .push(DataSpec::new(DataKind::Binary, value));
            }
            "data-urlencode" => {
                let value = self.value_for(name, inline_value)?;
                self.current()
                    .data
                    .push(DataSpec::new(DataKind::UrlEncodeField, value));
            }
            "json" => {
                let value = self.value_for(name, inline_value)?;
                self.current()
                    .data
                    .push(DataSpec::new(DataKind::Json, value));
            }
            "url-query" => {
                let value = self.value_for(name, inline_value)?;
                let (kind, value) = if let Some(raw) = value.strip_prefix('+') {
                    (DataKind::Raw, raw.to_string())
                } else {
                    (DataKind::UrlEncodeField, value)
                };
                self.current().url_query.push(DataSpec::new(kind, value));
            }
            "form" => {
                let value = self.value_for(name, inline_value)?;
                self.current()
                    .forms
                    .push(FormSpec::new(FormKind::Form, value));
            }
            "form-string" => {
                let value = self.value_for(name, inline_value)?;
                self.current()
                    .forms
                    .push(FormSpec::new(FormKind::FormString, value));
            }
            "output" => {
                let value = self.value_for(name, inline_value)?;
                self.current().output = Some(value);
            }
            "output-dir" => {
                let value = self.value_for(name, inline_value)?;
                self.current().output_dir = Some(PathBuf::from(value));
            }
            "remote-name" => self.current().remote_name = true,
            "remote-header-name" => self.current().remote_header_name = true,
            "dump-header" => {
                let value = self.value_for(name, inline_value)?;
                self.current().dump_header = Some(PathBuf::from(value));
            }
            "etag-compare" => {
                let value = self.value_for(name, inline_value)?;
                self.current().etag_compare = Some(PathBuf::from(value));
            }
            "etag-save" => {
                let value = self.value_for(name, inline_value)?;
                self.current().etag_save = Some(PathBuf::from(value));
            }
            "time-cond" => {
                let value = self.value_for(name, inline_value)?;
                self.current().time_cond = Some(value);
            }
            "write-out" => {
                let value = self.value_for(name, inline_value)?;
                self.current().write_out = Some(value);
            }
            "location" | "location-trusted" => self.current().follow_location = true,
            "max-redirs" => {
                let value = self.value_for(name, inline_value)?;
                self.current().max_redirs = parse_usize(name, &value)?;
            }
            "retry" => {
                let value = self.value_for(name, inline_value)?;
                self.current().retry = parse_usize(name, &value)?;
            }
            "retry-all-errors" => self.current().retry_all_errors = true,
            "retry-connrefused" => self.current().retry_connrefused = true,
            "retry-delay" => {
                let value = self.value_for(name, inline_value)?;
                self.current().retry_delay = parse_retry_delay(name, &value)?;
            }
            "retry-max-time" => {
                let value = self.value_for(name, inline_value)?;
                self.current().retry_max_time = parse_duration(name, &value)?;
            }
            "fail" => self.current().fail = true,
            "fail-with-body" => {
                self.current().fail = true;
                self.current().fail_with_body = true;
            }
            "user" => {
                let value = self.value_for(name, inline_value)?;
                self.current().user = Some(value);
            }
            "oauth2-bearer" => {
                let value = self.value_for(name, inline_value)?;
                self.current().oauth2_bearer = Some(value);
            }
            "proxy" => {
                let value = self.value_for(name, inline_value)?;
                self.current().proxy = Some(value);
            }
            "proxy-user" => {
                let value = self.value_for(name, inline_value)?;
                self.current().proxy_user = Some(value);
            }
            "noproxy" => {
                let value = self.value_for(name, inline_value)?;
                self.current().noproxy = Some(value);
            }
            "insecure" => self.current().insecure = true,
            "connect-timeout" => {
                let value = self.value_for(name, inline_value)?;
                self.current().connect_timeout = Some(parse_duration(name, &value)?);
            }
            "max-time" => {
                let value = self.value_for(name, inline_value)?;
                self.current().max_time = Some(parse_duration(name, &value)?);
            }
            "user-agent" => {
                let value = self.value_for(name, inline_value)?;
                self.current().user_agent = Some(value);
            }
            "cookie" => {
                let value = self.value_for(name, inline_value)?;
                self.current().cookie = Some(value);
            }
            "cookie-jar" => {
                let value = self.value_for(name, inline_value)?;
                self.current().cookie_jar = Some(parse_nonempty_path(name, &value)?);
            }
            "compressed" => self.current().compressed = true,
            "verbose" => self.current().verbose = true,
            "silent" | "no-progress-meter" => self.current().silent = true,
            "show-error" => self.current().show_error = true,
            "globoff" => self.current().globoff = true,
            "create-dirs" => self.current().create_dirs = true,
            "http1.0" => self.current().http_version = HttpVersionPreference::Http10,
            "http1.1" => self.current().http_version = HttpVersionPreference::Http11,
            "http2" => {
                self.current().http_version = HttpVersionPreference::Http2;
            }
            "http2-prior-knowledge" => {
                self.current().http_version = HttpVersionPreference::Http2PriorKnowledge;
            }
            "http3" | "http3-only" => {
                return Err(CurlError::Unsupported(format!("--{name}")));
            }
            other => return Err(CurlError::Usage(format!("unknown option --{other}"))),
        }

        Ok(())
    }

    fn parse_no_long(&mut self, name: &str) -> Result<()> {
        match name {
            "head" => self.current().head = false,
            "get" => self.current().get = false,
            "include" => self.current().include_headers = false,
            "remote-name" => self.current().remote_name = false,
            "remote-header-name" => self.current().remote_header_name = false,
            "location" | "location-trusted" => self.current().follow_location = false,
            "retry-all-errors" => self.current().retry_all_errors = false,
            "retry-connrefused" => self.current().retry_connrefused = false,
            "fail" => {
                self.current().fail = false;
                self.current().fail_with_body = false;
            }
            "fail-with-body" => self.current().fail_with_body = false,
            "insecure" => self.current().insecure = false,
            "compressed" => self.current().compressed = false,
            "verbose" => self.current().verbose = false,
            "silent" => self.current().silent = false,
            "show-error" => self.current().show_error = false,
            "globoff" => self.current().globoff = false,
            "create-dirs" => self.current().create_dirs = false,
            other => return Err(CurlError::Usage(format!("unknown option --no-{other}"))),
        }
        Ok(())
    }

    fn parse_short(&mut self, raw: &str) -> Result<()> {
        let mut chars = raw.char_indices().peekable();
        while let Some((idx, ch)) = chars.next() {
            let rest_start = idx + ch.len_utf8();
            let rest = &raw[rest_start..];
            match ch {
                'h' => {
                    if rest.is_empty() {
                        self.config.show_help = true;
                    } else {
                        self.current().headers.push(rest.to_string());
                        break;
                    }
                }
                'V' => self.config.show_version = true,
                'q' => {}
                'K' => {
                    let value = self.short_value('K', rest)?;
                    self.insert_config_file(&value)?;
                    break;
                }
                ':' => self.config.transfers.push(TransferConfig::default()),
                'X' => {
                    let value = self.short_value('X', rest)?;
                    self.current().method = Some(value);
                    break;
                }
                'I' => self.current().head = true,
                'G' => self.current().get = true,
                'i' => self.current().include_headers = true,
                'H' => {
                    let value = self.short_value('H', rest)?;
                    self.current().headers.push(value);
                    break;
                }
                'e' => {
                    let value = self.short_value('e', rest)?;
                    self.current().referer = Some(value);
                    break;
                }
                'r' => {
                    let value = self.short_value('r', rest)?;
                    if self.current().continue_at.is_some() {
                        return Err(CurlError::Usage(
                            "--range is mutually exclusive with --continue-at".to_string(),
                        ));
                    }
                    self.current().range = Some(value);
                    break;
                }
                'C' => {
                    let value = self.short_value('C', rest)?;
                    if self.current().range.is_some() {
                        return Err(CurlError::Usage(
                            "--continue-at is mutually exclusive with --range".to_string(),
                        ));
                    }
                    self.current().continue_at = Some(parse_continue_at("continue-at", &value)?);
                    break;
                }
                'd' => {
                    let value = self.short_value('d', rest)?;
                    self.current()
                        .data
                        .push(DataSpec::new(DataKind::UrlEncoded, value));
                    break;
                }
                'F' => {
                    let value = self.short_value('F', rest)?;
                    self.current()
                        .forms
                        .push(FormSpec::new(FormKind::Form, value));
                    break;
                }
                'o' => {
                    let value = self.short_value('o', rest)?;
                    self.current().output = Some(value);
                    break;
                }
                'O' => self.current().remote_name = true,
                'J' => self.current().remote_header_name = true,
                'D' => {
                    let value = self.short_value('D', rest)?;
                    self.current().dump_header = Some(PathBuf::from(value));
                    break;
                }
                'z' => {
                    let value = self.short_value('z', rest)?;
                    self.current().time_cond = Some(value);
                    break;
                }
                'w' => {
                    let value = self.short_value('w', rest)?;
                    self.current().write_out = Some(value);
                    break;
                }
                'L' => self.current().follow_location = true,
                'f' => self.current().fail = true,
                'u' => {
                    let value = self.short_value('u', rest)?;
                    self.current().user = Some(value);
                    break;
                }
                'U' => {
                    let value = self.short_value('U', rest)?;
                    self.current().proxy_user = Some(value);
                    break;
                }
                'x' => {
                    let value = self.short_value('x', rest)?;
                    self.current().proxy = Some(value);
                    break;
                }
                'k' => self.current().insecure = true,
                'm' => {
                    let value = self.short_value('m', rest)?;
                    self.current().max_time = Some(parse_duration("max-time", &value)?);
                    break;
                }
                'A' => {
                    let value = self.short_value('A', rest)?;
                    self.current().user_agent = Some(value);
                    break;
                }
                'b' => {
                    let value = self.short_value('b', rest)?;
                    self.current().cookie = Some(value);
                    break;
                }
                'c' => {
                    let value = self.short_value('c', rest)?;
                    self.current().cookie_jar = Some(parse_nonempty_path("cookie-jar", &value)?);
                    break;
                }
                's' => self.current().silent = true,
                'S' => self.current().show_error = true,
                'v' => self.current().verbose = true,
                'g' => self.current().globoff = true,
                '0' => self.current().http_version = HttpVersionPreference::Http10,
                '1' => self.current().http_version = HttpVersionPreference::Http11,
                '2' => self.current().http_version = HttpVersionPreference::Http2,
                '?' => self.config.show_help = true,
                other => return Err(CurlError::Usage(format!("unknown option -{other}"))),
            }

            if chars.peek().is_none() {
                break;
            }
        }

        Ok(())
    }

    fn value_for(&mut self, name: &str, inline_value: Option<String>) -> Result<String> {
        inline_value.map_or_else(
            || {
                self.next()
                    .ok_or_else(|| CurlError::Usage(format!("option --{name} requires a value")))
            },
            Ok,
        )
    }

    fn short_value(&mut self, option: char, rest: &str) -> Result<String> {
        if rest.is_empty() {
            self.next()
                .ok_or_else(|| CurlError::Usage(format!("option -{option} requires a value")))
        } else {
            Ok(rest.to_string())
        }
    }

    fn next(&mut self) -> Option<String> {
        let next = self.args.get(self.pos).cloned();
        self.pos += usize::from(next.is_some());
        next
    }

    fn current(&mut self) -> &mut TransferConfig {
        self.config
            .transfers
            .last_mut()
            .expect("parser always has a current transfer")
    }

    fn insert_config_file(&mut self, path: &str) -> Result<()> {
        self.loaded_configs += 1;
        if self.loaded_configs > 20 {
            return Err(CurlError::Usage(
                "too many nested --config files".to_string(),
            ));
        }

        let tokens = if path == "-" {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            tokenize_config(&text)?
        } else {
            read_config_tokens(PathBuf::from(path).as_path())?
        };

        self.args.splice(self.pos..self.pos, tokens);
        Ok(())
    }
}

impl TransferConfig {
    fn has_options(&self) -> bool {
        !self.urls.is_empty()
            || self.method.is_some()
            || self.head
            || self.get
            || self.include_headers
            || !self.headers.is_empty()
            || !self.data.is_empty()
            || !self.url_query.is_empty()
            || !self.forms.is_empty()
            || self.output.is_some()
            || self.output_dir.is_some()
            || self.remote_name
            || self.remote_header_name
            || self.dump_header.is_some()
            || self.etag_compare.is_some()
            || self.etag_save.is_some()
            || self.time_cond.is_some()
            || self.write_out.is_some()
            || self.follow_location
            || self.retry != 0
            || self.retry_all_errors
            || self.retry_connrefused
            || self.retry_delay != Duration::ZERO
            || self.retry_max_time != Duration::ZERO
            || self.fail
            || self.fail_with_body
            || self.user.is_some()
            || self.oauth2_bearer.is_some()
            || self.proxy.is_some()
            || self.proxy_user.is_some()
            || self.noproxy.is_some()
            || self.insecure
            || self.connect_timeout.is_some()
            || self.max_time.is_some()
            || self.user_agent.is_some()
            || self.referer.is_some()
            || self.range.is_some()
            || self.continue_at.is_some()
            || self.cookie.is_some()
            || self.cookie_jar.is_some()
            || self.compressed
            || self.verbose
            || self.silent
            || self.show_error
            || self.globoff
            || self.create_dirs
            || self.http_version != HttpVersionPreference::Any
    }
}

fn parse_usize(name: &str, value: &str) -> Result<usize> {
    value
        .parse()
        .map_err(|_| CurlError::Usage(format!("option --{name} expects an integer")))
}

fn parse_u64(name: &str, value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| CurlError::Usage(format!("option --{name} expects an integer")))
}

fn parse_continue_at(name: &str, value: &str) -> Result<ContinueAt> {
    if value == "-" {
        Ok(ContinueAt::Auto)
    } else {
        Ok(ContinueAt::Offset(parse_u64(name, value)?))
    }
}

fn parse_nonempty_path(name: &str, value: &str) -> Result<PathBuf> {
    if value.is_empty() {
        Err(CurlError::Usage(format!(
            "option --{name} requires a non-empty value"
        )))
    } else {
        Ok(PathBuf::from(value))
    }
}

fn parse_duration(name: &str, value: &str) -> Result<Duration> {
    let seconds: f64 = value
        .parse()
        .map_err(|_| CurlError::Usage(format!("option --{name} expects seconds")))?;
    if seconds.is_sign_negative() || !seconds.is_finite() || seconds > u64::MAX as f64 {
        return Err(CurlError::Usage(format!(
            "option --{name} expects a non-negative duration"
        )));
    }
    Ok(Duration::from_secs_f64(seconds))
}

fn parse_retry_delay(name: &str, value: &str) -> Result<Duration> {
    let duration = parse_duration(name, value)?;
    if duration.as_millis() > i32::MAX as u128 {
        return Err(CurlError::Usage(format!(
            "option --{name} value is too large"
        )));
    }
    Ok(duration)
}

pub fn print_help() {
    println!(
        "Usage: curl [options...] <url>\n\
         Rust curl rewrite prototype\n\n\
         Common options:\n\
           -d, --data <data>           HTTP POST data\n\
               --data-binary <data>    HTTP POST binary data\n\
               --data-urlencode <data> Percent-encode POST data\n\
           -F, --form <name=content>   Specify multipart form data\n\
               --url-query <data>      Add URL query data\n\
               --json <data>           JSON request body\n\
           -e, --referer <url>         Send Referer header\n\
           -r, --range <range>         Request a byte range\n\
           -C, --continue-at <offset>  Resume transfer at offset\n\
           -H, --header <header>       Pass custom header\n\
           -I, --head                  Show document information only\n\
           -L, --location              Follow redirects\n\
               --retry <num>           Retry transient transfer problems\n\
               --retry-delay <seconds> Wait time between retries\n\
               --retry-max-time <sec>  Retry only within this period\n\
           -o, --output <file>         Write output to file\n\
           -O, --remote-name           Write output to remote filename\n\
               --etag-compare <file>   Load ETag from file\n\
               --etag-save <file>      Save response ETag to file\n\
           -z, --time-cond <time>      Transfer based on time condition\n\
           -w, --write-out <format>    Write transfer metrics\n\
           -X, --request <method>      Specify request method\n\
           -u, --user <user:pass>      Server user and password\n\
           -b, --cookie <data>         Send cookies from string\n\
           -c, --cookie-jar <file>     Save cookies to file\n\
               --oauth2-bearer <token> OAuth 2 Bearer token\n\
           -U, --proxy-user <user:pass> Proxy user and password\n\
               --noproxy <list>        List hosts that do not use proxy\n\
           -k, --insecure              Allow insecure TLS\n\
           -s, --silent                Silent mode\n\
           -v, --verbose               Verbose transfer trace\n\
           -V, --version               Show version"
    );
}

pub fn print_version() {
    println!(
        "curl-rust {} (Rust rewrite) HTTP HTTPS FILE",
        env!("CARGO_PKG_VERSION")
    );
}

fn should_load_default_config(args: &[String]) -> bool {
    !matches!(args.first().map(String::as_str), Some("-q" | "--disable"))
}

fn default_config_path() -> Option<PathBuf> {
    std::env::var_os("CURL_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .map(|home| home.join(".curlrc"))
}

fn read_config_tokens(path: &std::path::Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)?;
    tokenize_config(&text)
}

fn tokenize_config(text: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    for line in text.lines() {
        let line = strip_config_comment(line).trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = shell_words(line)?;
        if parts.is_empty() {
            continue;
        }

        if parts[0].starts_with('-') {
            tokens.extend(parts);
            continue;
        }

        let key = parts.remove(0);
        let key = key.trim_end_matches('=');
        if key.is_empty() {
            continue;
        }
        tokens.push(format!("--{key}"));

        if let Some(first) = parts.first_mut() {
            if first == "=" {
                parts.remove(0);
            } else if let Some(value) = first.strip_prefix('=') {
                *first = value.to_string();
            }
        }
        tokens.extend(parts);
    }
    Ok(tokens)
}

fn strip_config_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..index],
            _ => {}
        }
    }
    line
}

fn shell_words(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut has_word = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            has_word = true;
            escaped = false;
            continue;
        }

        match ch {
            '\\' if !in_single => escaped = true,
            '\'' if !in_double => {
                in_single = !in_single;
                has_word = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_word = true;
            }
            '=' if !in_single && !in_double => {
                if has_word {
                    words.push(std::mem::take(&mut current));
                }
                words.push("=".to_string());
                has_word = false;
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if has_word {
                    words.push(std::mem::take(&mut current));
                    has_word = false;
                }
            }
            other => {
                current.push(other);
                has_word = true;
            }
        }
    }

    if escaped || in_single || in_double {
        return Err(CurlError::Usage(
            "unterminated quote or escape in config file".to_string(),
        ));
    }
    if has_word {
        words.push(current);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_request_options() {
        let config = parse_args([
            "-q",
            "-sSL",
            "-e",
            "https://refer.example/",
            "-r",
            "0-99",
            "-H",
            "Accept: text/plain",
            "--data",
            "a=b",
            "-o",
            "out.txt",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(transfer.silent);
        assert!(transfer.show_error);
        assert!(transfer.follow_location);
        assert_eq!(transfer.referer.as_deref(), Some("https://refer.example/"));
        assert_eq!(transfer.range.as_deref(), Some("0-99"));
        assert_eq!(transfer.headers, ["Accept: text/plain"]);
        assert_eq!(transfer.data[0].value, "a=b");
        assert_eq!(transfer.output.as_deref(), Some("out.txt"));
        assert_eq!(transfer.urls, ["https://example.com"]);
    }

    #[test]
    fn splits_transfer_groups_on_next() {
        let config = parse_args([
            "-q",
            "https://one.example",
            "--next",
            "-I",
            "https://two.example",
        ])
        .unwrap();

        assert_eq!(config.transfers.len(), 2);
        assert!(!config.transfers[0].head);
        assert!(config.transfers[1].head);
    }

    #[test]
    fn tokenizes_curl_config_lines() {
        let tokens = tokenize_config(
            r#"
            # comment
            silent
            header = "Accept: application/json"
            --url https://example.com
            "#,
        )
        .unwrap();

        assert_eq!(
            tokens,
            [
                "--silent",
                "--header",
                "Accept: application/json",
                "--url",
                "https://example.com"
            ]
        );
    }

    #[test]
    fn rejects_url_less_option_group() {
        let error = parse_args(["-q", "-d", "x"]).unwrap_err();
        assert!(error.to_string().contains("no URL specified"));
    }

    #[test]
    fn distinguishes_http2_modes() {
        let config = parse_args(["-q", "--http2", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].http_version,
            HttpVersionPreference::Http2
        );

        let config = parse_args(["-q", "--http2-prior-knowledge", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].http_version,
            HttpVersionPreference::Http2PriorKnowledge
        );
    }

    #[test]
    fn parses_url_query_and_form_options() {
        let config = parse_args([
            "-q",
            "--url-query",
            "q=hello world",
            "--url-query",
            "+already=encoded%20value",
            "-F",
            "field=value",
            "--form-string",
            "literal=@not-file",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.url_query.len(), 2);
        assert_eq!(transfer.url_query[0].kind, DataKind::UrlEncodeField);
        assert_eq!(transfer.url_query[0].value, "q=hello world");
        assert_eq!(transfer.url_query[1].kind, DataKind::Raw);
        assert_eq!(transfer.url_query[1].value, "already=encoded%20value");
        assert_eq!(transfer.forms.len(), 2);
        assert_eq!(transfer.forms[0].kind, FormKind::Form);
        assert_eq!(transfer.forms[1].kind, FormKind::FormString);
    }

    #[test]
    fn parses_bearer_proxy_user_and_noproxy() {
        let config = parse_args([
            "-q",
            "--oauth2-bearer",
            "token",
            "--etag-compare",
            "etag.in",
            "--etag-save",
            "etag.out",
            "-z",
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "-x",
            "http://proxy.example:8080",
            "-U",
            "proxy-user:secret",
            "--noproxy",
            "example.com",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.oauth2_bearer.as_deref(), Some("token"));
        assert_eq!(
            transfer.etag_compare.as_deref(),
            Some(std::path::Path::new("etag.in"))
        );
        assert_eq!(
            transfer.etag_save.as_deref(),
            Some(std::path::Path::new("etag.out"))
        );
        assert_eq!(
            transfer.time_cond.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
        assert_eq!(transfer.proxy.as_deref(), Some("http://proxy.example:8080"));
        assert_eq!(transfer.proxy_user.as_deref(), Some("proxy-user:secret"));
        assert_eq!(transfer.noproxy.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_cookie_jar_options() {
        let config = parse_args(["-q", "-c", "jar.txt", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].cookie_jar.as_deref(),
            Some(std::path::Path::new("jar.txt"))
        );

        let config = parse_args(["-q", "-cjar.txt", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].cookie_jar.as_deref(),
            Some(std::path::Path::new("jar.txt"))
        );

        let config = parse_args(["-q", "--cookie-jar=jar.txt", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].cookie_jar.as_deref(),
            Some(std::path::Path::new("jar.txt"))
        );
    }

    #[test]
    fn rejects_empty_cookie_jar_path() {
        let error = parse_args(["-q", "--cookie-jar=", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("non-empty"));
    }

    #[test]
    fn parses_continue_at_options() {
        let config = parse_args(["-q", "-C", "42", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].continue_at,
            Some(ContinueAt::Offset(42))
        );

        let config = parse_args(["-q", "-C42", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].continue_at,
            Some(ContinueAt::Offset(42))
        );

        let config = parse_args(["-q", "--continue-at", "-", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].continue_at, Some(ContinueAt::Auto));
    }

    #[test]
    fn rejects_bad_continue_at_offsets() {
        for value in ["abc", "-1", ""] {
            let error = parse_args(["-q", "-C", value, "https://example.com"]).unwrap_err();
            assert!(error.to_string().contains("expects an integer"));
        }
    }

    #[test]
    fn rejects_continue_at_range_combination() {
        let error = parse_args([
            "-q",
            "--continue-at",
            "42",
            "--range",
            "42-",
            "https://example.com",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"));

        let error = parse_args([
            "-q",
            "--range",
            "42-",
            "--continue-at",
            "42",
            "https://example.com",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn parses_retry_options() {
        let config = parse_args([
            "-q",
            "--retry",
            "3",
            "--retry-all-errors",
            "--retry-connrefused",
            "--retry-delay",
            "0.1",
            "--retry-max-time",
            "10",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.retry, 3);
        assert!(transfer.retry_all_errors);
        assert!(transfer.retry_connrefused);
        assert_eq!(transfer.retry_delay, Duration::from_millis(100));
        assert_eq!(transfer.retry_max_time, Duration::from_secs(10));
    }

    #[test]
    fn no_prefixed_retry_booleans_disable_previous_values() {
        let config = parse_args([
            "-q",
            "--retry-all-errors",
            "--retry-connrefused",
            "--no-retry-all-errors",
            "--no-retry-connrefused",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(!transfer.retry_all_errors);
        assert!(!transfer.retry_connrefused);
    }

    #[test]
    fn rejects_retry_delay_overflow() {
        let error = parse_args([
            "-q",
            "--retry-delay",
            "9223372036854776",
            "https://example.com",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("too large"));
    }

    #[test]
    fn no_prefixed_boolean_options_disable_previous_values() {
        let config = parse_args([
            "-q",
            "--location",
            "--compressed",
            "--no-location",
            "--no-compressed",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(!transfer.follow_location);
        assert!(!transfer.compressed);
    }
}
