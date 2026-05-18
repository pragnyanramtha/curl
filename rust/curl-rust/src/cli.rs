use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use crate::data::{DataKind, DataSpec, FormKind, FormSpec};
use crate::error::{CurlError, Result};

pub const PARALLEL_DEFAULT: usize = 50;
pub const PARALLEL_MAX_LIMIT: usize = 65_535;
pub const PARALLEL_MAX_HOST_DEFAULT: usize = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub show_help: bool,
    pub show_version: bool,
    pub libcurl: Option<PathBuf>,
    pub parallel: bool,
    pub parallel_immediate: bool,
    pub parallel_max: usize,
    pub parallel_max_host: usize,
    pub transfers: Vec<TransferConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferConfig {
    pub urls: Vec<String>,
    pub method: Option<String>,
    pub head: bool,
    pub get: bool,
    pub list_only: bool,
    pub include_headers: bool,
    pub headers: Vec<String>,
    pub data: Vec<DataSpec>,
    pub url_query: Vec<DataSpec>,
    pub forms: Vec<FormSpec>,
    pub upload_file: Option<String>,
    pub mail_from: Option<String>,
    pub mail_rcpt: Vec<String>,
    pub mail_rcpt_allowfails: bool,
    pub ssh_private_key: Option<PathBuf>,
    pub ssh_public_key: Option<PathBuf>,
    pub ssh_known_hosts: Option<PathBuf>,
    pub ssh_hostpubmd5: Option<String>,
    pub ssh_hostpubsha256: Option<String>,
    pub compressed_ssh: bool,
    pub tftp_blksize: Option<u16>,
    pub tftp_no_options: bool,
    pub telnet_options: Vec<String>,
    pub ipfs_gateway: Option<String>,
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
    pub max_filesize: Option<u64>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub auto_referer: bool,
    pub range: Option<String>,
    pub continue_at: Option<ContinueAt>,
    pub cookie: Option<String>,
    pub cookie_files: Vec<String>,
    pub cookie_jar: Option<PathBuf>,
    pub junk_session_cookies: bool,
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
            libcurl: None,
            parallel: false,
            parallel_immediate: false,
            parallel_max: PARALLEL_DEFAULT,
            parallel_max_host: PARALLEL_MAX_HOST_DEFAULT,
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
            list_only: false,
            include_headers: false,
            headers: Vec::new(),
            data: Vec::new(),
            url_query: Vec::new(),
            forms: Vec::new(),
            upload_file: None,
            mail_from: None,
            mail_rcpt: Vec::new(),
            mail_rcpt_allowfails: false,
            ssh_private_key: None,
            ssh_public_key: None,
            ssh_known_hosts: None,
            ssh_hostpubmd5: None,
            ssh_hostpubsha256: None,
            compressed_ssh: false,
            tftp_blksize: None,
            tftp_no_options: false,
            telnet_options: Vec::new(),
            ipfs_gateway: None,
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
            max_filesize: None,
            user_agent: None,
            referer: None,
            auto_referer: false,
            range: None,
            continue_at: None,
            cookie: None,
            cookie_files: Vec::new(),
            cookie_jar: None,
            junk_session_cookies: false,
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
            "libcurl" => {
                let value = self.value_for(name, inline_value)?;
                self.config.libcurl = Some(parse_nonempty_path(name, &value)?);
            }
            "url" => {
                let value = self.value_for(name, inline_value)?;
                self.current().urls.push(value);
            }
            "next" => {
                self.config.transfers.push(TransferConfig::default());
            }
            "parallel" => self.config.parallel = true,
            "parallel-immediate" => self.config.parallel_immediate = true,
            "parallel-max" => {
                let value = self.value_for(name, inline_value)?;
                self.config.parallel_max =
                    parse_limited_usize(name, &value, PARALLEL_DEFAULT, PARALLEL_MAX_LIMIT)?;
            }
            "parallel-max-host" => {
                let value = self.value_for(name, inline_value)?;
                self.config.parallel_max_host = parse_limited_usize(
                    name,
                    &value,
                    PARALLEL_MAX_HOST_DEFAULT,
                    PARALLEL_MAX_LIMIT,
                )?;
            }
            "request" => {
                let value = self.value_for(name, inline_value)?;
                self.current().method = Some(value);
            }
            "head" => self.current().head = true,
            "get" => self.current().get = true,
            "list-only" => self.current().list_only = true,
            "include" => self.current().include_headers = true,
            "header" => {
                let value = self.value_for(name, inline_value)?;
                self.current().headers.push(value);
            }
            "referer" => {
                let value = self.value_for(name, inline_value)?;
                self.set_referer(value);
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
            "upload-file" => {
                let value = self.value_for(name, inline_value)?;
                self.current().upload_file = Some(value);
            }
            "mail-from" => {
                let value = self.value_for(name, inline_value)?;
                self.current().mail_from = Some(value);
            }
            "mail-rcpt" => {
                let value = self.value_for(name, inline_value)?;
                self.current().mail_rcpt.push(value);
            }
            "mail-rcpt-allowfails" => self.current().mail_rcpt_allowfails = true,
            "key" => {
                let value = self.value_for(name, inline_value)?;
                self.current().ssh_private_key = Some(parse_nonempty_path(name, &value)?);
            }
            "pubkey" => {
                let value = self.value_for(name, inline_value)?;
                self.current().ssh_public_key = Some(parse_nonempty_path(name, &value)?);
            }
            "knownhosts" => {
                let value = self.value_for(name, inline_value)?;
                self.current().ssh_known_hosts = Some(parse_nonempty_path(name, &value)?);
            }
            "hostpubmd5" => {
                let value = self.value_for(name, inline_value)?;
                self.current().ssh_hostpubmd5 = Some(parse_nonempty_string(name, value)?);
            }
            "hostpubsha256" => {
                let value = self.value_for(name, inline_value)?;
                self.current().ssh_hostpubsha256 = Some(parse_nonempty_string(name, value)?);
            }
            "compressed-ssh" => self.current().compressed_ssh = true,
            "tftp-blksize" => {
                let value = self.value_for(name, inline_value)?;
                self.current().tftp_blksize = Some(parse_tftp_blksize(name, &value)?);
            }
            "tftp-no-options" => self.current().tftp_no_options = true,
            "telnet-option" => {
                let value = self.value_for(name, inline_value)?;
                self.current().telnet_options.push(value);
            }
            "ipfs-gateway" => {
                let value = self.value_for(name, inline_value)?;
                self.current().ipfs_gateway = Some(parse_nonempty_string(name, value)?);
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
            "fail" => self.set_fail_without_body(),
            "fail-with-body" => self.set_fail_with_body(),
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
            "max-filesize" => {
                let value = self.value_for(name, inline_value)?;
                self.current().max_filesize = Some(parse_size_parameter(name, &value)?);
            }
            "user-agent" => {
                let value = self.value_for(name, inline_value)?;
                self.current().user_agent = Some(value);
            }
            "cookie" => {
                let value = self.value_for(name, inline_value)?;
                self.add_cookie_input(value);
            }
            "cookie-jar" => {
                let value = self.value_for(name, inline_value)?;
                self.current().cookie_jar = Some(parse_nonempty_path(name, &value)?);
            }
            "junk-session-cookies" => self.current().junk_session_cookies = true,
            "compressed" => self.current().compressed = true,
            "verbose" => self.current().verbose = true,
            "trace" | "trace-ascii" => {
                let _ = self.value_for(name, inline_value)?;
            }
            "trace-time" => {
                if inline_value.is_some() {
                    return Err(CurlError::Usage(
                        "option --trace-time does not take a value".to_string(),
                    ));
                }
            }
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
            "list-only" => self.current().list_only = false,
            "include" => self.current().include_headers = false,
            "parallel" => self.config.parallel = false,
            "parallel-immediate" => self.config.parallel_immediate = false,
            "remote-name" => self.current().remote_name = false,
            "remote-header-name" => self.current().remote_header_name = false,
            "location" | "location-trusted" => self.current().follow_location = false,
            "retry-all-errors" => self.current().retry_all_errors = false,
            "retry-connrefused" => self.current().retry_connrefused = false,
            "fail" => {
                self.current().fail = false;
                self.current().fail_with_body = false;
            }
            "fail-with-body" => {
                self.current().fail = false;
                self.current().fail_with_body = false;
            }
            "insecure" => self.current().insecure = false,
            "junk-session-cookies" => self.current().junk_session_cookies = false,
            "mail-rcpt-allowfails" => self.current().mail_rcpt_allowfails = false,
            "compressed-ssh" => self.current().compressed_ssh = false,
            "tftp-no-options" => self.current().tftp_no_options = false,
            "compressed" => self.current().compressed = false,
            "verbose" => self.current().verbose = false,
            "progress-meter" => self.current().silent = true,
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
                'Z' => self.config.parallel = true,
                ':' => self.config.transfers.push(TransferConfig::default()),
                'X' => {
                    let value = self.short_value('X', rest)?;
                    self.current().method = Some(value);
                    break;
                }
                'I' => self.current().head = true,
                'G' => self.current().get = true,
                'l' => self.current().list_only = true,
                'i' => self.current().include_headers = true,
                'H' => {
                    let value = self.short_value('H', rest)?;
                    self.current().headers.push(value);
                    break;
                }
                'e' => {
                    let value = self.short_value('e', rest)?;
                    self.set_referer(value);
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
                'T' => {
                    let value = self.short_value('T', rest)?;
                    self.current().upload_file = Some(value);
                    break;
                }
                't' => {
                    let value = self.short_value('t', rest)?;
                    self.current().telnet_options.push(value);
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
                'f' => self.set_fail_without_body(),
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
                    self.add_cookie_input(value);
                    break;
                }
                'c' => {
                    let value = self.short_value('c', rest)?;
                    self.current().cookie_jar = Some(parse_nonempty_path("cookie-jar", &value)?);
                    break;
                }
                'j' => self.current().junk_session_cookies = true,
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

    fn add_cookie_input(&mut self, value: String) {
        if value.contains('=') {
            append_cookie_header(&mut self.current().cookie, value);
        } else {
            self.current().cookie_files.push(value);
        }
    }

    fn set_fail_without_body(&mut self) {
        let transfer = self.current();
        if transfer.fail_with_body {
            eprintln!("Warning: --fail deselects --fail-with-body here");
        }
        transfer.fail = true;
        transfer.fail_with_body = false;
    }

    fn set_fail_with_body(&mut self) {
        let transfer = self.current();
        if transfer.fail && !transfer.fail_with_body {
            eprintln!("Warning: --fail-with-body deselects --fail here");
        }
        transfer.fail = true;
        transfer.fail_with_body = true;
    }

    fn set_referer(&mut self, value: String) {
        let transfer = self.current();
        if let Some(referer) = value.strip_suffix(";auto") {
            transfer.auto_referer = true;
            transfer.referer = (!referer.is_empty()).then(|| referer.to_string());
        } else {
            transfer.auto_referer = false;
            transfer.referer = (!value.is_empty()).then_some(value);
        }
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
            || self.list_only
            || self.include_headers
            || !self.headers.is_empty()
            || !self.data.is_empty()
            || !self.url_query.is_empty()
            || !self.forms.is_empty()
            || self.upload_file.is_some()
            || self.mail_from.is_some()
            || !self.mail_rcpt.is_empty()
            || self.mail_rcpt_allowfails
            || self.ssh_private_key.is_some()
            || self.ssh_public_key.is_some()
            || self.ssh_known_hosts.is_some()
            || self.ssh_hostpubmd5.is_some()
            || self.ssh_hostpubsha256.is_some()
            || self.compressed_ssh
            || self.tftp_blksize.is_some()
            || self.tftp_no_options
            || !self.telnet_options.is_empty()
            || self.ipfs_gateway.is_some()
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
            || self.max_filesize.is_some()
            || self.user_agent.is_some()
            || self.referer.is_some()
            || self.auto_referer
            || self.range.is_some()
            || self.continue_at.is_some()
            || self.cookie.is_some()
            || !self.cookie_files.is_empty()
            || self.cookie_jar.is_some()
            || self.junk_session_cookies
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

fn parse_limited_usize(name: &str, value: &str, default: usize, limit: usize) -> Result<usize> {
    let value = parse_usize(name, value)?;
    Ok(if value == 0 {
        default
    } else {
        value.min(limit)
    })
}

fn parse_u64(name: &str, value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| CurlError::Usage(format!("option --{name} expects an integer")))
}

fn parse_size_parameter(name: &str, value: &str) -> Result<u64> {
    const MAX_SIZE: u128 = i64::MAX as u128;
    let bytes = value.as_bytes();
    let mut index = 0;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    if index == 0 {
        return Err(CurlError::Usage(format!(
            "option --{name} expects a non-negative byte count"
        )));
    }

    let whole = value[..index]
        .parse::<u128>()
        .map_err(|_| CurlError::Usage(format!("option --{name} value is too large")))?;

    let mut fraction = "";
    if bytes.get(index) == Some(&b'.') {
        let start = index + 1;
        let mut end = start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return Err(CurlError::Usage(format!(
                "option --{name} expects digits after the decimal point"
            )));
        }
        fraction = &value[start..end];
        index = end;
    }

    let unit = &bytes[index..];
    let (multiplier, multiplier_digits) = match unit {
        b"" | b"b" | b"B" => {
            if !fraction.is_empty() {
                return Err(CurlError::Usage(format!(
                    "option --{name} only supports fractional values with K/M/G/T/P units"
                )));
            }
            (1_u128, 1_usize)
        }
        [unit] if unit.eq_ignore_ascii_case(&b'k') => (1024, 4),
        [unit] if unit.eq_ignore_ascii_case(&b'm') => (1_048_576, 7),
        [unit] if unit.eq_ignore_ascii_case(&b'g') => (1_073_741_824, 10),
        [unit] if unit.eq_ignore_ascii_case(&b't') => (1_099_511_627_776, 13),
        [unit] if unit.eq_ignore_ascii_case(&b'p') => (1_125_899_906_842_624, 16),
        _ => {
            return Err(CurlError::Usage(format!(
                "option --{name} has an unsupported size suffix"
            )));
        }
    };

    let mut add = 0_u128;
    if !fraction.is_empty() {
        let keep = fraction.len().min(multiplier_digits.saturating_sub(1));
        let fraction = &fraction[..keep];
        if !fraction.is_empty() {
            let fraction_value = fraction.parse::<u128>().map_err(|_| {
                CurlError::Usage(format!("option --{name} fractional value is too large"))
            })?;
            let divisor = 10_u128.pow(keep as u32);
            add = fraction_value.saturating_mul(multiplier) / divisor;
        }
    }

    let total = whole
        .checked_mul(multiplier)
        .and_then(|value| value.checked_add(add))
        .filter(|value| *value <= MAX_SIZE)
        .ok_or_else(|| CurlError::Usage(format!("option --{name} value is too large")))?;
    Ok(total as u64)
}

fn parse_continue_at(name: &str, value: &str) -> Result<ContinueAt> {
    if value == "-" {
        Ok(ContinueAt::Auto)
    } else {
        Ok(ContinueAt::Offset(parse_u64(name, value)?))
    }
}

fn parse_tftp_blksize(name: &str, value: &str) -> Result<u16> {
    const MIN_BLKSIZE: u64 = 8;
    const MAX_BLKSIZE: u64 = 65_464;
    let value = parse_u64(name, value)?;
    if !(MIN_BLKSIZE..=MAX_BLKSIZE).contains(&value) {
        return Err(CurlError::Usage(format!(
            "option --{name} expects a value from {MIN_BLKSIZE} to {MAX_BLKSIZE}"
        )));
    }
    Ok(value as u16)
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

fn parse_nonempty_string(name: &str, value: String) -> Result<String> {
    if value.is_empty() {
        Err(CurlError::Usage(format!(
            "option --{name} requires a non-empty value"
        )))
    } else {
        Ok(value)
    }
}

fn append_cookie_header(cookie: &mut Option<String>, value: String) {
    if let Some(existing) = cookie {
        if !existing.is_empty() && !value.is_empty() {
            existing.push_str("; ");
        }
        existing.push_str(&value);
    } else {
        *cookie = Some(value);
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
           -T, --upload-file <file>    Transfer local file to remote URL\n\
               --mail-from <address>   Mail from this address\n\
               --mail-rcpt <address>   Mail to this address\n\
               --key <file>            SSH private key file\n\
               --pubkey <file>         SSH public key file\n\
               --knownhosts <file>     SSH known_hosts file\n\
               --compressed-ssh        Enable SSH compression\n\
               --tftp-blksize <value>  Set TFTP BLKSIZE option\n\
               --tftp-no-options       Do not send TFTP options\n\
           -t, --telnet-option <opt>   Set telnet option\n\
               --ipfs-gateway <URL>    Gateway for IPFS/IPNS URLs\n\
               --url-query <data>      Add URL query data\n\
               --json <data>           JSON request body\n\
           -e, --referer <url>         Send Referer header\n\
           -r, --range <range>         Request a byte range\n\
           -C, --continue-at <offset>  Resume transfer at offset\n\
           -H, --header <header>       Pass custom header\n\
           -I, --head                  Show document information only\n\
           -l, --list-only             List only mode\n\
           -L, --location              Follow redirects\n\
           -Z, --parallel              Perform transfers in parallel\n\
               --parallel-max <num>    Maximum parallel transfer count\n\
               --retry <num>           Retry transient transfer problems\n\
               --retry-delay <seconds> Wait time between retries\n\
               --retry-max-time <sec>  Retry only within this period\n\
              --max-filesize <bytes> Maximum file size to download\n\
           -o, --output <file>         Write output to file\n\
           -O, --remote-name           Write output to remote filename\n\
               --etag-compare <file>   Load ETag from file\n\
               --etag-save <file>      Save response ETag to file\n\
           -z, --time-cond <time>      Transfer based on time condition\n\
           -w, --write-out <format>    Write transfer metrics\n\
               --libcurl <file>        Generate libcurl code\n\
           -X, --request <method>      Specify request method\n\
           -u, --user <user:pass>      Server user and password\n\
           -b, --cookie <data>         Send cookies from string\n\
           -c, --cookie-jar <file>     Save cookies to file\n\
           -j, --junk-session-cookies  Ignore session cookies from file\n\
               --oauth2-bearer <token> OAuth 2 Bearer token\n\
           -U, --proxy-user <user:pass> Proxy user and password\n\
               --noproxy <list>        List hosts that do not use proxy\n\
           -k, --insecure              Allow insecure TLS/SSH\n\
           -s, --silent                Silent mode\n\
           -v, --verbose               Verbose transfer trace\n\
               --trace-ascii <file>    Accepted for compatibility\n\
               --trace-time            Accepted for compatibility\n\
           -V, --version               Show version"
    );
}

pub fn print_version() {
    let curl_version = curl_compat_version();
    println!(
        "curl {curl_version} (curl-rust/{}) libcurl/{curl_version}",
        env!("CARGO_PKG_VERSION")
    );
    println!("Release-Date: [unreleased]");
    println!(
        "Protocols: DICT FILE FTP GOPHER HTTP HTTPS IMAP IPFS IPNS LDAP MQTT POP3 RTSP SCP SFTP SMB SMTP TELNET TFTP WS"
    );
    println!("Features: AsynchDNS IPv6 Largefile SSL threadsafe");
}

fn curl_compat_version() -> &'static str {
    const CURLVER_H: &str = include_str!("../../../include/curl/curlver.h");
    CURLVER_H
        .lines()
        .find_map(|line| {
            line.strip_prefix("#define LIBCURL_VERSION \"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .unwrap_or("8.21.0-DEV")
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
    use std::path::Path;

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
    fn accepts_trace_options_for_corpus_runner() {
        let config = parse_args([
            "-q",
            "--trace-ascii",
            "log/trace1",
            "--trace-time",
            "file:///tmp/input",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.urls, ["file:///tmp/input"]);
    }

    #[test]
    fn parses_upload_file_and_telnet_options() {
        let config = parse_args([
            "-q",
            "-T",
            "input.txt",
            "-tTTYPE=vt100",
            "--telnet-option",
            "NEW_ENV=USER,me",
            "telnet://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.upload_file.as_deref(), Some("input.txt"));
        assert_eq!(transfer.telnet_options, ["TTYPE=vt100", "NEW_ENV=USER,me"]);
        assert_eq!(transfer.urls, ["telnet://example.com"]);
    }

    #[test]
    fn parses_list_only_option() {
        let config = parse_args(["-q", "-l", "pop3://example.com/1"]).unwrap();
        assert!(config.transfers[0].list_only);

        let config = parse_args([
            "-q",
            "--list-only",
            "--no-list-only",
            "pop3://example.com/1",
        ])
        .unwrap();
        assert!(!config.transfers[0].list_only);
    }

    #[test]
    fn parses_mail_options() {
        let config = parse_args([
            "-q",
            "--mail-from",
            "sender@example.com",
            "--mail-rcpt",
            "one@example.com",
            "--mail-rcpt=two@example.com",
            "--mail-rcpt-allowfails",
            "smtp://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.mail_from.as_deref(), Some("sender@example.com"));
        assert_eq!(transfer.mail_rcpt, ["one@example.com", "two@example.com"]);
        assert!(transfer.mail_rcpt_allowfails);

        let config = parse_args([
            "-q",
            "--mail-rcpt-allowfails",
            "--no-mail-rcpt-allowfails",
            "smtp://example.com",
        ])
        .unwrap();
        assert!(!config.transfers[0].mail_rcpt_allowfails);
    }

    #[test]
    fn parses_ssh_options() {
        let config = parse_args([
            "-q",
            "--key",
            "id_ed25519",
            "--pubkey=client.pub",
            "--knownhosts",
            "known_hosts",
            "--hostpubmd5",
            "00:11",
            "--hostpubsha256=abc",
            "--compressed-ssh",
            "sftp://example.com/file",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(
            transfer.ssh_private_key.as_deref(),
            Some(Path::new("id_ed25519"))
        );
        assert_eq!(
            transfer.ssh_public_key.as_deref(),
            Some(Path::new("client.pub"))
        );
        assert_eq!(
            transfer.ssh_known_hosts.as_deref(),
            Some(Path::new("known_hosts"))
        );
        assert_eq!(transfer.ssh_hostpubmd5.as_deref(), Some("00:11"));
        assert_eq!(transfer.ssh_hostpubsha256.as_deref(), Some("abc"));
        assert!(transfer.compressed_ssh);

        let config = parse_args([
            "-q",
            "--compressed-ssh",
            "--no-compressed-ssh",
            "sftp://example.com/file",
        ])
        .unwrap();
        assert!(!config.transfers[0].compressed_ssh);
    }

    #[test]
    fn parses_tftp_options() {
        let config = parse_args([
            "-q",
            "--tftp-blksize",
            "1024",
            "--tftp-no-options",
            "tftp://example.com/file",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.tftp_blksize, Some(1024));
        assert!(transfer.tftp_no_options);

        let config = parse_args([
            "-q",
            "--tftp-no-options",
            "--no-tftp-no-options",
            "tftp://example.com/file",
        ])
        .unwrap();
        assert!(!config.transfers[0].tftp_no_options);
    }

    #[test]
    fn rejects_bad_tftp_blksize_values() {
        assert!(parse_args(["-q", "--tftp-blksize", "7", "tftp://example.com"]).is_err());
        assert!(parse_args(["-q", "--tftp-blksize", "65465", "tftp://example.com"]).is_err());
    }

    #[test]
    fn parses_max_filesize_units_and_fractions() {
        let config = parse_args(["-q", "--max-filesize", "2.5M", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].max_filesize, Some(2_621_440));

        assert_eq!(parse_size_parameter("max-filesize", "1b").unwrap(), 1);
        assert_eq!(parse_size_parameter("max-filesize", "99B").unwrap(), 99);
        assert_eq!(
            parse_size_parameter("max-filesize", "1.001k").unwrap(),
            1025
        );
        assert_eq!(
            parse_size_parameter("max-filesize", "22.000000001m").unwrap(),
            23_068_672
        );
        assert_eq!(parse_size_parameter("max-filesize", "0").unwrap(), 0);
    }

    #[test]
    fn rejects_bad_max_filesize_values() {
        for value in ["3.4", "3.14b", "a", "-2", "+2", "2,2k", "8192P"] {
            let error =
                parse_args(["-q", "--max-filesize", value, "https://example.com"]).unwrap_err();
            assert!(error.to_string().contains("max-filesize"));
        }
    }

    #[test]
    fn parses_ipfs_gateway() {
        let config = parse_args([
            "-q",
            "--ipfs-gateway",
            "http://localhost:8080",
            "ipfs://example",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(
            transfer.ipfs_gateway.as_deref(),
            Some("http://localhost:8080")
        );
        assert_eq!(transfer.urls, ["ipfs://example"]);
    }

    #[test]
    fn rejects_empty_ipfs_gateway() {
        let error = parse_args(["-q", "--ipfs-gateway=", "ipfs://example"]).unwrap_err();

        assert!(error.to_string().contains("non-empty"));
    }

    #[test]
    fn parses_referer_auto_suffix() {
        let config = parse_args([
            "-q",
            "--referer",
            "https://refer.example/source;auto",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(
            config.transfers[0].referer.as_deref(),
            Some("https://refer.example/source")
        );
        assert!(config.transfers[0].auto_referer);

        let config = parse_args(["-q", "-e", ";auto", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].referer, None);
        assert!(config.transfers[0].auto_referer);

        let config =
            parse_args(["-q", "-e", "https://refer.example/", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].referer.as_deref(),
            Some("https://refer.example/")
        );
        assert!(!config.transfers[0].auto_referer);
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
    fn parses_cookie_headers_and_file_inputs() {
        let config = parse_args([
            "-q",
            "-b",
            "sid=abc",
            "--cookie",
            "theme=light",
            "--cookie",
            "cookies.txt",
            "--cookie=",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.cookie.as_deref(), Some("sid=abc; theme=light"));
        assert_eq!(
            transfer.cookie_files,
            vec!["cookies.txt".to_string(), "".to_string()]
        );
    }

    #[test]
    fn parses_junk_session_cookie_options() {
        let config = parse_args(["-q", "-j", "-b", "cookies.txt", "https://example.com"]).unwrap();
        assert!(config.transfers[0].junk_session_cookies);

        let config = parse_args([
            "-q",
            "--junk-session-cookies",
            "--no-junk-session-cookies",
            "https://example.com",
        ])
        .unwrap();
        assert!(!config.transfers[0].junk_session_cookies);
    }

    #[test]
    fn rejects_empty_cookie_jar_path() {
        let error = parse_args(["-q", "--cookie-jar=", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("non-empty"));
    }

    #[test]
    fn parses_libcurl_options_as_global_state() {
        let config = parse_args(["-q", "--libcurl", "client.c", "https://example.com"]).unwrap();
        assert_eq!(
            config.libcurl.as_deref(),
            Some(std::path::Path::new("client.c"))
        );

        let config = parse_args(["-q", "--libcurl=client.c", "https://example.com"]).unwrap();
        assert_eq!(
            config.libcurl.as_deref(),
            Some(std::path::Path::new("client.c"))
        );
    }

    #[test]
    fn rejects_empty_libcurl_path() {
        let error = parse_args(["-q", "--libcurl=", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("non-empty"));
    }

    #[test]
    fn libcurl_alone_still_requires_a_url() {
        let error = parse_args(["-q", "--libcurl", "client.c"]).unwrap_err();
        assert!(error.to_string().contains("no URL specified"));
    }

    #[test]
    fn libcurl_does_not_retain_empty_next_group() {
        let config = parse_args([
            "-q",
            "--libcurl",
            "client.c",
            "--next",
            "https://example.com",
        ])
        .unwrap();

        assert_eq!(config.transfers.len(), 1);
        assert_eq!(config.transfers[0].urls, ["https://example.com"]);
    }

    #[test]
    fn parses_parallel_options_as_global_state() {
        let config = parse_args([
            "-q",
            "-Z",
            "--parallel-immediate",
            "--parallel-max",
            "2",
            "--parallel-max-host",
            "3",
            "https://example.com",
        ])
        .unwrap();

        assert!(config.parallel);
        assert!(config.parallel_immediate);
        assert_eq!(config.parallel_max, 2);
        assert_eq!(config.parallel_max_host, 3);

        let config =
            parse_args(["-q", "--parallel", "--no-parallel", "https://example.com"]).unwrap();
        assert!(!config.parallel);

        let config = parse_args([
            "-q",
            "--parallel-immediate",
            "--no-parallel-immediate",
            "https://example.com",
        ])
        .unwrap();
        assert!(!config.parallel_immediate);
    }

    #[test]
    fn clamps_parallel_limits_like_c_curl() {
        let config = parse_args([
            "-q",
            "--parallel-max",
            "0",
            "--parallel-max-host",
            "0",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(config.parallel_max, PARALLEL_DEFAULT);
        assert_eq!(config.parallel_max_host, PARALLEL_MAX_HOST_DEFAULT);

        let config = parse_args([
            "-q",
            "--parallel-max",
            "70000",
            "--parallel-max-host",
            "70000",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(config.parallel_max, PARALLEL_MAX_LIMIT);
        assert_eq!(config.parallel_max_host, PARALLEL_MAX_LIMIT);
    }

    #[test]
    fn rejects_bad_parallel_limits() {
        let error = parse_args(["-q", "--parallel-max", "abc", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("expects an integer"));

        let error =
            parse_args(["-q", "--parallel-max-host", "abc", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("expects an integer"));
    }

    #[test]
    fn parallel_options_do_not_retain_empty_groups() {
        let config = parse_args([
            "-q",
            "--parallel",
            "--parallel-max",
            "2",
            "--next",
            "https://example.com",
        ])
        .unwrap();

        assert_eq!(config.transfers.len(), 1);
        assert_eq!(config.transfers[0].urls, ["https://example.com"]);
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

    #[test]
    fn parses_no_progress_meter_as_silent_progress_suppression() {
        let config = parse_args(["-q", "--no-progress-meter", "https://example.com"]).unwrap();

        assert!(config.transfers[0].silent);
    }

    #[test]
    fn fail_options_are_mutexed_with_last_one_winning() {
        let config =
            parse_args(["-q", "--fail-with-body", "--fail", "https://example.com"]).unwrap();
        assert!(config.transfers[0].fail);
        assert!(!config.transfers[0].fail_with_body);

        let config =
            parse_args(["-q", "--fail", "--fail-with-body", "https://example.com"]).unwrap();
        assert!(config.transfers[0].fail);
        assert!(config.transfers[0].fail_with_body);

        let config = parse_args([
            "-q",
            "--fail-with-body",
            "--no-fail-with-body",
            "https://example.com",
        ])
        .unwrap();
        assert!(!config.transfers[0].fail);
        assert!(!config.transfers[0].fail_with_body);
    }
}
