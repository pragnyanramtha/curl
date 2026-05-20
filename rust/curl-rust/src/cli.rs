use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

use crate::data::{DataKind, DataSpec, FormKind, FormSpec};
use crate::error::{CurlError, Result};

pub const PARALLEL_DEFAULT: usize = 50;
pub const PARALLEL_MAX_LIMIT: usize = 65_535;
pub const PARALLEL_MAX_HOST_DEFAULT: usize = 0;
const MAX_VARIABLE_NAME_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub show_help: bool,
    pub help_category: Option<String>,
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
    pub url_remote_names: Vec<bool>,
    pub url_globoffs: Vec<bool>,
    pub method: Option<String>,
    pub request_target: Option<String>,
    pub head: bool,
    pub get: bool,
    pub list_only: bool,
    pub use_ascii: bool,
    pub ftp_append: bool,
    pub ftp_create_dirs: bool,
    pub ftp_disable_epsv: bool,
    pub ftp_skip_pasv_ip: Option<bool>,
    pub ftp_quote: Vec<String>,
    pub ftp_prequote: Vec<String>,
    pub ftp_postquote: Vec<String>,
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
    pub proto_default: Option<String>,
    pub output: Option<String>,
    pub output_slots: Vec<OutputTarget>,
    pub out_null: bool,
    pub output_dir: Option<PathBuf>,
    pub remote_name: bool,
    pub remote_header_name: bool,
    pub dump_header: Option<PathBuf>,
    pub etag_compare: Option<PathBuf>,
    pub etag_save: Option<PathBuf>,
    pub time_cond: Option<String>,
    pub write_out: Option<String>,
    pub follow_location: bool,
    pub location_trusted: bool,
    pub post301: bool,
    pub post302: bool,
    pub post303: bool,
    pub max_redirs: usize,
    pub retry: usize,
    pub retry_all_errors: bool,
    pub retry_connrefused: bool,
    pub retry_delay: Duration,
    pub retry_max_time: Duration,
    pub fail: bool,
    pub fail_with_body: bool,
    pub user: Option<String>,
    pub http_auth: AuthMethods,
    pub oauth2_bearer: Option<String>,
    pub aws_sigv4: Option<String>,
    pub resolve: Vec<String>,
    pub connect_to: Vec<String>,
    pub disallow_username_in_url: bool,
    pub proxy: Option<String>,
    pub proxy_user: Option<String>,
    pub proxy_auth: ProxyAuthMethods,
    pub noproxy: Option<String>,
    pub insecure: bool,
    pub interface: Option<String>,
    pub local_port: Option<LocalPortRange>,
    pub connect_timeout: Option<Duration>,
    pub max_time: Option<Duration>,
    pub low_speed_limit: u64,
    pub low_speed_time: Duration,
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
    pub http09_allowed: bool,
    pub http_version: HttpVersionPreference,
    pub ssl_version: Option<SslVersionPreference>,
    pub ssl_version_max: Option<SslVersionMaxPreference>,
    pub ip_version: IpVersionPreference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalPortRange {
    pub start: u16,
    pub end: u16,
}

impl LocalPortRange {
    pub fn attempts(self) -> u32 {
        u32::from(self.end) - u32::from(self.start) + 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinueAt {
    Offset(u64),
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputTarget {
    File(String),
    Null,
    RemoteName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersionPreference {
    Any,
    Http10,
    Http11,
    Http2,
    Http2PriorKnowledge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslVersionPreference {
    TlsV1_0,
    TlsV1_1,
    TlsV1_2,
    TlsV1_3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslVersionMaxPreference {
    Default,
    TlsV1_0,
    TlsV1_1,
    TlsV1_2,
    TlsV1_3,
}

impl SslVersionPreference {
    fn order(self) -> u8 {
        match self {
            Self::TlsV1_0 => 1,
            Self::TlsV1_1 => 2,
            Self::TlsV1_2 => 3,
            Self::TlsV1_3 => 4,
        }
    }
}

impl SslVersionMaxPreference {
    fn order(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::TlsV1_0 => 1,
            Self::TlsV1_1 => 2,
            Self::TlsV1_2 => 3,
            Self::TlsV1_3 => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersionPreference {
    Any,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthMethods {
    bits: u32,
}

impl AuthMethods {
    const BASIC_BITS: u32 = 1 << 0;
    const DIGEST_BITS: u32 = 1 << 1;
    const NEGOTIATE_BITS: u32 = 1 << 2;
    const NTLM_BITS: u32 = 1 << 3;
    const DIGEST_IE_BITS: u32 = 1 << 4;
    const BEARER_BITS: u32 = 1 << 6;
    const AWS_SIGV4_BITS: u32 = 1 << 7;
    const KNOWN_BITS: u32 = Self::BASIC_BITS
        | Self::DIGEST_BITS
        | Self::NEGOTIATE_BITS
        | Self::NTLM_BITS
        | Self::BEARER_BITS
        | Self::AWS_SIGV4_BITS;

    pub const BASIC: Self = Self {
        bits: Self::BASIC_BITS,
    };
    pub const DIGEST: Self = Self {
        bits: Self::DIGEST_BITS,
    };
    pub const NEGOTIATE: Self = Self {
        bits: Self::NEGOTIATE_BITS,
    };
    pub const NTLM: Self = Self {
        bits: Self::NTLM_BITS,
    };
    pub const BEARER: Self = Self {
        bits: Self::BEARER_BITS,
    };
    pub const AWS_SIGV4: Self = Self {
        bits: Self::AWS_SIGV4_BITS,
    };
    pub const ANY: Self = Self {
        bits: !Self::DIGEST_IE_BITS,
    };
    pub const ANYSAFE: Self = Self {
        bits: !(Self::BASIC_BITS | Self::DIGEST_IE_BITS),
    };

    pub fn is_empty(self) -> bool {
        self.bits == 0
    }

    pub fn contains(self, method: Self) -> bool {
        self.bits & method.bits == method.bits
    }

    pub fn insert(&mut self, method: Self) {
        self.bits |= method.bits;
    }

    pub fn remove(&mut self, method: Self) {
        self.bits &= !method.bits;
    }

    pub fn set_any(&mut self) {
        self.bits = Self::ANY.bits;
    }

    pub fn requires_unsupported_http_runtime(self) -> bool {
        self.bits & !(Self::BASIC_BITS | Self::BEARER_BITS) != 0
    }

    pub fn to_curlauth_expr(self) -> Option<String> {
        let bits = self.bits;
        if bits == 0 {
            return None;
        }
        if bits == Self::ANY.bits {
            return Some("CURLAUTH_ANY".to_string());
        }
        if bits == Self::ANYSAFE.bits {
            return Some("CURLAUTH_ANYSAFE".to_string());
        }

        let known = [
            (Self::BASIC_BITS, "CURLAUTH_BASIC"),
            (Self::DIGEST_BITS, "CURLAUTH_DIGEST"),
            (Self::NEGOTIATE_BITS, "CURLAUTH_NEGOTIATE"),
            (Self::NTLM_BITS, "CURLAUTH_NTLM"),
            (Self::BEARER_BITS, "CURLAUTH_BEARER"),
            (Self::AWS_SIGV4_BITS, "CURLAUTH_AWS_SIGV4"),
        ];
        if bits & !Self::KNOWN_BITS != 0 {
            let removed = known
                .iter()
                .filter_map(|(bit, name)| (bits & bit == 0).then_some(*name))
                .collect::<Vec<_>>();
            if removed.is_empty() {
                Some("CURLAUTH_ANY".to_string())
            } else {
                Some(format!("(CURLAUTH_ANY & ~({}))", removed.join(" | ")))
            }
        } else {
            let names = known
                .iter()
                .filter_map(|(bit, name)| (bits & bit != 0).then_some(*name))
                .collect::<Vec<_>>();
            Some(names.join(" | "))
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyAuthMethods {
    anyauth: bool,
    basic: bool,
    digest: bool,
    negotiate: bool,
    ntlm: bool,
}

impl ProxyAuthMethods {
    pub fn is_empty(self) -> bool {
        !self.anyauth && !self.basic && !self.digest && !self.negotiate && !self.ntlm
    }

    pub fn anyauth(self) -> bool {
        self.anyauth
    }

    pub fn basic(self) -> bool {
        self.basic
    }

    pub fn digest(self) -> bool {
        self.digest
    }

    pub fn negotiate(self) -> bool {
        self.negotiate
    }

    pub fn ntlm(self) -> bool {
        self.ntlm
    }

    pub fn set_anyauth(&mut self, enabled: bool) {
        self.anyauth = enabled;
    }

    pub fn set_basic(&mut self, enabled: bool) {
        self.basic = enabled;
    }

    pub fn set_digest(&mut self, enabled: bool) {
        self.digest = enabled;
    }

    pub fn set_negotiate(&mut self, enabled: bool) {
        self.negotiate = enabled;
    }

    pub fn set_ntlm(&mut self, enabled: bool) {
        self.ntlm = enabled;
    }

    pub fn requires_unsupported_proxy_runtime(self) -> bool {
        self.anyauth || self.digest || self.negotiate || self.ntlm
    }

    pub fn to_curlauth_expr(self) -> Option<&'static str> {
        if self.anyauth {
            Some("CURLAUTH_ANY")
        } else if self.negotiate {
            Some("CURLAUTH_GSSNEGOTIATE")
        } else if self.ntlm {
            Some("CURLAUTH_NTLM")
        } else if self.digest {
            Some("CURLAUTH_DIGEST")
        } else if self.basic {
            Some("CURLAUTH_BASIC")
        } else {
            None
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            show_help: false,
            help_category: None,
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
            url_remote_names: Vec::new(),
            url_globoffs: Vec::new(),
            method: None,
            request_target: None,
            head: false,
            get: false,
            list_only: false,
            use_ascii: false,
            ftp_append: false,
            ftp_create_dirs: false,
            ftp_disable_epsv: false,
            ftp_skip_pasv_ip: None,
            ftp_quote: Vec::new(),
            ftp_prequote: Vec::new(),
            ftp_postquote: Vec::new(),
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
            proto_default: None,
            output: None,
            output_slots: Vec::new(),
            out_null: false,
            output_dir: None,
            remote_name: false,
            remote_header_name: false,
            dump_header: None,
            etag_compare: None,
            etag_save: None,
            time_cond: None,
            write_out: None,
            follow_location: false,
            location_trusted: false,
            post301: false,
            post302: false,
            post303: false,
            max_redirs: 50,
            retry: 0,
            retry_all_errors: false,
            retry_connrefused: false,
            retry_delay: Duration::ZERO,
            retry_max_time: Duration::ZERO,
            fail: false,
            fail_with_body: false,
            user: None,
            http_auth: AuthMethods::default(),
            oauth2_bearer: None,
            aws_sigv4: None,
            resolve: Vec::new(),
            connect_to: Vec::new(),
            disallow_username_in_url: false,
            proxy: None,
            proxy_user: None,
            proxy_auth: ProxyAuthMethods::default(),
            noproxy: None,
            insecure: false,
            interface: None,
            local_port: None,
            connect_timeout: None,
            max_time: None,
            low_speed_limit: 0,
            low_speed_time: Duration::ZERO,
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
            http09_allowed: false,
            http_version: HttpVersionPreference::Any,
            ssl_version: None,
            ssl_version_max: None,
            ip_version: IpVersionPreference::Any,
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
        variables: HashMap::new(),
    };
    parser.parse()
}

struct Parser {
    args: Vec<String>,
    pos: usize,
    config: Config,
    loaded_configs: usize,
    variables: HashMap<String, Vec<u8>>,
}

impl Parser {
    fn parse(&mut self) -> Result<Config> {
        while let Some(arg) = self.next() {
            if arg == "--" {
                while let Some(url) = self.next() {
                    self.append_url_value(url)?;
                }
                break;
            }

            if let Some(long) = arg.strip_prefix("--") {
                self.parse_long(long)?;
            } else if arg.starts_with('-') && arg.len() > 1 {
                self.parse_short(&arg[1..])?;
            } else {
                self.append_url_value(arg)?;
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
        let (mut name, mut inline_value) = raw
            .split_once('=')
            .map_or((raw, None), |(name, value)| (name, Some(value.to_string())));
        let expand = if let Some(expanded) = name.strip_prefix("expand-") {
            name = expanded;
            true
        } else {
            false
        };

        if let Some(name) = name.strip_prefix("no-") {
            if inline_value.is_some() {
                return Err(CurlError::Usage(format!(
                    "option --no-{name} does not take a value"
                )));
            }
            self.parse_no_long(name)?;
            return Ok(());
        }

        if expand {
            if !option_takes_value(name) {
                return Err(CurlError::Usage(format!(
                    "option --expand-{name} cannot be used with an option that takes no value"
                )));
            }
            let value = self.value_for(name, inline_value)?;
            inline_value = Some(self.expand_value(&value)?);
        }

        match name {
            "help" => {
                self.config.show_help = true;
                self.config.help_category = self.optional_help_category(inline_value);
            }
            "version" => self.config.show_version = true,
            "disable" => {}
            "config" => {
                let value = self.value_for(name, inline_value)?;
                self.insert_config_file(&value)?;
            }
            "variable" => {
                let value = self.value_for(name, inline_value)?;
                self.set_variable(&value)?;
            }
            "libcurl" => {
                let value = self.value_for(name, inline_value)?;
                self.config.libcurl = Some(parse_nonempty_path(name, &value)?);
            }
            "url" => {
                let value = self.value_for(name, inline_value)?;
                self.append_url_value(value)?;
            }
            "next" => {
                if self.current().urls.is_empty() {
                    return Err(CurlError::Usage("missing URL before --next".to_string()));
                }
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
            "request-target" => {
                let value = self.value_for(name, inline_value)?;
                self.current().request_target = Some(parse_nonempty_string(name, value)?);
            }
            "head" => self.current().head = true,
            "get" => self.current().get = true,
            "list-only" => self.current().list_only = true,
            "use-ascii" => self.current().use_ascii = true,
            "append" => self.current().ftp_append = true,
            "ftp-create-dirs" => self.current().ftp_create_dirs = true,
            "disable-epsv" => self.current().ftp_disable_epsv = true,
            "epsv" => self.current().ftp_disable_epsv = false,
            "ftp-pasv" => {}
            "ftp-skip-pasv-ip" => self.current().ftp_skip_pasv_ip = Some(true),
            "quote" => {
                let value = self.value_for(name, inline_value)?;
                self.add_ftp_quote(value);
            }
            "include" => self.current().include_headers = true,
            "header" => {
                let value = self.value_for(name, inline_value)?;
                self.append_header_value(value)?;
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
            "proto-default" => {
                let value = self.value_for(name, inline_value)?;
                self.current().proto_default = Some(parse_protocol_name(name, value)?);
            }
            "output" => {
                let value = self.value_for(name, inline_value)?;
                self.set_output_file(value);
            }
            "out-null" => self.set_output_null(),
            "output-dir" => {
                let value = self.value_for(name, inline_value)?;
                self.current().output_dir = Some(PathBuf::from(value));
            }
            "remote-name" => self.set_output_remote_name(),
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
                self.current().write_out = Some(self.read_write_out_value(&value)?);
            }
            "location" => self.current().follow_location = true,
            "location-trusted" => {
                let transfer = self.current();
                transfer.follow_location = true;
                transfer.location_trusted = true;
            }
            "post301" => self.current().post301 = true,
            "post302" => self.current().post302 = true,
            "post303" => self.current().post303 = true,
            "max-redirs" => {
                let value = self.value_for(name, inline_value)?;
                self.current().max_redirs = parse_max_redirs(name, &value)?;
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
            "anyauth" => self.current().http_auth.set_any(),
            "basic" => self.current().http_auth.insert(AuthMethods::BASIC),
            "digest" => self.current().http_auth.insert(AuthMethods::DIGEST),
            "negotiate" => self.current().http_auth.insert(AuthMethods::NEGOTIATE),
            "ntlm" => self.current().http_auth.insert(AuthMethods::NTLM),
            "oauth2-bearer" => {
                let value = self.value_for(name, inline_value)?;
                self.current().http_auth.insert(AuthMethods::BEARER);
                self.current().oauth2_bearer = Some(value);
            }
            "aws-sigv4" => {
                let value = self.value_for(name, inline_value)?;
                let transfer = self.current();
                transfer.http_auth.insert(AuthMethods::AWS_SIGV4);
                transfer.aws_sigv4 = Some(value);
            }
            "resolve" => {
                let value = self.value_for(name, inline_value)?;
                self.current().resolve.push(value);
            }
            "connect-to" => {
                let value = self.value_for(name, inline_value)?;
                self.current().connect_to.push(value);
            }
            "disallow-username-in-url" => self.current().disallow_username_in_url = true,
            "proxy" => {
                let value = self.value_for(name, inline_value)?;
                self.current().proxy = Some(value);
            }
            "proxy-user" => {
                let value = self.value_for(name, inline_value)?;
                self.current().proxy_user = Some(value);
            }
            "interface" => {
                let value = self.value_for(name, inline_value)?;
                self.current().interface = Some(parse_nonempty_string(name, value)?);
            }
            "local-port" => {
                let value = self.value_for(name, inline_value)?;
                self.current().local_port = Some(parse_local_port_range(name, &value)?);
            }
            "proxy-anyauth" => self.current().proxy_auth.set_anyauth(true),
            "proxy-basic" => self.current().proxy_auth.set_basic(true),
            "proxy-digest" => self.current().proxy_auth.set_digest(true),
            "proxy-negotiate" => self.current().proxy_auth.set_negotiate(true),
            "proxy-ntlm" => self.current().proxy_auth.set_ntlm(true),
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
            "speed-limit" => {
                let value = self.value_for(name, inline_value)?;
                self.set_low_speed_limit(parse_c_long_u64(name, &value)?);
            }
            "speed-time" => {
                let value = self.value_for(name, inline_value)?;
                self.set_low_speed_time(parse_c_long_u64(name, &value)?);
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
                self.add_cookie_input(value)?;
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
            "http0.9" => self.current().http09_allowed = true,
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
            "ipv4" => self.current().ip_version = IpVersionPreference::Ipv4,
            "ipv6" => self.current().ip_version = IpVersionPreference::Ipv6,
            "tls-max" => {
                let value = self.value_for(name, inline_value)?;
                self.set_ssl_version_max(parse_tls_max(name, &value)?)?;
            }
            "tlsv1" | "tlsv1.0" => self.set_ssl_version_min(SslVersionPreference::TlsV1_0)?,
            "tlsv1.1" => self.set_ssl_version_min(SslVersionPreference::TlsV1_1)?,
            "tlsv1.2" => self.set_ssl_version_min(SslVersionPreference::TlsV1_2)?,
            "tlsv1.3" => self.set_ssl_version_min(SslVersionPreference::TlsV1_3)?,
            "proxy-tlsv1" => return Err(CurlError::Unsupported(format!("--{name}"))),
            "sslv2" | "sslv3" => warn_deprecated_ssl_option(name),
            other => return Err(CurlError::Usage(format!("unknown option --{other}"))),
        }

        Ok(())
    }

    fn parse_no_long(&mut self, name: &str) -> Result<()> {
        match name {
            "head" => self.current().head = false,
            "get" => self.current().get = false,
            "list-only" => self.current().list_only = false,
            "use-ascii" => self.current().use_ascii = false,
            "append" => self.current().ftp_append = false,
            "ftp-create-dirs" => self.current().ftp_create_dirs = false,
            "disable-epsv" => self.current().ftp_disable_epsv = false,
            "epsv" => self.current().ftp_disable_epsv = true,
            "ftp-skip-pasv-ip" => self.current().ftp_skip_pasv_ip = Some(false),
            "include" => self.current().include_headers = false,
            "parallel" => self.config.parallel = false,
            "parallel-immediate" => self.config.parallel_immediate = false,
            "remote-name" => self.current().remote_name = false,
            "remote-header-name" => self.current().remote_header_name = false,
            "location" => self.current().follow_location = false,
            "location-trusted" => {
                let transfer = self.current();
                transfer.follow_location = false;
                transfer.location_trusted = false;
            }
            "post301" => self.current().post301 = false,
            "post302" => self.current().post302 = false,
            "post303" => self.current().post303 = false,
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
            "basic" => self.current().http_auth.remove(AuthMethods::BASIC),
            "digest" => self.current().http_auth.remove(AuthMethods::DIGEST),
            "negotiate" => self.current().http_auth.remove(AuthMethods::NEGOTIATE),
            "ntlm" => self.current().http_auth.remove(AuthMethods::NTLM),
            "disallow-username-in-url" => self.current().disallow_username_in_url = false,
            "proxy-anyauth" => self.current().proxy_auth.set_anyauth(false),
            "proxy-basic" => self.current().proxy_auth.set_basic(false),
            "proxy-digest" => self.current().proxy_auth.set_digest(false),
            "proxy-negotiate" => self.current().proxy_auth.set_negotiate(false),
            "proxy-ntlm" => self.current().proxy_auth.set_ntlm(false),
            "insecure" => self.current().insecure = false,
            "junk-session-cookies" => self.current().junk_session_cookies = false,
            "mail-rcpt-allowfails" => self.current().mail_rcpt_allowfails = false,
            "compressed-ssh" => self.current().compressed_ssh = false,
            "tftp-no-options" => self.current().tftp_no_options = false,
            "proto-default" => self.current().proto_default = None,
            "out-null" => self.set_output_null(),
            "compressed" => self.current().compressed = false,
            "verbose" => self.current().verbose = false,
            "progress-meter" => self.current().silent = true,
            "silent" => self.current().silent = false,
            "show-error" => self.current().show_error = false,
            "globoff" => self.current().globoff = false,
            "create-dirs" => self.current().create_dirs = false,
            "http0.9" => self.current().http09_allowed = false,
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
                        self.config.help_category = self.optional_help_category(None);
                    } else {
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
                'B' => self.current().use_ascii = true,
                'a' => self.current().ftp_append = true,
                'Q' => {
                    let value = self.short_value('Q', rest)?;
                    self.add_ftp_quote(value);
                    break;
                }
                'i' => self.current().include_headers = true,
                'H' => {
                    let value = self.short_value('H', rest)?;
                    self.append_header_value(value)?;
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
                    self.set_output_file(value);
                    break;
                }
                'O' => self.set_output_remote_name(),
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
                    self.current().write_out = Some(self.read_write_out_value(&value)?);
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
                'Y' => {
                    let value = self.short_value('Y', rest)?;
                    self.set_low_speed_limit(parse_c_long_u64("speed-limit", &value)?);
                    break;
                }
                'y' => {
                    let value = self.short_value('y', rest)?;
                    self.set_low_speed_time(parse_c_long_u64("speed-time", &value)?);
                    break;
                }
                'A' => {
                    let value = self.short_value('A', rest)?;
                    self.current().user_agent = Some(value);
                    break;
                }
                'b' => {
                    let value = self.short_value('b', rest)?;
                    self.add_cookie_input(value)?;
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
                '1' => self.set_ssl_version_min(SslVersionPreference::TlsV1_0)?,
                '2' => warn_deprecated_ssl_option("sslv2"),
                '3' => warn_deprecated_ssl_option("sslv3"),
                '4' => self.current().ip_version = IpVersionPreference::Ipv4,
                '6' => self.current().ip_version = IpVersionPreference::Ipv6,
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

    fn set_low_speed_limit(&mut self, limit: u64) {
        let transfer = self.current();
        transfer.low_speed_limit = limit;
        if transfer.low_speed_time == Duration::ZERO {
            transfer.low_speed_time = Duration::from_secs(30);
        }
    }

    fn set_low_speed_time(&mut self, seconds: u64) {
        let transfer = self.current();
        transfer.low_speed_time = Duration::from_secs(seconds);
        if transfer.low_speed_limit == 0 {
            transfer.low_speed_limit = 1;
        }
    }

    fn next(&mut self) -> Option<String> {
        let next = self.args.get(self.pos).cloned();
        self.pos += usize::from(next.is_some());
        next
    }

    fn optional_help_category(&mut self, inline_value: Option<String>) -> Option<String> {
        inline_value.or_else(|| {
            self.args
                .get(self.pos)
                .filter(|arg| !arg.starts_with('-'))
                .cloned()
                .inspect(|_| self.pos += 1)
        })
    }

    fn current(&mut self) -> &mut TransferConfig {
        self.config
            .transfers
            .last_mut()
            .expect("parser always has a current transfer")
    }

    fn add_cookie_input(&mut self, value: String) -> Result<()> {
        if value.contains('=') {
            append_cookie_header(&mut self.current().cookie, value)?;
        } else {
            self.current().cookie_files.push(value);
        }
        Ok(())
    }

    fn add_ftp_quote(&mut self, value: String) {
        if let Some(command) = value.strip_prefix('-') {
            self.current().ftp_postquote.push(command.to_string());
        } else if let Some(command) = value.strip_prefix('+') {
            self.current().ftp_prequote.push(command.to_string());
        } else {
            self.current().ftp_quote.push(value);
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

    fn set_ssl_version_min(&mut self, version: SslVersionPreference) -> Result<()> {
        let transfer = self.current();
        if let Some(max) = transfer.ssl_version_max
            && max != SslVersionMaxPreference::Default
            && max.order() < version.order()
        {
            return Err(CurlError::Usage(
                "Minimum TLS version set higher than max".to_string(),
            ));
        }
        transfer.ssl_version = Some(version);
        Ok(())
    }

    fn set_ssl_version_max(&mut self, version: SslVersionMaxPreference) -> Result<()> {
        let transfer = self.current();
        if let Some(min) = transfer.ssl_version
            && version.order() < min.order()
        {
            return Err(CurlError::Usage(
                "--tls-max set lower than minimum accepted version".to_string(),
            ));
        }
        transfer.ssl_version_max = Some(version);
        Ok(())
    }

    fn set_output_file(&mut self, value: String) {
        let transfer = self.current();
        transfer.output = Some(value.clone());
        transfer.out_null = false;
        transfer.output_slots.push(OutputTarget::File(value));
    }

    fn set_output_null(&mut self) {
        let transfer = self.current();
        transfer.out_null = true;
        transfer.output = None;
        transfer.output_slots.push(OutputTarget::Null);
    }

    fn set_output_remote_name(&mut self) {
        let transfer = self.current();
        transfer.remote_name = true;
        transfer.output = None;
        transfer.out_null = false;
        transfer.output_slots.push(OutputTarget::RemoteName);
    }

    fn push_url(&mut self, url: String, remote_name: bool, globoff: bool) {
        let transfer = self.current();
        transfer.urls.push(url);
        transfer.url_remote_names.push(remote_name);
        transfer.url_globoffs.push(globoff);
    }

    fn append_url_value(&mut self, value: String) -> Result<()> {
        if let Some(lines) = read_at_lines_argument(&value)? {
            for line in lines {
                self.push_url(line, true, true);
            }
        } else {
            self.push_url(value, false, false);
        }
        Ok(())
    }

    fn append_header_value(&mut self, value: String) -> Result<()> {
        if let Some(lines) = read_at_lines_argument(&value)? {
            self.current().headers.extend(lines);
        } else {
            self.current().headers.push(value);
        }
        Ok(())
    }

    fn read_write_out_value(&mut self, value: &str) -> Result<String> {
        if let Some(text) = read_at_text_argument(value)? {
            Ok(text
                .chars()
                .filter(|ch| !matches!(ch, '\r' | '\n'))
                .collect())
        } else {
            Ok(value.to_string())
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

    fn set_variable(&mut self, input: &str) -> Result<()> {
        let mut rest = input;
        let import = if let Some(stripped) = rest.strip_prefix('%') {
            rest = stripped;
            true
        } else {
            false
        };

        let name_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if name_len == 0 || name_len >= MAX_VARIABLE_NAME_LEN {
            return Ok(());
        }

        let name = &rest[..name_len];
        rest = &rest[name_len..];

        let mut range = VariableRange::default();
        if let Some(stripped) = rest.strip_prefix('[') {
            let Some((parsed_range, after_range)) = parse_variable_range(stripped)? else {
                return Ok(());
            };
            range = parsed_range;
            rest = after_range;
        }

        let env_value = import.then(|| std::env::var_os(name)).flatten();
        let mut content = if let Some(value) = env_value {
            value.to_string_lossy().into_owned().into_bytes()
        } else if rest.is_empty() {
            if import {
                return Err(CurlError::Usage(format!(
                    "Variable '{name}' import fail, not set"
                )));
            }
            return Ok(());
        } else if let Some(value) = rest.strip_prefix('=') {
            range.apply(value.as_bytes()).to_vec()
        } else if let Some(path) = rest.strip_prefix('@') {
            let bytes = if path == "-" {
                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes)?;
                bytes
            } else {
                std::fs::read(path).map_err(|error| CurlError::ReadError(error.to_string()))?
            };
            range.apply(&bytes).to_vec()
        } else {
            return Ok(());
        };

        if import && !rest.is_empty() && !range.is_default() && !content.is_empty() {
            content = range.apply(&content).to_vec();
        }

        self.variables.insert(name.to_string(), content);
        Ok(())
    }

    fn expand_value(&self, input: &str) -> Result<String> {
        let mut output = Vec::new();
        let bytes = input.as_bytes();
        let mut pos = 0;
        let mut replaced = false;

        while let Some(relative) = find_bytes(&bytes[pos..], b"{{") {
            let start = pos + relative;
            if start > 0 && bytes[start - 1] == b'\\' {
                output.extend_from_slice(&bytes[pos..start - 1]);
                output.extend_from_slice(b"{{");
                pos = start + 2;
                continue;
            }

            output.extend_from_slice(&bytes[pos..start]);
            let name_start = start + 2;
            let Some(close_relative) = find_bytes(&bytes[name_start..], b"}}") else {
                output.extend_from_slice(&bytes[start..]);
                pos = bytes.len();
                break;
            };
            let close = name_start + close_relative;
            let expression = std::str::from_utf8(&bytes[name_start..close])
                .map_err(|_| variable_expansion_error("variable expression is not UTF-8"))?;

            if let Some(expanded) = self.expand_variable_expression(expression)? {
                if expanded.contains(&0) {
                    return Err(variable_expansion_error("variable contains null byte"));
                }
                output.extend_from_slice(&expanded);
                replaced = true;
            } else {
                output.extend_from_slice(&bytes[start..close + 2]);
            }
            pos = close + 2;
        }

        output.extend_from_slice(&bytes[pos..]);

        if !replaced {
            return Ok(input.to_string());
        }

        String::from_utf8(output)
            .map_err(|_| variable_expansion_error("expanded value is not UTF-8"))
    }

    fn expand_variable_expression(&self, expression: &str) -> Result<Option<Vec<u8>>> {
        let (name, functions) = expression
            .split_once(':')
            .map_or((expression, ""), |(name, functions)| (name, functions));
        if name.is_empty()
            || name.len() >= MAX_VARIABLE_NAME_LEN
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Ok(None);
        }

        let mut value = self.variables.get(name).cloned().unwrap_or_default();
        if !functions.is_empty() {
            for function in functions.split(':') {
                value = apply_variable_function(function, &value)?;
            }
        }
        Ok(Some(value))
    }
}

impl TransferConfig {
    fn has_options(&self) -> bool {
        !self.urls.is_empty()
            || self.method.is_some()
            || self.request_target.is_some()
            || self.head
            || self.get
            || self.list_only
            || self.use_ascii
            || self.ftp_append
            || self.ftp_create_dirs
            || self.ftp_disable_epsv
            || self.ftp_skip_pasv_ip.is_some()
            || !self.ftp_quote.is_empty()
            || !self.ftp_prequote.is_empty()
            || !self.ftp_postquote.is_empty()
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
            || self.proto_default.is_some()
            || self.output.is_some()
            || !self.output_slots.is_empty()
            || self.out_null
            || self.output_dir.is_some()
            || self.remote_name
            || self.remote_header_name
            || self.dump_header.is_some()
            || self.etag_compare.is_some()
            || self.etag_save.is_some()
            || self.time_cond.is_some()
            || self.write_out.is_some()
            || self.follow_location
            || self.location_trusted
            || self.post301
            || self.post302
            || self.post303
            || self.retry != 0
            || self.retry_all_errors
            || self.retry_connrefused
            || self.retry_delay != Duration::ZERO
            || self.retry_max_time != Duration::ZERO
            || self.fail
            || self.fail_with_body
            || self.user.is_some()
            || !self.http_auth.is_empty()
            || self.oauth2_bearer.is_some()
            || self.aws_sigv4.is_some()
            || !self.resolve.is_empty()
            || !self.connect_to.is_empty()
            || self.disallow_username_in_url
            || self.proxy.is_some()
            || self.proxy_user.is_some()
            || !self.proxy_auth.is_empty()
            || self.noproxy.is_some()
            || self.insecure
            || self.interface.is_some()
            || self.local_port.is_some()
            || self.connect_timeout.is_some()
            || self.max_time.is_some()
            || self.low_speed_limit != 0
            || self.low_speed_time != Duration::ZERO
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
            || self.http09_allowed
            || self.http_version != HttpVersionPreference::Any
            || self.ssl_version.is_some()
            || self.ssl_version_max.is_some()
            || self.ip_version != IpVersionPreference::Any
    }
}

fn option_takes_value(name: &str) -> bool {
    matches!(
        name,
        "config"
            | "libcurl"
            | "variable"
            | "url"
            | "parallel-max"
            | "parallel-max-host"
            | "request"
            | "request-target"
            | "quote"
            | "header"
            | "referer"
            | "range"
            | "continue-at"
            | "data"
            | "data-ascii"
            | "data-raw"
            | "data-binary"
            | "data-urlencode"
            | "json"
            | "url-query"
            | "form"
            | "form-string"
            | "upload-file"
            | "mail-from"
            | "mail-rcpt"
            | "key"
            | "pubkey"
            | "knownhosts"
            | "hostpubmd5"
            | "hostpubsha256"
            | "tftp-blksize"
            | "telnet-option"
            | "ipfs-gateway"
            | "proto-default"
            | "output"
            | "output-dir"
            | "dump-header"
            | "etag-compare"
            | "etag-save"
            | "time-cond"
            | "write-out"
            | "max-redirs"
            | "retry"
            | "retry-delay"
            | "retry-max-time"
            | "user"
            | "aws-sigv4"
            | "oauth2-bearer"
            | "resolve"
            | "connect-to"
            | "proxy"
            | "proxy-user"
            | "interface"
            | "local-port"
            | "noproxy"
            | "connect-timeout"
            | "max-time"
            | "speed-limit"
            | "speed-time"
            | "max-filesize"
            | "user-agent"
            | "cookie"
            | "cookie-jar"
            | "trace"
            | "trace-ascii"
            | "tls-max"
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct VariableRange {
    start: usize,
    end: Option<usize>,
    specified: bool,
}

impl VariableRange {
    fn apply<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        if !self.specified {
            return bytes;
        }
        if self.start >= bytes.len() {
            return &bytes[0..0];
        }

        let end = self
            .end
            .unwrap_or(bytes.len() - 1)
            .min(bytes.len().saturating_sub(1));
        &bytes[self.start..=end]
    }

    fn is_default(&self) -> bool {
        !self.specified
    }
}

fn parse_variable_range(input: &str) -> Result<Option<(VariableRange, &str)>> {
    let Some(dash) = input.find('-') else {
        return Ok(None);
    };
    let start = &input[..dash];
    if start.is_empty() || !start.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }

    let after_dash = &input[dash + 1..];
    let Some(close) = after_dash.find(']') else {
        return Err(CurlError::Usage("bad --variable byte range".to_string()));
    };
    let end = &after_dash[..close];
    let start = start
        .parse::<usize>()
        .map_err(|_| CurlError::Usage("bad --variable byte range".to_string()))?;
    let end = if end.is_empty() {
        None
    } else {
        if !end.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CurlError::Usage("bad --variable byte range".to_string()));
        }
        Some(
            end.parse::<usize>()
                .map_err(|_| CurlError::Usage("bad --variable byte range".to_string()))?,
        )
    };
    if end.is_some_and(|end| start > end) {
        return Err(CurlError::Usage("bad --variable byte range".to_string()));
    }

    Ok(Some((
        VariableRange {
            start,
            end,
            specified: true,
        },
        &after_dash[close + 1..],
    )))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn apply_variable_function(function: &str, value: &[u8]) -> Result<Vec<u8>> {
    match function {
        "trim" => Ok(trim_ascii_whitespace(value).to_vec()),
        "json" => Ok(json_quote_bytes(value)),
        "url" => Ok(percent_encode_bytes(value).into_bytes()),
        "b64" => Ok(BASE64_STANDARD.encode(value).into_bytes()),
        "64dec" => Ok(BASE64_STANDARD
            .decode(value)
            .unwrap_or_else(|_| b"[64dec-fail]".to_vec())),
        _ => Err(variable_expansion_error(format!(
            "unknown variable function in '{function}'"
        ))),
    }
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn json_quote_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\x08' => out.extend_from_slice(b"\\b"),
            b'\x0c' => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0..=31 => out.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            other => out.push(other),
        }
    }
    out
}

fn percent_encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn variable_expansion_error(message: impl Into<String>) -> CurlError {
    CurlError::Usage(format!("variable expansion failure: {}", message.into()))
}

fn parse_usize(name: &str, value: &str) -> Result<usize> {
    value
        .parse()
        .map_err(|_| CurlError::Usage(format!("option --{name} expects an integer")))
}

fn parse_max_redirs(name: &str, value: &str) -> Result<usize> {
    if value == "-1" {
        Ok(usize::MAX)
    } else {
        parse_usize(name, value)
    }
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

fn parse_c_long_u64(name: &str, value: &str) -> Result<u64> {
    let value = parse_u64(name, value)?;
    if value > i64::MAX as u64 {
        return Err(CurlError::Usage(format!(
            "option --{name} value is too large"
        )));
    }
    Ok(value)
}

fn parse_local_port_range(name: &str, value: &str) -> Result<LocalPortRange> {
    let bytes = value.as_bytes();
    let mut split = 0;
    while bytes.get(split).is_some_and(u8::is_ascii_digit) {
        split += 1;
    }

    let port = parse_local_port_component(name, &value[..split])?;
    if split == value.len() {
        return Ok(LocalPortRange {
            start: port,
            end: port,
        });
    }

    let mut rest = &value[split..];
    if rest
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        rest = &rest[1..];
    }
    let Some(after_dash) = rest.strip_prefix('-') else {
        return Err(local_port_bad_use(name));
    };
    rest = after_dash;
    if rest
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        rest = &rest[1..];
    }
    let end = parse_local_port_component(name, rest)?;
    if end < port {
        return Err(local_port_bad_use(name));
    }
    Ok(LocalPortRange { start: port, end })
}

fn parse_local_port_component(name: &str, value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(local_port_bad_use(name));
    }
    value.parse::<u16>().map_err(|_| local_port_bad_use(name))
}

fn local_port_bad_use(name: &str) -> CurlError {
    CurlError::Usage(format!("option --{name}: is badly used here"))
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

fn parse_tls_max(name: &str, value: &str) -> Result<SslVersionMaxPreference> {
    match value {
        "default" => Ok(SslVersionMaxPreference::Default),
        "1.0" => Ok(SslVersionMaxPreference::TlsV1_0),
        "1.1" => Ok(SslVersionMaxPreference::TlsV1_1),
        "1.2" => Ok(SslVersionMaxPreference::TlsV1_2),
        "1.3" => Ok(SslVersionMaxPreference::TlsV1_3),
        _ => Err(CurlError::Usage(format!(
            "option --{name}: is badly used here"
        ))),
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

fn parse_nonempty_string(name: &str, value: String) -> Result<String> {
    if value.is_empty() {
        Err(CurlError::Usage(format!(
            "option --{name} requires a non-empty value"
        )))
    } else {
        Ok(value)
    }
}

fn parse_protocol_name(name: &str, value: String) -> Result<String> {
    let value = parse_nonempty_string(name, value)?.to_ascii_lowercase();
    match value.as_str() {
        "dict" | "file" | "ftp" | "ftps" | "gopher" | "gophers" | "http" | "https" | "imap"
        | "imaps" | "ipfs" | "ipns" | "ldap" | "ldaps" | "mqtt" | "mqtts" | "pop3" | "pop3s"
        | "rtsp" | "scp" | "sftp" | "smb" | "smbs" | "smtp" | "smtps" | "telnet" | "tftp"
        | "ws" | "wss" => Ok(value),
        _ => Err(CurlError::UnsupportedProtocol(value)),
    }
}

fn warn_deprecated_ssl_option(name: &str) {
    eprintln!("Warning: --{name} is deprecated and has no function anymore");
}

const MAX_LITERAL_COOKIE_HEADER_LEN: usize = 8200;

fn append_cookie_header(cookie: &mut Option<String>, value: String) -> Result<()> {
    if let Some(existing) = cookie {
        if !existing.is_empty() && !value.is_empty() {
            existing.push(';');
            if !value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_whitespace)
            {
                existing.push(' ');
            }
        }
        existing.push_str(&value);
    } else {
        *cookie = Some(value);
    }
    if cookie
        .as_ref()
        .is_some_and(|cookie| cookie.len() > MAX_LITERAL_COOKIE_HEADER_LEN)
    {
        Err(CurlError::Usage(
            "option --cookie literal cookie header is too long".to_string(),
        ))
    } else {
        Ok(())
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

pub fn print_help(category: Option<&str>) {
    if category.is_some_and(is_help_category) {
        print_common_help();
    } else if category.is_some() {
        print_help_categories();
    } else {
        print_common_help();
    }
}

fn is_help_category(category: &str) -> bool {
    matches!(
        category,
        "auth"
            | "connection"
            | "curl"
            | "deprecated"
            | "dns"
            | "file"
            | "ftp"
            | "global"
            | "http"
            | "imap"
            | "ldap"
            | "output"
            | "pop3"
            | "post"
            | "proxy"
            | "scp"
            | "sftp"
            | "smtp"
            | "ssh"
            | "telnet"
            | "tftp"
            | "timeout"
            | "tls"
            | "upload"
            | "verbose"
    )
}

fn print_help_categories() {
    println!(
        "{}",
        concat!(
            "Unknown category provided, here is a list of all categories:\n\n",
            " auth        Authentication methods\n",
            " connection  Manage connections\n",
            " curl        The command line tool itself\n",
            " deprecated  Legacy\n",
            " dns         Names and resolving\n",
            " file        FILE protocol\n",
            " ftp         FTP protocol\n",
            " global      Global options\n",
            " http        HTTP and HTTPS protocol\n",
            " imap        IMAP protocol\n",
            " ldap        LDAP protocol\n",
            " output      File system output\n",
            " pop3        POP3 protocol\n",
            " post        HTTP POST specific\n",
            " proxy       Options for proxies\n",
            " scp         SCP protocol\n",
            " sftp        SFTP protocol\n",
            " smtp        SMTP protocol\n",
            " ssh         SSH protocol\n",
            " telnet      TELNET protocol\n",
            " tftp        TFTP protocol\n",
            " timeout     Timeouts and delays\n",
            " tls         TLS/SSL related\n",
            " upload      Upload, sending data\n",
            " verbose     Tracing, logging etc"
        )
    );
}

fn print_common_help() {
    println!(
        "Usage: curl [options...] <url>\n\
         Rust curl rewrite prototype\n\n\
         Common options:\n\
           -d, --data <data>           HTTP POST data\n\
               --data-binary <data>    HTTP POST binary data\n\
               --data-urlencode <data> Percent-encode POST data\n\
           -F, --form <name=content>   Specify multipart form data\n\
           -T, --upload-file <file>    Transfer local file to remote URL\n\
           -a, --append                Append to target file when uploading\n\
               --mail-from <address>   Mail from this address\n\
               --mail-rcpt <address>   Mail to this address\n\
               --key <file>            SSH private key file\n\
               --pubkey <file>         SSH public key file\n\
               --knownhosts <file>     SSH known_hosts file\n\
               --compressed-ssh        Enable SSH compression\n\
               --tftp-blksize <value>  Set TFTP BLKSIZE option\n\
               --tftp-no-options       Do not send TFTP options\n\
          -B, --use-ascii             Use ASCII/text transfer\n\
          -t, --telnet-option <opt>    Set telnet option\n\
               --ipfs-gateway <URL>    Gateway for IPFS/IPNS URLs\n\
               --proto-default <proto> Default protocol for schemeless URLs\n\
               --url-query <data>      Add URL query data\n\
               --json <data>           JSON request body\n\
           -e, --referer <url>         Send Referer header\n\
           -r, --range <range>         Request a byte range\n\
           -C, --continue-at <offset>  Resume transfer at offset\n\
           -H, --header <header>       Pass custom header\n\
           -I, --head                  Show document information only\n\
           -l, --list-only             List only mode\n\
           -L, --location              Follow redirects\n\
               --post301               Keep POST after 301 redirect\n\
               --post302               Keep POST after 302 redirect\n\
               --post303               Keep POST after 303 redirect\n\
           -Z, --parallel              Perform transfers in parallel\n\
               --parallel-max <num>    Maximum parallel transfer count\n\
               --retry <num>           Retry transient transfer problems\n\
               --retry-delay <seconds> Wait time between retries\n\
               --retry-max-time <sec>  Retry only within this period\n\
               --max-filesize <bytes> Maximum file size to download\n\
           -o, --output <file>         Write output to file\n\
               --out-null              Discard response data\n\
           -O, --remote-name           Write output to remote filename\n\
               --etag-compare <file>   Load ETag from file\n\
               --etag-save <file>      Save response ETag to file\n\
           -z, --time-cond <time>      Transfer based on time condition\n\
           -w, --write-out <format>    Write transfer metrics\n\
               --variable <name=data>  Set command-line variable\n\
               --expand-* <value>      Expand variables in option value\n\
               --libcurl <file>        Generate libcurl code\n\
               --http0.9              Allow HTTP/0.9 responses\n\
           -X, --request <method>      Specify request method\n\
               --request-target <path> Specify request target\n\
           -u, --user <user:pass>      Server user and password\n\
               --basic                 Use HTTP Basic Authentication\n\
               --digest                Use HTTP Digest Authentication\n\
               --negotiate             Use HTTP Negotiate Authentication\n\
               --ntlm                  Use HTTP NTLM Authentication\n\
               --anyauth               Pick any authentication method\n\
               --aws-sigv4 <provider>  Use AWS V4 signature authentication\n\
               --disallow-username-in-url Reject URL user names\n\
               --resolve <host:port:addr> Resolve host to address\n\
               --connect-to <rule>     Connect to alternate host\n\
           -b, --cookie <data>         Send cookies from string\n\
           -c, --cookie-jar <file>     Save cookies to file\n\
           -j, --junk-session-cookies  Ignore session cookies from file\n\
               --oauth2-bearer <token> OAuth 2 Bearer token\n\
           -U, --proxy-user <user:pass> Proxy user and password\n\
               --proxy-basic           Use Basic proxy authentication\n\
               --proxy-digest          Use Digest proxy authentication\n\
               --proxy-negotiate       Use Negotiate proxy authentication\n\
               --proxy-ntlm            Use NTLM proxy authentication\n\
               --proxy-anyauth         Pick any proxy authentication method\n\
               --noproxy <list>        List hosts that do not use proxy\n\
               --interface <name>      Use network interface\n\
               --local-port <range>    Use a local port number within range\n\
           -k, --insecure              Allow insecure TLS/SSH\n\
           -Y, --speed-limit <speed>   Stop transfers slower than this\n\
           -y, --speed-time <seconds>  Trigger speed-limit after this time\n\
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
    match args.first().map(String::as_str) {
        Some("--disable") => false,
        Some(arg) if arg.starts_with("-q") => false,
        _ => true,
    }
}

fn default_config_path() -> Option<PathBuf> {
    let curl_home = nonempty_env_path("CURL_HOME");
    let xdg_config_home = nonempty_env_path("XDG_CONFIG_HOME");
    let home = nonempty_env_path("HOME");
    let mut dotscore = true;
    let mut locations = vec![
        (curl_home.clone(), false),
        (xdg_config_home, true),
        (home.clone(), false),
    ];

    #[cfg(windows)]
    {
        let user_profile = nonempty_env_path("USERPROFILE");
        let app_data = nonempty_env_path("APPDATA");
        locations.push((user_profile.clone(), false));
        locations.push((app_data, false));
        locations.push((
            user_profile.map(|path| path.join("Application Data")),
            false,
        ));
    }

    locations.push((curl_home.map(|path| path.join(".config")), true));
    locations.push((home.map(|path| path.join(".config")), true));

    for (base, without_dot) in locations {
        let Some(base) = base else {
            continue;
        };
        if without_dot {
            if !dotscore {
                continue;
            }
            dotscore = false;
            let path = base.join("curlrc");
            if is_readable_config_candidate(&path) {
                return Some(path);
            }
        } else if let Some(path) = find_dot_curlrc(&base, dotscore) {
            return Some(path);
        }
    }

    None
}

fn nonempty_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn is_readable_config_candidate(path: &std::path::Path) -> bool {
    std::fs::File::open(path).is_ok()
}

#[cfg(windows)]
fn find_dot_curlrc(base: &std::path::Path, dotscore: bool) -> Option<PathBuf> {
    for filename in [".curlrc", "_curlrc"]
        .into_iter()
        .take(if dotscore { 2 } else { 1 })
    {
        let path = base.join(filename);
        if is_readable_config_candidate(&path) {
            return Some(path);
        }
    }
    None
}

#[cfg(not(windows))]
fn find_dot_curlrc(base: &std::path::Path, _dotscore: bool) -> Option<PathBuf> {
    let path = base.join(".curlrc");
    if is_readable_config_candidate(&path) {
        Some(path)
    } else {
        None
    }
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

        if line.starts_with('-') {
            tokens.extend(shell_words(line, true)?);
            continue;
        }

        let (key, rest) = split_config_key_value(line);
        if key.is_empty() {
            continue;
        }
        tokens.push(format!("--{key}"));

        let rest = rest.trim_start_matches(|ch: char| ch.is_whitespace() || ch == '=' || ch == ':');
        if !rest.is_empty() {
            tokens.extend(shell_words(rest, false)?);
        }
    }
    Ok(tokens)
}

fn split_config_key_value(line: &str) -> (&str, &str) {
    line.char_indices()
        .find(|(_, ch)| ch.is_whitespace() || *ch == '=' || *ch == ':')
        .map_or((line, ""), |(index, _)| (&line[..index], &line[index..]))
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

fn shell_words(line: &str, split_equals: bool) -> Result<Vec<String>> {
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
            '=' if split_equals && !in_single && !in_double => {
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

fn read_at_lines_argument(value: &str) -> Result<Option<Vec<String>>> {
    let Some(text) = read_at_text_argument(value)? else {
        return Ok(None);
    };
    let lines = text
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(ToString::to_string)
        .collect();
    Ok(Some(lines))
}

fn read_at_text_argument(value: &str) -> Result<Option<String>> {
    let Some(path) = value.strip_prefix('@') else {
        return Ok(None);
    };
    let text = if path == "-" {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        text
    } else {
        std::fs::read_to_string(path).map_err(|error| CurlError::ReadError(error.to_string()))?
    };
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use tempfile::tempdir;

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
        assert_eq!(
            transfer.output_slots,
            [OutputTarget::File("out.txt".to_string())]
        );
        assert_eq!(transfer.urls, ["https://example.com"]);
    }

    #[test]
    fn parses_out_null_as_output_slot() {
        let config = parse_args([
            "-q",
            "https://example.com/one",
            "https://example.com/two",
            "--out-null",
            "-o",
            "-",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(!transfer.out_null);
        assert_eq!(transfer.output.as_deref(), Some("-"));
        assert_eq!(
            transfer.output_slots,
            [OutputTarget::Null, OutputTarget::File("-".to_string())]
        );
    }

    #[test]
    fn parses_no_out_null_as_output_slot() {
        let config = parse_args(["-q", "--no-out-null", "https://example.com"]).unwrap();

        let transfer = &config.transfers[0];
        assert!(transfer.out_null);
        assert_eq!(transfer.output_slots, [OutputTarget::Null]);
    }

    #[test]
    fn parses_remote_name_as_ordered_output_slot() {
        let config = parse_args([
            "-q",
            "https://example.com/one",
            "-O",
            "https://example.com/two",
            "--out-null",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(
            transfer.urls,
            ["https://example.com/one", "https://example.com/two"]
        );
        assert_eq!(
            transfer.output_slots,
            [OutputTarget::RemoteName, OutputTarget::Null]
        );
    }

    #[test]
    fn parses_remote_name_as_output_slot() {
        let config = parse_args([
            "-q",
            "https://example.com/one.txt",
            "https://example.com/two.txt",
            "-O",
            "--out-null",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(transfer.remote_name);
        assert_eq!(
            transfer.output_slots,
            [OutputTarget::RemoteName, OutputTarget::Null]
        );
    }

    #[test]
    fn parses_location_trusted_separately_from_location() {
        let config = parse_args(["-q", "--location-trusted", "https://example.com"]).unwrap();
        assert!(config.transfers[0].follow_location);
        assert!(config.transfers[0].location_trusted);

        let config = parse_args([
            "-q",
            "--location-trusted",
            "--no-location-trusted",
            "https://example.com",
        ])
        .unwrap();
        assert!(!config.transfers[0].follow_location);
        assert!(!config.transfers[0].location_trusted);
    }

    #[test]
    fn parses_unlimited_max_redirs() {
        let config = parse_args(["-q", "-L", "--max-redirs", "-1", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].max_redirs, usize::MAX);

        let error = parse_args(["-q", "--max-redirs", "-2", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("max-redirs"));
    }

    #[test]
    fn parses_request_target_option() {
        let config = parse_args(["-q", "--request-target", "*", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].request_target.as_deref(), Some("*"));
    }

    #[test]
    fn parses_http09_boolean_option() {
        let config = parse_args(["-q", "--http0.9", "https://example.com"]).unwrap();
        assert!(config.transfers[0].http09_allowed);

        let config =
            parse_args(["-q", "--http0.9", "--no-http0.9", "https://example.com"]).unwrap();
        assert!(!config.transfers[0].http09_allowed);
    }

    #[test]
    fn config_files_parse_request_target_option() {
        let temp = tempdir().unwrap();
        let config_file = temp.path().join("curlrc");
        std::fs::write(
            &config_file,
            "request-target = \"*\"\nurl = https://example.com\n",
        )
        .unwrap();

        let config = parse_args(["-q", "--config", config_file.to_str().unwrap()]).unwrap();
        assert_eq!(config.transfers[0].request_target.as_deref(), Some("*"));
    }

    #[test]
    fn config_files_parse_http09_boolean_option() {
        let temp = tempdir().unwrap();
        let config_file = temp.path().join("curlrc");
        std::fs::write(
            &config_file,
            "http0.9\nno-http0.9\nurl = https://example.com\n",
        )
        .unwrap();

        let config = parse_args(["-q", "--config", config_file.to_str().unwrap()]).unwrap();
        assert!(!config.transfers[0].http09_allowed);
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
    fn expands_at_file_arguments_while_parsing() {
        let temp = tempdir().unwrap();
        let urls = temp.path().join("urls.txt");
        let headers = temp.path().join("headers.txt");
        let writeout = temp.path().join("writeout.txt");
        std::fs::write(
            &urls,
            "# skipped\nhttps://example.com/one\n\nhttps://example.com/two\n",
        )
        .unwrap();
        std::fs::write(&headers, "# skipped\nAccept:\nX-Blank;\n").unwrap();
        std::fs::write(&writeout, "code=%{http_code}\nsize=%{size_download}\r\n").unwrap();

        let config = parse_args([
            "-q",
            "--url",
            &format!("@{}", urls.display()),
            "-H",
            &format!("@{}", headers.display()),
            "-w",
            &format!("@{}", writeout.display()),
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(
            transfer.urls,
            ["https://example.com/one", "https://example.com/two"]
        );
        assert_eq!(transfer.url_remote_names, [true, true]);
        assert_eq!(transfer.url_globoffs, [true, true]);
        assert_eq!(transfer.headers, ["Accept:", "X-Blank;"]);
        assert_eq!(
            transfer.write_out.as_deref(),
            Some("code=%{http_code}size=%{size_download}")
        );
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
    fn parses_append_option() {
        let config = parse_args(["-q", "-a", "ftp://example.com/file"]).unwrap();
        assert!(config.transfers[0].ftp_append);

        let config =
            parse_args(["-q", "--append", "--no-append", "ftp://example.com/file"]).unwrap();
        assert!(!config.transfers[0].ftp_append);
    }

    #[test]
    fn parses_ftp_create_dirs_option() {
        let config = parse_args(["-q", "--ftp-create-dirs", "ftp://example.com/file"]).unwrap();
        assert!(config.transfers[0].ftp_create_dirs);

        let config = parse_args([
            "-q",
            "--ftp-create-dirs",
            "--no-ftp-create-dirs",
            "ftp://example.com/file",
        ])
        .unwrap();
        assert!(!config.transfers[0].ftp_create_dirs);
    }

    #[test]
    fn parses_ftp_quote_options_by_phase() {
        let config = parse_args([
            "-q",
            "-Q",
            "NOOP 1",
            "--quote",
            "+NOOP 2",
            "-Q-*DELE after",
            "--quote=*FAIL",
            "ftp://example.com/file",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.ftp_quote, ["NOOP 1", "*FAIL"]);
        assert_eq!(transfer.ftp_prequote, ["NOOP 2"]);
        assert_eq!(transfer.ftp_postquote, ["*DELE after"]);
    }

    #[test]
    fn parses_ftp_passive_options() {
        let config = parse_args([
            "-q",
            "--disable-epsv",
            "--ftp-pasv",
            "--ftp-skip-pasv-ip",
            "ftp://example.com/file",
        ])
        .unwrap();
        assert!(config.transfers[0].ftp_disable_epsv);
        assert_eq!(config.transfers[0].ftp_skip_pasv_ip, Some(true));

        let config = parse_args([
            "-q",
            "--disable-epsv",
            "--epsv",
            "--ftp-skip-pasv-ip",
            "--no-ftp-skip-pasv-ip",
            "ftp://example.com/file",
        ])
        .unwrap();
        assert!(!config.transfers[0].ftp_disable_epsv);
        assert_eq!(config.transfers[0].ftp_skip_pasv_ip, Some(false));

        let config = parse_args(["-q", "--no-epsv", "ftp://example.com/file"]).unwrap();
        assert!(config.transfers[0].ftp_disable_epsv);

        let config = parse_args(["-q", "ftp://example.com/file"]).unwrap();
        assert_eq!(config.transfers[0].ftp_skip_pasv_ip, None);
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
    fn parses_use_ascii_option() {
        let config = parse_args(["-q", "-B", "tftp://example.com/file"]).unwrap();
        assert!(config.transfers[0].use_ascii);

        let config = parse_args([
            "-q",
            "--use-ascii",
            "--no-use-ascii",
            "tftp://example.com/file",
        ])
        .unwrap();
        assert!(!config.transfers[0].use_ascii);
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
            url: https://colon.example
            url:https://attached.example/?q=a=b
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
                "https://colon.example",
                "--url",
                "https://attached.example/?q=a=b",
                "--url",
                "https://example.com"
            ]
        );
    }

    #[test]
    fn dashed_config_options_do_not_use_colon_separator() {
        let tokens = tokenize_config("--url: https://example.com").unwrap();
        assert_eq!(tokens, ["--url:", "https://example.com"]);
    }

    #[test]
    fn config_options_use_at_file_expansion() {
        let temp = tempdir().unwrap();
        let urls = temp.path().join("urls.txt");
        let headers = temp.path().join("headers.txt");
        let writeout = temp.path().join("writeout.txt");
        let config_file = temp.path().join("curlrc");
        std::fs::write(&urls, "https://example.com/config\n").unwrap();
        std::fs::write(&headers, "X-Config: yes\n").unwrap();
        std::fs::write(&writeout, "%{http_code}\n").unwrap();
        std::fs::write(
            &config_file,
            format!(
                "url = @{}\nheader = @{}\nwrite-out = @{}\n",
                urls.display(),
                headers.display(),
                writeout.display()
            ),
        )
        .unwrap();

        let config = parse_args(["-q", "-K", config_file.to_str().unwrap()]).unwrap();
        let transfer = &config.transfers[0];
        assert_eq!(transfer.urls, ["https://example.com/config"]);
        assert_eq!(transfer.url_remote_names, [true]);
        assert_eq!(transfer.url_globoffs, [true]);
        assert_eq!(transfer.headers, ["X-Config: yes"]);
        assert_eq!(transfer.write_out.as_deref(), Some("%{http_code}"));
    }

    #[test]
    fn expands_command_line_variables() {
        let config = parse_args([
            "-q",
            "--variable",
            "name=  hello world ",
            "--expand-data",
            "{{name:trim:url}}",
            "https://example.com",
        ])
        .unwrap();

        assert_eq!(config.transfers[0].data[0].value, "hello%20world");
    }

    #[test]
    fn expands_variables_with_range_and_base64_functions() {
        let config = parse_args([
            "-q",
            "--variable",
            "slice[5-9]=0123456789abcdef",
            "--expand-variable",
            "encoded={{slice:b64}}",
            "--expand-url",
            "https://example.com/{{encoded:64dec}}",
        ])
        .unwrap();

        assert_eq!(config.transfers[0].urls, ["https://example.com/56789"]);
    }

    #[test]
    fn expands_file_variables_and_json_quotes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("value.txt");
        std::fs::write(&path, b" \n\"quoted\"\n ").unwrap();

        let config = parse_args([
            "-q",
            "--variable",
            &format!("body@{}", path.display()),
            "--expand-data",
            "{{body:trim:json}}",
            "https://example.com",
        ])
        .unwrap();

        assert_eq!(config.transfers[0].data[0].value, "\\\"quoted\\\"");
    }

    #[test]
    fn escaped_invalid_and_missing_variables_match_curl_expansion_shape() {
        let config = parse_args([
            "-q",
            "--variable",
            "name=value",
            "--expand-data",
            r"1{{name}}2\{{raw}}3{{unset}}4{{not.good}}5{{}}",
            "https://example.com",
        ])
        .unwrap();

        assert_eq!(
            config.transfers[0].data[0].value,
            "1value2{{raw}}34{{not.good}}5{{}}"
        );
    }

    #[test]
    fn missing_imported_environment_variable_is_an_error() {
        let error = parse_args([
            "-q",
            "--variable",
            "%CURL_RUST_TEST_MISSING_VARIABLE_91D34294",
            "--expand-data",
            "{{CURL_RUST_TEST_MISSING_VARIABLE_91D34294}}",
            "https://example.com",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("import fail"));
    }

    #[test]
    fn variable_expansion_rejects_unknown_functions_and_raw_nul_bytes() {
        let error = parse_args([
            "-q",
            "--variable",
            "name=hello",
            "--expand-data",
            "{{name:trim,url}}",
            "https://example.com",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("unknown variable function"));

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nul.bin");
        std::fs::write(&path, b"\0hello").unwrap();
        let error = parse_args([
            "-q",
            "--variable",
            &format!("body@{}", path.display()),
            "--expand-data",
            "{{body}}",
            "https://example.com",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("null byte"));
    }

    #[test]
    fn rejects_url_less_option_group() {
        let error = parse_args(["-q", "-d", "x"]).unwrap_err();
        assert!(error.to_string().contains("no URL specified"));
    }

    #[test]
    fn parses_optional_help_category() {
        let config = parse_args(["-q", "--help", "http"]).unwrap();
        assert!(config.show_help);
        assert_eq!(config.help_category.as_deref(), Some("http"));
        assert!(config.transfers.is_empty());

        let config = parse_args(["-q", "--help=ldap"]).unwrap();
        assert!(config.show_help);
        assert_eq!(config.help_category.as_deref(), Some("ldap"));
        assert!(config.transfers.is_empty());

        let config = parse_args(["-q", "-h", "tls"]).unwrap();
        assert!(config.show_help);
        assert_eq!(config.help_category.as_deref(), Some("tls"));
        assert!(config.transfers.is_empty());
    }

    #[test]
    fn help_option_without_category_leaves_following_option() {
        let config = parse_args(["-q", "--help", "--version"]).unwrap();
        assert!(config.show_help);
        assert!(config.show_version);
        assert_eq!(config.help_category, None);
    }

    #[test]
    fn separates_short_help_from_header_alias() {
        let config = parse_args(["-q", "-h"]).unwrap();
        assert!(config.show_help);

        let config = parse_args(["-q", "-HAccept: text/plain", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].headers, ["Accept: text/plain"]);

        let config = parse_args(["-q", "-hAccept:", "https://example.com"]).unwrap();
        assert!(!config.show_help);
        assert!(config.transfers[0].headers.is_empty());

        let error = parse_args(["-q", "-?", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("unknown option -?"));
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

        let config = parse_args(["-q", "-0", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].http_version,
            HttpVersionPreference::Http10
        );

        let config = parse_args(["-q", "--http1.1", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].http_version,
            HttpVersionPreference::Http11
        );
    }

    #[test]
    fn tls_short_aliases_are_not_http_version_aliases() {
        let config = parse_args(["-q", "-1", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].http_version, HttpVersionPreference::Any);
        assert_eq!(
            config.transfers[0].ssl_version,
            Some(SslVersionPreference::TlsV1_0)
        );

        let config = parse_args(["-q", "--tlsv1.2", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].http_version, HttpVersionPreference::Any);
        assert_eq!(
            config.transfers[0].ssl_version,
            Some(SslVersionPreference::TlsV1_2)
        );

        let config = parse_args([
            "-q",
            "-2",
            "-3",
            "--sslv2",
            "--sslv3",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(config.transfers[0].http_version, HttpVersionPreference::Any);
        assert_eq!(config.transfers[0].ssl_version, None);
    }

    #[test]
    fn parses_tls_max_options() {
        let config = parse_args(["-q", "--tls-max", "default", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].ssl_version_max,
            Some(SslVersionMaxPreference::Default)
        );

        let config = parse_args(["-q", "--tls-max", "1.0", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].ssl_version_max,
            Some(SslVersionMaxPreference::TlsV1_0)
        );

        let config = parse_args(["-q", "--tls-max", "1.1", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].ssl_version_max,
            Some(SslVersionMaxPreference::TlsV1_1)
        );

        let config = parse_args(["-q", "--tls-max", "1.2", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].ssl_version_max,
            Some(SslVersionMaxPreference::TlsV1_2)
        );

        let config = parse_args(["-q", "--tls-max", "1.3", "https://example.com"]).unwrap();
        assert_eq!(
            config.transfers[0].ssl_version_max,
            Some(SslVersionMaxPreference::TlsV1_3)
        );
    }

    #[test]
    fn rejects_bad_tls_max_combinations() {
        let error = parse_args(["-q", "--tls-max", "1.4", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("option --tls-max"));

        let error = parse_args(["-q", "--tls-max"]).unwrap_err();
        assert!(error.to_string().contains("requires a value"));

        let error =
            parse_args(["-q", "--tls-max", "1.1", "--tlsv1.2", "https://example.com"]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Minimum TLS version set higher than max")
        );

        let error =
            parse_args(["-q", "--tlsv1.2", "--tls-max", "1.1", "https://example.com"]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--tls-max set lower than minimum accepted version")
        );

        let error = parse_args([
            "-q",
            "--tlsv1.2",
            "--tls-max",
            "default",
            "https://example.com",
        ])
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--tls-max set lower than minimum accepted version")
        );

        let config = parse_args([
            "-q",
            "--tls-max",
            "default",
            "--tlsv1.2",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(
            config.transfers[0].ssl_version,
            Some(SslVersionPreference::TlsV1_2)
        );
    }

    #[test]
    fn parses_ip_version_short_aliases() {
        let config = parse_args(["-q", "-4", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].ip_version, IpVersionPreference::Ipv4);

        let config = parse_args(["-q", "--ipv6", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].ip_version, IpVersionPreference::Ipv6);

        let config = parse_args(["-q", "--ipv4", "-6", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].ip_version, IpVersionPreference::Ipv6);

        let config = parse_args(["-q", "-46", "https://example.com"]).unwrap();
        assert_eq!(config.transfers[0].ip_version, IpVersionPreference::Ipv6);
    }

    #[test]
    fn config_files_parse_ip_version_options() {
        let temp = tempdir().unwrap();
        let config_file = temp.path().join("curlrc");
        std::fs::write(&config_file, "ipv4\nipv6\nurl = https://example.com\n").unwrap();

        let config = parse_args(["-q", "--config", config_file.to_str().unwrap()]).unwrap();
        assert_eq!(config.transfers[0].ip_version, IpVersionPreference::Ipv6);
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
    fn parses_interface_option() {
        let config = parse_args([
            "-q",
            "--interface",
            "host!127.0.0.1",
            "tftp://example.com/file",
        ])
        .unwrap();

        assert_eq!(
            config.transfers[0].interface.as_deref(),
            Some("host!127.0.0.1")
        );

        assert!(parse_args(["-q", "--interface", "", "tftp://example.com/file"]).is_err());
    }

    #[test]
    fn parses_low_speed_options() {
        let config = parse_args([
            "-q",
            "--speed-limit",
            "1000",
            "--speed-time",
            "2",
            "tftp://example.com/file",
        ])
        .unwrap();
        let transfer = &config.transfers[0];
        assert_eq!(transfer.low_speed_limit, 1000);
        assert_eq!(transfer.low_speed_time, Duration::from_secs(2));

        let config =
            parse_args(["-q", "--speed-limit", "1000", "tftp://example.com/file"]).unwrap();
        assert_eq!(config.transfers[0].low_speed_limit, 1000);
        assert_eq!(config.transfers[0].low_speed_time, Duration::from_secs(30));

        let config = parse_args(["-q", "-Y1000", "-y2", "tftp://example.com/file"]).unwrap();
        assert_eq!(config.transfers[0].low_speed_limit, 1000);
        assert_eq!(config.transfers[0].low_speed_time, Duration::from_secs(2));

        let config = parse_args(["-q", "--speed-time", "2", "tftp://example.com/file"]).unwrap();
        assert_eq!(config.transfers[0].low_speed_limit, 1);
        assert_eq!(config.transfers[0].low_speed_time, Duration::from_secs(2));

        let config = parse_args(["-q", "-Y1000", "-y0", "tftp://example.com/file"]).unwrap();
        assert_eq!(config.transfers[0].low_speed_limit, 1000);
        assert_eq!(config.transfers[0].low_speed_time, Duration::ZERO);

        let config = parse_args(["-q", "-Y0", "-y2", "tftp://example.com/file"]).unwrap();
        assert_eq!(config.transfers[0].low_speed_limit, 1);
        assert_eq!(config.transfers[0].low_speed_time, Duration::from_secs(2));

        let config = parse_args(["-q", "-y0", "-Y1000", "tftp://example.com/file"]).unwrap();
        assert_eq!(config.transfers[0].low_speed_limit, 1000);
        assert_eq!(config.transfers[0].low_speed_time, Duration::from_secs(30));

        assert!(
            parse_args([
                "-q",
                "--speed-limit",
                "9223372036854775808",
                "tftp://example.com/file"
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_local_port_option() {
        let config = parse_args([
            "-q",
            "--local-port",
            "44444-45444",
            "tftp://example.com/file",
        ])
        .unwrap();

        assert_eq!(
            config.transfers[0].local_port,
            Some(LocalPortRange {
                start: 44444,
                end: 45444
            })
        );
        assert_eq!(config.transfers[0].local_port.unwrap().attempts(), 1001);

        let config =
            parse_args(["-q", "--local-port", "44444", "tftp://example.com/file"]).unwrap();
        assert_eq!(
            config.transfers[0].local_port,
            Some(LocalPortRange {
                start: 44444,
                end: 44444
            })
        );

        let config =
            parse_args(["-q", "--local-port", "1 - 3", "tftp://example.com/file"]).unwrap();
        assert_eq!(
            config.transfers[0].local_port,
            Some(LocalPortRange { start: 1, end: 3 })
        );

        let config = parse_args(["-q", "--local-port", "0-1", "tftp://example.com/file"]).unwrap();
        assert_eq!(
            config.transfers[0].local_port,
            Some(LocalPortRange { start: 0, end: 1 })
        );
    }

    #[test]
    fn rejects_bad_local_port_values() {
        for value in [
            "", "abc", "1-0", "65536", "1-65536", "-2", "1-", "1  -2", "1 - 2 ",
        ] {
            assert!(
                parse_args(["-q", "--local-port", value, "tftp://example.com"]).is_err(),
                "accepted invalid --local-port value {value:?}"
            );
        }
    }

    #[test]
    fn parses_auth_selector_options() {
        let config = parse_args([
            "-q",
            "--basic",
            "--digest",
            "--negotiate",
            "--ntlm",
            "--aws-sigv4",
            "aws:amz:us-east-1:service",
            "--proxy-basic",
            "--proxy-digest",
            "--proxy-negotiate",
            "--proxy-ntlm",
            "--proxy-anyauth",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(transfer.http_auth.contains(AuthMethods::BASIC));
        assert!(transfer.http_auth.contains(AuthMethods::DIGEST));
        assert!(transfer.http_auth.contains(AuthMethods::NEGOTIATE));
        assert!(transfer.http_auth.contains(AuthMethods::NTLM));
        assert!(transfer.http_auth.contains(AuthMethods::AWS_SIGV4));
        assert_eq!(
            transfer.aws_sigv4.as_deref(),
            Some("aws:amz:us-east-1:service")
        );
        assert!(transfer.proxy_auth.anyauth());
        assert!(transfer.proxy_auth.basic());
        assert!(transfer.proxy_auth.digest());
        assert!(transfer.proxy_auth.negotiate());
        assert!(transfer.proxy_auth.ntlm());
    }

    #[test]
    fn no_prefixed_auth_selectors_disable_previous_values() {
        let config = parse_args([
            "-q",
            "--basic",
            "--digest",
            "--no-basic",
            "--proxy-anyauth",
            "--proxy-basic",
            "--no-proxy-anyauth",
            "--no-proxy-basic",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(!transfer.http_auth.contains(AuthMethods::BASIC));
        assert!(transfer.http_auth.contains(AuthMethods::DIGEST));
        assert!(!transfer.proxy_auth.anyauth());
        assert!(!transfer.proxy_auth.basic());
    }

    #[test]
    fn rejects_no_prefix_for_non_boolean_auth_selectors() {
        let error = parse_args(["-q", "--no-anyauth", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("no-anyauth"));

        let error = parse_args(["-q", "--no-aws-sigv4", "https://example.com"]).unwrap_err();
        assert!(error.to_string().contains("no-aws-sigv4"));
    }

    #[test]
    fn parses_resolve_connect_to_and_disallow_username_options() {
        let config = parse_args([
            "-q",
            "--resolve",
            "example.com:80:127.0.0.1",
            "--connect-to",
            "::backend.example:8080",
            "--disallow-username-in-url",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert_eq!(transfer.resolve, ["example.com:80:127.0.0.1"]);
        assert_eq!(transfer.connect_to, ["::backend.example:8080"]);
        assert!(transfer.disallow_username_in_url);

        let config = parse_args([
            "-q",
            "--disallow-username-in-url",
            "--no-disallow-username-in-url",
            "https://example.com",
        ])
        .unwrap();
        assert!(!config.transfers[0].disallow_username_in_url);
    }

    #[test]
    fn parses_proto_default_option() {
        let config = parse_args(["-q", "--proto-default", "FILE", "/tmp/input.txt"]).unwrap();
        assert_eq!(config.transfers[0].proto_default.as_deref(), Some("file"));

        let config = parse_args([
            "-q",
            "--proto-default",
            "file",
            "--no-proto-default",
            "http://example.com",
        ])
        .unwrap();
        assert_eq!(config.transfers[0].proto_default, None);

        let config = parse_args(["-q", "--proto-default", "ftp", "example.com"]).unwrap();
        assert_eq!(config.transfers[0].proto_default.as_deref(), Some("ftp"));

        let error = parse_args(["-q", "--proto-default", "doesnotexist"]).unwrap_err();
        assert!(
            matches!(error, CurlError::UnsupportedProtocol(protocol) if protocol == "doesnotexist")
        );
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
    fn rejects_literal_cookie_header_over_cap() {
        let cookie = format!("name={}", "x".repeat(MAX_LITERAL_COOKIE_HEADER_LEN));
        let error = parse_args(["-q", "-b", &cookie, "https://example.com"]).unwrap_err();

        assert!(error.to_string().contains("cookie"));
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
    fn next_requires_url_before_new_group() {
        let error = parse_args([
            "-q",
            "--libcurl",
            "client.c",
            "--next",
            "https://example.com",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("missing URL before --next"));
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
    fn next_rejects_global_options_without_url() {
        let error = parse_args([
            "-q",
            "--parallel",
            "--parallel-max",
            "2",
            "--next",
            "https://example.com",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("missing URL before --next"));
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
            "--post301",
            "--post302",
            "--post303",
            "--no-location",
            "--no-compressed",
            "--no-post302",
            "https://example.com",
        ])
        .unwrap();

        let transfer = &config.transfers[0];
        assert!(!transfer.follow_location);
        assert!(!transfer.compressed);
        assert!(transfer.post301);
        assert!(!transfer.post302);
        assert!(transfer.post303);
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
