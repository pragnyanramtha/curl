# Rust curl parity roadmap

Status values:

- `verified`: implemented and covered by focused Rust tests plus mapped curl tests.
- `partial`: implemented for a limited subset, with known curl behavior missing.
- `missing`: not implemented in the Rust sidecar.
- `blocked`: blocked by architecture, dependencies, or test environment.

The Rust sidecar is incomplete until every required protocol, option, transfer
behavior, and test mapping is `verified` or explicitly accepted as out of scope.

## Source of truth

- CLI options: `src/tool_getparam.c`, `src/tool_parsecfg.c`,
  `docs/cmdline-opts/`
- Transfer behavior: `src/tool_operate.c`, `src/tool_cfgable.c`,
  `src/tool_cb_hdr.c`, `src/tool_cb_wrt.c`, `lib/`
- Protocol behavior: `lib/`, `docs/FEATURES.md`, `README.md`
- Tests: `tests/data/`, `tests/http/`, `tests/unit/`, `tests/libtest/`

## Protocol parity

| Protocol | Status | Rust entry point | Required behavior/tests | Notes |
| --- | --- | --- | --- | --- |
| FILE | partial | `transfer.rs::run_file_transfer` | file URL, headers, range, output modes | GET/HEAD and simple ranges only |
| HTTP | partial | `transfer.rs::run_http_transfer` | HTTP test corpus mapping | reqwest-backed subset |
| HTTPS | partial | `transfer.rs::run_http_transfer` | TLS/proxy/cert tests | rustls-backed subset |
| FTP/FTPS | missing | none | FTP tests in `tests/data/` | |
| GOPHER/GOPHERS | missing | none | protocol tests | |
| IMAP/IMAPS | missing | none | protocol tests | |
| LDAP/LDAPS | missing | none | protocol tests | |
| MQTT/MQTTS | missing | none | protocol tests | |
| POP3/POP3S | missing | none | protocol tests | |
| RTSP | missing | none | protocol tests | |
| SCP/SFTP | missing | none | protocol tests | |
| SMB/SMBS | missing | none | protocol tests | |
| SMTP/SMTPS | missing | none | protocol tests | |
| TELNET | missing | none | protocol tests | |
| TFTP | missing | none | protocol tests | |
| WS/WSS | missing | none | websocket tests | |

## CLI option parity

Every `docs/cmdline-opts/*.md` option must be tracked here or in generated
companion data before this rewrite can be called complete.

| Option or behavior | Status | Rust field/parser | Behavior tests | Notes |
| --- | --- | --- | --- | --- |
| `--config`, default `.curlrc`, `-q` | partial | `cli.rs::insert_config_file` | `tokenizes_curl_config_lines` | Limited tokenizer and recursion handling |
| `--next` | partial | `TransferConfig` groups | `splits_transfer_groups_on_next` | Needs full option reset audit |
| `--no-*` boolean negation | partial | `cli.rs::parse_no_long` | `no_prefixed_boolean_options_disable_previous_values` | Only supported booleans are recognized |
| `--data`, `--data-binary`, `--data-raw`, `--data-urlencode` | partial | `TransferConfig::data` | unit body tests | Needs full corpus mapping |
| `--json` | partial | `TransferConfig::data` | `sends_json_body_and_default_json_headers` | Basic defaults only |
| `--url-query` | partial | `TransferConfig::url_query` | `sends_referer_range_and_url_query` | Basic encoding and `+` passthrough only |
| `--form`, `--form-string` | partial | `TransferConfig::forms` | `sends_multipart_form_body` | Basic fields/files only |
| `--output`, `--remote-name`, `--remote-header-name` | partial | output module | output and `-OJ` tests | Needs full Content-Disposition parity |
| `--dump-header` | partial | `TransferConfig::dump_header` | `dump_header_dash_writes_headers_to_stdout` | Redirect header history incomplete |
| `--write-out` | partial | `writeout.rs` | `renders_common_variables` | Many variables missing |
| `--referer` | partial | `TransferConfig::referer` | `sends_referer_range_and_url_query` | `;auto` semantics missing |
| `--range` | partial | `TransferConfig::range` | `file_range_outputs_slice`, HTTP header test | Multipart ranges and resume interactions missing |
| `--etag-save`, `--etag-compare` | partial | `TransferConfig::etag_save`, `TransferConfig::etag_compare` | `etag_compare_sends_if_none_match`, `etag_save_writes_response_etag` | Single URL semantics and full corpus mapping missing |
| `--time-cond` | partial | `TransferConfig::time_cond` | `time_cond_sends_if_modified_since`, `negative_time_cond_sends_if_unmodified_since` | Date parsing and file mtime semantics missing |
| `--user` | partial | `TransferConfig::user` | `username_only_basic_auth_encodes_empty_password` | Basic auth only |
| `--oauth2-bearer` | partial | `TransferConfig::oauth2_bearer` | `sends_oauth2_bearer_authorization_header` | Redirect credential scoping needs parity work |
| `--proxy` | partial | `TransferConfig::proxy` | `proxy_user_sets_proxy_authorization_header`, `noproxy_bypasses_configured_proxy` | Basic HTTP proxy path only |
| `--proxy-user` | partial | `TransferConfig::proxy_user` | `proxy_user_sets_proxy_authorization_header` | Basic proxy auth only |
| `--noproxy` | partial | `TransferConfig::noproxy` | `noproxy_bypasses_configured_proxy` | Delegates matching to reqwest |
| `--compressed` | partial | `TransferConfig::compressed` | default encoding assertion | Compression negotiation subset |
| `--location` | partial | reqwest redirect policy | parser tests only | Manual redirect behavior needed for full parity |
| `--fail`, `--fail-with-body` | partial | transfer status handling | none | Needs corpus mapping |
| `--connect-timeout`, `--max-time` | partial | reqwest client builder | none | Needs edge case tests |
| `--http1.0`, `--http1.1`, `--http2` | partial | reqwest versions | `http2_does_not_force_prior_knowledge` | HTTP/3 missing |
| `--retry*` | partial | `TransferConfig::retry` | `retries_transient_http_status_then_succeeds`, `retry_all_errors_retries_failed_http_status` | HTTP transient status retry and basic retry timers only; FTP, upload rewind, partial-output resume, and full error taxonomy missing |
| `--continue-at` | partial | `TransferConfig::continue_at` | `continue_at_fixed_offset_sends_range_and_appends_output`, `continue_at_auto_uses_existing_output_size`, `continue_at_fixed_offset_to_stdout_sends_range`, `continue_at_resumes_file_url_output` | Download resume for HTTP/file output and stdout only; upload resume, HTTP resume response validation, partial-output retry resume, and remote-header filename auto-resume incomplete |
| `--cookie-jar` | partial | `TransferConfig::cookie_jar` | `cookie_jar_saves_response_cookies`, `cookie_jar_creates_header_only_file_without_cookies`, `cookie_jar_sends_cookie_on_later_url_in_group` | Basic HTTP cookie engine and Netscape jar output only; full `--cookie` file import, PSL/supercookie rejection, exact expiry/order/domain/path parity, and complete redirect-cookie export remain incomplete |
| `--parallel`, `--parallel-max`, `--parallel-immediate`, `--parallel-max-host` | partial | `Config::parallel*`, `transfer.rs::run_parallel` | `parses_parallel_options_as_global_state`, `parallel_runs_transfers_concurrently_to_files` | Basic bounded async scheduling for expanded URL jobs; `--parallel-immediate` and `--parallel-max-host` are parsed/stored but no-op, stdout/write-out/cookie timing/order, retry queue behavior, fail-early, multiplexing, and full corpus parity remain incomplete |
| `--libcurl` | partial | `Config::libcurl`, `libcurl.rs` | `parses_libcurl_options_as_global_state`, `libcurl_writes_source_file_for_supported_options` | Emits C source for supported HTTP/file URL expansion and common scalar/string/slist options; exact C curl formatting, callbacks, multipart MIME source, protocol-specific options, multi-transfer ordering, and full fixture parity remain incomplete |

## Build and test parity

| Gate | Status | Evidence |
| --- | --- | --- |
| Cargo locked build/test | partial | `cargo test -p curl-rust --locked` |
| Cargo clippy | partial | `cargo clippy -p curl-rust --all-targets --locked -- -D warnings` |
| CMake sidecar build | partial | `BUILD_RUST_CURL_EXE=ON`, `curl-rust-test` |
| Autotools sidecar build | partial | `--enable-rust-curl`, `make check` |
| Existing curl Perl suite with C binary | verified for C path | Does not prove Rust parity |
| Existing curl Perl suite with Rust binary | missing | Required before full parity |
| Pytest HTTP suite with Rust binary | missing | Required before full parity |
