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
| DICT | partial | `transfer.rs::run_dict_transfer` | `dict_define_outputs_server_lines_and_sends_request`, `dict_aliases_preserve_case_and_ignore_extra_fields`, `dict_match_alias_sends_database_strategy_and_word`, `dict_empty_fields_use_curl_defaults`, `dict_generic_command_replaces_colons_with_spaces`, `dict_percent_decodes_and_escapes_words`, `dict_query_is_ignored_when_building_request`, `dict_head_sends_request_without_output_body`, `dict_dump_header_creates_empty_file`, `dict_dump_header_dash_writes_no_extra_output`, `dict_include_does_not_add_header_bytes`, `dict_writeout_reports_zero_http_code_and_download_size`, `dict_remote_name_writes_url_filename`, `dict_rejects_decoded_control_path`, `version_lists_dict_protocol` | Plain `dict://` TCP command send/read support only; DICT response lines are body data, `--dump-header` creates empty header output, `--include` does not add bytes, `%{header_json}` stays empty, and buffered `--max-filesize` limiting is shared with the plain TCP body path; auth, proxying, timeout/read cancellation parity, Rust-binary corpus mapping, and exact C `CLIENT libcurl` token parity remain incomplete |
| FILE | partial | `transfer.rs::run_file_transfer` | file URL, headers, range, output modes | GET/HEAD, simple ranges, and buffered `--max-filesize` body limiting only |
| HTTP | partial | `transfer.rs::run_http_transfer` | HTTP test corpus mapping | reqwest-backed subset; `--max-filesize` handles known `Content-Length` preflight and buffered unknown-size body truncation, but overflow `Content-Length`, exact streaming, and decompression parity remain incomplete |
| HTTPS | partial | `transfer.rs::run_http_transfer` | TLS/proxy/cert tests | rustls-backed subset |
| FTP/FTPS | missing | none | FTP tests in `tests/data/` | |
| GOPHER/GOPHERS | partial | `transfer.rs::run_gopher_transfer` | `downloads_gopher_selector`, `gopher_decodes_selector_before_sending`, `gopher_degenerate_selector_sends_only_crlf`, `gopher_appends_and_decodes_query_component`, `gopher_writeout_reports_zero_http_code_and_download_size`, `gopher_remote_name_writes_url_filename`, `gopher_rejects_decoded_nul_selector`, `gopher_include_does_not_echo_selector_header_data`, `gopher_dump_header_writes_selector_as_header_data`, `gopher_dump_header_dash_writes_selector_before_body`, `gopher_head_sends_selector_without_output_body`, `gopher_head_dump_header_writes_selector_without_body`, `gopher_header_json_remains_empty` | Plain `gopher://` selector send/read support only; request selector is surfaced as raw header callback data for `--dump-header`, `--include` does not echo it, structured `%{header_json}` remains empty, and buffered `--max-filesize` limiting is shared with the plain TCP body path; `gophers://`, IPv6 fixture coverage, proxying, redirects, timeout parity, and full corpus mapping remain incomplete |
| IPFS/IPNS | partial | `ipfs.rs::maybe_rewrite_url` plus HTTP transfer path | `ipfs_gateway_rewrites_to_http_path`, `ipfs_path_and_query_with_gateway_path`, `ipns_path_and_query_with_gateway_path`, `ipfs_gateway_env_overrides_gateway_file`, `ipfs_gateway_file_discovery_uses_first_line`, `ipfs_path_env_discovery_accepts_no_trailing_slash`, `ipfs_gateway_query_is_malformed_exit_3`, `ipfs_auto_gateway_missing_exits_37`, `ipfs_malformed_explicit_gateway_exits_43`, `libcurl_rewrites_ipfs_url_to_gateway_url`, `version_lists_ipfs_and_ipns_protocols` | Rewrites `ipfs://` and `ipns://` through explicit/env/file gateway discovery into the existing HTTP path, preserving path/query and gateway-path joins; gateway URL query rejection, generated libcurl URL rewriting, and key exit codes are covered, but full C URL encoding parity, trustless gateway concerns, `IPFS_PATH` trailing slash matrix, Rust-binary corpus mapping, and exact C `curl -V` protocol formatting remain incomplete |
| IMAP/IMAPS | missing | none | protocol tests | |
| LDAP/LDAPS | missing | none | protocol tests | |
| MQTT/MQTTS | missing | none | protocol tests | |
| POP3/POP3S | partial | `transfer.rs::run_pop3_transfer` | `pop3_retr_downloads_message_and_unstuffs_dot_lines`, `pop3_uses_url_userinfo_when_user_option_is_absent`, `pop3_empty_path_lists_messages`, `pop3_list_only_sends_list_for_message_id_without_body`, `pop3_command_error_returns_weird_server_reply`, `pop3_custom_top_outputs_multiline_body`, `pop3_head_custom_stat_suppresses_body_and_keeps_zero_http_code`, `pop3_rejects_decoded_control_path`, `pop3_login_failure_returns_login_denied`, `version_lists_pop3_protocol` | Plain `pop3://` TCP support only; sends CAPA, USER/PASS cleartext auth, LIST/RETR/default and custom `-X` commands, handles multiline terminators and dot-stuffing, keeps POP3 protocol replies out of headers and `%{http_code}`, supports URL userinfo, `--list-only`, `--max-filesize`, and exit codes 8/67 for command/login failures. `pop3s://`, STLS, SASL/APOP/OAuth, URL `;AUTH=`, proxying, connection reuse, exact command-reply diagnostics, and full corpus mapping remain incomplete |
| RTSP | missing | none | protocol tests | |
| SCP/SFTP | missing | none | protocol tests | |
| SMB/SMBS | missing | none | protocol tests | |
| SMTP/SMTPS | missing | none | protocol tests | |
| TELNET | partial | `transfer.rs::run_telnet_transfer` | `telnet_upload_file_sends_file_and_outputs_response`, `telnet_sends_stdin_without_upload_file`, `telnet_upload_dash_reads_stdin_and_escapes_iac`, `telnet_filters_negotiation_and_replies_to_peer`, `telnet_writeout_reports_zero_http_code_and_download_size`, `telnet_dump_header_creates_empty_file_and_include_adds_nothing`, `telnet_options_fail_explicitly_until_negotiation_options_are_supported`, `max_filesize_truncates_telnet_body_then_fails`, `version_lists_telnet_protocol` | Plain `telnet://` TCP stream support only; stdin/`--upload-file` bytes are sent, outbound IAC bytes are escaped, basic peer-started WILL/DO negotiation is filtered/rejected, `--max-filesize` truncates buffered output and exits 63, and TELNET output remains body-only; `--telnet-option`, proactive C curl negotiation preferences, NAWS/TTYPE/XDISPLOC/NEW_ENV suboptions, interactive polling parity, TLS/proxying, and full corpus mapping remain incomplete |
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
| `--list-only` | partial | `TransferConfig::list_only` | `parses_list_only_option`, `pop3_list_only_sends_list_for_message_id_without_body`, `libcurl_writes_source_file_for_supported_options` | Implemented for POP3 message-specific LIST and emitted in `--libcurl`; FTP/SFTP/FILE behavior and full corpus mapping remain incomplete |
| `--data`, `--data-binary`, `--data-raw`, `--data-urlencode` | partial | `TransferConfig::data` | unit body tests | Needs full corpus mapping |
| `--json` | partial | `TransferConfig::data` | `sends_json_body_and_default_json_headers` | Basic defaults only |
| `--url-query` | partial | `TransferConfig::url_query` | `sends_referer_range_and_url_query` | Basic encoding and `+` passthrough only |
| `--form`, `--form-string` | partial | `TransferConfig::forms` | `sends_multipart_form_body` | Basic fields/files only |
| `--upload-file` | partial | `TransferConfig::upload_file` | `telnet_upload_file_sends_file_and_outputs_response`, `telnet_upload_dash_reads_stdin_and_escapes_iac`, `http_upload_file_sends_put_body`, `http_upload_dash_reads_stdin`, `http_upload_to_directory_url_appends_local_filename`, `http_upload_to_query_url_does_not_append_local_filename`, `http_upload_respects_custom_request_method`, `http_upload_rejects_data_body_combination`, `http_upload_missing_file_exits_read_error`, `libcurl_writes_http_upload_options`, `parses_upload_file_and_telnet_options` | TELNET upload source plus basic HTTP/HTTPS in-memory PUT upload from a file or stdin; HTTP upload defaults to PUT, respects explicit `-X`, appends the local basename for directory URLs without queries, reports missing upload files as exit 26, and emits basic `--libcurl` upload options. FTP/SFTP uploads, upload globs and URL pairing, `-T .`, chunked stdin/`Expect: 100-continue`, upload resume/`Content-Range`, auth/redirect rewind parity, multipart/data mixing parity, parallel timing, and full corpus mapping are missing |
| `--telnet-option` | partial | `TransferConfig::telnet_options` | `telnet_options_fail_explicitly_until_negotiation_options_are_supported`, `parses_upload_file_and_telnet_options` | Parsed and rejected explicitly for TELNET until TTYPE/XDISPLOC/NEW_ENV/NAWS negotiation support is implemented |
| `--ipfs-gateway` | partial | `TransferConfig::ipfs_gateway` | `parses_ipfs_gateway`, `rejects_empty_ipfs_gateway`, IPFS/IPNS rewrite tests | Explicit gateway parsing and IPFS/IPNS HTTP rewrite support only; generated libcurl rewrites URL through the same helper, but full corpus mapping and exact C URL parser edge cases remain incomplete |
| `--output`, `--remote-name`, `--remote-header-name` | partial | output module | output and `-OJ` tests | Needs full Content-Disposition parity |
| `--dump-header` | partial | `TransferConfig::dump_header` | `dump_header_dash_writes_headers_to_stdout` | Redirect header history incomplete |
| `--write-out` | partial | `writeout.rs` | `renders_common_variables` | Many variables missing |
| `--referer` | partial | `TransferConfig::referer`, `TransferConfig::auto_referer` | `sends_referer_range_and_url_query`, `location_does_not_auto_referer_without_referer_auto`, `fixed_referer_is_reused_across_redirects_without_auto`, `auto_referer_strips_credentials_and_fragment_on_redirect`, `auto_referer_tracks_immediately_previous_redirect_url`, `auto_referer_respects_max_redirs_limit`, `initial_referer_auto_replaces_referer_after_redirect`, `custom_referer_header_suppresses_generated_referer` | Basic header, `;auto` redirect behavior, `%{referer}`, max-redirs exhaustion for the auto path, and libcurl `CURLOPT_AUTOREFERER` covered; method rewriting, auth/cookie redirect scoping, and full corpus mapping remain incomplete |
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
| `--fail`, `--fail-with-body` | partial | transfer status handling | `fail_suppresses_http_error_body`, `fail_with_body_outputs_http_error_body_and_fails`, `fail_after_fail_with_body_suppresses_error_body`, `fail_with_body_after_fail_outputs_error_body`, `no_fail_with_body_disables_http_error_failure`, `fail_include_outputs_headers_without_error_body`, `fail_writeout_reports_zero_delivered_body_bytes`, `fail_with_body_retry_outputs_failed_and_successful_bodies`, `fail_options_are_mutexed_with_last_one_winning` | Basic HTTP 4xx/5xx exit 22 handling is covered; `--fail` suppresses bodies while preserving included headers and zero delivered body bytes, `--fail-with-body` preserves bodies, retry preserves failed bodies for stdout, and option mutex ordering follows C warnings. Auth negotiation edge cases, 416 resume exception, exact stderr/`%{errormsg}` wording, output-file retry truncation parity, and full corpus mapping remain incomplete |
| `--connect-timeout`, `--max-time` | partial | reqwest client builder | none | Needs edge case tests |
| `--max-filesize` | partial | `TransferConfig::max_filesize` | `parses_max_filesize_units_and_fractions`, `rejects_bad_max_filesize_values`, `max_filesize_allows_http_body_within_limit`, `max_filesize_zero_disables_limit`, `max_filesize_rejects_http_content_length_before_body_output`, `max_filesize_truncates_unknown_http_body_then_fails`, `max_filesize_does_not_fail_head_with_large_content_length`, `max_filesize_truncates_telnet_body_then_fails`, `libcurl_writes_source_file_for_supported_options` | Parses curl-style bytes plus `b/K/M/G/T/P` suffixes and fractional unit values, with `0` disabling the limit; HTTP known `Content-Length` fails with exit 63 before body output, unknown-size HTTP and TELNET buffered bodies write up to the limit then fail, and `--libcurl` emits `CURLOPT_MAXFILESIZE_LARGE`. Overflow `Content-Length`, exact C stderr variants, true streaming cutoff, decompressed `--compressed` accounting, redirect/retry edge cases, FTP/MQTT preflight support, and full corpus mapping remain incomplete |
| `--http1.0`, `--http1.1`, `--http2` | partial | reqwest versions | `http2_does_not_force_prior_knowledge` | HTTP/3 missing |
| `--retry*` | partial | `TransferConfig::retry` | `retries_transient_http_status_then_succeeds`, `retry_all_errors_retries_failed_http_status` | HTTP transient status retry and basic retry timers only; FTP, upload rewind, partial-output resume, and full error taxonomy missing |
| `--continue-at` | partial | `TransferConfig::continue_at` | `continue_at_fixed_offset_sends_range_and_appends_output`, `continue_at_auto_uses_existing_output_size`, `continue_at_fixed_offset_to_stdout_sends_range`, `continue_at_resumes_file_url_output` | Download resume for HTTP/file output and stdout only; upload resume, HTTP resume response validation, partial-output retry resume, and remote-header filename auto-resume incomplete |
| `--cookie`, `--cookie-jar`, `--junk-session-cookies` | partial | `TransferConfig::cookie`, `TransferConfig::cookie_files`, `TransferConfig::cookie_jar`, `TransferConfig::junk_session_cookies` | `empty_cookie_input_activates_cookie_engine`, `cookie_header_appends_repeated_literals`, `cookie_file_sends_netscape_cookie`, `junk_session_cookies_ignores_file_session_cookies`, `cookie_file_and_literal_cookie_are_combined`, `cookie_jar_saves_response_cookies`, `cookie_jar_creates_header_only_file_without_cookies`, `cookie_jar_sends_cookie_on_later_url_in_group` | Basic direct Cookie headers, repeated literal joining, engine activation, Netscape/Set-Cookie file import, session-cookie skipping for file import, HTTP cookie engine, file-plus-literal sends, and Netscape jar output only; PSL/supercookie rejection, exact expiry/order/domain/path/sorting parity, redirect-cookie export, and full corpus mapping remain incomplete |
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
