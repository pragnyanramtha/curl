# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

RUST_CARGO_TARGET_DIR = $(abs_builddir)/target
RUST_CURL_BINARY = $(RUST_CARGO_TARGET_DIR)/debug/curl$(EXEEXT)
RUST_CURL_SIDECAR = $(abs_builddir)/curl-rust$(EXEEXT)

EXTRA_DIST =                                      \
  README.md                                      \
  PARITY.md                                      \
  CMakeLists.txt                                 \
  curl-rust/Cargo.toml                           \
  curl-rust/src/cli.rs                           \
  curl-rust/src/cookie.rs                        \
  curl-rust/src/data.rs                          \
  curl-rust/src/error.rs                         \
  curl-rust/src/glob.rs                          \
  curl-rust/src/ipfs.rs                          \
  curl-rust/src/lib.rs                           \
  curl-rust/src/libcurl.rs                       \
  curl-rust/src/main.rs                          \
  curl-rust/src/output.rs                        \
  curl-rust/src/transfer.rs                      \
  curl-rust/src/writeout.rs                      \
  curl-rust/tests/cli_integration.rs

all-local: rust-curl

rust-curl:
	CARGO_TARGET_DIR="$(RUST_CARGO_TARGET_DIR)" $(CARGO) build --locked --manifest-path "$(abs_srcdir)/curl-rust/Cargo.toml" --bin curl
	cp "$(RUST_CURL_BINARY)" "$(RUST_CURL_SIDECAR)"

check-local: rust-test

rust-test:
	CARGO_TARGET_DIR="$(RUST_CARGO_TARGET_DIR)" $(CARGO) test --locked --manifest-path "$(abs_srcdir)/curl-rust/Cargo.toml"

clean-local:
	rm -rf "$(RUST_CARGO_TARGET_DIR)" "$(RUST_CURL_SIDECAR)"

.PHONY: rust-curl rust-test
