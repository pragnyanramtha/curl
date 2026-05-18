# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

RUST_CARGO_TARGET_DIR = $(abs_builddir)/target
RUST_CURL_BINARY = $(RUST_CARGO_TARGET_DIR)/debug/curl$(EXEEXT)
RUST_CURL_SIDECAR = $(abs_builddir)/bin/curl-rust$(EXEEXT)
RUST_CURL_CORPUS_TESTS = \
  23 200 231 271 283 426 900 909 912 923 927 928 929 930 \
  100 102 104 1016 1017 1018 1019 1020 1190 1191 \
  1198 1199 1200 1201 1202 1220 1224 1242 1450 \
  1452 1548 1673 1714 2072

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
	mkdir -p "$(abs_builddir)/bin"
	cp "$(RUST_CURL_BINARY)" "$(RUST_CURL_SIDECAR)"

check-local: rust-test rust-corpus-test

rust-test:
	CARGO_TARGET_DIR="$(RUST_CARGO_TARGET_DIR)" $(CARGO) test --locked --manifest-path "$(abs_srcdir)/curl-rust/Cargo.toml"

rust-corpus-test: rust-curl
	@(cd "$(abs_top_builddir)/tests" && \
	  srcdir="$(abs_top_srcdir)/tests" $(PERL) "$(abs_top_srcdir)/tests/runtests.pl" \
	    -n -a -s -c "$(RUST_CURL_SIDECAR)" \
	    $(RUST_CURL_CORPUS_TESTS) $(TFLAGS))

clean-local:
	rm -rf "$(RUST_CARGO_TARGET_DIR)" "$(abs_builddir)/bin"

.PHONY: rust-curl rust-test rust-corpus-test
