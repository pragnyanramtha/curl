# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

RUST_CARGO_TARGET_DIR = $(abs_builddir)/target
RUST_CURL_BINARY = $(RUST_CARGO_TARGET_DIR)/debug/curl$(EXEEXT)
RUST_CURL_SIDECAR = $(abs_builddir)/bin/curl-rust$(EXEEXT)
RUST_CURL_CORPUS_TESTS = \
  23 200 201 202 203 231 271 283 284 286 290 291 332 419 426 600 601 604 605 606 616 617 640 641 723 725 726 738 739 741 800 801 802 803 806 807 808 809 810 811 812 813 814 817 818 829 846 847 850 851 852 853 854 855 856 857 858 859 860 861 862 863 875 894 900 901 902 909 910 912 917 923 925 927 928 929 930 \
  100 102 104 993 997 1016 1017 1018 1019 1020 1190 1191 \
  1198 1199 1200 1201 1202 1219 1220 1224 1242 1326 1327 1450 \
  1452 1460 1462 1548 1673 1714 1847 1848 2072 3206

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
