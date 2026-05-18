# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

RUST_CARGO_TARGET_DIR = $(abs_builddir)/target
RUST_CURL_BINARY = $(RUST_CARGO_TARGET_DIR)/debug/curl$(EXEEXT)
RUST_CURL_SIDECAR = $(abs_builddir)/bin/curl-rust$(EXEEXT)
RUST_CURL_CORPUS_TESTS = \
  23 200 201 202 203 219 225 226 231 238 261 271 283 284 285 286 290 291 295 332 333 419 426 462 467 496 600 601 604 605 606 616 617 640 641 723 725 726 738 739 741 774 800 801 802 803 806 807 808 809 810 811 812 813 814 817 818 829 846 847 850 851 852 853 854 855 856 857 858 859 860 861 862 863 875 894 900 901 902 909 910 912 917 923 925 927 928 929 930 \
  100 102 104 126 136 137 138 993 997 1000 1003 1005 1006 1016 1017 1018 1019 1020 1062 1094 1153 1190 1191 1192 1193 \
  1194 1196 1198 1199 1200 1201 1202 1219 1220 1224 1234 1236 1242 1243 1264 1269 1281 \
  1289 1326 1327 1409 1410 1450 1451 1452 1460 1462 1474 1548 1673 1714 1847 1848 1850 2072 2080 2092 2200 2201 2202 \
  2203 2204 2206 2207 3017 3018 3206

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
