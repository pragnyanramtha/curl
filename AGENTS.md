# Agent Instructions

This repository is being rewritten in Rust. Treat the acceptance bar as a full
curl rewrite, not a prototype.

## Required Deliverables

- Rust code must compile fully with a locked dependency graph.
- All curl command-line features and protocol behavior must be present or
  explicitly tracked as incomplete work; do not mark the rewrite complete while
  known features are missing.
- The Rust build must be integrated into the repository build systems without
  breaking the existing C build.
- CMake builds with `BUILD_RUST_CURL_EXE=ON` must build the Rust sidecar during
  a normal build, not only through a manually selected target.
- Autotools builds with `--enable-rust-curl` must build the Rust sidecar.
- Cargo invocations from repository build systems must use `--locked`.
- All applicable test suites must run before completion is claimed.

## Commit Discipline

- Make frequent local commits at coherent checkpoints.
- Prefer one focused behavior or integration slice per commit.
- Do not leave passing verification only in the working tree when a commit can
  safely capture it.

## Verification Gates

Run every feasible gate and record hard blockers when tools or external
services are unavailable:

```sh
cargo fmt --all --check
CARGO_TARGET_DIR=/tmp/curl-rust-target cargo test -p curl-rust --locked
CARGO_TARGET_DIR=/tmp/curl-rust-target cargo clippy -p curl-rust --all-targets --locked -- -D warnings
CARGO_TARGET_DIR=/tmp/curl-rust-target cargo build -p curl-rust --locked --bin curl
CARGO_TARGET_DIR=/tmp/curl-rust-target cargo run -q -p curl-rust --locked -- --version
cmake -S . -B build-rust-sidecar -DBUILD_RUST_CURL_EXE=ON
cmake --build build-rust-sidecar
cmake --build build-rust-sidecar --target curl-rust-test
cmake --build build-rust-sidecar --target curl-rust-corpus-test
autoreconf -fi
./configure --enable-rust-curl --with-openssl
make -j"$(nproc)"
make -C rust rust-corpus-test
make check
```

If a verifier cannot run, the blocker is part of the remaining work. Passing the
Rust sidecar tests alone is not enough to call the project complete.

## Subagent Use

Use manager agents and nested subagents extensively for this rewrite. At minimum,
delegate independent reviews of:

- CLI option parity against `src/tool_getparam.c` and `src/tool_parsecfg.c`.
- Protocol and transfer parity against `lib/`, `src/tool_operate.c`, and the
  existing test corpus.
- CMake, autotools, packaging, and lockfile integration.
- Full test execution, CI failures, and missing environment dependencies.

Subagents must not revert unrelated edits. They should report concrete file and
line findings, commands run, commands blocked, and remaining gaps.
