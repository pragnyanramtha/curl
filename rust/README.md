# Rust curl rewrite

This directory contains a Rust implementation of the curl command line tool
that can be built and tested without changing the existing C, autotools, or
CMake build paths.

Build and test it with:

```sh
cargo test -p curl-rust --locked
cargo run -p curl-rust --locked -- --version
```

The first Rust binary supports a limited sidecar surface. Track implemented,
partial, and missing curl behavior in [PARITY.md](PARITY.md). Protocols and
options outside that roadmap still belong to the C implementation until they
are ported and verified.
