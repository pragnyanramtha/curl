# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(_curl_rust_target_dir "${CMAKE_CURRENT_BINARY_DIR}/target")
set(_curl_rust_binary "${_curl_rust_target_dir}/debug/curl${CMAKE_EXECUTABLE_SUFFIX}")
set(_curl_rust_sidecar "${CMAKE_CURRENT_BINARY_DIR}/bin/curl-rust${CMAKE_EXECUTABLE_SUFFIX}")

file(GLOB_RECURSE _curl_rust_sources CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/Cargo.toml"
  "${PROJECT_SOURCE_DIR}/Cargo.lock"
  "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/Cargo.toml"
  "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/src/*.rs"
  "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/tests/*.rs"
)

add_custom_command(
  OUTPUT "${_curl_rust_sidecar}"
  COMMAND ${CMAKE_COMMAND} -E env
    "CARGO_TARGET_DIR=${_curl_rust_target_dir}"
    "${CARGO_EXECUTABLE}" build
      --locked
      --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/Cargo.toml"
      --bin curl
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/bin"
  COMMAND ${CMAKE_COMMAND} -E copy "${_curl_rust_binary}" "${_curl_rust_sidecar}"
  DEPENDS ${_curl_rust_sources}
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Building experimental Rust curl sidecar"
  VERBATIM
)

add_custom_target(curl-rust ALL DEPENDS "${_curl_rust_sidecar}")

add_custom_target(curl-rust-test
  COMMAND ${CMAKE_COMMAND} -E env
    "CARGO_TARGET_DIR=${_curl_rust_target_dir}"
    "${CARGO_EXECUTABLE}" test
      --locked
      --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/Cargo.toml"
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Testing experimental Rust curl sidecar"
  VERBATIM
)
