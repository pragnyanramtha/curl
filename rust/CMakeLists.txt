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

set(_curl_rust_corpus_tests
  23
  100
  102
  104
  200
  231
  271
  283
  284
  286
  332
  419
  426
  806
  807
  850
  851
  852
  855
  900
  901
  902
  909
  910
  912
  917
  923
  925
  927
  928
  929
  930
  1016
  1017
  1018
  1019
  1020
  1190
  1191
  1198
  1199
  1200
  1201
  1202
  1219
  1220
  1224
  1242
  1450
  1452
  1460
  1548
  1673
  1714
  2072
)

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

if(CURL_BUILD_TESTING AND PERL_EXECUTABLE)
  add_custom_target(curl-rust-corpus-test
    COMMAND ${CMAKE_COMMAND} -E env
      "srcdir=${PROJECT_SOURCE_DIR}/tests"
      "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/runtests.pl"
        -n -a -s
        -c "${_curl_rust_sidecar}"
        ${_curl_rust_corpus_tests}
        "\$TFLAGS"
    DEPENDS curl-rust testdeps
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/tests"
    COMMENT "Running curl corpus smoke tests with Rust sidecar"
    VERBATIM USES_TERMINAL
  )
endif()
