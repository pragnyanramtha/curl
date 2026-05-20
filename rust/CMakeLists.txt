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
  "${PROJECT_SOURCE_DIR}/include/curl/curlver.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/Cargo.toml"
  "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/src/*.rs"
  "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/tests/*.rs"
)

add_custom_command(
  OUTPUT "${_curl_rust_sidecar}"
  COMMAND ${CMAKE_COMMAND} -E make_directory
    "${_curl_rust_target_dir}"
    "${CMAKE_CURRENT_BINARY_DIR}/bin"
  COMMAND ${CMAKE_COMMAND} -E env
    "CARGO_TARGET_DIR=${_curl_rust_target_dir}"
    "${CARGO_EXECUTABLE}" build
      --locked
      --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/curl-rust/Cargo.toml"
      --bin curl
  COMMAND ${CMAKE_COMMAND} -E copy "${_curl_rust_binary}" "${_curl_rust_sidecar}"
  DEPENDS ${_curl_rust_sources}
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Building experimental Rust curl sidecar"
  VERBATIM
)

add_custom_target(curl-rust ALL DEPENDS "${_curl_rust_sidecar}")

if(NOT CURL_DISABLE_INSTALL)
  install(PROGRAMS "${_curl_rust_sidecar}"
    DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

set(_curl_rust_corpus_tests
  14
  21
  23
  41
  48
  100
  102
  104
  107
  113
  114
  115
  117
  118
  120
  121
  124
  125
  126
  136
  137
  138
  147
  148
  182
  200
  201
  202
  203
  204
  205
  219
  220
  222
  224
  225
  226
  227
  230
  231
  232
  237
  238
  261
  270
  271
  283
  284
  285
  286
  288
  290
  291
  292
  293
  295
  332
  333
  378
  393
  419
  426
  452
  454
  457
  460
  462
  467
  477
  496
  580
  600
  601
  602
  603
  604
  605
  606
  607
  608
  609
  610
  611
  612
  615
  616
  617
  618
  619
  622
  623
  624
  625
  626
  628
  629
  633
  634
  635
  636
  637
  638
  639
  640
  641
  642
  656
  664
  665
  697
  723
  725
  726
  738
  739
  741
  754
  759
  774
  787
  800
  801
  802
  803
  806
  807
  808
  809
  810
  811
  812
  813
  814
  817
  818
  829
  841
  846
  847
  850
  851
  852
  853
  854
  855
  856
  857
  858
  859
  860
  861
  862
  863
  875
  894
  900
  901
  902
  909
  910
  911
  912
  913
  914
  915
  916
  917
  918
  923
  925
  926
  927
  928
  929
  930
  931
  950
  951
  952
  993
  997
  1000
  1003
  1005
  1006
  1007
  1009
  1016
  1017
  1018
  1019
  1020
  1022
  1023
  1027
  1049
  1062
  1093
  1094
  1099
  1146
  1153
  1181
  1190
  1191
  1192
  1193
  1194
  1196
  1198
  1199
  1200
  1201
  1202
  1203
  1219
  1220
  1224
  1234
  1236
  1238
  1242
  1243
  1264
  1269
  1278
  1281
  1282
  1289
  1326
  1327
  1409
  1410
  1427
  1450
  1451
  1452
  1453
  1460
  1462
  1474
  1548
  1563
  1673
  1714
  1847
  1848
  1850
  2004
  2007
  2008
  2044
  2045
  2072
  2075
  2080
  2092
  2200
  2201
  2202
  2203
  2204
  2206
  2207
  3002
  3003
  3004
  3005
  3006
  3007
  3017
  3018
  3019
  3020
  3021
  3022
  3206
)

add_custom_target(curl-rust-test
  COMMAND ${CMAKE_COMMAND} -E make_directory "${_curl_rust_target_dir}"
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
