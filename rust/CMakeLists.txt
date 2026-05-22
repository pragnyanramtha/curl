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
  1
  2
  6
  12
  13
  14
  15
  17
  19
  21
  23
  24
  32
  34
  37
  41
  47
  48
  57
  59
  66
  77
  78
  80
  87
  100
  102
  104
  105
  106
  107
  109
  110
  111
  112
  113
  114
  115
  117
  118
  120
  121
  122
  123
  124
  125
  126
  127
  128
  135
  136
  137
  138
  141
  142
  143
  147
  148
  151
  152
  161
  180
  181
  182
  191
  192
  194
  195
  197
  198
  199
  200
  201
  202
  203
  204
  205
  207
  219
  220
  222
  224
  225
  226
  227
  228
  229
  230
  231
  232
  235
  236
  237
  238
  240
  244
  249
  260
  261
  266
  269
  270
  271
  280
  282
  283
  284
  285
  286
  288
  289
  290
  291
  292
  293
  294
  295
  296
  297
  298
  319
  326
  328
  332
  333
  334
  336
  337
  339
  341
  344
  345
  348
  350
  351
  352
  353
  354
  362
  366
  369
  370
  371
  372
  376
  378
  379
  387
  389
  391
  393
  395
  416
  418
  419
  426
  428
  434
  448
  449
  452
  454
  457
  459
  460
  462
  467
  468
  475
  476
  477
  481
  482
  484
  485
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
  681
  682
  683
  684
  685
  690
  691
  692
  693
  697
  722
  723
  724
  725
  726
  727
  730
  731
  732
  733
  734
  735
  736
  737
  738
  739
  740
  741
  743
  752
  754
  756
  759
  762
  774
  784
  785
  786
  787
  788
  794
  796
  797
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
  865
  866
  871
  872
  875
  892
  893
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
  941
  950
  951
  952
  978
  993
  994
  995
  996
  997
  1000
  1003
  1004
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
  1091
  1093
  1094
  1099
  1107
  1108
  1116
  1122
  1123
  1124
  1125
  1126
  1127
  1128
  1132
  1137
  1146
  1153
  1170
  1171
  1174
  1181
  1190
  1191
  1192
  1193
  1194
  1195
  1196
  1198
  1199
  1200
  1201
  1202
  1203
  1219
  1220
  1223
  1224
  1226
  1227
  1234
  1236
  1238
  1239
  1242
  1243
  1247
  1264
  1269
  1272
  1277
  1278
  1281
  1282
  1288
  1289
  1298
  1299
  1310
  1311
  1312
  1313
  1326
  1327
  1340
  1341
  1409
  1410
  1424
  1427
  1429
  1438
  1439
  1440
  1441
  1442
  1443
  1444
  1445
  1446
  1450
  1451
  1452
  1453
  1457
  1460
  1462
  1474
  1489
  1490
  1491
  1492
  1497
  1546
  1548
  1563
  1566
  1569
  1570
  1584
  1585
  1613
  1617
  1619
  1633
  1634
  1635
  1637
  1641
  1642
  1643
  1673
  1680
  1681
  1682
  1683
  1712
  1714
  1847
  1848
  1850
  1851
  1909
  1983
  1984
  2004
  2005
  2007
  2008
  2044
  2045
  2050
  2072
  2075
  2080
  2092
  2200
  2201
  2202
  2203
  2204
  2205
  2206
  2207
  3002
  3003
  3004
  3005
  3006
  3007
  3014
  3017
  3018
  3019
  3020
  3021
  3022
  3035
  3036
  3204
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
  set(_curl_rust_corpus_deps
    curl-rust
    testdeps
  )
  if(TARGET ${EXE_NAME})
    list(APPEND _curl_rust_corpus_deps ${EXE_NAME})
  endif()
  if(TARGET curlinfo)
    list(APPEND _curl_rust_corpus_deps curlinfo)
  endif()

  add_custom_target(curl-rust-corpus-test
    COMMAND ${CMAKE_COMMAND} -E env
      "srcdir=${PROJECT_SOURCE_DIR}/tests"
      "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/runtests.pl"
        -n -a -s -p
        -c "${_curl_rust_sidecar}"
        ${_curl_rust_corpus_tests}
        "\$TFLAGS"
    DEPENDS ${_curl_rust_corpus_deps}
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/tests"
    COMMENT "Running curl corpus smoke tests with Rust sidecar"
    VERBATIM USES_TERMINAL
  )
endif()

if(CURL_BUILD_TESTING AND TARGET curlinfo AND TARGET libtests AND TARGET build-certs)
  set(_curl_rust_pytest_deps
    curl-rust
    curlinfo
    libtests
    build-certs
  )

  add_custom_target(curl-rust-pytest
    COMMAND ${CMAKE_COMMAND} -E env
      "CURL=${_curl_rust_sidecar}"
      pytest -n auto "${PROJECT_SOURCE_DIR}/tests/http"
    DEPENDS ${_curl_rust_pytest_deps}
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/tests"
    COMMENT "Running HTTP pytest suite with Rust sidecar"
    VERBATIM USES_TERMINAL
  )

  add_custom_target(curl-rust-pytest-ci
    COMMAND ${CMAKE_COMMAND} -E env
      "CURL=${_curl_rust_sidecar}"
      pytest -n auto -v "${PROJECT_SOURCE_DIR}/tests/http"
    DEPENDS ${_curl_rust_pytest_deps}
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/tests"
    COMMENT "Running HTTP pytest CI suite with Rust sidecar"
    VERBATIM USES_TERMINAL
  )
endif()
