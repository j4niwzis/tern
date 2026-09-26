# The tests: googletest's, as a module.
#
# googletest is j4niwzis/googletest-modules, the fork that builds it as one:
# a test here imports std, and a header that includes the standard library
# textually would give a translation unit two views of it. It comes from
# cmake-everywhere, pinned to a commit, and never from the machine -- a
# googletest installed anywhere is the one that is a header.
#
# cmake-everywhere is asked without being installed as the dependency
# provider: which provider a build has is for whoever builds tern, and only
# the tests need anything fetched.
if(NOT COMMAND cme_find_package)
  set(CME_WITHOUT_PROVIDER ON)
  include(${PROJECT_SOURCE_DIR}/cmake/get_cme.cmake)
endif()
cme_declare_port(NAME googletest-modules PROVIDES GTest
  GITHUB_REPOSITORY j4niwzis/googletest-modules
  GIT_TAG 706920f1d230f0316d271466d8885735be3e300e
  LICENSE BSD-3-Clause
  SYSTEM NEVER
  TARGETS gtest_main)
cme_options(googletest-modules
  "BUILD_GMOCK OFF" "INSTALL_GTEST OFF" "gtest_build_modules ON"
  "gtest_build_tests OFF" "gtest_build_samples OFF")
cme_find_package(GTest REQUIRED)
# A copy from a prefix names it GTest::gtest_main, and one built here
# gtest_main.
if(TARGET GTest::gtest_main)
  set(tern_gtest GTest::gtest_main)
else()
  set(tern_gtest gtest_main)
endif()

add_executable(tern-sasl-test sasl_test.cc)
target_link_libraries(tern-sasl-test PRIVATE tern ${tern_gtest})
add_test(NAME sasl COMMAND tern-sasl-test)
# Three files, one binary: each compiles in the memory of a small machine.
add_executable(tern-stream-test stream_negotiation_test.cc stream_requests_test.cc stream_answers_test.cc
  stream_im_test.cc stream_park_test.cc stream_threads_test.cc stream_inbox_test.cc stream_conditions_test.cc
  stream_xep_test.cc)
target_link_libraries(tern-stream-test PRIVATE tern ${tern_gtest})
add_test(NAME stream COMMAND tern-stream-test)
add_executable(tern-jid-test jid_test.cc)
target_link_libraries(tern-jid-test PRIVATE tern ${tern_gtest})
add_test(NAME jid COMMAND tern-jid-test)
add_executable(tern-srv-test srv_test.cc)
target_link_libraries(tern-srv-test PRIVATE tern ${tern_gtest})
add_test(NAME srv COMMAND tern-srv-test)

# Every CONSTEXPR_TEST run by the compiler as well, as a constant expression,
# as alef's are. CI turns it on; off by default, because it is the slow half.
option(TERN_CONSTEXPR_TESTS "Run every CONSTEXPR_TEST while it is compiled as well" OFF)
get_property(tern_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
foreach(one IN ITEMS constexpr)
  add_executable(tern-${one}-test ${one}_test.cc)
  target_link_libraries(tern-${one}-test PRIVATE tern ${tern_gtest})
  add_test(NAME ${one} COMMAND tern-${one}-test)
  if(NOT TERN_CONSTEXPR_TESTS)
    continue()
  endif()
  # A target for each test, compiling it alone with its body as a
  # static_assert: what a test that is not a constant expression builds, to
  # show what the compiler says of it.
  target_compile_definitions(tern-${one}-test PRIVATE
    TERN_CONSTEXPR_TESTS
    "TERN_TEST_CMAKE=\"${CMAKE_COMMAND}\""
    "TERN_TEST_BUILD_DIR=\"${CMAKE_BINARY_DIR}\""
    $<${tern_multi_config}:TERN_TEST_CONFIG="$<CONFIG>">)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${one}_test.cc)
  file(STRINGS ${one}_test.cc declared REGEX "^CONSTEXPR_TEST\\(")
  foreach(line IN LISTS declared)
    if(line MATCHES "^CONSTEXPR_TEST\\(([A-Za-z0-9_]+), *([A-Za-z0-9_]+)\\)")
      set(test ${CMAKE_MATCH_1}.${CMAKE_MATCH_2})
      add_library(tern-constexpr-${test} OBJECT EXCLUDE_FROM_ALL ${one}_test.cc)
      target_link_libraries(tern-constexpr-${test} PRIVATE tern ${tern_gtest})
      target_compile_definitions(tern-constexpr-${test} PRIVATE
        TERN_CONSTEXPR_TESTS "TERN_CONSTEXPR_DIAGNOSE=\"${test}\"")
    endif()
  endforeach()
endforeach()
