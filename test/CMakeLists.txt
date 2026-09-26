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
add_executable(tern-stream-test stream_test.cc)
target_link_libraries(tern-stream-test PRIVATE tern ${tern_gtest})
add_test(NAME stream COMMAND tern-stream-test)
add_executable(tern-jid-test jid_test.cc)
target_link_libraries(tern-jid-test PRIVATE tern ${tern_gtest})
add_test(NAME jid COMMAND tern-jid-test)
