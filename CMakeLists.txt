cmake_minimum_required(VERSION 4.3.4 FATAL_ERROR)

# tern: an XMPP client library, as C++23 modules -- over any input range of
# bytes, with the control flow the caller's.
include(${CMAKE_CURRENT_LIST_DIR}/cmake/import-std.cmake)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

project(tern VERSION 0.1 LANGUAGES CXX)

option(TERN_TESTS "Build the tests" ${PROJECT_IS_TOP_LEVEL})
option(TERN_EXAMPLES "Build the examples" ${PROJECT_IS_TOP_LEVEL})

if(NOT COMMAND cme_find_package)
  set(CME_WITHOUT_PROVIDER ON)
  include(${CMAKE_CURRENT_LIST_DIR}/cmake/get_cme.cmake)
endif()

# chevron, for the XML of the stream, and alef, for addresses (PRECIS and
# IDNA, RFC 7622): cme ports, pinned to commits and fetched from GitHub. Both
# are private, so git has to be able to authenticate -- a credential helper,
# or a token in CI. A checkout is used instead with
# -DCPM_chevron_SOURCE=<path> and -DCPM_alef_SOURCE=<path>.
cme_declare_port(NAME chevron PROVIDES chevron
  GITHUB_REPOSITORY j4niwzis/chevron
  GIT_TAG ef13469f3d42e7dc5873a332f58a3dcb03775703
  LICENSE LicenseRef-proprietary
  SYSTEM NEVER
  TARGETS chevron)
cme_options(chevron "CHEVRON_TESTS OFF")
cme_find_package(chevron REQUIRED)

cme_declare_port(NAME alef PROVIDES alef
  GITHUB_REPOSITORY j4niwzis/alef
  GIT_TAG 578d82d9c280e15c209e4cc71ddd227f47423bcb
  LICENSE LicenseRef-proprietary
  SYSTEM NEVER
  TARGETS alef_precis)
cme_options(alef "ALEF_TESTS OFF")
cme_find_package(alef REQUIRED)

set(TERN_CONSTEXPR_STEPS 100000000 CACHE STRING
  "clang's -fconstexpr-steps for tern and what imports it")

# One module to a target. The PUBLIC option is a usage requirement of every
# module, as in alef and chevron: besides giving constant evaluation room, it
# makes the modules' settings differ from those of the std target, so that
# they, their consumers and the googletest those consume share one std.
function(tern_module target file)
  add_library(${target})
  target_sources(${target}
    PUBLIC FILE_SET CXX_MODULES BASE_DIRS src FILES ${file})
  target_compile_features(${target} PUBLIC cxx_std_23)
  if(ARGN)
    target_link_libraries(${target} PUBLIC ${ARGN})
  endif()
  target_compile_options(${target} PUBLIC
    $<$<COMPILE_LANG_AND_ID:CXX,Clang,AppleClang>:-fconstexpr-steps=${TERN_CONSTEXPR_STEPS}>)
endfunction()

tern_module(tern_crypto src/crypto.cc)
tern_module(tern_sasl src/sasl.cc tern_crypto)
tern_module(tern_jid src/jid.cc alef_utf alef_precis alef_idna)
tern_module(tern_stream src/stream.cc tern_crypto tern_sasl tern_jid chevron Boost::pfr)
tern_module(tern src/tern.cc tern_crypto tern_sasl tern_stream tern_jid)

add_library(tern::crypto ALIAS tern_crypto)
add_library(tern::sasl ALIAS tern_sasl)
add_library(tern::stream ALIAS tern_stream)
add_library(tern::jid ALIAS tern_jid)
add_library(tern::tern ALIAS tern)

if(TERN_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

# tern against a real server, over a socket or openssl s_client (POSIX).
if(TERN_EXAMPLES AND UNIX)
  add_executable(tern-live examples/live.cc)
  target_link_libraries(tern-live PRIVATE tern)
endif()
