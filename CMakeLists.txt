cmake_minimum_required(VERSION 4.3.4 FATAL_ERROR)

# tern: an XMPP client library, as C++23 modules -- over any input range of
# bytes, with the control flow the caller's.
include(${CMAKE_CURRENT_LIST_DIR}/cmake/import-std.cmake)
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_EXTENSIONS OFF)

project(tern VERSION 0.1 LANGUAGES CXX)

option(TERN_TESTS "Build the tests" ${PROJECT_IS_TOP_LEVEL})
option(TERN_EXAMPLES "Build the examples" ${PROJECT_IS_TOP_LEVEL})

if(NOT COMMAND cme_find_package)
  set(CME_WITHOUT_PROVIDER ON)
  include(${CMAKE_CURRENT_LIST_DIR}/cmake/get_cme.cmake)
endif()

# splice: the variant tern's stanzas and answers are held in, and the
# visiting. The family's step count (tern's, chevron's and alef's), so that
# all of them share one std.
set(SPLICE_CONSTEXPR_STEPS 100000000 CACHE STRING
  "clang's -fconstexpr-steps for splice, as tern and its family set it")
cme_declare_port(NAME splice PROVIDES splice
  GITHUB_REPOSITORY j4niwzis/splice
  GIT_TAG 39bc67a00185f488c989d3c18b98e5995e4dc8dd
  LICENSE GPL-3.0-only
  SYSTEM NEVER
  TARGETS splice)
cme_options(splice "SPLICE_TESTS OFF")
cme_find_package(splice REQUIRED)

# chevron, for the XML of the stream, and alef, for addresses (PRECIS and
# IDNA, RFC 7622): cme ports, pinned to commits and fetched from GitHub. Both
# are private, so git has to be able to authenticate -- a credential helper,
# or a token in CI. A checkout is used instead with
# -DCPM_chevron_SOURCE=<path> and -DCPM_alef_SOURCE=<path>.
cme_declare_port(NAME chevron PROVIDES chevron
  GITHUB_REPOSITORY j4niwzis/chevron
  GIT_TAG 29e716ec45db10407960cbe40294c18a270289c0
  LICENSE AGPL-3.0-only
  SYSTEM NEVER
  TARGETS chevron)
cme_options(chevron "CHEVRON_TESTS OFF")
cme_find_package(chevron REQUIRED)

cme_declare_port(NAME alef PROVIDES alef
  GITHUB_REPOSITORY j4niwzis/alef
  GIT_TAG 902f701a1277335b228ca7252af9b6bf940468ac
  LICENSE AGPL-3.0-only
  SYSTEM NEVER
  TARGETS alef)
cme_options(alef "ALEF_TESTS OFF")
# Of alef, what a JID needs: PRECIS for its parts and IDNA for its domain,
# with what they import -- not alef's segmentation, collation or confusables.
cme_find_package(alef COMPONENTS precis idna REQUIRED)

set(TERN_CONSTEXPR_STEPS 100000000 CACHE STRING
  "clang's -fconstexpr-steps for tern and what imports it")

# One module to a target. The PUBLIC option is a usage requirement of every
# module, as in alef and chevron: besides giving constant evaluation room, it
# makes the modules' settings differ from those of the std target, so that
# they, their consumers and the googletest those consume share one std.
# One library, libtern.a, with its modules in one file set: modules are what
# separates it, and archives did not need to as well. Every part of it is
# what a session needs -- SASL's crypto, JIDs, the stream, SRV -- so it has
# no components.
add_library(tern)
target_sources(tern PUBLIC FILE_SET CXX_MODULES BASE_DIRS src
  FILES src/crypto.cc src/sasl.cc src/jid.cc src/stream.cc src/srv.cc src/tern.cc)
target_compile_features(tern PUBLIC cxx_std_26)
target_link_libraries(tern PUBLIC alef chevron splice Boost::pfr)
target_compile_options(tern PUBLIC
  $<$<COMPILE_LANG_AND_ID:CXX,Clang,AppleClang>:-fconstexpr-steps=${TERN_CONSTEXPR_STEPS}>)

# The names the targets used to have, each the one library now.
add_library(tern::tern ALIAS tern)
foreach(name IN ITEMS crypto sasl stream jid srv)
  add_library(tern::${name} ALIAS tern)
  add_library(tern_${name} ALIAS tern)
endforeach()

if(TERN_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

# tern against a real server, over a socket or openssl s_client (POSIX).
if(TERN_EXAMPLES AND UNIX)
  add_executable(tern-live examples/live.cc)
  target_link_libraries(tern-live PRIVATE tern)
endif()
