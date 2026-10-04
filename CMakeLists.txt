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
  GIT_TAG f2c25443061ba5353720eccd0a9438793c2ea053
  LICENSE GPL-3.0-only
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
  GIT_TAG bbc3e0d2a2b67f1cd039c582ef131bafa2d81348
  LICENSE AGPL-3.0-only
  TARGETS chevron)
cme_options(chevron "CHEVRON_TESTS OFF")
cme_find_package(chevron REQUIRED)

cme_declare_port(NAME alef PROVIDES alef
  GITHUB_REPOSITORY j4niwzis/alef
  GIT_TAG 6dc139f9590dc0d3ac1cc0e9748e67d7a1485480
  LICENSE AGPL-3.0-only
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

# ---- What this library is, said by the library; and installing it ----
#
# A consumer writes find_package(tern) and this says the rest: where it
# comes from, what it needs, and what it produces -- installed beside the
# library by cmake-everywhere, under share/cmake-everywhere/ports, so that a
# prefix that has tern describes it too.
if(COMMAND cme_declare_port)
  cme_declare_port(
    NAME tern
    PROVIDES tern
    VERSION ${PROJECT_VERSION}
    GITHUB_REPOSITORY j4niwzis/tern
    GIT_TAG main
    LICENSE AGPL-3.0-only
    DEPENDS splice chevron "alef[precis,idna]" "boost-pfr[modules]"
    TARGETS tern::tern)
endif()
# The library, its module interface units -- a consumer compiles its own
# binary interfaces from them -- and a package: find_package(tern) on a
# machine that has it installed finds it there, by the names it has here
# too, and what it needs again from the ports it came from.
option(TERN_INSTALL "Install tern and its CMake package" ${PROJECT_IS_TOP_LEVEL})
if(TERN_INSTALL)
  set(tern_aliases "")
  foreach(name IN ITEMS crypto sasl stream jid srv)
    list(APPEND tern_aliases tern::${name} tern_${name})
  endforeach()
  cme_install_package(tern ALIASES ${tern_aliases})
endif()
