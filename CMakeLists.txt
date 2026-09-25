cmake_minimum_required(VERSION 4.3.4 FATAL_ERROR)

# tern: an XMPP client library, as C++23 modules -- over any input range of
# bytes, with the control flow the caller's.
include(${CMAKE_CURRENT_LIST_DIR}/cmake/import-std.cmake)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

project(tern VERSION 0.1 LANGUAGES CXX)

option(TERN_TESTS "Build the tests" ${PROJECT_IS_TOP_LEVEL})

if(NOT COMMAND cme_find_package)
  set(CME_WITHOUT_PROVIDER ON)
  include(${CMAKE_CURRENT_LIST_DIR}/cmake/get_cme.cmake)
endif()

# chevron, for the XML of the stream. It is private and not fetched yet: a
# checkout of it, where TERN_CHEVRON_DIR says.
set(TERN_CHEVRON_DIR "" CACHE PATH "A checkout of chevron")
if(NOT TERN_CHEVRON_DIR)
  message(FATAL_ERROR "tern: set TERN_CHEVRON_DIR to a checkout of chevron")
endif()
add_subdirectory(${TERN_CHEVRON_DIR} ${CMAKE_BINARY_DIR}/_chevron EXCLUDE_FROM_ALL)

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
tern_module(tern_stream src/stream.cc tern_crypto tern_sasl chevron)
tern_module(tern src/tern.cc tern_crypto tern_sasl tern_stream)

add_library(tern::crypto ALIAS tern_crypto)
add_library(tern::sasl ALIAS tern_sasl)
add_library(tern::stream ALIAS tern_stream)
add_library(tern::tern ALIAS tern)

if(TERN_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
