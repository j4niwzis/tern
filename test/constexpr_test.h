// A googletest test that is run while it is compiled, too.
//
//   CONSTEXPR_TEST(Suite, Name) {
//     CONSTEXPR_EXPECT_EQ(what, expected);
//   }
//
// is a TEST whose body is a constexpr function. When the program runs it,
// CONSTEXPR_EXPECT_* are googletest's EXPECT_*. Built with
// TERN_CONSTEXPR_TESTS -- CI is, a build at a desk need not be -- the
// compiler runs the body as well, as a constant expression, and the test
// reports what that found when it runs:
//
// - an expectation that did not hold while compiled fails the test at its
//   line;
// - a body that is not a constant expression at all -- undefined behaviour,
//   a call to something that is not constexpr, too many steps -- does not
//   stop the build. Whether it is one is asked in a template argument, where
//   an expression that is not constant makes the substitution fail instead of
//   the program ill-formed, and the test branches on the answer. It fails
//   when it runs, and compiles itself once more, alone: the target
//   tern-constexpr-Suite.Name, where the body is a static_assert, so what the
//   compiler says of it is in the test's output.
//
// Included after gtest/gtest-macros.h, by a file that imports std and gtest.
#pragma once

namespace tern::test {

// What a test found wrong while it was compiled: how many expectations did
// not hold, and the lines of the first of them. Nothing in it points
// anywhere, so that it can be the value of a template argument.
struct outcome {
  std::size_t failed = 0;
  std::array<std::uint_least32_t, 8> lines{};

  constexpr void fail(std::uint_least32_t line) noexcept {
    if (failed < lines.size())
      lines[failed] = line;
    ++failed;
  }
};

// Running a body while compiled, as a type: std::integral_constant holding
// the outcome if the run is a constant expression, std::false_type if not.
template <auto Run>
auto compiled(int) -> std::integral_constant<outcome, Run()>;
template <auto Run>
auto compiled(...) -> std::false_type;

// Whether `test` is the one a compile for one test alone is for.
consteval bool alone([[maybe_unused]] std::string_view test) {
#if defined(TERN_CONSTEXPR_DIAGNOSE)
  return test == TERN_CONSTEXPR_DIAGNOSE;
#else
  return false;
#endif
}

// Builds the target that compiles `test` alone, as a constant expression the
// program cannot be compiled without, so the compiler says what it makes of
// it.
inline void compile_alone([[maybe_unused]] std::string_view test) {
#if defined(TERN_TEST_CMAKE)
  std::string command = std::format("\"{}\" --build \"{}\" --target tern-constexpr-{}",
                                    TERN_TEST_CMAKE, TERN_TEST_BUILD_DIR, test);
#if defined(TERN_TEST_CONFIG)
  command += std::format(" --config \"{}\"", TERN_TEST_CONFIG);
#endif
  std::println("{}", command);
  std::fflush(nullptr);
  [[maybe_unused]] const int status = std::system(command.c_str());
  std::fflush(nullptr);
#endif
}

template <auto Run, bool Alone>
void check_compiled([[maybe_unused]] const char* file,
                    [[maybe_unused]] int line,
                    [[maybe_unused]] std::string_view test) {
#if defined(TERN_CONSTEXPR_DIAGNOSE)
  if constexpr (Alone)
    static_assert((Run(), true), "the test is not a constant expression");
#else
  using result = decltype(compiled<Run>(0));
  if constexpr (std::same_as<result, std::false_type>) {
    ADD_FAILURE_AT(file, line)
        << test << " is not a constant expression. Compiled alone, to say why:";
    compile_alone(test);
  } else {
    constexpr outcome found = result::value;
    for (std::size_t at = 0; at < std::min(found.failed, found.lines.size()); ++at)
      ADD_FAILURE_AT(file, static_cast<int>(found.lines[at]))
          << "This did not hold while " << test << " was compiled.";
    if (found.failed > found.lines.size())
      ADD_FAILURE_AT(file, line)
          << "And " << found.failed - found.lines.size() << " more.";
  }
#endif
}

}  // namespace tern::test

#define CONSTEXPR_TEST(suite, name)                                          \
  constexpr void tern_constexpr_##suite##_##name(::tern::test::outcome&);   \
  TEST(suite, name) {                                                       \
    ::tern::test::outcome at_run_time;                                      \
    tern_constexpr_##suite##_##name(at_run_time);                           \
    TERN_CONSTEXPR_COMPILED_(suite, name)                                   \
  }                                                                         \
  constexpr void tern_constexpr_##suite##_##name(                           \
      [[maybe_unused]] ::tern::test::outcome& tern_constexpr_outcome_)

#if defined(TERN_CONSTEXPR_TESTS)
#define TERN_CONSTEXPR_COMPILED_(suite, name)                                \
  ::tern::test::check_compiled<                                              \
      [] {                                                                   \
        ::tern::test::outcome found;                                         \
        tern_constexpr_##suite##_##name(found);                              \
        return found;                                                        \
      },                                                                     \
      ::tern::test::alone(#suite "." #name)>(__FILE__, __LINE__,             \
                                             #suite "." #name);
#else
#define TERN_CONSTEXPR_COMPILED_(suite, name)
#endif

// While compiled, an expectation that does not hold is written down; when
// run, it is googletest's.
#define TERN_CONSTEXPR_EXPECT_(holds, at_run_time)                           \
  do {                                                                       \
    if consteval {                                                           \
      if (!(holds))                                                          \
        tern_constexpr_outcome_.fail(__LINE__);                              \
    } else {                                                                 \
      at_run_time;                                                           \
    }                                                                        \
  } while (false)

#define CONSTEXPR_EXPECT_TRUE(...)                                           \
  TERN_CONSTEXPR_EXPECT_(static_cast<bool>(__VA_ARGS__), EXPECT_TRUE((__VA_ARGS__)))
#define CONSTEXPR_EXPECT_FALSE(...)                                          \
  TERN_CONSTEXPR_EXPECT_(!static_cast<bool>(__VA_ARGS__), EXPECT_FALSE((__VA_ARGS__)))
#define CONSTEXPR_EXPECT_EQ(one, other)                                      \
  TERN_CONSTEXPR_EXPECT_((one) == (other), EXPECT_EQ(one, other))
