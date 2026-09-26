// Addresses, RFC 7622: the examples of its section 3.5, and the ones it says
// are not addresses.
import std;
import tern;
import gtest;

#include "gtest/gtest-macros.h"

namespace {

std::string parsed(std::string_view text) {
  const auto got = tern::jid::parse(text);
  return got ? got->str() : std::string("!");
}

TEST(Jid, ValidExamples) {
  EXPECT_EQ(parsed("juliet@example.com"), "juliet@example.com");
  EXPECT_EQ(parsed("juliet@example.com/foo"), "juliet@example.com/foo");
  EXPECT_EQ(parsed("juliet@example.com/foo bar"), "juliet@example.com/foo bar");
  EXPECT_EQ(parsed("juliet@example.com/foo@bar"), "juliet@example.com/foo@bar");
  EXPECT_EQ(parsed("foo\\20bar@example.com"), "foo\\20bar@example.com");
  EXPECT_EQ(parsed("fussball@example.com"), "fussball@example.com");
  EXPECT_EQ(parsed("fu\xc3\x9f" "ball@example.com"), "fu\xc3\x9f" "ball@example.com");
  EXPECT_EQ(parsed("\xcf\x80@example.com"), "\xcf\x80@example.com");
  EXPECT_EQ(parsed("\xce\xa3@example.com/foo"), "\xcf\x83@example.com/foo");     // lower-cased
  EXPECT_EQ(parsed("\xcf\x83@example.com/foo"), "\xcf\x83@example.com/foo");
  EXPECT_EQ(parsed("\xcf\x82@example.com/foo"), "\xcf\x82@example.com/foo");     // final sigma kept
  EXPECT_EQ(parsed("king@example.com/\xe2\x99\x9a"), "king@example.com/\xe2\x99\x9a");
  EXPECT_EQ(parsed("example.com"), "example.com");
  EXPECT_EQ(parsed("example.com/foobar"), "example.com/foobar");
  EXPECT_EQ(parsed("a.example.com/b@example.net"), "a.example.com/b@example.net");
  EXPECT_EQ(parsed("Juliet@Example.COM/Balcony"), "juliet@example.com/Balcony");
  EXPECT_EQ(parsed("juliet@example.com./x"), "juliet@example.com/x");  // the trailing dot
  EXPECT_EQ(parsed("juliet@[::1]"), "juliet@[::1]");
  EXPECT_EQ(parsed("juliet@192.0.2.1"), "juliet@192.0.2.1");
}

TEST(Jid, NotAddresses) {
  for (const std::string_view text : {
           "\"juliet\"@example.com",   // quotes
           "foo bar@example.com",      // a space in the localpart
           "henry\xe2\x85\xa3@example.com",  // U+2163, a compatibility character
           "\xe2\x99\x9a@example.com",       // a symbol in the localpart
           "@example.com",             // empty localpart
           "example.com/",             // empty resourcepart
           "juliet@",                  // empty domainpart
           "/foo",                     // no domainpart
       }) {
    EXPECT_FALSE(tern::jid::parse(text).has_value()) << text;
  }
  EXPECT_FALSE(tern::jid::parse("juliet@example.com/" + std::string(1024, 'a')).has_value());
}

TEST(Jid, Bare) {
  const auto full = tern::jid::parse("juliet@example.com/balcony");
  ASSERT_TRUE(full);
  EXPECT_EQ(full->bare().str(), "juliet@example.com");
  EXPECT_EQ(full->bare(), *tern::jid::parse("JULIET@example.com"));
}

}  // namespace
