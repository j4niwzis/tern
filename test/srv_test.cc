// SRV (RFC 6120, 3.2.1; RFC 2782): the query's bytes, answers read -- names
// compressed, and answers that are not -- and the order to try them in.
import std;
import tern;
import gtest;

#include "gtest/gtest-macros.h"

namespace {

using bytes = std::vector<std::uint8_t>;

void u16(bytes& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

bytes labels(std::string_view name) {
  bytes out;
  for (std::size_t from = 0; from < name.size();) {
    std::size_t to = name.find('.', from);
    if (to == std::string_view::npos)
      to = name.size();
    out.push_back(static_cast<std::uint8_t>(to - from));
    out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(from), name.begin() + static_cast<std::ptrdiff_t>(to));
    from = to + 1;
  }
  out.push_back(0);
  return out;
}

// An SRV record whose owner points at the question's name; its target given
// as its bytes.
bytes record(std::uint16_t priority, std::uint16_t weight, std::uint16_t port, const bytes& target) {
  bytes out{0xc0, 0x0c};
  u16(out, 33);
  u16(out, 1);
  out.insert(out.end(), {0, 0, 0x0e, 0x10});
  u16(out, static_cast<std::uint16_t>(6 + target.size()));
  u16(out, priority);
  u16(out, weight);
  u16(out, port);
  out.insert(out.end(), target.begin(), target.end());
  return out;
}

bytes response(std::uint16_t id, std::uint16_t flags, const std::vector<bytes>& records) {
  const bytes question = tern::srv::query("example.com", id);
  bytes out;
  u16(out, id);
  u16(out, flags);
  u16(out, 1);
  u16(out, static_cast<std::uint16_t>(records.size()));
  u16(out, 0);
  u16(out, 0);
  out.insert(out.end(), question.begin() + 12, question.end());
  for (const bytes& one : records)
    out.insert(out.end(), one.begin(), one.end());
  return out;
}

}  // namespace

TEST(Srv, Query) {
  const bytes expected = [] {
    bytes out{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    const bytes name = labels("_xmpp-client._tcp.example.com");
    out.insert(out.end(), name.begin(), name.end());
    out.insert(out.end(), {0, 0x21, 0, 1});
    return out;
  }();
  EXPECT_EQ(tern::srv::query("example.com", 0x1234), expected);
}

TEST(Srv, Answers) {
  // "example.com" in the question starts at 12 + 13 + 5 = 30.
  const bytes got = response(7, 0x8180, {record(10, 60, 5222, labels("a.example.com")), record(5, 0, 5223, {0xc0, 30})});
  const auto targets = tern::srv::answers(got, 7);
  ASSERT_TRUE(targets.has_value()) << targets.error();
  ASSERT_EQ(targets->size(), 2u);
  EXPECT_EQ((*targets)[0].host, "a.example.com");
  EXPECT_EQ((*targets)[0].port, 5222);
  EXPECT_EQ((*targets)[0].weight, 60);
  EXPECT_EQ((*targets)[1].host, "example.com");  // compressed
  EXPECT_EQ((*targets)[1].priority, 5);

  EXPECT_FALSE(tern::srv::answers(got, 8).has_value());                       // another query's
  EXPECT_FALSE(tern::srv::answers(response(7, 0x8380, {}), 7).has_value());   // truncated
  EXPECT_TRUE(tern::srv::answers(response(7, 0x8183, {}), 7)->empty());       // no such name
  EXPECT_FALSE(tern::srv::answers(bytes(5, 0), 7).has_value());               // too short
  // A name that points at itself ends, refused.
  bytes looping = response(7, 0x8180, {});
  looping[7] = 1;  // one answer, whose name points at itself
  const std::size_t at = looping.size();
  looping.insert(looping.end(), {static_cast<std::uint8_t>(0xc0 | (at >> 8)), static_cast<std::uint8_t>(at & 0xff)});
  EXPECT_FALSE(tern::srv::answers(looping, 7).has_value());
}

TEST(Srv, Order) {
  std::mt19937 random(42);
  const std::vector<tern::srv::target> targets{
      {10, 0, 5222, "c"}, {5, 10, 5222, "a"}, {10, 100, 5222, "d"}, {5, 90, 5222, "b"}};
  for (int round = 0; round < 50; ++round) {
    const auto order = tern::srv::ordered(targets, random);
    ASSERT_EQ(order.size(), 4u);
    EXPECT_EQ(order[0].priority, 5);
    EXPECT_EQ(order[1].priority, 5);
    EXPECT_EQ(order[2].priority, 10);
  }
  EXPECT_TRUE(tern::srv::ordered(std::vector<tern::srv::target>{{0, 0, 0, "."}}, random).empty());  // no service
  EXPECT_EQ(tern::srv::fallback("example.com").port, 5222);
}
