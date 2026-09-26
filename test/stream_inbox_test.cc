// Inboxes in threads that really run at once, with tern::thread_scheduler:
// each thread waits for what comes from someone, and none takes anything
// from another. The server says nothing until both have opened theirs.
import std;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"

namespace {

struct gate {
  std::mutex lock;
  std::condition_variable changed;
  int opened = 0;
  void open() {
    std::lock_guard held(lock);
    ++opened;
    changed.notify_all();
  }
};

struct gated_input {
  std::string_view text;
  std::size_t at_gate;
  gate* waits_for;
  std::size_t at = 0;

  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    gated_input* in = nullptr;
    char operator*() const {
      if (in->at == in->at_gate) {
        std::unique_lock held(in->waits_for->lock);
        in->waits_for->changed.wait(held, [&] { return in->waits_for->opened >= 2; });
      }
      return in->text[in->at];
    }
    iterator& operator++() {
      ++in->at;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(std::default_sentinel_t) const { return in->at == in->text.size(); }
  };
  iterator begin() { return {this}; }
  std::default_sentinel_t end() const { return {}; }
};

std::string body_of(const tern::stanza_t* one) {
  if (!one)
    return "(the end)";
  const auto* message = std::get_if<tern::message_t>(one);
  if (!message || !std::holds_alternative<tern::message::chat>(*message))
    return "(not a chat message)";
  return std::get<tern::message::chat>(*message).body.value_or("");
}

}  // namespace

TEST(Stream, InboxesInThreads) {
  const std::string after = "<message from='romeo@example.net/a' type='chat'><body>r1</body></message>"
                            "<message from='juliet@example.com/b' type='chat'><body>j1</body></message>"
                            "<message from='Romeo@Example.NET/c' type='chat'><body>r2</body></message>"
                            "<message from='juliet@example.com/b' type='chat'><body>j2</body></message>"
                            "</stream:stream>";
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      after;
  gate g;
  gated_input input{server, server.find(after), &g};
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how, tern::answering<>{}, tern::thread_scheduler{});
  auto everyone = session.open_inbox();
  std::vector<std::string> romeo, juliet;
  std::thread one([&] {
    auto mine = session.open_inbox("romeo@example.net");
    g.open();
    for (const tern::stanza_t* got; (got = mine.next());)
      romeo.push_back(body_of(got));
  });
  std::thread two([&] {
    auto mine = session.open_inbox("juliet@example.com");
    g.open();
    for (const tern::stanza_t* got; (got = mine.next());)
      juliet.push_back(body_of(got));
  });
  one.join();
  two.join();
  // Romeo's, however his address was written.
  EXPECT_EQ(romeo, (std::vector<std::string>{"r1", "r2"}));
  EXPECT_EQ(juliet, (std::vector<std::string>{"j1", "j2"}));
  std::vector<std::string> all;
  for (const tern::stanza_t* got; (got = everyone.next());)
    all.push_back(body_of(got));
  EXPECT_EQ(all, (std::vector<std::string>{"r1", "j1", "r2", "j2"}));
}
