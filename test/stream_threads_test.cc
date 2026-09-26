// Threads that really run at once, with tern::thread_scheduler: two ask
// while the main one reads, and the server answers only once both requests
// have gone out.
import std;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"

namespace {

// What the client wrote, counted, and a gate the server's answers wait at.
struct wire {
  std::mutex lock;
  std::condition_variable changed;
  std::string written;
  int asked = 0;
};

struct wire_writer {
  using difference_type = std::ptrdiff_t;
  wire* to = nullptr;
  wire_writer& operator*() { return *this; }
  wire_writer& operator=(char one) {
    std::lock_guard held(to->lock);
    to->written += one;
    if (one == '>' && to->written.ends_with("type=\"get\"/>")) {
      ++to->asked;
      to->changed.notify_all();
    }
    return *this;
  }
  wire_writer& operator++() { return *this; }
  wire_writer operator++(int) { return *this; }
};

struct gated_input {
  std::string_view text;
  std::size_t gate;
  wire* from;
  std::size_t at = 0;

  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    gated_input* in = nullptr;
    char operator*() const {
      if (in->at == in->gate) {
        std::unique_lock held(in->from->lock);
        in->from->changed.wait(held, [&] { return in->from->asked >= 2; });
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

}  // namespace

TEST(Stream, ParallelThreads) {
  const std::string answers = "<iq type='result' id='tern-1' from='example.com'/>"
                              "<iq type='result' id='tern-2' from='example.com'/>"
                              "<message from='romeo@example.net' type='chat'><body>after</body></message>"
                              "</stream:stream>";
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      answers;
  wire w;
  gated_input input{server, server.find(answers), &w};
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, wire_writer{&w}, how, tern::answering<>{}, tern::thread_scheduler{});
  std::optional<std::expected<tern::iq::result, tern::request_error>> first, second;
  std::thread one([&] { first.emplace(session.try_request(tern::iq::get{.to = "example.com"})); });
  std::thread two([&] { second.emplace(session.try_request(tern::iq::get{.to = "example.com"})); });
  const auto message = session.receive();  // reads -- and lets them send -- until the message
  one.join();
  two.join();
  ASSERT_TRUE(message.has_value());
  EXPECT_EQ(std::get<tern::message::chat>(std::get<tern::message_t>(*message)).body, "after");
  ASSERT_TRUE(first && first->has_value());
  ASSERT_TRUE(second && second->has_value());
  std::set<std::string> ids{(*first)->id, (*second)->id};
  EXPECT_EQ(ids, (std::set<std::string>{"tern-1", "tern-2"}));
}
