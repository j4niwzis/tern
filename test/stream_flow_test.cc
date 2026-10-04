// Control traffic must progress even when the peer waits before sending the
// next stanza. Buffer limits must fail explicitly, without partial writes.
import std;
import splice;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"

namespace {
std::string connected(std::string_view rest, bool managed = false) {
  return server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      (managed ? "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
                 "<sm xmlns='urn:xmpp:sm:3'/></stream:features>" : bind_features) + bind_result +
      (managed ? "<enabled xmlns='urn:xmpp:sm:3' id='resume-id' resume='true'/>" : "") + std::string(rest);
}
tern::options plain(bool managed = false) {
  auto how = rfc7677();
  how.plain_without_tls = true;
  how.stream_management = managed;
  return how;
}
std::string body_of(const tern::stanza_t& stanza) {
  return splice::get<tern::message::chat>(splice::get<tern::message_t>(stanza)).body.value_or("");
}
const std::string first = "<message type='chat' from='romeo@example.net'><body>one</body></message>";
const std::string second = "<message type='chat' from='romeo@example.net'><body>two</body></message>";

// At gate the server has sent <r/> and waits for <a/>. Report an early read
// and end the script rather than hanging a regression test indefinitely.
struct waiting_peer {
  std::string_view data;
  std::size_t at = 0, gate = std::string_view::npos;
  std::string expected, written;
  bool read_before_reply = false;
  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    waiting_peer* peer;
    char operator*() const { return peer->data[peer->at]; }
    iterator& operator++() { ++peer->at; return *this; }
    void operator++(int) { ++*this; }
    bool operator==(std::default_sentinel_t) const {
      if (peer->at == peer->gate && peer->written.find(peer->expected) == std::string::npos) {
        peer->read_before_reply = true;
        return true;
      }
      return peer->at == peer->data.size();
    }
  };
  struct input_range {
    waiting_peer* peer;
    iterator begin() { return {peer}; }
    std::default_sentinel_t end() const { return {}; }
  } range{this};
  auto& input() { return range; }
  void write(std::string_view text) { written += text; }
  void flush() {}
};
}

TEST(Flow, AcknowledgesBeforeWaitingForMoreInput) {
  const std::string request = "<r xmlns='urn:xmpp:sm:3'/>";
  const std::string server = connected(first + request + second + request + "</stream:stream>", true);
  waiting_peer wire{.data = server, .gate = server.find(second), .expected = "<a xmlns='urn:xmpp:sm:3' h='1'/>"};
  auto session = tern::connect(wire, plain(true));
  ASSERT_TRUE(session.receive());
  const auto next = session.try_receive();
  ASSERT_TRUE(next && *next);
  EXPECT_EQ(body_of(**next), "two");
  EXPECT_FALSE(wire.read_before_reply);
  wire.gate = server.find("</stream:stream>");
  wire.expected = "<a xmlns='urn:xmpp:sm:3' h='2'/>";
  EXPECT_FALSE(session.receive());
  EXPECT_FALSE(wire.read_before_reply);
}

TEST(Flow, PendingLimitPreservesQueuedValuesAndReportsFailure) {
  const std::string server = connected(first + second + "<iq type='result' id='tern-1'/>", true);
  std::string_view input = server;
  std::string output;
  auto how = plain(true);
  how.buffers.pending_stanzas = 1;
  auto session = tern::connect(input, std::back_inserter(output), how);
  const auto answer = session.try_request(tern::iq::get{});
  ASSERT_FALSE(answer);
  ASSERT_TRUE(answer.error().connection);
  EXPECT_EQ(answer.error().connection->code, tern::connect_code::resource_limit);
  auto kept = session.try_receive();
  ASSERT_TRUE(kept && *kept);
  EXPECT_EQ(body_of(**kept), "one");
  EXPECT_EQ(session.try_receive().error().code, tern::connect_code::resource_limit);
  EXPECT_FALSE(session.sm());  // the stanza that did not fit cannot be acknowledged on resume
}

TEST(Flow, SlowInboxCannotRetainAnUnlimitedLog) {
  const std::string server = connected(first + second);
  std::string_view input = server;
  std::string output;
  auto how = plain();
  how.buffers.inbox_stanzas = 1;
  auto session = tern::connect(input, std::back_inserter(output), how);
  auto slow = session.open_inbox();
  auto active = session.open_inbox("romeo@example.net");
  EXPECT_EQ(body_of(*active.next()), "one");
  EXPECT_EQ(active.try_next().error().code, tern::connect_code::resource_limit);
  EXPECT_EQ(body_of(*slow.next()), "one");
  EXPECT_EQ(slow.try_next().error().code, tern::connect_code::resource_limit);
}

TEST(Flow, RequestLimitDoesNotWriteOrPoisonTheSession) {
  const std::string server = connected(first);
  std::string_view input = server;
  std::string output;
  auto how = plain();
  how.buffers.requests = 0;
  auto session = tern::connect(input, std::back_inserter(output), how);
  output.clear();
  const auto answer = session.try_request(tern::iq::get{});
  ASSERT_FALSE(answer);
  EXPECT_EQ(answer.error().connection->code, tern::connect_code::resource_limit);
  EXPECT_TRUE(output.empty());
  EXPECT_EQ(body_of(*session.receive()), "one");
}

TEST(Flow, UnacknowledgedCapacityCanBeRetriedAfterAnAck) {
  const std::string server = connected("<a xmlns='urn:xmpp:sm:3' h='1'/>" + first, true);
  std::string_view input = server;
  std::string output;
  auto how = plain(true);
  how.buffers.unacked_stanzas = 1;
  auto session = tern::connect(input, std::back_inserter(output), how);
  const tern::message::chat message{.body = "outgoing"};
  ASSERT_TRUE(session.try_send(message));
  const auto written = output;
  EXPECT_EQ(session.try_send(message).error().code, tern::connect_code::resource_limit);
  EXPECT_EQ(output, written);
  EXPECT_EQ(body_of(*session.receive()), "one");
  ASSERT_TRUE(session.try_send(message));
  ASSERT_TRUE(session.sm());
  EXPECT_EQ(session.sm()->unacked.size(), 1u);
  EXPECT_EQ(session.sm()->acked, 1u);
}

TEST(Flow, UnacknowledgedByteLimitIsExactAndRefusesBeforeWriting) {
  const tern::message::chat message{.body = "outgoing & escaped"};
  const auto encoded = chevron::to_xml(message) | std::ranges::to<std::string>();
  for (const auto bytes : {encoded.size() - 1, encoded.size()}) {
    const std::string server = connected("", true);
    std::string_view input = server;
    std::string output;
    auto how = plain(true);
    how.buffers.unacked_bytes = bytes;
    auto session = tern::connect(input, std::back_inserter(output), how);
    output.clear();
    auto sent = session.try_send(message);
    if (bytes < encoded.size()) {
      ASSERT_FALSE(sent);
      EXPECT_EQ(sent.error().code, tern::connect_code::resource_limit);
      EXPECT_TRUE(output.empty());
      EXPECT_TRUE(session.sm()->unacked.empty());
    } else {
      EXPECT_TRUE(sent);
      EXPECT_EQ(output, encoded);
      EXPECT_EQ(session.sm()->unacked, std::vector<std::string>{encoded});
    }
  }
}

namespace {
struct cancelled {};
struct cancelling_scheduler {
  using handle = int;
  int* running;
  int current() { return *running; }
  void park() { throw cancelled{}; }
  void wake(int) {}
};
}
TEST(Flow, CancellationHistoryIsBoundedAndIdsAreNotReusedWithinIt) {
  const std::string server = connected("<iq type='result' id='tern-1'/><iq type='result' id='tern-2'/>" + first);
  std::string_view input = server;
  std::string output;
  auto how = plain();
  how.buffers.abandoned_requests = 1;
  int current = 0;
  auto session = tern::connect(input, std::back_inserter(output), how, tern::answering<>{}, cancelling_scheduler{&current});
  current = 1;  // requests from a non-reader park and are then cancelled
  EXPECT_THROW(session.request(tern::iq::get{.id = "tern-1"}), cancelled);
  EXPECT_EQ(session.try_request(tern::iq::get{.id = "tern-1"}).error().connection->code,
            tern::connect_code::request_conflict);
  EXPECT_THROW(session.request(tern::iq::get{}), cancelled);  // skips the occupied generated id
  current = 0;
  auto expired = session.receive();
  ASSERT_TRUE(expired);
  EXPECT_EQ(splice::get<tern::iq::result>(splice::get<tern::iq_t>(*expired)).id, "tern-1");
  EXPECT_EQ(body_of(*session.receive()), "one");  // the recent cancellation is still discarded
}

TEST(Flow, InvalidAcknowledgmentDoesNotDiscardRetransmissions) {
  const std::string server = connected("<a xmlns='urn:xmpp:sm:3' h='2'/>", true);
  std::string_view input = server;
  std::string output;
  auto session = tern::connect(input, std::back_inserter(output), plain(true));
  session.send(tern::message::chat{.body = "one"});
  EXPECT_EQ(session.try_receive().error().code, tern::connect_code::invalid_ack);
  EXPECT_FALSE(session.sm());
}

namespace {
struct observing_wire {
  std::string_view data;
  std::string output;
  const char* body = nullptr;
  bool borrowed = false;
  std::size_t writes = 0, flushes = 0;
  auto& input() { return data; }
  void write(std::string_view bytes) {
    ++writes;
    borrowed |= bytes.data() == body;
    output += bytes;
  }
  void flush() { ++flushes; }
};
}
TEST(Flow, UnmanagedWritesBorrowLargeRunsAndCoalesceSmallFragments) {
  const std::string server = connected("");
  observing_wire wire{.data = server};
  auto session = tern::connect(wire, plain());
  const tern::message::chat message{.body = std::string(100000, 'x') + "&" + std::string(100000, 'y')};
  wire.output.clear();
  wire.writes = wire.flushes = 0;
  wire.body = message.body->data();
  EXPECT_TRUE(session.try_send(message));
  EXPECT_TRUE(wire.borrowed);
  EXPECT_EQ(wire.flushes, 1u);
  EXPECT_LE(wire.writes, 5u);
  EXPECT_EQ(wire.output, chevron::to_xml(message) | std::ranges::to<std::string>());
  wire.writes = 0;
  session.send(tern::message::chat{.body = "small & text"});
  EXPECT_EQ(wire.writes, 1u);
}

namespace {
struct inbox_gates {
  std::mutex lock;
  std::condition_variable changed;
  bool reader_started = false, parked = false, consumed = false, stalled = false;
};
struct watched_scheduler {
  using handle = tern::thread_scheduler::handle;
  tern::thread_scheduler threads;
  inbox_gates* gates;
  auto hold() const { return threads.hold(); }
  auto release() const { return threads.release(); }
  handle current() const { return threads.current(); }
  void park() const {
    {
      std::lock_guard held(gates->lock);
      gates->parked = true;
      gates->changed.notify_all();
    }
    threads.park();
  }
  void wake(handle who) const { threads.wake(who); }
};
struct inbox_peer {
  std::string_view data;
  std::size_t at = 0, first_gate, second_gate;
  inbox_gates* gates;
  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    inbox_peer* peer;
    char operator*() const {
      if (peer->at == peer->first_gate || peer->at == peer->second_gate) {
        auto& g = *peer->gates;
        std::unique_lock held(g.lock);
        const bool first = peer->at == peer->first_gate;
        if (first) { g.reader_started = true; g.changed.notify_all(); }
        if (!g.changed.wait_for(held, std::chrono::seconds(2), [&] { return first ? g.parked : g.consumed; }))
          g.stalled = true;
      }
      return peer->data[peer->at];
    }
    iterator& operator++() { ++peer->at; return *this; }
    void operator++(int) { ++*this; }
    bool operator==(std::default_sentinel_t) const { return peer->at == peer->data.size(); }
  };
  struct range_type {
    inbox_peer* peer;
    iterator begin() { return {peer}; }
    std::default_sentinel_t end() const { return {}; }
  } range{this};
  auto& input() { return range; }
  void write(std::string_view) {}
  void flush() {}
};
}

TEST(Flow, FilteredInboxWakesBeforeTheReaderGetsItsOwnStanza) {
  const std::string juliet = "<message type='chat' from='juliet@example.net'><body>juliet</body></message>";
  const std::string server = connected(first + juliet + "</stream:stream>");
  inbox_gates gates;
  inbox_peer wire{.data = server, .first_gate = server.find(first), .second_gate = server.find(juliet), .gates = &gates};
  auto session = tern::connect(wire, plain(), tern::answering<>{}, watched_scheduler{{}, &gates});
  std::string romeo_body, juliet_body;
  std::thread reading([&] {
    auto inbox = session.open_inbox("juliet@example.net");
    const auto* stanza = inbox.next();
    if (stanza) juliet_body = body_of(*stanza);
  });
  {
    std::unique_lock held(gates.lock);
    if (!gates.changed.wait_for(held, std::chrono::seconds(2), [&] { return gates.reader_started; }))
      gates.stalled = true;
  }
  std::thread waiting([&] {
    auto inbox = session.open_inbox("romeo@example.net");
    const auto* stanza = inbox.next();
    if (stanza) romeo_body = body_of(*stanza);
    std::lock_guard held(gates.lock);
    gates.consumed = true;
    gates.changed.notify_all();
  });
  reading.join();
  waiting.join();
  EXPECT_FALSE(gates.stalled);
  EXPECT_EQ(romeo_body, "one");
  EXPECT_EQ(juliet_body, "juliet");
}

namespace {
struct chunk_peer {
  std::array<std::string, 2> pieces;
  std::string output;
  bool advanced_before_reply = false;
  struct iterator {
    using value_type = std::string_view;
    using difference_type = std::ptrdiff_t;
    chunk_peer* peer;
    std::size_t index = 0;
    std::string_view operator*() const { return peer->pieces[index]; }
    iterator& operator++() {
      if (index == 0 && peer->output.find("<a xmlns='urn:xmpp:sm:3' h='0'/>") == std::string::npos)
        peer->advanced_before_reply = true;
      ++index;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(std::default_sentinel_t) const { return index == peer->pieces.size(); }
  };
  struct range_type {
    chunk_peer* peer;
    iterator begin() { return {peer}; }
    std::default_sentinel_t end() const { return {}; }
  } range{this};
  auto& input() { return range; }
  void write(std::string_view text) { output += text; }
  void flush() {}
};
}
TEST(Flow, ChunkIteratorDoesNotFetchAheadOfControlReplies) {
  chunk_peer wire{.pieces = {connected("<r xmlns='urn:xmpp:sm:3'/>", true), first + "</stream:stream>"}};
  auto session = tern::connect(wire, plain(true));
  EXPECT_EQ(body_of(*session.receive()), "one");
  EXPECT_FALSE(wire.advanced_before_reply);
  EXPECT_FALSE(session.receive());
}

TEST(Flow, ResumeChecksRemainingBytesAndAcknowledgmentWraparound) {
  const std::string server = server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      "<stream:features><sm xmlns='urn:xmpp:sm:3'/></stream:features>"
      "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='resume-id'/>";
  const tern::sm_state state{.id = "resume-id", .jid = "user@example.com/tern", .inbound = 3,
      .acked = std::numeric_limits<std::uint32_t>::max(), .unacked = {"<presence/>", "<message/>"}};
  for (std::size_t bytes : {9u, 10u}) {
    observing_wire wire{.data = server};
    auto how = plain(true);
    how.buffers.unacked_stanzas = 1;
    how.buffers.unacked_bytes = bytes;
    auto session = tern::try_resume(wire, how, state);
    if (bytes == 9) {
      ASSERT_FALSE(session);
      EXPECT_EQ(session.error().code, tern::connect_code::resource_limit);
      EXPECT_FALSE(wire.output.ends_with("<message/>"));
    } else {
      ASSERT_TRUE(session);
      EXPECT_EQ(session->sm()->acked, 0u);
      EXPECT_EQ(session->sm()->unacked, std::vector<std::string>{"<message/>"});
      EXPECT_TRUE(wire.output.ends_with("<message/>"));
    }
  }
}

TEST(Flow, AutomaticReplyCapacityFailureReachesTheExpectedApi) {
  const std::string server = connected("<iq type='get' id='ping-1'><ping xmlns='urn:xmpp:ping'/></iq>", true);
  std::string_view input = server;
  std::string output;
  auto how = plain(true);
  how.buffers.unacked_stanzas = 0;
  auto session = tern::connect(input, std::back_inserter(output), how);
  output.clear();
  const auto result = session.try_receive();
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error().code, tern::connect_code::resource_limit);
  EXPECT_TRUE(output.empty());
  EXPECT_FALSE(session.sm());
}
