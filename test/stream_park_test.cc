// Requests from coroutines other than the reader: parked, and woken by it
// with their answers -- in any order; killed while parked; or woken when the
// stream ends. The coroutines are threads, one running at a time, as fibers
// on one thread are.
import std;
import splice;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"

namespace {

struct killed {};

// A scheduler of threads that run one at a time, holding `run`. park() lets
// the others run until this one is woken; one killed unwinds from its park(),
// as a fiber destroyed where it waits does.
struct thread_fibers {
  struct fiber {
    std::binary_semaphore woken{0};
    bool killed = false;
  };
  using handle = fiber*;

  std::mutex* run;

  static fiber& mine() {
    thread_local fiber self;
    return self;
  }
  handle current() { return &mine(); }
  void park() {
    run->unlock();
    mine().woken.acquire();
    run->lock();
    if (mine().killed)
      throw killed{};
  }
  void wake(handle one) { one->woken.release(); }
};

std::string connected(const std::string& rest) {
  return server_header("s1") +
         "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
         "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
         "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
         rest;
}

const std::string after = "<message from='romeo@example.net' type='chat'><body>after</body></message>";

tern::options plain() {
  auto how = rfc7677();
  how.plain_without_tls = true;
  return how;
}

std::string body_of(const std::optional<tern::stanza_t>& one) {
  if (!one)
    return "(the end)";
  const auto* message = splice::get_if<tern::message_t>(&*one);
  if (!message || !splice::holds_alternative<tern::message::chat>(*message))
    return "(not a chat message)";
  return splice::get<tern::message::chat>(*message).body.value_or("");
}

// A coroutine started, run until it parks, the reader -- this thread --
// holding `run` again after.
template <class Body>
std::thread spawn(std::mutex& run, Body body) {
  std::atomic<bool> started{false};
  std::thread one([&run, &started, body] {
    run.lock();
    started = true;
    body();
    run.unlock();
  });
  run.unlock();
  while (!started)
    std::this_thread::yield();
  run.lock();  // it holds `run` until it parks, or ends
  return one;
}

using outcome = std::optional<std::expected<tern::iq::result, tern::request_error>>;

}  // namespace

// Two coroutines ask, and park; the answers come the other way round; the
// reader wakes each with its own -- one read straight into tern::version.
TEST(Stream, ParkedRequests) {
  const std::string server = connected(
      "<iq type='result' id='tern-2' from='example.com'><query xmlns='jabber:iq:version'><name>ejabberd</name>"
      "<version>26.7.0</version></query></iq>"
      "<iq type='result' id='tern-1' from='example.com'><a xmlns='urn:x'/></iq>" + after + "</stream:stream>");
  std::string_view input = server;
  std::string written;
  std::mutex run;
  run.lock();
  auto session =
      tern::connect(input, std::back_inserter(written), plain(), tern::answering<>{}, thread_fibers{&run});
  outcome first;
  std::optional<std::expected<tern::version, tern::request_error>> second;
  std::thread one = spawn(run, [&] { first.emplace(session.try_request(tern::iq::get{.to = "example.com"})); });
  std::thread two = spawn(run, [&] { second.emplace(session.try_request<tern::query::version>({.to = "example.com"})); });
  EXPECT_FALSE(first.has_value());  // parked
  EXPECT_FALSE(second.has_value());
  EXPECT_EQ(body_of(session.receive()), "after");  // the reader: both woken on the way
  run.unlock();
  one.join();
  two.join();
  ASSERT_TRUE(second.has_value() && second->has_value());
  EXPECT_EQ((*second)->name, "ejabberd");
  ASSERT_TRUE(first.has_value() && first->has_value());
  EXPECT_EQ((*first)->id, "tern-1");
  EXPECT_EQ((*first)->payload.at(0).as<chevron::any>().local, "a");
}

// A coroutine killed while it is parked: its answer is dropped, not handed
// out, and the other is as it would be.
TEST(Stream, KilledWhileParked) {
  const std::string server = connected(
      "<iq type='result' id='tern-2' from='example.com'/><iq type='result' id='tern-1' from='example.com'/>" +
      after + "</stream:stream>");
  std::string_view input = server;
  std::string written;
  std::mutex run;
  run.lock();
  auto session =
      tern::connect(input, std::back_inserter(written), plain(), tern::answering<>{}, thread_fibers{&run});
  outcome kept;
  thread_fibers::fiber* doomed = nullptr;
  std::atomic<bool> died{false};
  std::thread one = spawn(run, [&] { kept.emplace(session.try_request(tern::iq::get{.to = "example.com"})); });
  std::thread two = spawn(run, [&] {
    doomed = &thread_fibers::mine();
    try {
      (void)session.try_request(tern::iq::get{.to = "example.com"});
    } catch (const killed&) {
      died = true;
    }
  });
  doomed->killed = true;  // its time is up
  doomed->woken.release();
  run.unlock();
  while (!died)
    std::this_thread::yield();
  two.join();
  run.lock();
  EXPECT_EQ(body_of(session.receive()), "after");  // tern-2's answer dropped on the way
  EXPECT_FALSE(session.receive().has_value());     // nothing of it handed out: the end
  run.unlock();
  one.join();
  ASSERT_TRUE(kept.has_value() && kept->has_value());
  EXPECT_EQ((*kept)->id, "tern-1");
}

// The stream ends while a coroutine is parked on a request: it is woken, and
// hears so.
TEST(Stream, StreamEndsWhileParked) {
  const std::string server = connected("</stream:stream>");
  std::string_view input = server;
  std::string written;
  std::mutex run;
  run.lock();
  auto session =
      tern::connect(input, std::back_inserter(written), plain(), tern::answering<>{}, thread_fibers{&run});
  outcome waiting;
  std::thread one = spawn(run, [&] { waiting.emplace(session.try_request(tern::iq::get{.to = "example.com"})); });
  EXPECT_FALSE(session.receive().has_value());
  run.unlock();
  one.join();
  ASSERT_TRUE(waiting.has_value());
  ASSERT_FALSE(waiting->has_value());
  EXPECT_EQ(waiting->error().code, tern::request_code::connection);
}
