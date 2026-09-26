// The stream, against a scripted server: what the client writes, byte for
// byte, what it reads, and how far it reads.
import std;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"

namespace {

std::string b64(std::string_view text) { return tern::crypto::base64_encode(tern::crypto::to_bytes(text)); }

const std::string header =
    "<?xml version='1.0'?><stream:stream to='example.com' from='user@example.com' version='1.0' "
    "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";

std::string server_header(std::string_view id) {
  return "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' "
         "id='" + std::string(id) + "' from='example.com' version='1.0'>";
}

const std::string bind_features =
    "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";
const std::string bind_result =
    "<iq type='result' id='bind_1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
    "<jid>user@example.com/tern</jid></bind></iq>";
const std::string bind_request =
    "<iq type='set' id='bind_1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>tern</resource></bind></iq>";

tern::options rfc7677() {
  return {.username = "user", .domain = "example.com", .password = "pencil", .resource = "tern",
          .nonce = "rOprNGfwEbeRWgbNEkqO"};
}

}  // namespace

// SCRAM-SHA-256 with the values of RFC 7677, then a stanza each way, then the
// server ends the stream.
TEST(Stream, ScramBindAndStanzas) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>SCRAM-SHA-256</mechanism><mechanism>PLAIN</mechanism></mechanisms></stream:features>" +
      "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
      b64("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096") +
      "</challenge><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
      b64("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=") + "</success>" + server_header("s2") +
      bind_features + bind_result +
      "<message from='romeo@example.net/orchard' to='user@example.com/tern' type='chat'><body>hi</body></message>"
      "</stream:stream>";
  std::string_view input = server;
  std::string written;
  auto session = tern::try_connect(input, std::back_inserter(written), rfc7677());
  ASSERT_TRUE(session.has_value()) << (session ? "" : session.error().detail);
  EXPECT_EQ(session->jid(), "user@example.com/tern");
  EXPECT_EQ(written, header +
                         "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'>" +
                         b64("n,,n=user,r=rOprNGfwEbeRWgbNEkqO") + "</auth>" +
                         "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
                         b64("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                             "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=") +
                         "</response>" + header + bind_request);

  written.clear();
  std::vector<tern::message::chat> received;
  for (auto&& one : session->stanzas()) {
    ASSERT_TRUE(one.has_value()) << one.error().detail;
    received.push_back(std::get<tern::message::chat>(std::get<tern::message_t>(*one)));
    session->send(tern::message::chat{.to = "romeo@example.net", .body = "hello"});
  }
  // One message, and the loop ended where the server ended the stream.
  ASSERT_EQ(received.size(), 1u);
  EXPECT_EQ(received[0].from, std::optional<std::string>("romeo@example.net/orchard"));
  EXPECT_EQ(received[0].body, std::optional<std::string>("hi"));
  EXPECT_EQ(written, "<message xmlns=\"jabber:client\" to=\"romeo@example.net\" type=\"chat\"><body>hello</body></message>");
}

// STARTTLS: nothing past <proceed/> is read before the hook has run; then
// PLAIN, allowed now that the stream is secured.
TEST(Stream, StartTlsThenPlain) {
  const std::string proceed = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
  const std::string before_tls =
      server_header("s1") +
      "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>" +
      proceed;
  const std::string server =
      before_tls + server_header("s2") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism>"
      "</mechanisms></stream:features><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" +
      server_header("s3") + bind_features + bind_result;
  std::size_t read = 0;
  auto counted = std::views::transform(std::string_view(server), [&read](char one) {
    ++read;
    return one;
  });
  std::size_t read_at_hook = 0;
  tern::options how = rfc7677();
  how.start_tls = [&] { read_at_hook = read; };
  std::string written;
  auto session = tern::try_connect(counted, std::back_inserter(written), how);
  ASSERT_TRUE(session.has_value()) << (session ? "" : session.error().detail);
  EXPECT_EQ(read_at_hook, before_tls.size());
  EXPECT_EQ(written, header + "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" + header +
                         "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>" +
                         b64(std::string("\0user\0pencil", 12)) + "</auth>" + header + bind_request);
}

TEST(Stream, WhatStopsIt) {
  using tern::connect_code;
  const auto code = [](const std::string& server, tern::options how) {
    std::string_view input = server;
    std::string written;
    auto session = tern::try_connect(input, std::back_inserter(written), how);
    return session ? std::optional<connect_code>() : std::optional<connect_code>(session.error().code);
  };
  const std::string tls_only =
      server_header("s1") +
      "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
  EXPECT_EQ(code(tls_only, rfc7677()), connect_code::tls_required);

  const std::string plain_only = server_header("s1") +
                                 "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                                 "<mechanism>PLAIN</mechanism></mechanisms></stream:features>";
  EXPECT_EQ(code(plain_only, rfc7677()), connect_code::no_mechanism);  // not over plain text

  const std::string refused =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism>"
      "</mechanisms></stream:features><failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>";
  EXPECT_EQ(code(refused, rfc7677()), connect_code::not_authorized);

  const std::string liar =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism>"
      "</mechanisms></stream:features><challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
      b64("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096") +
      "</challenge><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" + b64("v=AAAA") + "</success>";
  EXPECT_EQ(code(liar, rfc7677()), connect_code::authentication);  // the server did not prove itself

  EXPECT_EQ(code(server_header("s1"), rfc7677()), connect_code::xml);  // the input ended before the features
}

namespace {

struct ping {};
constexpr auto xml_schema(chevron::type<ping>) {
  return chevron::schema<ping>().name("urn:xmpp:ping", "ping");
}

struct version {
  std::optional<std::string> name, version;
};
constexpr auto xml_schema(chevron::type<version>) {
  return chevron::schema<version>().name("jabber:iq:version", "query");
}

struct version_query {
  using kind = tern::iq::get;
  using answer = version;
};
constexpr auto xml_schema(chevron::type<version_query>) {
  return chevron::schema<version_query>().name("jabber:iq:version", "query");
}

}  // namespace

// A request waits for its answer; what arrives meanwhile is kept for later.
TEST(Stream, RequestAndAnswer) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      bind_features + bind_result +
      "<message from='romeo@example.net' xml:lang='en'><body>before</body></message>"
      "<iq type='result' id='other' from='example.com'/>"
      "<iq type='result' id='tern-1' from='example.com'/>"
      "<presence from='romeo@example.net'/>"
      "<iq type='result' id='tern-2' from='example.com'>"
      "<query xmlns='jabber:iq:version'><name>server</name><version>1.0</version></query></iq>"
      "<iq type='error' id='tern-3' from='example.com'><error type='cancel'>"
      "<feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
      "</stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::try_connect(input, std::back_inserter(written), how);
  ASSERT_TRUE(session.has_value()) << (session ? "" : session.error().detail);

  written.clear();
  const auto pong = session->try_request(tern::iq::get{.payload = {chevron::to_any(ping{})}});
  ASSERT_TRUE(pong.has_value());
  EXPECT_EQ(pong->id, "tern-1");
  EXPECT_EQ(written, "<iq xmlns=\"jabber:client\" id=\"tern-1\" type=\"get\"><ping xmlns=\"urn:xmpp:ping\"/></iq>");

  const auto server_version = session->try_request<version_query>();
  ASSERT_TRUE(server_version.has_value());
  EXPECT_EQ(server_version->name, "server");
  EXPECT_EQ(server_version->version, "1.0");

  const auto refused = session->try_request<version_query>();
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.error().code, tern::request_code::error_reply);
  ASSERT_TRUE(refused.error().reply.has_value());
  EXPECT_EQ(refused.error().reply->reason.condition(), "feature-not-implemented");
  EXPECT_TRUE(std::holds_alternative<tern::error_types::cancel>(*refused.error().reply->reason.type));

  // What arrived meanwhile, in order.
  std::vector<std::size_t> kinds;
  std::optional<std::string> lang;
  for (auto&& one : session->stanzas()) {
    ASSERT_TRUE(one.has_value());
    kinds.push_back(one->index());
    if (const auto* m = std::get_if<tern::message_t>(&*one)) lang = std::get<tern::message::normal>(*m).lang;
  }
  EXPECT_EQ(kinds, (std::vector<std::size_t>{0, 2, 1}));  // message, the other iq, presence
  EXPECT_EQ(lang, "en");
}

namespace {

// Characters of a string, one at a time; at one place, the reader is
// suspended and the other side runs -- a stackful coroutine, made of two
// threads that never run at once.
struct baton {
  std::binary_semaphore first{0}, second{0};
};

struct suspending_input {
  std::string_view text;
  std::size_t at_which;
  baton* pass;
  bool* passed;

  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    const suspending_input* in = nullptr;
    std::size_t at = 0;
    char operator*() const {
      if (at == in->at_which && !*in->passed) {
        *in->passed = true;
        in->pass->second.release();  // the other one runs...
        in->pass->first.acquire();   // ...until it lets this one go on
      }
      return in->text[at];
    }
    iterator& operator++() {
      ++at;
      return *this;
    }
    void operator++(int) { ++at; }
    friend bool operator==(const iterator& one, std::default_sentinel_t) {
      return one.at == one.in->text.size();
    }
  };
  iterator begin() const { return {this, 0}; }
  std::default_sentinel_t end() const { return {}; }
};

}  // namespace

// Two requests in flight: the first reads the second's answer before its own,
// and hands it over; the second waits, yielding, until it has it.
TEST(Stream, TwoRequestsInFlight) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      bind_features + bind_result +
      "<iq type='result' id='tern-2' from='example.com'><b xmlns='urn:x'/></iq>"
      "<iq type='result' id='tern-1' from='example.com'><a xmlns='urn:x'/></iq>"
      "</stream:stream>";
  baton pass;
  bool passed = false;
  suspending_input input{server, server.find("<iq type='result' id='tern-2'"), &pass, &passed};
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  how.yield = [&] {
    pass.first.release();
    pass.second.acquire();
  };
  auto session = tern::try_connect(input, std::back_inserter(written), how);
  ASSERT_TRUE(session.has_value()) << (session ? "" : session.error().detail);

  std::optional<std::expected<tern::iq::result, tern::request_error>> first, second;
  std::thread b([&] {
    pass.second.acquire();
    second.emplace(session->try_request(tern::iq::get{}));
  });
  std::thread a([&] {
    first.emplace(session->try_request(tern::iq::get{}));
    pass.second.release();
  });
  a.join();
  b.join();
  ASSERT_TRUE(first && first->has_value());
  ASSERT_TRUE(second && second->has_value());
  EXPECT_EQ((*first)->id, "tern-1");
  EXPECT_EQ((*first)->payload.at(0).local, "a");
  EXPECT_EQ((*second)->id, "tern-2");
  EXPECT_EQ((*second)->payload.at(0).local, "b");
}

// The same, throwing.
TEST(Stream, Throwing) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      bind_features + bind_result +
      "<iq type='result' id='tern-1' from='example.com'/>"
      "<iq type='error' id='tern-2' from='example.com'><error type='cancel'>"
      "<feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
      "</stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  EXPECT_EQ(session.request(tern::iq::get{}).id, "tern-1");
  try {
    session.request(tern::iq::get{});
    ADD_FAILURE() << "an error answer was not thrown";
  } catch (const tern::request_failure& failure) {
    EXPECT_EQ(failure.error.code, tern::request_code::error_reply);
    EXPECT_TRUE(failure.error.reply.has_value());
  }
  EXPECT_FALSE(session.receive());  // the stream ends, cleanly

  std::string_view refused = "<?xml version='1.0'?>";
  std::string nowhere;
  EXPECT_THROW(tern::connect(refused, std::back_inserter(nowhere), how), tern::connect_failure);
}
