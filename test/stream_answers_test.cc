// The stream, against a scripted server: what the client writes, byte for
// byte, what it reads, and how far it reads.
import std;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"
namespace {

// XEP-0060's <unsupported/>, an application-specific condition.
struct pubsub_unsupported {
  std::string feature;
};
constexpr auto xml_schema(chevron::type<pubsub_unsupported>) {
  using namespace chevron::members;
  return chevron::schema<pubsub_unsupported>()
      .name("http://jabber.org/protocol/pubsub#errors", "unsupported")
      .member<"feature">(attribute());
}

using pubsub_protocol =
    tern::protocol<tern::queries<>, tern::answers<>, tern::extensions<>, tern::errors<pubsub_unsupported>>;

}  // namespace

// Payloads the protocol names are read straight into their types; what it
// does not name is kept as chevron::any. A typed request's answer, and a
// void one.
TEST(Stream, TypedPayloads) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      "<iq type='result' id='tern-1' from='example.com'><query xmlns='jabber:iq:version'><name>ejabberd</name>"
      "<version>26.7.0</version></query></iq>"
      "<iq type='result' id='tern-2' from='example.com'/>"
      "<iq type='get' id='p1' from='example.com'><ping xmlns='urn:xmpp:ping'/></iq>"
      "<iq type='get' id='v1' from='romeo@example.net/orchard'><query xmlns='jabber:iq:version'/></iq>"
      "<message from='romeo@example.net' type='chat'><body>hi</body><active "
      "xmlns='http://jabber.org/protocol/chatstates'/></message></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  std::size_t pinged = 0;
  auto session = tern::connect(input, std::back_inserter(written), how,
                               tern::answering{[&](const tern::query::ping&) { ++pinged; },
                                               [](const tern::query::version&) {
                                                 return tern::version{"tern", "0.1", std::nullopt};
                                               }});
  written.clear();
  const tern::version server_version = session.request<tern::query::version>({.to = "example.com"});
  EXPECT_EQ(server_version.name, "ejabberd");
  EXPECT_EQ(server_version.version, "26.7.0");
  EXPECT_NE(written.find("<query xmlns=\"jabber:iq:version\"/>"), std::string::npos) << written;
  EXPECT_TRUE(session.try_request<tern::query::ping>({.to = "example.com"}).has_value());

  written.clear();
  const auto one = session.receive();  // the ping and the version asked of us, answered on the way
  ASSERT_TRUE(one.has_value());
  EXPECT_EQ(pinged, 1u);
  EXPECT_NE(written.find("id=\"p1\" type=\"result\"/>"), std::string::npos) << written;
  EXPECT_NE(written.find("id=\"v1\" type=\"result\"><query xmlns=\"jabber:iq:version\"><name>tern</name>"),
            std::string::npos)
      << written;
  const auto& chat = std::get<tern::message::chat>(std::get<tern::message_t>(*one));
  EXPECT_EQ(chat.body, "hi");
  ASSERT_EQ(chat.payload.size(), 1u);
  EXPECT_EQ(chat.payload[0].as<chevron::any>().local, "active");  // no protocol type names it
}

TEST(Stream, NoReadingAhead) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      bind_features + bind_result + "<iq type='result' id='tern-1' from='example.com'/>";
  live_input input{server};
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  EXPECT_FALSE(input.asked_past);
  const auto pong = session.try_request(tern::iq::get{.to = "example.com"});
  EXPECT_TRUE(pong.has_value());
  EXPECT_FALSE(input.asked_past);  // the answer's '>' was the last byte read
}

// Input as chunks -- what each read of a socket brought -- split anywhere,
// inside a tag or a UTF-8 sequence: the same session as from the bytes.
TEST(Stream, FromChunks) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      "<iq type='result' id='tern-1' from='example.com'/>"
      "<message from='juliet@example.com/balcony' type='chat'><body>\xd0\x9f\xd1\x80\xd0\xb8</body></message>";
  for (const std::size_t size : {1u, 3u, 7u, 4096u}) {
    std::vector<std::string> chunks;
    for (std::size_t at = 0; at < server.size(); at += size)
      chunks.push_back(server.substr(at, size));
    std::string written;
    auto how = rfc7677();
    how.plain_without_tls = true;
    auto made = tern::try_connect(chunks, std::back_inserter(written), how);
    if (!made) {
      ADD_FAILURE() << "size " << size << ": " << made.error().detail << " / " << written;
      continue;
    }
    auto& session = *made;
    EXPECT_FALSE(session.jid().empty()) << size;
    EXPECT_TRUE(session.try_request(tern::iq::get{.to = "example.com"}).has_value()) << size;
    const auto one = session.receive();
    ASSERT_TRUE(one.has_value()) << size;
    const auto* message = std::get_if<tern::message_t>(&*one);
    ASSERT_NE(message, nullptr);
    EXPECT_EQ(std::get<tern::message::chat>(*message).body, "\xd0\x9f\xd1\x80\xd0\xb8") << size;
  }
}

// RFC 6120, 8.3.2: an application-specific condition the protocol names is
// read straight into its type; one it does not name is passed over.
TEST(Stream, ApplicationConditions) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      "<iq type='error' id='tern-1' from='pubsub.example.com'><error type='cancel'>"
      "<feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
      "<unsupported xmlns='http://jabber.org/protocol/pubsub#errors' feature='retrieve-items'/></error></iq>"
      "<iq type='error' id='tern-2' from='pubsub.example.com'><error type='cancel'>"
      "<feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><other xmlns='urn:x'/></error></iq>"
      "</stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect<pubsub_protocol>(input, std::back_inserter(written), how);
  const auto first = session.try_request(tern::iq::get{.to = "pubsub.example.com"});
  ASSERT_FALSE(first.has_value());
  ASSERT_TRUE(first.error().reply.has_value());
  EXPECT_EQ(first.error().reply->condition(), "feature-not-implemented");
  ASSERT_TRUE(first.error().reply->application.has_value());
  EXPECT_EQ(first.error().reply->application->as<pubsub_unsupported>().feature, "retrieve-items");
  const auto second = session.try_request(tern::iq::get{.to = "pubsub.example.com"});
  ASSERT_FALSE(second.has_value());
  ASSERT_TRUE(second.error().reply.has_value());
  EXPECT_FALSE(second.error().reply->application.has_value());  // not named: passed over, no tree
}

// A stanza that does not fit its type does not end the stream: an answer's
// failure goes to its request, a request that cannot be read is refused with
// bad-request and reported, anything else is reported -- and what follows is
// read as ever.
TEST(Stream, MalformedStanzas) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      "<iq type='result' id='tern-1' from='example.com'><query xmlns='jabber:iq:roster'><item name='no jid'/>"
      "</query></iq>"
      "<iq type='set' id='s1'><query xmlns='jabber:iq:roster'><item/></query></iq>"
      "<presence from='romeo@example.net'><priority>high</priority></presence>"
      "<message from='romeo@example.net' type='chat'><body>still here</body></message></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  written.clear();
  const auto roster = session.try_request<tern::query::roster>({.to = "example.com"});
  ASSERT_FALSE(roster.has_value());
  EXPECT_EQ(roster.error().code, tern::request_code::bad_answer);
  ASSERT_TRUE(roster.error().malformed.has_value());
  EXPECT_EQ(roster.error().malformed->id, "tern-1");
  EXPECT_EQ(roster.error().malformed->why.code, chevron::read_code::missing_attribute);

  std::vector<std::string> seen;
  for (auto&& one : session.stanzas()) {
    if (!one) {
      ASSERT_EQ(one.error().code, tern::connect_code::malformed_stanza) << one.error().detail;
      seen.push_back("malformed " + one.error().malformed->element);
      continue;
    }
    seen.push_back(std::get<tern::message::chat>(std::get<tern::message_t>(*one)).body.value_or(""));
  }
  EXPECT_EQ(seen, (std::vector<std::string>{"malformed iq", "malformed presence", "still here"}));
  EXPECT_NE(written.find("id=\"s1\" type=\"error\"><error type=\"modify\"><bad-request"), std::string::npos)
      << written;
}
