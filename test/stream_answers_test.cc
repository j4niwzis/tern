// The stream, against a scripted server: what the client writes, byte for
// byte, what it reads, and how far it reads.
import std;
import splice;
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
  const auto& chat = spl::get<tern::message::chat>(spl::get<tern::message_t>(*one));
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
    const auto* message = spl::get_if<tern::message_t>(&*one);
    ASSERT_NE(message, nullptr);
    EXPECT_EQ(spl::get<tern::message::chat>(*message).body, "\xd0\x9f\xd1\x80\xd0\xb8") << size;
  }
}
