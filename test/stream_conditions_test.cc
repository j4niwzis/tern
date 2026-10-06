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
    seen.push_back(spl::get<tern::message::chat>(spl::get<tern::message_t>(*one)).body.value_or(""));
  }
  EXPECT_EQ(seen, (std::vector<std::string>{"malformed iq", "malformed presence", "still here"}));
  EXPECT_NE(written.find("id=\"s1\" type=\"error\"><error type=\"modify\"><bad-request"), std::string::npos)
      << written;
}
