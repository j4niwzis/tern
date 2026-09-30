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
  auto session = tern::try_connect<test_protocol>(input, std::back_inserter(written), how);
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
  EXPECT_EQ(refused.error().reply->condition(), "feature-not-implemented");
  EXPECT_TRUE(refused.error().reply->what->is<tern::conditions::feature_not_implemented>());
  EXPECT_TRUE(splice::holds_alternative<tern::error_types::cancel>(*refused.error().reply->type));

  // What arrived meanwhile, in order.
  std::vector<std::size_t> kinds;
  std::optional<std::string> lang;
  for (auto&& one : session->stanzas()) {
    ASSERT_TRUE(one.has_value());
    kinds.push_back(one->index());
    if (const auto* m = splice::get_if<test_protocol::message_t>(&*one)) lang = splice::get<test_protocol::message::normal>(*m).lang;
  }
  EXPECT_EQ(kinds, (std::vector<std::size_t>{0, 2, 1}));  // message, the other iq, presence
  EXPECT_EQ(lang, "en");
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

// RFC 6120, 8.2.3: every get and set gets exactly one reply -- from its
// handler, or service-unavailable where there is none.
TEST(Stream, EveryRequestIsAnswered) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      bind_features + bind_result +
      "<iq type='get' id='v1' from='romeo@example.net/orchard'><query xmlns='jabber:iq:version'/></iq>"
      "<iq type='set' id='u1' from='romeo@example.net/orchard'><unknown xmlns='urn:x'/></iq>"
      "<message from='romeo@example.net/orchard' type='chat'><body>after</body></message>"
      "</stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect<test_protocol>(
      input, std::back_inserter(written), how,
      tern::answering{[](const version_query&) { return version{"tern", "0.1"}; }});
  written.clear();
  std::vector<std::size_t> kinds;
  for (auto&& one : session.stanzas()) {
    ASSERT_TRUE(one.has_value());
    kinds.push_back(one->index());
  }
  EXPECT_EQ(kinds, (std::vector<std::size_t>{0}));  // only the message: the requests were answered
  EXPECT_NE(written.find("id=\"v1\" type=\"result\"><query xmlns=\"jabber:iq:version\"><name>tern</name>"
                         "<version>0.1</version></query></iq>"),
            std::string::npos)
      << written;
  EXPECT_NE(written.find("id=\"u1\" type=\"error\"><error type=\"cancel\"><service-unavailable "
                         "xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/></error></iq>"),
            std::string::npos)
      << written;
  EXPECT_NE(written.find("to=\"romeo@example.net/orchard\""), std::string::npos) << written;
}
