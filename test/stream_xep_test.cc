// XEPs a client needs: disco and caps, carbons, the archive, stream
// management -- against a scripted server.
import std;
import splice;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"

namespace {

const std::string logged_in =
    server_header("s1") +
    "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
    "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
    "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2");

tern::options plain() {
  auto how = rfc7677();
  how.plain_without_tls = true;
  return how;
}

}  // namespace

// XEP-0115, 5.2: the verification string of the example.
TEST(Xep, CapsVer) {
  tern::disco::info info{.identities = {{.category = "client", .type = "pc", .name = "Exodus 0.9.1"}},
                         .features = {{"http://jabber.org/protocol/caps"},
                                      {"http://jabber.org/protocol/disco#info"},
                                      {"http://jabber.org/protocol/disco#items"},
                                      {"http://jabber.org/protocol/muc"}}};
  EXPECT_EQ(tern::caps::ver_of(info), "QgayPKawpkPSDYmwT/WM94uAlu0=");
}

// XEP-0030 answered by tern itself, and XEP-0115 in the presence it sends.
TEST(Xep, DiscoAndCaps) {
  const std::string server =
      logged_in + bind_features + bind_result +
      "<iq type='get' id='d1' from='romeo@example.net/orchard'><query "
      "xmlns='http://jabber.org/protocol/disco#info'/></iq>"
      "<iq type='get' id='p1' from='example.com'><ping xmlns='urn:xmpp:ping'/></iq></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto session = tern::connect(input, std::back_inserter(written), plain());
  written.clear();
  session.available();
  EXPECT_NE(written.find("<c xmlns=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" "
                         "node=\"https://github.com/j4niwzis/tern\" ver=\""),
            std::string::npos)
      << written;
  written.clear();
  EXPECT_FALSE(session.receive().has_value());  // both answered, the stream ends
  EXPECT_NE(written.find("id=\"d1\" type=\"result\"><query xmlns=\"http://jabber.org/protocol/disco#info\">"
                         "<identity category=\"client\" type=\"pc\" name=\"tern\"/>"),
            std::string::npos)
      << written;
  EXPECT_NE(written.find("<feature var=\"http://jabber.org/protocol/caps\"/>"), std::string::npos) << written;
  EXPECT_NE(written.find("id=\"p1\" type=\"result\"/>"), std::string::npos) << written;
}

// XEP-0280: a carbon copy, read straight into its types, the message inside
// too.
TEST(Xep, Carbons) {
  const std::string server =
      logged_in + bind_features + bind_result +
      "<iq type='result' id='tern-1'/>"
      "<message from='user@example.com' to='user@example.com/tern'><received xmlns='urn:xmpp:carbons:2'>"
      "<forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='juliet@capulet.example/balcony' "
      "to='user@example.com/phone' type='chat'><body>What man art thou</body></message></forwarded></received>"
      "</message></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto session = tern::connect(input, std::back_inserter(written), plain());
  written.clear();
  EXPECT_TRUE(session.try_request<tern::query::carbons_enable>().has_value());
  EXPECT_NE(written.find("<enable xmlns=\"urn:xmpp:carbons:2\"/>"), std::string::npos) << written;
  const auto one = session.receive();
  ASSERT_TRUE(one.has_value());
  const auto& copy = splice::get<tern::message::normal>(splice::get<tern::message_t>(*one));
  ASSERT_EQ(copy.payload.size(), 1u);
  const auto& received = copy.payload[0].as<tern::carbons::received>();
  ASSERT_TRUE(received.forwarded.message.has_value());
  const auto& inner = received.forwarded.message->as<tern::basic::message_chat<tern::forward::plain>>();
  EXPECT_EQ(inner.body, "What man art thou");
  EXPECT_EQ(inner.from, "juliet@capulet.example/balcony");

  // The same without nesting: the kind, its payload, and any kind at all.
  const auto* normal = tern::get_if<tern::message::normal>(*one);
  ASSERT_NE(normal, nullptr);
  EXPECT_EQ(tern::get_if<tern::message::chat>(*one), nullptr);
  EXPECT_EQ(tern::get_if<tern::iq::result>(*one), nullptr);
  const auto* carbon = tern::find<tern::carbons::received>(*normal);
  ASSERT_NE(carbon, nullptr);
  EXPECT_EQ(tern::find<tern::carbons::received>(*one), carbon);
  EXPECT_EQ(tern::find<tern::delay>(*one), nullptr);
  EXPECT_EQ(tern::visit([](const auto& kind) { return kind.from; }, *one), "user@example.com");
}

// XEP-0313: a page of the archive, its messages taken by the query's id.
TEST(Xep, Archive) {
  const auto archived = [](std::string_view id, std::string_view body) {
    return "<message from='user@example.com' to='user@example.com/tern'><result xmlns='urn:xmpp:mam:2' "
           "queryid='tern-mam-1' id='" + std::string(id) + "'><forwarded xmlns='urn:xmpp:forward:0'>"
           "<delay xmlns='urn:xmpp:delay' stamp='2010-07-10T23:08:25Z'/><message xmlns='jabber:client' "
           "from='juliet@capulet.lit/balcony' to='user@example.com' type='chat'><body>" + std::string(body) +
           "</body></message></forwarded></result></message>";
  };
  const std::string server =
      logged_in + bind_features + bind_result + archived("28482-98726-73623", "Hail to thee") +
      "<message from='romeo@example.net' type='chat'><body>live</body></message>" +
      archived("09af3-cc343-b409f", "Art thou not Romeo") +
      "<iq type='result' id='tern-2'><fin xmlns='urn:xmpp:mam:2' complete='true'><set "
      "xmlns='http://jabber.org/protocol/rsm'><first>28482-98726-73623</first><last>09af3-cc343-b409f</last>"
      "</set></fin></iq></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto session = tern::connect(input, std::back_inserter(written), plain());
  written.clear();
  const tern::archive_page page = session.archive({.filter = tern::mam::filter("juliet@capulet.lit")});
  EXPECT_NE(written.find("<query xmlns=\"urn:xmpp:mam:2\" queryid=\"tern-mam-1\"><x xmlns=\"jabber:x:data\" "
                         "type=\"submit\"><field var=\"FORM_TYPE\" type=\"hidden\"><value>urn:xmpp:mam:2</value>"
                         "</field><field var=\"with\"><value>juliet@capulet.lit</value></field></x></query>"),
            std::string::npos)
      << written;
  ASSERT_EQ(page.results.size(), 2u);
  EXPECT_EQ(page.results[0].id, "28482-98726-73623");
  EXPECT_EQ(page.results[0].forwarded.delay->stamp, "2010-07-10T23:08:25Z");
  EXPECT_EQ(page.results[1].forwarded.message->as<tern::basic::message_chat<tern::forward::plain>>().body,
            "Art thou not Romeo");
  EXPECT_EQ(page.fin.complete, true);
  EXPECT_EQ(page.fin.page->last, "09af3-cc343-b409f");
  const auto live = session.receive();  // what was not the archive's, still to be had
  ASSERT_TRUE(live.has_value());
  EXPECT_EQ(splice::get<tern::message::chat>(splice::get<tern::message_t>(*live)).body, "live");
}

// XEP-0198: enabled after binding; <r/> answered with the stanzas handled;
// <a/> dropping what the server has; the state to resume from.
TEST(Xep, StreamManagement) {
  const std::string server =
      logged_in +
      "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><sm xmlns='urn:xmpp:sm:3'/>"
      "</stream:features>" + bind_result +
      "<enabled xmlns='urn:xmpp:sm:3' id='some-long-sm-id' resume='true'/>"
      "<message from='romeo@example.net' type='chat'><body>one</body></message>"
      "<r xmlns='urn:xmpp:sm:3'/><a xmlns='urn:xmpp:sm:3' h='1'/></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = plain();
  how.stream_management = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  EXPECT_NE(written.find("<enable xmlns='urn:xmpp:sm:3' resume='true'/>"), std::string::npos) << written;
  session.send(tern::message::chat{.to = "romeo@example.net", .body = "first"});
  session.send(tern::message::chat{.to = "romeo@example.net", .body = "second"});
  written.clear();
  const auto one = session.receive();
  ASSERT_TRUE(one.has_value());
  EXPECT_FALSE(session.receive().has_value());  // <r/> answered, <a/> taken, the end
  EXPECT_NE(written.find("<a xmlns='urn:xmpp:sm:3' h='1'/>"), std::string::npos) << written;
  const auto state = session.sm();
  ASSERT_TRUE(state.has_value());
  EXPECT_EQ(state->id, "some-long-sm-id");
  EXPECT_EQ(state->inbound, 1u);
  ASSERT_EQ(state->unacked.size(), 1u);
  EXPECT_NE(state->unacked[0].find("second"), std::string::npos);
}

// XEP-0198, 5: resumed instead of bound, and what was not acknowledged sent
// again.
TEST(Xep, Resume) {
  const std::string server =
      logged_in +
      "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><sm xmlns='urn:xmpp:sm:3'/>"
      "</stream:features><resumed xmlns='urn:xmpp:sm:3' h='1' previd='some-long-sm-id'/></stream:stream>";
  tern::sm_state state{.id = "some-long-sm-id", .jid = "user@example.com/tern", .inbound = 5, .acked = 0,
                       .unacked = {"<message>1</message>", "<message>2</message>"}};
  scripted script{.data = server};
  auto how = plain();
  auto session = tern::try_resume(script, how, state);
  ASSERT_TRUE(session.has_value()) << (session ? "" : session.error().detail);
  EXPECT_EQ(session->jid(), "user@example.com/tern");
  EXPECT_TRUE(script.written.ends_with("<resume xmlns='urn:xmpp:sm:3' h='5' previd='some-long-sm-id'/>"
                                       "<message>2</message>"))
      << script.written;
}
