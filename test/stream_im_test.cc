// The stream, against a scripted server: what the client writes, byte for
// byte, what it reads, and how far it reads.
import std;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"

// RFC 6120, 4.9: a stream error after binding ends the stanzas with its
// condition. 4.4: after closing from this side, what the server sends before
// its own closing tag still arrives.
TEST(Stream, StreamErrorAndClosing) {
  const auto connected = [](const std::string& after, std::string& written) {
    return server_header("s1") +
           "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
           "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
           "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
           bind_features + bind_result + after;
  };
  auto how = rfc7677();
  how.plain_without_tls = true;
  {
    std::string written;
    const std::string server = connected(
        "<message from='romeo@example.net' type='chat'><body>first</body></message>"
        "<stream:error><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
        "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Replaced by new connection</text></stream:error>"
        "</stream:stream>",
        written);
    std::string_view input = server;
    auto session = tern::connect(input, std::back_inserter(written), how);
    std::vector<bool> fine;
    std::optional<tern::connect_error> ended;
    for (auto&& one : session.stanzas()) {
      fine.push_back(one.has_value());
      if (!one) ended = one.error();
    }
    EXPECT_EQ(fine, (std::vector<bool>{true, false}));
    ASSERT_TRUE(ended);
    EXPECT_EQ(ended->code, tern::connect_code::stream_error);
    EXPECT_EQ(ended->detail, "conflict");

    // The error read as types: its condition, and its text.
    const auto error = chevron::read<tern::stream_error>(std::string_view(
        "<stream:error xmlns:stream='http://etherx.jabber.org/streams'>"
        "<conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
        "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Replaced by new connection</text>"
        "</stream:error>") | chevron::events);
    ASSERT_TRUE(error.has_value());
    ASSERT_TRUE(error->what.has_value());
    EXPECT_TRUE(error->what->is<tern::stream_conditions::conflict>());
    ASSERT_TRUE(error->text.has_value());
    EXPECT_EQ(error->text->content, "Replaced by new connection");
    EXPECT_EQ(error->text->lang, "en");
  }
  {
    std::string written;
    const std::string server = connected(
        "<message from='romeo@example.net' type='chat'><body>late</body></message></stream:stream>", written);
    std::string_view input = server;
    auto session = tern::connect(input, std::back_inserter(written), how);
    written.clear();
    session.close();
    std::size_t late = 0;
    for (auto&& one : session.stanzas()) {
      ASSERT_TRUE(one.has_value());
      ++late;
    }
    EXPECT_EQ(late, 1u);  // arrived after this side closed, and still read
    EXPECT_EQ(written, "</stream:stream>");
  }
}

// RFC 6121, 2: the roster asked for, and pushes -- answered where they come
// from the account, ignored where they come from anyone else.
TEST(Stream, RosterAndPushes) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      bind_features + bind_result +
      "<iq type='result' id='tern-1'><query xmlns='jabber:iq:roster' ver='ver7'>"
      "<item jid='nurse@example.com' name='Nurse' subscription='both'><group>Servants</group></item>"
      "<item jid='romeo@example.net' subscription='none' ask='subscribe'/></query></iq>"
      "<iq type='set' id='push1'><query xmlns='jabber:iq:roster' ver='ver8'>"
      "<item jid='tybalt@example.org' subscription='remove'/></query></iq>"
      "<iq type='set' id='push2' from='mallory@evil.example'><query xmlns='jabber:iq:roster'>"
      "<item jid='mallory@evil.example' subscription='both'/></query></iq>"
      "</stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  written.clear();
  const tern::roster contacts = session.request<tern::query::roster>();
  EXPECT_EQ(contacts.ver, "ver7");
  ASSERT_EQ(contacts.items.size(), 2u);
  EXPECT_EQ(contacts.items[0].name, "Nurse");
  EXPECT_TRUE(std::holds_alternative<tern::subscription::both>(*contacts.items[0].subscription));
  EXPECT_EQ(contacts.items[0].group, (std::vector<std::string>{"Servants"}));
  EXPECT_TRUE(contacts.items[1].ask.has_value());
  EXPECT_NE(written.find("<query xmlns=\"jabber:iq:roster\"/>"), std::string::npos) << written;

  written.clear();
  std::size_t delivered = 0;
  for (auto&& one : session.stanzas()) {
    ASSERT_TRUE(one.has_value());
    ++delivered;
  }
  EXPECT_EQ(delivered, 1u);  // the push from the account; the other is ignored
  EXPECT_NE(written.find("id=\"push1\" type=\"result\""), std::string::npos) << written;
  EXPECT_EQ(written.find("push2"), std::string::npos) << written;
}

// RFC 6121, 2.6: the roster kept between sessions -- asked for from its
// version where the server versions rosters, pushes applied, and an empty
// answer leaving it as it is.
TEST(Stream, RosterVersioning) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
      "<ver xmlns='urn:xmpp:features:rosterver'/></stream:features>" + bind_result +
      "<iq type='result' id='tern-1'><query xmlns='jabber:iq:roster' ver='ver7'>"
      "<item jid='nurse@example.com' subscription='both'/><item jid='romeo@example.net' subscription='none'/>"
      "</query></iq>"
      "<iq type='set' id='push1'><query xmlns='jabber:iq:roster' ver='ver8'>"
      "<item jid='nurse@example.com' subscription='remove'/></query></iq>"
      "<iq type='result' id='tern-2'/></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  EXPECT_TRUE(session.roster_versioning());
  written.clear();
  tern::roster_cache cache;
  session.sync(cache);
  EXPECT_NE(written.find("ver=\"\""), std::string::npos) << written;
  EXPECT_EQ(cache.ver, "ver7");
  EXPECT_EQ(cache.items.size(), 2u);

  const auto push = session.try_receive();
  ASSERT_TRUE(push.has_value() && push->has_value());
  const auto* iq = std::get_if<tern::iq_t>(&**push);
  ASSERT_NE(iq, nullptr);
  const auto* set = std::get_if<tern::iq::set>(iq);
  ASSERT_NE(set, nullptr);
  EXPECT_TRUE(cache.apply(*set));
  EXPECT_EQ(cache.ver, "ver8");
  EXPECT_EQ(cache.items.size(), 1u);
  EXPECT_TRUE(cache.items.contains("romeo@example.net"));

  written.clear();
  session.sync(cache);  // nothing changed: the empty answer
  EXPECT_NE(written.find("ver=\"ver8\""), std::string::npos) << written;
  EXPECT_EQ(cache.ver, "ver8");
  EXPECT_EQ(cache.items.size(), 1u);
}

// RFC 6121, 3 and 4: subscriptions to bare JIDs, initial presence, and
// unavailable presence before the stream ends.
TEST(Stream, PresenceAndSubscriptions) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
      bind_features + bind_result + "</stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  written.clear();
  session.available(tern::presence::available{.show = "chat"});
  ASSERT_TRUE(session.subscribe("Romeo@Example.NET/orchard"));
  ASSERT_TRUE(session.approve("nurse@example.com"));
  EXPECT_FALSE(session.deny("@example.com"));  // not an address: nothing sent
  session.close();
  EXPECT_EQ(written,
            "<presence xmlns=\"jabber:client\"><show>chat</show><c xmlns=\"http://jabber.org/protocol/caps\" "
            "hash=\"sha-1\" node=\"https://github.com/j4niwzis/tern\" ver=\"+J9YpfimwBXMGvuf/xQmyA3I36g=\"/></presence>"
            "<presence xmlns=\"jabber:client\" to=\"romeo@example.net\" type=\"subscribe\"/>"
            "<presence xmlns=\"jabber:client\" to=\"nurse@example.com\" type=\"subscribed\"/>"
            "<presence xmlns=\"jabber:client\" type=\"unavailable\"/>"
            "</stream:stream>");
}

// RFC 6121, 5.2.3 and 5.2.5: <subject/> and <thread/>, read and written.
TEST(Stream, SubjectAndThread) {
  const std::string text =
      "<message xmlns='jabber:client' to='juliet@example.com' type='chat'><subject>I implore you!</subject>"
      "<body>Wherefore art thou, Romeo?</body>"
      "<thread parent='7edac73ab41e45c4aafa7b2d7b749080'>e0ffe42b28561960c6b12b944a092794b9683a38</thread>"
      "</message>";
  const auto read = chevron::read<tern::message::chat>(std::string_view(text) | chevron::events);
  ASSERT_TRUE(read.has_value());
  EXPECT_EQ(read->subject, "I implore you!");
  ASSERT_TRUE(read->thread.has_value());
  EXPECT_EQ(read->thread->id, "e0ffe42b28561960c6b12b944a092794b9683a38");
  EXPECT_EQ(read->thread->parent, "7edac73ab41e45c4aafa7b2d7b749080");
  EXPECT_TRUE(read->payload.empty());
  const std::string written = chevron::to_xml(*read) | std::ranges::to<std::string>();
  const auto again = chevron::read<tern::message::chat>(std::string_view(written) | chevron::events);
  ASSERT_TRUE(again.has_value()) << written;
  EXPECT_EQ(again->thread->id, read->thread->id);
  EXPECT_EQ(again->thread->parent, read->thread->parent);
  EXPECT_EQ(again->subject, read->subject);
}

namespace {
using dropping = tern::protocol<tern::queries<tern::roster>, tern::answers<tern::roster>, tern::extensions<>,
                                tern::errors<>, tern::drop_unknown>;
}  // namespace

// With drop_unknown, what no type of the protocol names is passed over: no
// tree is made, in an answer or in a message.
TEST(Stream, DropUnknown) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      "<iq type='result' id='tern-1' from='example.com'><query xmlns='urn:x:unknown'><deep><deeper/></deep>"
      "</query></iq>"
      "<message from='romeo@example.net' type='chat'><body>hi</body>"
      "<active xmlns='http://jabber.org/protocol/chatstates'/></message></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect<dropping>(input, std::back_inserter(written), how);
  const auto answer = session.try_request(tern::iq::get{.to = "example.com"});
  ASSERT_TRUE(answer.has_value());
  EXPECT_TRUE(answer->payload.empty());
  const auto one = session.receive();
  ASSERT_TRUE(one.has_value());
  const auto& chat = std::get<dropping::message::chat>(std::get<dropping::message_t>(*one));
  EXPECT_EQ(chat.body, "hi");
  EXPECT_TRUE(chat.payload.empty());
}

// RFC 6121, 2.3 to 2.5: a contact added with its name and groups, and one
// taken out; the pushes that follow are the server's.
TEST(Stream, RosterChanges) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
      "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features + bind_result +
      "<iq type='result' id='tern-1'/><iq type='result' id='tern-2'/></stream:stream>";
  std::string_view input = server;
  std::string written;
  auto how = rfc7677();
  how.plain_without_tls = true;
  auto session = tern::connect(input, std::back_inserter(written), how);
  written.clear();
  session.update_contact({.jid = "nurse@example.com", .name = "Nurse", .group = {"Servants"}});
  session.remove_contact("tybalt@example.org");
  EXPECT_EQ(written,
            "<iq xmlns=\"jabber:client\" id=\"tern-1\" type=\"set\"><query xmlns=\"jabber:iq:roster\">"
            "<item jid=\"nurse@example.com\" name=\"Nurse\"><group>Servants</group></item></query></iq>"
            "<iq xmlns=\"jabber:client\" id=\"tern-2\" type=\"set\"><query xmlns=\"jabber:iq:roster\">"
            "<item jid=\"tybalt@example.org\" subscription=\"remove\"/></query></iq>");
}

// XEP-0045: a room's presence says who the occupant is; joining carries
// <x xmlns='http://jabber.org/protocol/muc'/>.
TEST(Stream, RoomPresence) {
  const std::string text =
      "<presence xmlns='jabber:client' from='coven@chat.shakespeare.lit/firstwitch' to='hag66@shakespeare.lit/pda'>"
      "<x xmlns='http://jabber.org/protocol/muc#user'>"
      "<item affiliation='owner' role='moderator'/><status code='110'/></x></presence>";
  const auto read = chevron::read<tern::client::presence::available>(std::string_view(text) | chevron::events);
  ASSERT_TRUE(read.has_value());
  ASSERT_EQ(read->payload.size(), 1u);
  const auto* user = read->payload.front().get_if<tern::muc::user>();
  ASSERT_NE(user, nullptr);
  ASSERT_EQ(user->items.size(), 1u);
  EXPECT_EQ(user->items.front().affiliation, "owner");
  EXPECT_EQ(user->items.front().role, "moderator");
  ASSERT_EQ(user->statuses.size(), 1u);
  EXPECT_EQ(user->statuses.front().code, "110");

  tern::client::presence::available joining{.to = "coven@chat.shakespeare.lit/thirdwitch"};
  joining.payload.emplace_back(tern::muc::join{.history = tern::muc::history{.maxstanzas = "20"}});
  const std::string written = chevron::to_xml(joining) | std::ranges::to<std::string>();
  EXPECT_NE(written.find("http://jabber.org/protocol/muc"), std::string::npos) << written;
  EXPECT_NE(written.find("maxstanzas=\"20\""), std::string::npos) << written;
}

// XEP-0402: the bookmarks node's items, each a room.
TEST(Stream, Bookmarks) {
  const std::string text =
      "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:bookmarks:1'>"
      "<item id='theplay@conference.shakespeare.lit'>"
      "<conference xmlns='urn:xmpp:bookmarks:1' name='The Play&apos;s the Thing' autojoin='true'>"
      "<nick>JC</nick></conference></item></items></pubsub>";
  const auto read = chevron::read<tern::bookmarks::pubsub>(std::string_view(text) | chevron::events);
  ASSERT_TRUE(read.has_value());
  ASSERT_TRUE(read->items.has_value());
  ASSERT_EQ(read->items->items.size(), 1u);
  const auto& one = read->items->items.front();
  EXPECT_EQ(one.id, "theplay@conference.shakespeare.lit");
  ASSERT_TRUE(one.conference.has_value());
  EXPECT_EQ(one.conference->name, "The Play's the Thing");
  EXPECT_EQ(one.conference->nick, "JC");
  EXPECT_TRUE(tern::bookmarks::autojoins(*one.conference));
}

// XEP-0333: a displayed marker, written.
TEST(Stream, DisplayedMarker) {
  tern::client::message::chat marker{.to = "romeo@montague.lit"};
  marker.payload.emplace_back(tern::markers::displayed{.id = "message-1"});
  const std::string written = chevron::to_xml(marker) | std::ranges::to<std::string>();
  EXPECT_NE(written.find("urn:xmpp:chat-markers:0"), std::string::npos) << written;
  EXPECT_NE(written.find("id=\"message-1\""), std::string::npos) << written;
}

// XEP-0308, 0424 and 0461: a correction, a retraction and a reply, read.
TEST(Stream, CorrectionsRetractionsReplies) {
  const std::string text =
      "<message xmlns='jabber:client' from='juliet@capulet.lit/balcony' type='chat' id='m2'>"
      "<body>Wherefore art thou, Romeo?</body><replace xmlns='urn:xmpp:message-correct:0' id='m1'/>"
      "<reply xmlns='urn:xmpp:reply:0' to='romeo@montague.lit/orchard' id='r1'/></message>";
  const auto read = chevron::read<tern::client::message::chat>(std::string_view(text) | chevron::events);
  ASSERT_TRUE(read.has_value());
  bool replaced = false, replied = false;
  for (const auto& one : read->payload) {
    if (const auto* correction = one.get_if<tern::corrections::replace>()) {
      replaced = true;
      EXPECT_EQ(correction->id, "m1");
    }
    if (const auto* reply = one.get_if<tern::replies::reply>()) {
      replied = true;
      EXPECT_EQ(reply->id, "r1");
    }
  }
  EXPECT_TRUE(replaced);
  EXPECT_TRUE(replied);
  tern::client::message::chat retraction{.to = "juliet@capulet.lit"};
  retraction.payload.emplace_back(tern::retractions::retract{.id = "m2"});
  const std::string written = chevron::to_xml(retraction) | std::ranges::to<std::string>();
  EXPECT_NE(written.find("urn:xmpp:message-retract:1"), std::string::npos) << written;
}
