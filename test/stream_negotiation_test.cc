// The stream, against a scripted server: what the client writes, byte for
// byte, what it reads, and how far it reads.
import std;
import splice;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "stream_common.h"

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
    received.push_back(splice::get<tern::message::chat>(splice::get<tern::message_t>(*one)));
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
  scripted script{.data = server};
  auto session = tern::try_connect(script, rfc7677());
  ASSERT_TRUE(session.has_value()) << (session ? "" : session.error().detail);
  EXPECT_EQ(script.read_at_tls, before_tls.size());
  EXPECT_EQ(script.written, header + "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" + header +
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

// RFC 6120, 5.4.3.3 and 7.6.2.2: a STARTTLS failure closes this side of the
// stream; a refused bind says its whole error.
TEST(Stream, NegotiationErrors) {
  {
    const std::string server =
        server_header("s1") +
        "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
        "</stream:features><failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>";
    scripted script{.data = server};
    const auto session = tern::try_connect(script, rfc7677());
    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error().code, tern::connect_code::tls_refused);
    EXPECT_TRUE(script.written.ends_with("</stream:stream>")) << script.written;
  }
  {
    const std::string server =
        server_header("s1") +
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
        "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") + bind_features +
        "<iq type='error' id='bind_1'><error type='modify'>"
        "<conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>";
    std::string_view input = server;
    std::string written;
    auto how = rfc7677();
    how.plain_without_tls = true;
    const auto session = tern::try_connect(input, std::back_inserter(written), how);
    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error().code, tern::connect_code::bind_refused);
    EXPECT_EQ(session.error().detail, "conflict");
    ASSERT_TRUE(session.error().stanza.has_value());
    EXPECT_EQ(session.error().stanza->condition(), "conflict");
  }
}

// RFC 6120, 4.9: a stream error while negotiating says its condition, and
// see-other-host where to go -- there, or once the session is bound.
TEST(Stream, SeeOtherHost) {
  {
    const std::string server =
        server_header("s1") +
        "<stream:error><see-other-host xmlns='urn:ietf:params:xml:ns:xmpp-streams'>[2001:41D0:1:A49b::1]:9222"
        "</see-other-host></stream:error></stream:stream>";
    std::string_view input = server;
    std::string written;
    const auto session = tern::try_connect(input, std::back_inserter(written), rfc7677());
    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error().code, tern::connect_code::stream_error);
    EXPECT_EQ(session.error().detail, "see-other-host");
    EXPECT_EQ(session.error().other_host, "[2001:41D0:1:A49b::1]:9222");
  }
  {
    const std::string server =
        server_header("s1") +
        "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>";
    std::string_view input = server;
    std::string written;
    const auto session = tern::try_connect(input, std::back_inserter(written), rfc7677());
    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error().detail, "host-unknown");
    EXPECT_FALSE(session.error().other_host.has_value());
  }
  {
    const std::string server =
        server_header("s1") +
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
        "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
        bind_features + bind_result +
        "<stream:error><see-other-host xmlns='urn:ietf:params:xml:ns:xmpp-streams'>im.example.com:9090"
        "</see-other-host></stream:error></stream:stream>";
    std::string_view input = server;
    std::string written;
    auto how = rfc7677();
    how.plain_without_tls = true;
    auto session = tern::connect(input, std::back_inserter(written), how);
    const auto one = session.try_receive();
    ASSERT_FALSE(one.has_value());
    EXPECT_EQ(one.error().detail, "see-other-host");
    EXPECT_EQ(one.error().other_host, "im.example.com:9090");
  }
}

// RFC 6120, 6.4.5: a challenge the client cannot take is answered with
// <abort/>, and the server's <failure><aborted/></failure> read.
TEST(Stream, SaslAbort) {
  const std::string server =
      server_header("s1") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism>"
      "</mechanisms></stream:features><challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
      b64("r=someone-else,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096") +
      "</challenge><failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>";
  std::string_view input = server;
  std::string written;
  const auto session = tern::try_connect(input, std::back_inserter(written), rfc7677());
  ASSERT_FALSE(session.has_value());
  EXPECT_EQ(session.error().code, tern::connect_code::authentication);
  EXPECT_TRUE(written.ends_with("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")) << written;
}

// RFC 5802, 6 and RFC 9266: over TLS, with the TLS layer's binding data, a
// -PLUS mechanism where offered, the binding in the GS2 header and in c=;
// where none is offered, y,, says so.
TEST(Stream, ChannelBinding) {
  const auto written_for = [](const std::string& mechanisms) {
    const std::string server =
        server_header("s1") +
        "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" + server_header("s2") +
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" + mechanisms +
        "</mechanisms></stream:features><challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
        b64("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096") +
        "</challenge><failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>";
    scripted script{.data = server, .binding = tern::channel_binding{"tls-exporter", {1, 2, 3}}};
    (void)tern::try_connect(script, rfc7677());
    return script.written;
  };
  const std::string plus =
      written_for("<mechanism>SCRAM-SHA-256</mechanism><mechanism>SCRAM-SHA-256-PLUS</mechanism>");
  EXPECT_NE(plus.find("mechanism='SCRAM-SHA-256-PLUS'>" + b64("p=tls-exporter,,n=user,r=rOprNGfwEbeRWgbNEkqO")),
            std::string::npos) << plus;
  EXPECT_NE(plus.find(b64("c=" + b64(std::string("p=tls-exporter,,\x01\x02\x03", 19)) +
                          ",r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=").substr(0, 40)),
            std::string::npos) << plus;
  const std::string downgraded = written_for("<mechanism>SCRAM-SHA-256</mechanism>");
  EXPECT_NE(downgraded.find("mechanism='SCRAM-SHA-256'>" + b64("y,,n=user,r=rOprNGfwEbeRWgbNEkqO")),
            std::string::npos) << downgraded;
}

// RFC 6120, 6.5: a SASL failure says its condition; 4.6: white space between
// stanzas is a keepalive, and nothing more.
TEST(Stream, FailureConditionAndKeepalives) {
  {
    const std::string server =
        server_header("s1") +
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism>"
        "</mechanisms></stream:features><failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><account-disabled/>"
        "<text xml:lang='en'>Call 212-555-1212 for assistance.</text></failure>";
    std::string_view input = server;
    std::string written;
    const auto session = tern::try_connect(input, std::back_inserter(written), rfc7677());
    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error().code, tern::connect_code::not_authorized);
    EXPECT_EQ(session.error().detail, "account-disabled");
  }
  {
    const std::string server =
        server_header("s1") +
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
        "<mechanism>PLAIN</mechanism></mechanisms></stream:features>"
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" + server_header("s2") +
        bind_features + bind_result +
        " \n <message from='romeo@example.net' type='chat'><body>one</body></message>\n\n  "
        "<message from='romeo@example.net' type='chat'><body>two</body></message> </stream:stream>";
    std::string_view input = server;
    std::string written;
    auto how = rfc7677();
    how.plain_without_tls = true;
    auto session = tern::connect(input, std::back_inserter(written), how);
    std::size_t messages = 0;
    for (auto&& one : session.stanzas()) {
      ASSERT_TRUE(one.has_value()) << one.error().detail;
      ++messages;
    }
    EXPECT_EQ(messages, 2u);
  }
}
