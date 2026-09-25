// The stream, against a scripted server: what the client writes, byte for
// byte, what it reads, and how far it reads.
import std;
import tern;
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
  auto session = tern::connect(input, std::back_inserter(written), rfc7677());
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
  std::vector<tern::message> received;
  for (auto&& one : session->stanzas()) {
    ASSERT_TRUE(one.has_value()) << one.error().detail;
    received.push_back(std::get<tern::message>(*one));
    session->send(tern::message{.to = "romeo@example.net", .type = "chat", .body = "hello"});
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
  auto session = tern::connect(counted, std::back_inserter(written), how);
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
    auto session = tern::connect(input, std::back_inserter(written), how);
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
