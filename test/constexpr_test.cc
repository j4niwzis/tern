// What tern does, run by the compiler as well as by the program: the hashes
// and Base64, SASL PLAIN, SRV's query and answer, and a whole session --
// negotiated, a typed request answered, a message, the end -- over a script.
// Built with TERN_CONSTEXPR_TESTS, as CI is, each test runs while it is
// compiled too; see constexpr_test.h.
import std;
import tern;
import chevron;
import gtest;

#include "gtest/gtest-macros.h"
#include "constexpr_test.h"

CONSTEXPR_TEST(Constexpr, Crypto) {
  CONSTEXPR_EXPECT_EQ(tern::crypto::base64_encode(tern::crypto::to_bytes("pencil")), "cGVuY2ls");
  CONSTEXPR_EXPECT_EQ(tern::crypto::base64_encode(tern::crypto::sha1::digest(tern::crypto::to_bytes("abc"))),
                      "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=");
}

CONSTEXPR_TEST(Constexpr, Plain) {
  CONSTEXPR_EXPECT_EQ(tern::sasl::plain("user", "pencil"), std::string("\0user\0pencil", 12));
}

CONSTEXPR_TEST(Constexpr, Srv) {
  const auto question = tern::srv::query("example.com", 0x1234);
  CONSTEXPR_EXPECT_EQ(question.size(), 47u);
  CONSTEXPR_EXPECT_EQ(tern::srv::fallback("example.com").port, 5222);
  std::vector<std::uint8_t> answer = question;
  answer[2] = 0x81;
  answer[3] = 0x80;
  answer[7] = 1;  // one answer: 5 0 5223 example.com, the name compressed
  const std::vector<std::uint8_t> record{0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 0x0e, 0x10, 0, 8, 0, 5, 0, 0, 0x14, 0x67, 0xc0, 30};
  answer.insert(answer.end(), record.begin(), record.end());
  const auto targets = tern::srv::answers(answer, 0x1234);
  CONSTEXPR_EXPECT_TRUE(targets.has_value());
  if (targets) {
    CONSTEXPR_EXPECT_EQ(targets->size(), 1u);
    CONSTEXPR_EXPECT_EQ(targets->at(0).host, "example.com");
    CONSTEXPR_EXPECT_EQ(targets->at(0).port, 5223);
  }
}

CONSTEXPR_TEST(Constexpr, Session) {
  const std::string server =
      std::string("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' id='s1' from='example.com' version='1.0'>") +
      "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism>"
      "</mechanisms></stream:features><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
      "<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
      "xmlns:stream='http://etherx.jabber.org/streams' id='s2' from='example.com' version='1.0'>"
      "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>"
      "<iq type='result' id='bind_1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
      "<jid>user@example.com/tern</jid></bind></iq>"
      "<iq type='result' id='tern-1' from='example.com'><query xmlns='jabber:iq:version'><name>ejabberd</name>"
      "<version>26.7.0</version></query></iq>"
      "<message from='romeo@example.net' type='chat'><body>hi</body></message></stream:stream>";
  std::string_view input = server;
  std::string written;
  tern::options how{.username = "user", .domain = "example.com", .password = "pencil", .resource = "tern",
                    .plain_without_tls = true};
  auto session = tern::try_connect(input, std::back_inserter(written), how);
  CONSTEXPR_EXPECT_TRUE(session.has_value());
  if (!session)
    return;
  CONSTEXPR_EXPECT_EQ(session->jid(), "user@example.com/tern");
  const auto version = session->try_request<tern::query::version>({.to = "example.com"});
  CONSTEXPR_EXPECT_TRUE(version.has_value());
  if (version)
    CONSTEXPR_EXPECT_EQ(version->name.value_or(""), "ejabberd");
  const auto one = session->try_receive();
  CONSTEXPR_EXPECT_TRUE(one.has_value() && one->has_value());
  if (one && *one) {
    const auto* message = std::get_if<tern::message_t>(&**one);
    CONSTEXPR_EXPECT_TRUE(message != nullptr);
    if (message)
      CONSTEXPR_EXPECT_EQ(std::get<tern::message::chat>(*message).body.value_or(""), "hi");
  }
  const auto end = session->try_receive();
  CONSTEXPR_EXPECT_TRUE(end.has_value() && !end->has_value());
  CONSTEXPR_EXPECT_TRUE(written.find("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>") !=
                        std::string::npos);
}
