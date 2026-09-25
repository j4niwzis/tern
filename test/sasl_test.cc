// Authentication: the hashes and their uses against the standard vectors, and
// SCRAM against the exchanges RFC 5802 and RFC 7677 print.
import std;
import tern;
import gtest;

#include "gtest/gtest-macros.h"

namespace {

using tern::crypto::bytes;
using tern::crypto::hex;
using tern::crypto::to_bytes;

bytes repeated(std::uint8_t one, std::size_t count) { return bytes(count, one); }

}  // namespace

TEST(Crypto, Hashes) {
  // FIPS 180-2, appendices.
  EXPECT_EQ(hex(tern::crypto::sha1::digest(to_bytes("abc"))), "a9993e364706816aba3e25717850c26c9cd0d89d");
  EXPECT_EQ(hex(tern::crypto::sha1::digest(to_bytes(""))), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  EXPECT_EQ(hex(tern::crypto::sha256::digest(to_bytes("abc"))),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(hex(tern::crypto::sha256::digest(to_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  // A million a's: many blocks.
  EXPECT_EQ(hex(tern::crypto::sha256::digest(repeated('a', 1000000))),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  // And at compile time.
  static_assert(tern::crypto::sha1::digest(tern::crypto::to_bytes("abc"))[0] == 0xa9);
}

TEST(Crypto, HmacAndPbkdf2) {
  // RFC 4231, test case 1; RFC 2202, test case 1.
  EXPECT_EQ(hex(tern::crypto::hmac<tern::crypto::sha256>(repeated(0x0b, 20), to_bytes("Hi There"))),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  EXPECT_EQ(hex(tern::crypto::hmac<tern::crypto::sha1>(repeated(0x0b, 20), to_bytes("Hi There"))),
            "b617318655057264e28bc0b6fb378c8ef146be00");
  // RFC 4231, test case 6: a key longer than a block.
  EXPECT_EQ(hex(tern::crypto::hmac<tern::crypto::sha256>(
                repeated(0xaa, 131), to_bytes("Test Using Larger Than Block-Size Key - Hash Key First"))),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  // RFC 6070.
  const auto password = to_bytes("password");
  const auto salt = to_bytes("salt");
  EXPECT_EQ(hex(tern::crypto::pbkdf2<tern::crypto::sha1>(password, salt, 1, 20)),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6");
  EXPECT_EQ(hex(tern::crypto::pbkdf2<tern::crypto::sha1>(password, salt, 2, 20)),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
  EXPECT_EQ(hex(tern::crypto::pbkdf2<tern::crypto::sha1>(password, salt, 4096, 20)),
            "4b007901b765489abead49d926f721d065a429c1");
  EXPECT_EQ(hex(tern::crypto::pbkdf2<tern::crypto::sha1>(to_bytes("passwordPASSWORDpassword"),
                                                         to_bytes("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 25)),
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
}

TEST(Crypto, Base64) {
  // RFC 4648, section 10.
  const std::pair<std::string_view, std::string_view> all[] = {
      {"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"},
      {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"}};
  for (const auto& [plain, encoded] : all) {
    EXPECT_EQ(tern::crypto::base64_encode(to_bytes(plain)), encoded);
    EXPECT_EQ(tern::crypto::base64_decode(encoded), std::optional<bytes>(to_bytes(plain)));
  }
  EXPECT_FALSE(tern::crypto::base64_decode("Zm9").has_value());    // not a multiple of four
  EXPECT_FALSE(tern::crypto::base64_decode("Zm=v").has_value());   // padding out of place
  EXPECT_FALSE(tern::crypto::base64_decode("Zm9!").has_value());   // not the alphabet
}

// RFC 5802, section 5.
TEST(Scram, Sha1ExchangeOfRfc5802) {
  tern::sasl::scram_sha1 client("user", "pencil", "fyko+d2lbbFgONRv9qkxdawL");
  EXPECT_EQ(client.first(), "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
  const auto final_message =
      client.answer("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096");
  ASSERT_TRUE(final_message.has_value());
  EXPECT_EQ(*final_message, "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
  EXPECT_TRUE(client.verify("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=").has_value());
  EXPECT_EQ(client.verify("v=AAAAAAAAAAAAAAAAAAAAAAAAAAA=").error().code, tern::sasl::failure_code::bad_signature);
}

// RFC 7677, section 3.
TEST(Scram, Sha256ExchangeOfRfc7677) {
  tern::sasl::scram_sha256 client("user", "pencil", "rOprNGfwEbeRWgbNEkqO");
  EXPECT_EQ(client.first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
  const auto final_message = client.answer(
      "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
  ASSERT_TRUE(final_message.has_value());
  EXPECT_EQ(*final_message,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
  EXPECT_TRUE(client.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=").has_value());
}

TEST(Scram, WhatItRefuses) {
  using tern::sasl::failure_code;
  tern::sasl::scram_sha256 client("a=b,c", "p", "abc", 4096);
  EXPECT_EQ(client.first(), "n,,n=a=3Db=2Cc,r=abc");  // '=' and ',' escaped
  EXPECT_EQ(client.answer("r=xyz123,s=QSXCR+Q6sek8bf92,i=4096").error().code, failure_code::nonce_mismatch);
  EXPECT_EQ(client.answer("r=abc,s=QSXCR+Q6sek8bf92,i=4096").error().code, failure_code::nonce_mismatch);  // nothing added
  EXPECT_EQ(client.answer("r=abcdef,s=QSXCR+Q6sek8bf92,i=100").error().code, failure_code::too_few_iterations);
  EXPECT_EQ(client.answer("r=abcdef,s=!!!!,i=4096").error().code, failure_code::malformed);
  EXPECT_EQ(client.answer("r=abcdef,i=4096").error().code, failure_code::malformed);
  EXPECT_EQ(client.verify("e=invalid-proof").error().code, failure_code::server_error);
}

TEST(Plain, Message) {
  EXPECT_EQ(tern::sasl::plain("juliet", "r0m30"), std::string("\0juliet\0r0m30", 13));
  EXPECT_EQ(tern::sasl::plain("juliet", "r0m30", "admin"), std::string("admin\0juliet\0r0m30", 18));
  EXPECT_EQ(tern::sasl::random_nonce().size(), 32u);
}
