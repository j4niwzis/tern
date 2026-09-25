// What authentication needs of cryptography, and no more: SHA-1 and SHA-256
// (FIPS 180-4), HMAC (RFC 2104), PBKDF2 (RFC 8018) and Base64 (RFC 4648).
// All of it constexpr, and none of it for anything but SCRAM.
export module tern.crypto;

import std;

export namespace tern::crypto {

using bytes = std::vector<std::uint8_t>;

}  // namespace tern::crypto

namespace tern::crypto::detail {

constexpr std::uint32_t rotl(std::uint32_t x, int n) noexcept { return (x << n) | (x >> (32 - n)); }
constexpr std::uint32_t rotr(std::uint32_t x, int n) noexcept { return (x >> n) | (x << (32 - n)); }

// The message padded to whole 64-byte blocks, its length in bits at the end.
constexpr bytes padded(std::span<const std::uint8_t> message) {
  bytes out(message.begin(), message.end());
  const std::uint64_t bits = static_cast<std::uint64_t>(message.size()) * 8;
  out.push_back(0x80);
  while (out.size() % 64 != 56)
    out.push_back(0);
  for (int shift = 56; shift >= 0; shift -= 8)
    out.push_back(static_cast<std::uint8_t>(bits >> shift));
  return out;
}

constexpr std::uint32_t word_at(const bytes& block, std::size_t at) noexcept {
  return (std::uint32_t{block[at]} << 24) | (std::uint32_t{block[at + 1]} << 16) |
         (std::uint32_t{block[at + 2]} << 8) | std::uint32_t{block[at + 3]};
}

template <std::size_t N>
constexpr bytes digest_of(const std::array<std::uint32_t, N>& state) {
  bytes out;
  for (const std::uint32_t word : state)
    for (int shift = 24; shift >= 0; shift -= 8)
      out.push_back(static_cast<std::uint8_t>(word >> shift));
  return out;
}

}  // namespace tern::crypto::detail

export namespace tern::crypto {

struct sha1 {
  static constexpr std::size_t block_size = 64;
  static constexpr std::size_t size = 20;

  static constexpr bytes digest(std::span<const std::uint8_t> message) {
    using namespace detail;
    std::array<std::uint32_t, 5> h{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    const bytes data = padded(message);
    for (std::size_t block = 0; block < data.size(); block += 64) {
      std::array<std::uint32_t, 80> w{};
      for (std::size_t t = 0; t < 16; ++t)
        w[t] = word_at(data, block + 4 * t);
      for (std::size_t t = 16; t < 80; ++t)
        w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
      auto [a, b, c, d, e] = h;
      for (std::size_t t = 0; t < 80; ++t) {
        std::uint32_t f = 0, k = 0;
        if (t < 20) {
          f = (b & c) | (~b & d);
          k = 0x5A827999;
        } else if (t < 40) {
          f = b ^ c ^ d;
          k = 0x6ED9EBA1;
        } else if (t < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8F1BBCDC;
        } else {
          f = b ^ c ^ d;
          k = 0xCA62C1D6;
        }
        const std::uint32_t next = rotl(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = next;
      }
      h[0] += a;
      h[1] += b;
      h[2] += c;
      h[3] += d;
      h[4] += e;
    }
    return digest_of(h);
  }
};

struct sha256 {
  static constexpr std::size_t block_size = 64;
  static constexpr std::size_t size = 32;

  static constexpr bytes digest(std::span<const std::uint8_t> message) {
    using namespace detail;
    constexpr std::array<std::uint32_t, 64> k{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    std::array<std::uint32_t, 8> h{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const bytes data = padded(message);
    for (std::size_t block = 0; block < data.size(); block += 64) {
      std::array<std::uint32_t, 64> w{};
      for (std::size_t t = 0; t < 16; ++t)
        w[t] = word_at(data, block + 4 * t);
      for (std::size_t t = 16; t < 64; ++t) {
        const std::uint32_t s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        const std::uint32_t s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
      }
      auto [a, b, c, d, e, f, g, hh] = h;
      for (std::size_t t = 0; t < 64; ++t) {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = hh + s1 + ch + k[t] + w[t];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = s0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
      }
      h[0] += a;
      h[1] += b;
      h[2] += c;
      h[3] += d;
      h[4] += e;
      h[5] += f;
      h[6] += g;
      h[7] += hh;
    }
    return digest_of(h);
  }
};

constexpr bytes to_bytes(std::string_view text) { return bytes(text.begin(), text.end()); }

// HMAC, RFC 2104.
template <class Hash>
constexpr bytes hmac(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) {
  bytes k(key.begin(), key.end());
  if (k.size() > Hash::block_size)
    k = Hash::digest(k);
  k.resize(Hash::block_size, 0);
  bytes inner, outer;
  for (const std::uint8_t one : k) {
    inner.push_back(one ^ 0x36);
    outer.push_back(one ^ 0x5c);
  }
  inner.insert(inner.end(), message.begin(), message.end());
  const bytes first = Hash::digest(inner);
  outer.insert(outer.end(), first.begin(), first.end());
  return Hash::digest(outer);
}

// PBKDF2 with HMAC, RFC 8018, section 5.2: `length` bytes.
template <class Hash>
constexpr bytes pbkdf2(std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt,
                       std::uint32_t iterations, std::size_t length) {
  bytes out;
  for (std::uint32_t block = 1; out.size() < length; ++block) {
    bytes seed(salt.begin(), salt.end());
    for (int shift = 24; shift >= 0; shift -= 8)
      seed.push_back(static_cast<std::uint8_t>(block >> shift));
    bytes u = hmac<Hash>(password, seed);
    bytes t = u;
    for (std::uint32_t round = 1; round < iterations; ++round) {
      u = hmac<Hash>(password, u);
      for (std::size_t at = 0; at < t.size(); ++at)
        t[at] ^= u[at];
    }
    out.insert(out.end(), t.begin(), t.end());
  }
  out.resize(length);
  return out;
}

constexpr std::string base64_encode(std::span<const std::uint8_t> data) {
  constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  std::size_t at = 0;
  for (; at + 3 <= data.size(); at += 3) {
    const std::uint32_t v = (std::uint32_t{data[at]} << 16) | (std::uint32_t{data[at + 1]} << 8) | data[at + 2];
    out += alphabet[v >> 18];
    out += alphabet[(v >> 12) & 63];
    out += alphabet[(v >> 6) & 63];
    out += alphabet[v & 63];
  }
  if (const std::size_t rest = data.size() - at; rest > 0) {
    std::uint32_t v = std::uint32_t{data[at]} << 16;
    if (rest == 2)
      v |= std::uint32_t{data[at + 1]} << 8;
    out += alphabet[v >> 18];
    out += alphabet[(v >> 12) & 63];
    out += rest == 2 ? alphabet[(v >> 6) & 63] : '=';
    out += '=';
  }
  return out;
}

// Base64 back to bytes, or nothing where it is not Base64: characters out of
// the alphabet, padding out of place, or a length not a multiple of four.
constexpr std::optional<bytes> base64_decode(std::string_view text) {
  if (text.size() % 4 != 0)
    return std::nullopt;
  const auto value = [](char one) -> int {
    if (one >= 'A' && one <= 'Z') return one - 'A';
    if (one >= 'a' && one <= 'z') return one - 'a' + 26;
    if (one >= '0' && one <= '9') return one - '0' + 52;
    if (one == '+') return 62;
    if (one == '/') return 63;
    return -1;
  };
  bytes out;
  for (std::size_t at = 0; at < text.size(); at += 4) {
    const bool last = at + 4 == text.size();
    const int pad = text[at + 3] == '=' ? (text[at + 2] == '=' ? 2 : 1) : 0;
    if (pad && !last)
      return std::nullopt;
    std::uint32_t v = 0;
    for (int k = 0; k < 4; ++k) {
      const char one = text[at + k];
      int d = 0;
      if (one == '=') {
        if (k < 4 - pad)
          return std::nullopt;
      } else if ((d = value(one)) < 0) {
        return std::nullopt;
      }
      v = (v << 6) | static_cast<std::uint32_t>(d);
    }
    out.push_back(static_cast<std::uint8_t>(v >> 16));
    if (pad < 2)
      out.push_back(static_cast<std::uint8_t>(v >> 8));
    if (pad < 1)
      out.push_back(static_cast<std::uint8_t>(v));
  }
  return out;
}

constexpr std::string hex(std::span<const std::uint8_t> data) {
  constexpr std::string_view digits = "0123456789abcdef";
  std::string out;
  for (const std::uint8_t one : data) {
    out += digits[one >> 4];
    out += digits[one & 15];
  }
  return out;
}

}  // namespace tern::crypto
