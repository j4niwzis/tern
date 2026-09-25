// Authentication: the SASL mechanisms a client offers -- SCRAM-SHA-256 and
// SCRAM-SHA-1 (RFC 5802, RFC 7677), without channel binding, and PLAIN (RFC
// 4616), only for over TLS. Messages in and out; the caller carries them.
export module tern.sasl;

import std;
import tern.crypto;

export namespace tern::sasl {

enum class failure_code : std::uint8_t {
  malformed,           // the server's message is not what SCRAM says
  nonce_mismatch,      // its nonce does not begin with ours
  too_few_iterations,  // fewer iterations than the caller accepts
  server_error,        // it said e=...
  bad_signature,       // it could not prove it knows the password
};

struct failure {
  failure_code code;
  std::string detail;
};

// A fresh client nonce: 24 random bytes, in Base64.
inline std::string random_nonce() {
  std::random_device source;
  crypto::bytes raw(24);
  for (std::uint8_t& one : raw)
    one = static_cast<std::uint8_t>(source());
  return crypto::base64_encode(raw);
}

// One SCRAM exchange, as a client. The username and password are given
// already prepared -- by PRECIS, RFC 8265 -- as the protocol using SASL says.
template <class Hash>
class scram {
 public:
  scram(std::string_view username, std::string_view password, std::string nonce,
        std::uint32_t minimum_iterations = 1)
      : password_(password), nonce_(std::move(nonce)), minimum_(minimum_iterations) {
    // saslname: '=' and ',' escaped (RFC 5802, section 5.1).
    for (const char one : username) {
      if (one == '=')
        username_ += "=3D";
      else if (one == ',')
        username_ += "=2C";
      else
        username_ += one;
    }
  }

  // The client-first-message: no channel binding, no authorization identity.
  std::string first() const { return std::string(header) + first_bare(); }

  // The client-final-message, in answer to the server-first-message.
  std::expected<std::string, failure> answer(std::string_view server_first) {
    const auto fields = parse(server_first);
    const auto nonce = field(fields, 'r');
    const auto salt64 = field(fields, 's');
    const auto count = field(fields, 'i');
    if (!nonce || !salt64 || !count)
      return std::unexpected(failure{failure_code::malformed, std::string(server_first)});
    if (!nonce->starts_with(nonce_) || nonce->size() == nonce_.size())
      return std::unexpected(failure{failure_code::nonce_mismatch, std::string(*nonce)});
    const auto salt = crypto::base64_decode(*salt64);
    std::uint32_t iterations = 0;
    const auto [end, problem] = std::from_chars(count->data(), count->data() + count->size(), iterations);
    if (!salt || problem != std::errc{} || end != count->data() + count->size() || iterations == 0)
      return std::unexpected(failure{failure_code::malformed, std::string(server_first)});
    if (iterations < minimum_)
      return std::unexpected(failure{failure_code::too_few_iterations, std::to_string(iterations)});

    const crypto::bytes salted =
        crypto::pbkdf2<Hash>(crypto::to_bytes(password_), *salt, iterations, Hash::size);
    const crypto::bytes client_key = crypto::hmac<Hash>(salted, crypto::to_bytes("Client Key"));
    const crypto::bytes stored_key = Hash::digest(client_key);
    const std::string without_proof = "c=" + crypto::base64_encode(crypto::to_bytes(header)) + ",r=" + std::string(*nonce);
    const std::string auth_message = first_bare() + "," + std::string(server_first) + "," + without_proof;
    const crypto::bytes client_signature = crypto::hmac<Hash>(stored_key, crypto::to_bytes(auth_message));
    crypto::bytes proof = client_key;
    for (std::size_t at = 0; at < proof.size(); ++at)
      proof[at] ^= client_signature[at];
    const crypto::bytes server_key = crypto::hmac<Hash>(salted, crypto::to_bytes("Server Key"));
    server_signature_ = crypto::hmac<Hash>(server_key, crypto::to_bytes(auth_message));
    return without_proof + ",p=" + crypto::base64_encode(proof);
  }

  // Whether the server-final-message proves the server knows the password.
  std::expected<void, failure> verify(std::string_view server_final) const {
    const auto fields = parse(server_final);
    if (const auto error = field(fields, 'e'))
      return std::unexpected(failure{failure_code::server_error, std::string(*error)});
    const auto signature = field(fields, 'v');
    if (!signature || server_signature_.empty())
      return std::unexpected(failure{failure_code::malformed, std::string(server_final)});
    const auto decoded = crypto::base64_decode(*signature);
    if (!decoded || *decoded != server_signature_)
      return std::unexpected(failure{failure_code::bad_signature, std::string(*signature)});
    return {};
  }

 private:
  static constexpr std::string_view header = "n,,";

  std::string first_bare() const { return "n=" + username_ + ",r=" + nonce_; }

  static std::vector<std::pair<char, std::string_view>> parse(std::string_view message) {
    std::vector<std::pair<char, std::string_view>> out;
    while (!message.empty()) {
      const std::size_t comma = message.find(',');
      const std::string_view one = message.substr(0, comma);
      if (one.size() >= 2 && one[1] == '=')
        out.emplace_back(one[0], one.substr(2));
      if (comma == std::string_view::npos)
        break;
      message.remove_prefix(comma + 1);
    }
    return out;
  }

  static std::optional<std::string_view> field(const std::vector<std::pair<char, std::string_view>>& all, char name) {
    for (const auto& [key, value] : all)
      if (key == name)
        return value;
    return std::nullopt;
  }

  std::string username_;
  std::string password_;
  std::string nonce_;
  std::uint32_t minimum_;
  crypto::bytes server_signature_;
};

using scram_sha1 = scram<crypto::sha1>;
using scram_sha256 = scram<crypto::sha256>;

// PLAIN (RFC 4616): an authorization identity, which may be empty, the
// authentication identity and the password, each after a NUL.
inline std::string plain(std::string_view authcid, std::string_view password, std::string_view authzid = {}) {
  std::string out(authzid);
  out += '\0';
  out += authcid;
  out += '\0';
  out += password;
  return out;
}

}  // namespace tern::sasl
