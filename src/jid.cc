// tern.jid: XMPP addresses, RFC 7622.
//
//   auto who = tern::jid::parse("Juliet@Example.COM/balcony");   // std::expected<jid, jid_error>
//   who->local() == "juliet"; who->domain() == "example.com"; who->resource() == "balcony";
//
// Each part prepared as the RFC says -- the localpart by the
// UsernameCaseMapped profile of PRECIS, with the characters it forbids
// besides; the domainpart as an IDNA2008 domain name in its Unicode form, or
// an IP literal; the resourcepart by the OpaqueString profile -- and none
// longer than 1023 bytes. Two addresses are equal where their parts are,
// which after preparation is what the RFC means by the same address.
export module tern.jid;

import std;
import alef.utf;
import alef.precis;
import alef.idna;

export namespace tern {

enum class jid_code : std::uint8_t {
  empty_domain,  // nothing where the domainpart must be
  localpart,     // a localpart the profile refuses, or empty after an @
  domainpart,    // not a domain name, nor an IP literal
  resourcepart,  // a resourcepart the profile refuses, or empty after a /
  too_long,      // a part longer than 1023 bytes
};

struct jid_error {
  jid_code code;
};

class jid {
 public:
  jid() = default;

  // An address read and prepared, or why it is not one.
  static std::expected<jid, jid_error> parse(std::string_view text) {
    // The resourcepart is everything after the first '/'; the localpart
    // everything before the first '@' ahead of that (section 3.1).
    std::string_view rest = text;
    std::optional<std::string_view> resource;
    if (const auto slash = rest.find('/'); slash != std::string_view::npos) {
      resource = rest.substr(slash + 1);
      rest = rest.substr(0, slash);
    }
    std::optional<std::string_view> local;
    if (const auto at = rest.find('@'); at != std::string_view::npos) {
      local = rest.substr(0, at);
      rest = rest.substr(at + 1);
    }
    jid made;
    if (rest.empty())
      return std::unexpected(jid_error{jid_code::empty_domain});
    if (auto domain = prepare_domain(rest))
      made.domain_ = std::move(*domain);
    else
      return std::unexpected(jid_error{jid_code::domainpart});
    if (local) {
      auto prepared = prepare_local(*local);
      if (!prepared)
        return std::unexpected(jid_error{jid_code::localpart});
      made.local_ = std::move(*prepared);
    }
    if (resource) {
      auto prepared = prepare_resource(*resource);
      if (!prepared)
        return std::unexpected(jid_error{jid_code::resourcepart});
      made.resource_ = std::move(*prepared);
    }
    if (made.local_.size() > 1023 || made.domain_.size() > 1023 || made.resource_.size() > 1023)
      return std::unexpected(jid_error{jid_code::too_long});
    return made;
  }

  const std::string& local() const noexcept { return local_; }
  const std::string& domain() const noexcept { return domain_; }
  const std::string& resource() const noexcept { return resource_; }

  // The address without its resource.
  jid bare() const {
    jid made = *this;
    made.resource_.clear();
    return made;
  }

  // As text: localpart@domainpart/resourcepart, the parts there are.
  std::string str() const {
    std::string out;
    if (!local_.empty())
      out += local_ + "@";
    out += domain_;
    if (!resource_.empty())
      out += "/" + resource_;
    return out;
  }

  friend bool operator==(const jid&, const jid&) = default;

 private:
  static std::string utf8(const std::u32string& text) {
    std::string out;
    for (const char8_t unit : text | alef::as_utf8)
      out.push_back(static_cast<char>(unit));
    return out;
  }

  static std::optional<std::string> prepare_local(std::string_view text) {
    auto prepared = alef::prepare_username(text);
    if (!prepared)
      return std::nullopt;
    // Section 3.3.1: besides what the profile refuses, these.
    for (const char32_t one : *prepared)
      if (std::u32string_view(U"\"&'/:<>@").contains(one))
        return std::nullopt;
    return utf8(*prepared);
  }

  static std::optional<std::string> prepare_domain(std::string_view text) {
    // An IP literal: an IPv6 address in brackets, or an IPv4 address.
    if (text.starts_with('[') && text.ends_with(']'))
      return std::string(text);
    const bool ipv4 = !text.empty() && std::ranges::all_of(text, [](char one) {
      return (one >= '0' && one <= '9') || one == '.';
    });
    if (ipv4)
      return std::string(text);
    // A trailing dot is not part of the domainpart (section 3.2).
    if (text.ends_with('.'))
      text.remove_suffix(1);
    auto prepared = alef::idna_to_unicode(text);
    if (!prepared || prepared->empty())
      return std::nullopt;
    return utf8(*prepared);
  }

  static std::optional<std::string> prepare_resource(std::string_view text) {
    auto prepared = alef::prepare_opaque_string(text);
    if (!prepared)
      return std::nullopt;
    return utf8(*prepared);
  }

  std::string local_, domain_, resource_;
};

}  // namespace tern
