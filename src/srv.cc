// Where an XMPP service is (RFC 6120, 3.2.1, and RFC 2782): the DNS query for
// its SRV records, their answer read, and the order to try them in -- the
// bytes only; sending the query is the caller's, over whatever it has.
export module tern.srv;

import std;

export namespace tern::srv {

// One place to connect to.
struct target {
  std::uint16_t priority = 0;
  std::uint16_t weight = 0;
  std::uint16_t port = 0;
  std::string host;
};

// The query for the service's records at the domain (RFC 1035, 4.1): one
// question, of type SRV, recursion desired.
constexpr std::vector<std::uint8_t> query(std::string_view domain, std::uint16_t id,
                                       std::string_view service = "_xmpp-client._tcp") {
  std::vector<std::uint8_t> out{static_cast<std::uint8_t>(id >> 8), static_cast<std::uint8_t>(id & 0xff),
                                0x01, 0x00,   // flags: RD
                                0x00, 0x01,   // one question
                                0, 0, 0, 0, 0, 0};
  const std::string name = std::string(service) + "." + std::string(domain);
  for (std::size_t from = 0; from <= name.size();) {
    std::size_t to = name.find('.', from);
    if (to == std::string::npos)
      to = name.size();
    if (to > from) {
      out.push_back(static_cast<std::uint8_t>(to - from));
      out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(from),
                 name.begin() + static_cast<std::ptrdiff_t>(to));
    }
    from = to + 1;
  }
  out.push_back(0);
  out.insert(out.end(), {0x00, 0x21, 0x00, 0x01});  // SRV, IN
  return out;
}

namespace detail {

struct reader {
  std::span<const std::uint8_t> in;
  std::size_t at = 0;

  constexpr bool has(std::size_t n) const { return at + n <= in.size(); }
  constexpr std::uint16_t u16() {
    const std::uint16_t out = static_cast<std::uint16_t>(in[at] << 8 | in[at + 1]);
    at += 2;
    return out;
  }

  // A name, following compression pointers (RFC 1035, 4.1.4) -- a bounded
  // number of them, so that a loop ends.
  constexpr std::optional<std::string> name() {
    std::string out;
    std::size_t here = at;
    bool jumped = false;
    for (int hops = 0; hops < 64; ++hops) {
      if (here >= in.size())
        return std::nullopt;
      const std::uint8_t length = in[here];
      if ((length & 0xc0) == 0xc0) {
        if (here + 1 >= in.size())
          return std::nullopt;
        if (!jumped)
          at = here + 2;
        jumped = true;
        here = static_cast<std::size_t>((length & 0x3f) << 8 | in[here + 1]);
        continue;
      }
      if (length & 0xc0)
        return std::nullopt;
      if (length == 0) {
        if (!jumped)
          at = here + 1;
        return out;
      }
      if (here + 1 + length > in.size())
        return std::nullopt;
      if (!out.empty())
        out += '.';
      for (std::size_t i = 0; i < length; ++i)
        out.push_back(static_cast<char>(in[here + 1 + i]));
      here += 1 + length;
    }
    return std::nullopt;
  }
};

}  // namespace detail

// The SRV records a response holds, for the query with that id; why not,
// where it is not one.
constexpr std::expected<std::vector<target>, std::string> answers(std::span<const std::uint8_t> response,
                                                                std::uint16_t id) {
  detail::reader r{response};
  if (!r.has(12))
    return std::unexpected("too short");
  if (r.u16() != id)
    return std::unexpected("another query's answer");
  const std::uint16_t flags = r.u16();
  if (!(flags & 0x8000))
    return std::unexpected("not a response");
  if (flags & 0x0200)
    return std::unexpected("truncated");
  const unsigned rcode = flags & 0x000f;
  const std::uint16_t questions = r.u16(), count = r.u16();
  r.at += 4;  // authority and additional counts
  if (rcode == 3)
    return std::vector<target>{};  // no such name
  if (rcode != 0)
    return std::unexpected(std::string("server failure ") + static_cast<char>('0' + rcode % 10));
  for (std::uint16_t q = 0; q < questions; ++q) {
    if (!r.name() || !r.has(4))
      return std::unexpected("bad question");
    r.at += 4;
  }
  std::vector<target> out;
  for (std::uint16_t a = 0; a < count; ++a) {
    if (!r.name() || !r.has(10))
      return std::unexpected("bad answer");
    const std::uint16_t type = r.u16(), klass = r.u16();
    r.at += 4;  // TTL
    const std::uint16_t length = r.u16();
    if (!r.has(length))
      return std::unexpected("bad answer");
    const std::size_t next = r.at + length;
    if (type == 33 && klass == 1) {
      if (length < 7)
        return std::unexpected("bad SRV record");
      target one;
      one.priority = r.u16();
      one.weight = r.u16();
      one.port = r.u16();
      auto host = r.name();
      if (!host)
        return std::unexpected("bad SRV target");
      one.host = std::move(*host);
      out.push_back(std::move(one));
    }
    r.at = next;
  }
  return out;
}

// RFC 2782's order: by priority; within one, each next chosen at random with
// a chance in proportion to its weight -- those of weight 0 first in line
// for the smallest numbers, as the RFC has it. A single target "." says the
// service is not there: nothing to try.
template <std::uniform_random_bit_generator Random>
std::vector<target> ordered(std::vector<target> targets, Random& random) {
  if (targets.size() == 1 && (targets[0].host.empty() || targets[0].host == "."))
    return {};
  std::ranges::stable_sort(targets, {}, &target::priority);
  std::vector<target> out;
  for (std::size_t from = 0; from < targets.size();) {
    std::size_t to = from;
    while (to < targets.size() && targets[to].priority == targets[from].priority)
      ++to;
    std::vector<target> group(targets.begin() + static_cast<std::ptrdiff_t>(from),
                              targets.begin() + static_cast<std::ptrdiff_t>(to));
    std::ranges::stable_partition(group, [](const target& one) { return one.weight == 0; });
    while (!group.empty()) {
      std::uint32_t total = 0;
      for (const target& one : group)
        total += one.weight;
      const std::uint32_t pick = std::uniform_int_distribution<std::uint32_t>(0, total)(random);
      std::uint32_t running = 0;
      std::size_t chosen = group.size() - 1;
      for (std::size_t i = 0; i < group.size(); ++i) {
        running += group[i].weight;
        if (running >= pick) {
          chosen = i;
          break;
        }
      }
      out.push_back(std::move(group[chosen]));
      group.erase(group.begin() + static_cast<std::ptrdiff_t>(chosen));
    }
    from = to;
  }
  return out;
}

// Where there are no records at all (RFC 6120, 3.2.2): the domain itself,
// at the port XMPP clients use.
constexpr target fallback(std::string_view domain) { return {0, 0, 5222, std::string(domain)}; }

}  // namespace tern::srv
