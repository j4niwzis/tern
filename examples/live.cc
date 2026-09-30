// tern against a real server, through a transport of its own: a socket, or
// openssl s_client for TLS -- input as the chunks each read() brings, output
// flushed where tern ends a unit -- every byte both ways written to stderr.
//
//   tern-live plain <host> <port> <domain> <user> <password> [<user2> <password2>]
//   tern-live tls   <host> <port> <domain> <user> <password> [<user2> <password2>]
//
// With host "srv", where to connect comes from the domain's SRV records
// (RFC 6120, 3.2.1), asked of the resolver /etc/resolv.conf names, over UDP.
//
// With a second account: both connect, the first subscribes to the second
// where it has not yet, and sends it a message. With one: roster, version,
// ping.
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

import std;
import splice;
import tern;
import chevron;

extern char** environ;

namespace {

// A tern transport over two descriptors. Nothing is read before tern asks:
// the chunk is fetched where tern asks whether the input has ended.
struct fd_transport {
  int in = -1, out = -1;
  std::string name;
  bool tls_below = false;  // openssl s_client under it: secured from the start
  std::string pending;
  char buffer[4096];
  std::string_view current;
  bool fetched = false, ended = false;

  bool at_end() {
    if (!fetched) {
      fetched = true;
      const auto n = ::read(in, buffer, sizeof buffer);
      if (n <= 0) {
        ended = true;
        current = {};
      } else {
        current = std::string_view(buffer, static_cast<std::size_t>(n));
        std::println(stderr, "\x1b[36m{} <<\x1b[0m {}", name, current);
      }
    }
    return ended;
  }

  struct iterator {
    using value_type = std::string_view;
    using difference_type = std::ptrdiff_t;
    fd_transport* t = nullptr;
    std::string_view operator*() const { return t->current; }
    iterator& operator++() {
      t->fetched = false;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(std::default_sentinel_t) const { return t->at_end(); }
  };
  struct chunks {
    fd_transport* t = nullptr;
    iterator begin() const { return {t}; }
    std::default_sentinel_t end() const { return {}; }
  };
  chunks view;

  chunks& input() {
    view.t = this;
    return view;
  }
  void write(std::string_view bytes) { pending += bytes; }
  void flush() {
    if (pending.empty())
      return;
    std::println(stderr, "\x1b[33m{} >>\x1b[0m {}", name, pending);
    for (std::size_t sent = 0; sent < pending.size();) {
      const auto n = ::write(out, pending.data() + sent, pending.size() - sent);
      if (n <= 0)
        break;
      sent += static_cast<std::size_t>(n);
    }
    pending.clear();
  }
  bool secured() const { return tls_below; }
};

fd_transport tcp(const std::string& host, const std::string& port, std::string name) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* found = nullptr;
  if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &found) != 0)
    throw std::runtime_error("no address for " + host);
  int fd = -1;
  for (addrinfo* one = found; one; one = one->ai_next) {
    fd = ::socket(one->ai_family, one->ai_socktype, one->ai_protocol);
    if (fd >= 0 && ::connect(fd, one->ai_addr, one->ai_addrlen) == 0)
      break;
    if (fd >= 0)
      ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(found);
  if (fd < 0)
    throw std::runtime_error("cannot connect to " + host);
  timeval wait{8, 0};  // a read that waits longer ends the stream
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
  return {.in = fd, .out = fd, .name = std::move(name)};
}

// openssl s_client doing STARTTLS and TLS; tern speaks through its pipes, on
// a stream secured from the start.
fd_transport tls(const std::string& host, const std::string& port, const std::string& domain, std::string name) {
  int to_child[2], from_child[2];
  if (::pipe(to_child) != 0 || ::pipe(from_child) != 0)
    throw std::runtime_error("pipe");
  posix_spawn_file_actions_t actions;
  ::posix_spawn_file_actions_init(&actions);
  ::posix_spawn_file_actions_adddup2(&actions, to_child[0], 0);
  ::posix_spawn_file_actions_adddup2(&actions, from_child[1], 1);
  ::posix_spawn_file_actions_addclose(&actions, to_child[1]);
  ::posix_spawn_file_actions_addclose(&actions, from_child[0]);
  const std::string address = host + ":" + port;
  std::vector<std::string> args{"openssl", "s_client", "-quiet", "-verify_return_error", "-verify_quiet",
                                "-starttls", "xmpp", "-xmpphost", domain, "-servername", domain,
                                "-connect", address};
  if (std::getenv("TERN_LIVE_INSECURE"))  // a self-signed certificate, locally
    args.erase(args.begin() + 3);
  std::vector<char*> argv;
  for (std::string& one : args)
    argv.push_back(one.data());
  argv.push_back(nullptr);
  pid_t child;
  if (::posix_spawnp(&child, "openssl", &actions, nullptr, argv.data(), environ) != 0)
    throw std::runtime_error("cannot start openssl");
  ::close(to_child[0]);
  ::close(from_child[1]);
  return {.in = from_child[0], .out = to_child[1], .name = std::move(name), .tls_below = true};
}

// The domain's XMPP service, by its SRV records: the first to try, or the
// domain itself where there are none.
std::pair<std::string, std::string> locate(const std::string& domain) {
  std::string nameserver = "127.0.0.53";
  {
    std::ifstream conf("/etc/resolv.conf");
    std::string word;
    while (conf >> word)
      if (word == "nameserver" && conf >> nameserver)
        break;
  }
  std::vector<tern::srv::target> found;
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in to{};
  to.sin_family = AF_INET;
  to.sin_port = htons(53);
  if (fd >= 0 && ::inet_pton(AF_INET, nameserver.c_str(), &to.sin_addr) == 1) {
    timeval wait{3, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    const auto id = static_cast<std::uint16_t>(std::random_device{}());
    const auto question = tern::srv::query(domain, id);
    ::sendto(fd, question.data(), question.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
    std::uint8_t answer[4096];
    const auto n = ::recv(fd, answer, sizeof answer, 0);
    if (n > 0)
      if (auto targets = tern::srv::answers(std::span<const std::uint8_t>(answer, static_cast<std::size_t>(n)), id))
        found = std::move(*targets);
  }
  if (fd >= 0)
    ::close(fd);
  std::mt19937 random(std::random_device{}());
  const auto order = tern::srv::ordered(found, random);
  const tern::srv::target first = order.empty() ? tern::srv::fallback(domain) : order.front();
  std::println("SRV via {}: {} record(s); trying {}:{}", nameserver, found.size(), first.host, first.port);
  return {first.host, std::to_string(first.port)};
}

std::string why(const tern::request_error& failed) {
  if (failed.reply)
    return std::string(failed.reply->condition());
  if (failed.connection)
    return failed.connection->detail;
  return "an answer of another type";
}

void step(std::string_view what) { std::println("\n\x1b[1m== {}\x1b[0m", what); }

// Reads until a stanza for which `wanted` says true, or the stream is quiet.
template <class Session, class Wanted>
bool wait_for(Session& session, Wanted wanted) {
  for (;;) {
    auto one = session.try_receive();
    if (!one || !*one)
      return false;
    if (wanted(**one))
      return true;
  }
}

tern::options account(const std::string& domain, const std::string& user, const std::string& password) {
  tern::options how;
  how.domain = domain;
  how.username = user;
  how.password = password;
  how.resource = "tern-live";
  return how;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 7 && argc != 9) {
    std::println(stderr, "usage: {} plain|tls <host> <port> <domain> <user> <password> [<user2> <password2>]",
                 argv[0]);
    return 2;
  }
  const std::string mode = argv[1], domain = argv[4];
  std::string host = argv[2], port = argv[3];
  if (host == "srv")
    std::tie(host, port) = locate(domain);
  auto open = [&](std::string name) {
    return mode == "tls" ? tls(host, port, domain, std::move(name)) : tcp(host, port, std::move(name));
  };

  try {
    step("connect " + std::string(argv[5]) + "@" + domain + " (" + mode + ")");
    fd_transport first_wire = open(argv[5]);
    auto first = tern::connect(first_wire, account(domain, argv[5], argv[6]));
    std::println("bound: {}; roster versioning: {}", first.jid(), first.roster_versioning());

    step("roster");
    tern::roster_cache cache;
    first.sync(cache);
    std::println("roster version {}, {} item(s)", cache.ver.value_or("(none)"), cache.items.size());
    for (const auto& [jid, item] : cache.items)
      std::println("  {} {}", jid, item.name.value_or(""));

    step("software version of the server (XEP-0092), read straight into tern::version");
    if (auto version = first.try_request<tern::query::version>({.to = domain}))
      std::println("{} {} {}", version->name.value_or("?"), version->version.value_or("?"), version->os.value_or(""));
    else
      std::println("refused: {}", why(version.error()));

    step("ping the server (XEP-0199), an empty result");
    const auto pong = first.try_request<tern::query::ping>({.to = domain});
    std::println("{}", pong ? "pong" : "no pong: " + why(pong.error()));

    first.available();

    if (argc == 9) {
      const std::string first_bare = std::string(argv[5]) + "@" + domain;
      const std::string second_bare = std::string(argv[7]) + "@" + domain;

      step("connect " + second_bare);
      fd_transport second_wire = open(argv[7]);
      auto second = tern::connect(second_wire, account(domain, argv[7], argv[8]));
      std::println("bound: {}", second.jid());
      second.available();

      if (cache.items.contains(second_bare)) {
        step("already subscribed, from an earlier run: " + second_bare);
      } else {
        step(first_bare + " asks for " + second_bare + "'s presence; approved");
        (void)first.subscribe(second_bare);
        const bool asked = wait_for(second, [](const tern::stanza_t& one) {
          const auto* presence = splice::get_if<tern::presence_t>(&one);
          return presence && splice::holds_alternative<tern::presence::subscribe>(*presence);
        });
        std::println("subscribe arrived: {}", asked);
        (void)second.approve(first_bare);

        step("the roster push that follows, applied to the cache");
        const bool pushed = wait_for(first, [&](const tern::stanza_t& one) {
          const auto* iq = splice::get_if<tern::iq_t>(&one);
          const auto* set = iq ? splice::get_if<tern::iq::set>(iq) : nullptr;
          return set && cache.apply(*set) && cache.items.contains(second_bare) &&
                 cache.items.at(second_bare).subscription &&
                 !splice::holds_alternative<tern::subscription::none>(*cache.items.at(second_bare).subscription);
        });
        std::println("pushed: {}; roster version {}, {} item(s)", pushed, cache.ver.value_or("(none)"),
                     cache.items.size());
      }

      step("a message from " + first_bare + " to " + second_bare);
      first.send(tern::message::chat{.to = second_bare, .body = "Wherefore art thou, Romeo? (sent by tern)",
                                     .thread = tern::thread{.id = "tern-live-1"}});
      std::optional<std::string> body;
      wait_for(second, [&](const tern::stanza_t& one) {
        const auto* message = splice::get_if<tern::message_t>(&one);
        const auto* chat = message ? splice::get_if<tern::message::chat>(message) : nullptr;
        if (chat && chat->body)
          body = chat->body;
        return body.has_value();
      });
      std::println("received: {}", body.value_or("(nothing)"));

      step("sync again, from the version kept");
      first.sync(cache);
      std::println("roster version {}, {} item(s)", cache.ver.value_or("(none)"), cache.items.size());

      second.close();
    }

    step("close");
    first.close();
    std::println("done");
    return 0;
  } catch (const tern::connect_failure& failed) {
    std::println("connect failed: {} ({})", failed.error.detail, static_cast<int>(failed.error.code));
  } catch (const tern::request_failure& failed) {
    std::println("request failed: {}", failed.what());
  } catch (const std::exception& failed) {
    std::println("failed: {}", failed.what());
  }
  return 1;
}
