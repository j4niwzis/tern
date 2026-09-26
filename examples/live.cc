// tern against a real server: a socket, or openssl s_client for TLS, made
// the input range and output iterator tern takes -- every byte both ways
// written to stderr.
//
//   tern-live plain <host> <port> <domain> <user> <password> [<user2> <password2>]
//   tern-live tls   <host> <port> <domain> <user> <password> [<user2> <password2>]
//
// With a second account: both connect, subscribe to each other, and the
// first sends the second a message. With one: roster, version, ping.
#include <netdb.h>
#include <stdio.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

import std;
import tern;
import chevron;

extern char** environ;

namespace {

// Bytes from one descriptor, to another: what was written is sent before
// anything is waited for, so that tern's writes go out before it reads.
struct pipe_ends {
  int in = -1, out = -1;
  std::string name;
  std::string pending;
  char buffer[4096];
  std::size_t at = 0, size = 0;

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
  bool fill() {
    flush();
    const auto n = ::read(in, buffer, sizeof buffer);
    if (n <= 0)
      return false;
    at = 0;
    size = static_cast<std::size_t>(n);
    std::println(stderr, "\x1b[36m{} <<\x1b[0m {}", name, std::string_view(buffer, size));
    return true;
  }
};

struct byte_iterator {
  using value_type = char;
  using difference_type = std::ptrdiff_t;
  pipe_ends* ends = nullptr;
  char operator*() const { return ends->buffer[ends->at]; }
  byte_iterator& operator++() {
    ++ends->at;
    return *this;
  }
  void operator++(int) { ++*this; }
  bool operator==(std::default_sentinel_t) const { return ends->at == ends->size && !ends->fill(); }
};

struct byte_range {
  pipe_ends* ends;
  byte_iterator begin() const { return {ends}; }
  std::default_sentinel_t end() const { return {}; }
};

struct byte_writer {
  using difference_type = std::ptrdiff_t;
  pipe_ends* ends = nullptr;
  byte_writer& operator*() { return *this; }
  byte_writer& operator=(char one) {
    ends->pending += one;
    return *this;
  }
  byte_writer& operator++() { return *this; }
  byte_writer operator++(int) { return *this; }
};

pipe_ends tcp(const std::string& host, const std::string& port, std::string name) {
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
  return {fd, fd, std::move(name)};
}

// openssl s_client doing STARTTLS and TLS; tern speaks through its pipes.
pipe_ends tls(const std::string& host, const std::string& port, const std::string& domain, std::string name) {
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
  return {from_child[0], to_child[1], std::move(name)};
}

// XEP-0092, the software version of an entity.
struct software {
  std::string name;
  std::string version;
  std::optional<std::string> os;
};
constexpr auto xml_schema(chevron::type<software>) {
  return chevron::schema<software>().name("jabber:iq:version", "query");
}
struct version_query {
  using kind = tern::iq::get;
  using answer = software;
};
constexpr auto xml_schema(chevron::type<version_query>) {
  return chevron::schema<version_query>().name("jabber:iq:version", "query");
}

std::string why(const tern::request_error& failed) {
  if (failed.reply)
    return std::string(failed.reply->reason.condition());
  if (failed.connection)
    return failed.connection->detail;
  return "an answer of another type";
}

void step(std::string_view what) { std::println("\n\x1b[1m== {}\x1b[0m", what); }

std::string kind_of(const tern::stanza_t& one) {
  return std::visit(
      [](const auto& family) {
        return std::visit([](const auto& kind) { return std::string(typeid(kind).name()); }, family);
      },
      one);
}

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
  const std::string mode = argv[1], host = argv[2], port = argv[3], domain = argv[4];
  auto open = [&](std::string name) {
    return mode == "tls" ? tls(host, port, domain, std::move(name)) : tcp(host, port, std::move(name));
  };

  try {
    step("connect " + std::string(argv[5]) + "@" + domain + " (" + mode + ")");
    pipe_ends first_ends = open(argv[5]);
    byte_range first_input{&first_ends};
    auto first = tern::connect(first_input, byte_writer{&first_ends}, account(domain, argv[5], argv[6]));
    std::println("bound: {}; roster versioning: {}", first.jid(), first.roster_versioning());

    step("roster");
    tern::roster_cache cache;
    first.sync(cache);
    std::println("roster version {}, {} item(s)", cache.ver.value_or("(none)"), cache.items.size());
    for (const auto& [jid, item] : cache.items)
      std::println("  {} {}", jid, item.name.value_or(""));

    step("software version of the server (XEP-0092)");
    if (auto version = first.try_request<version_query>({.to = domain}))
      std::println("{} {} {}", version->name, version->version, version->os.value_or(""));
    else
      std::println("refused: {}", why(version.error()));

    step("ping the server (XEP-0199)");
    const auto pong = first.try_request(tern::iq::get{.to = domain, .payload = {chevron::any{.uri = "urn:xmpp:ping", .local = "ping"}}});
    std::println("{}", pong ? "pong" : "no pong: " + why(pong.error()));

    first.available();

    if (argc == 9) {
      const std::string first_bare = std::string(argv[5]) + "@" + domain;
      const std::string second_bare = std::string(argv[7]) + "@" + domain;

      step("connect " + second_bare);
      pipe_ends second_ends = open(argv[7]);
      byte_range second_input{&second_ends};
      auto second = tern::connect(second_input, byte_writer{&second_ends}, account(domain, argv[7], argv[8]));
      std::println("bound: {}", second.jid());
      second.available();

      if (cache.items.contains(second_bare)) {
        step("already subscribed, from an earlier run: " + second_bare);
      } else {
      step(first_bare + " asks for " + second_bare + "'s presence; approved");
      (void)first.subscribe(second_bare);
      first_ends.flush();
      const bool asked = wait_for(second, [](const tern::stanza_t& one) {
        const auto* presence = std::get_if<tern::presence_t>(&one);
        return presence && std::holds_alternative<tern::presence::subscribe>(*presence);
      });
      std::println("subscribe arrived: {}", asked);
      (void)second.approve(first_bare);
      second_ends.flush();

      step("the roster push that follows, applied to the cache");
      const bool pushed = wait_for(first, [&](const tern::stanza_t& one) {
        const auto* iq = std::get_if<tern::iq_t>(&one);
        const auto* set = iq ? std::get_if<tern::iq::set>(iq) : nullptr;
        return set && cache.apply(*set) && cache.items.contains(second_bare) &&
               cache.items.at(second_bare).subscription &&
               !std::holds_alternative<tern::subscription::none>(*cache.items.at(second_bare).subscription);
      });
      std::println("pushed: {}; roster version {}, {} item(s)", pushed, cache.ver.value_or("(none)"),
                   cache.items.size());

      }

      step("a message from " + first_bare + " to " + second_bare);
      first.send(tern::message::chat{.to = second_bare, .body = "Wherefore art thou, Romeo? (sent by tern)",
                                     .thread = tern::thread{.id = "tern-live-1"}});
      first_ends.flush();
      std::optional<std::string> body;
      wait_for(second, [&](const tern::stanza_t& one) {
        const auto* message = std::get_if<tern::message_t>(&one);
        const auto* chat = message ? std::get_if<tern::message::chat>(message) : nullptr;
        if (chat && chat->body)
          body = chat->body;
        return body.has_value();
      });
      std::println("received: {}", body.value_or("(nothing)"));

      step("sync again, from the version kept");
      first.sync(cache);
      std::println("roster version {}, {} item(s)", cache.ver.value_or("(none)"), cache.items.size());

      second.close();
      second_ends.flush();
    }

    step("close");
    first.close();
    first_ends.flush();
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
