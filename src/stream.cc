// A client's stream: connecting, securing, authenticating and binding a
// resource (RFC 6120), then stanzas in and out -- over any input range of
// bytes and any output iterator of chars, with nothing of its own running.
//
// The input is read only as far as the next thing needs, and never ahead:
// at <proceed/> nothing more is asked of it until the caller has put TLS
// underneath, through the hook it gave.
export module tern.stream;

import std;
import chevron;
import tern.crypto;
import tern.sasl;

export namespace tern {

inline constexpr std::string_view client_namespace = "jabber:client";
inline constexpr std::string_view stream_namespace = "http://etherx.jabber.org/streams";
inline constexpr std::string_view tls_namespace = "urn:ietf:params:xml:ns:xmpp-tls";
inline constexpr std::string_view sasl_namespace = "urn:ietf:params:xml:ns:xmpp-sasl";
inline constexpr std::string_view bind_namespace = "urn:ietf:params:xml:ns:xmpp-bind";
inline constexpr std::string_view xml_namespace = "http://www.w3.org/XML/1998/namespace";

// The three stanzas, as plain structs; what they carry beyond what is named
// here is kept whole.
struct message {
  std::optional<std::string> to, from, id, type;
  std::optional<std::string> lang;  // xml:lang
  std::optional<std::string> body;
  std::vector<chevron::any> payload;
};

struct presence {
  std::optional<std::string> to, from, id, type;
  std::optional<std::string> lang;  // xml:lang
  std::optional<std::string> show, status;
  std::optional<int> priority;
  std::vector<chevron::any> payload;
};

struct iq {
  std::optional<std::string> to, from;
  std::string id, type;
  std::optional<std::string> lang;  // xml:lang
  std::vector<chevron::any> payload;
};

// The two kinds of request an iq is.
inline constexpr std::string_view get = "get";
inline constexpr std::string_view set = "set";


constexpr auto xml_schema(chevron::type<message>) {
  using namespace chevron::members;
  return chevron::schema<message>()
      .name(client_namespace, "message")
      .members(attribute(), attribute(), attribute(), attribute(), attribute("lang", xml_namespace),
               child_text(), unknown_children());
}

constexpr auto xml_schema(chevron::type<presence>) {
  using namespace chevron::members;
  return chevron::schema<presence>()
      .name(client_namespace, "presence")
      .members(attribute(), attribute(), attribute(), attribute(), attribute("lang", xml_namespace),
               child_text(), child_text(), child_text(), unknown_children());
}

constexpr auto xml_schema(chevron::type<iq>) {
  using namespace chevron::members;
  return chevron::schema<iq>()
      .name(client_namespace, "iq")
      .members(attribute(), attribute(), attribute(), attribute(), attribute("lang", xml_namespace),
               unknown_children());
}

using stanza = std::variant<message, presence, iq>;

}  // namespace tern

namespace tern::detail {

// What negotiation reads: the stream's features, and the answers to it.
struct starttls_feature {
  std::vector<chevron::any> children;  // <required/>, if it is there

  bool required() const {
    return std::ranges::any_of(children, [](const chevron::any& one) {
      return one.uri == tls_namespace && one.local == "required";
    });
  }
};
struct mechanisms_feature {
  std::vector<std::string> mechanism;
};
struct bind_feature {
  std::vector<chevron::any> anything;
};
struct features {
  std::optional<starttls_feature> starttls;
  std::optional<mechanisms_feature> mechanisms;
  std::optional<bind_feature> bind;
  std::vector<chevron::any> other;
};

constexpr auto xml_schema(chevron::type<starttls_feature>) {
  using namespace chevron::members;
  return chevron::schema<starttls_feature>().name(tls_namespace, "starttls").members(unknown_children());
}
constexpr auto xml_schema(chevron::type<mechanisms_feature>) {
  return chevron::schema<mechanisms_feature>().name(sasl_namespace, "mechanisms");
}
constexpr auto xml_schema(chevron::type<bind_feature>) {
  using namespace chevron::members;
  return chevron::schema<bind_feature>().name(bind_namespace, "bind").members(unknown_children());
}
constexpr auto xml_schema(chevron::type<features>) {
  using namespace chevron::members;
  return chevron::schema<features>().name(stream_namespace, "features").members(_, _, _, unknown_children());
}

// <proceed/>, <failure/>, <challenge>, <success> and the rest: an element's
// name and its text, which is all negotiation needs of them.
struct nonza {
  std::string uri, local, text;
};

}  // namespace tern::detail

export namespace tern {

enum class connect_code : std::uint8_t {
  xml,               // the stream was not well-formed, or not what was asked
  closed,            // the input ended
  stream_error,      // the server ended the stream with an error
  tls_required,      // the server wants TLS and no way to start it was given
  tls_refused,       // the server refused STARTTLS
  no_mechanism,      // nothing both sides can authenticate with
  not_authorized,    // the server refused the credentials
  authentication,    // SCRAM went wrong: see sasl
  bind_refused,      // the server refused the resource
};

struct connect_error {
  connect_code code;
  std::string detail;
  std::optional<sasl::failure> sasl;
};

struct options {
  std::string username;  // the localpart, prepared
  std::string domain;
  std::string password;
  std::optional<std::string> resource;
  // Called at <proceed/>: put TLS under the input and the output, and return.
  // Without it, STARTTLS is not asked for, and a server that requires it is an
  // error.
  std::function<void()> start_tls;
  // PLAIN sends the password itself: only over TLS, unless this says so.
  bool plain_without_tls = false;
  std::uint32_t minimum_iterations = 4096;
  std::string nonce = {};  // for SCRAM; random where empty
  // Called by a request that has to wait while another one reads the stream:
  // suspend here and let the others run -- a coroutine's yield, or a wait on
  // a condition with threads. Without it, only one request may be in flight.
  std::function<void()> yield;
};

}  // namespace tern

namespace tern::detail {

// An input range read for chevron: bytes fed to a parser only as far as the
// next event needs -- up to a '>' or a '<', where an event can end -- and
// never further.
template <class I, class S>
class source {
 public:
  source(I at, S end) : at_(std::move(at)), end_(std::move(end)) {}

  std::expected<std::optional<chevron::event>, chevron::error> next() {
    for (;;) {
      auto one = parser_.next();
      if (!one || *one)
        return one;
      if (finished_)
        return one;
      std::string piece;
      while (at_ != end_) {
        const char unit = static_cast<char>(*at_);
        ++at_;
        piece.push_back(unit);
        if (unit == '>' || unit == '<')
          break;
      }
      parser_.feed(piece);
      if (at_ == end_ && piece.empty()) {
        parser_.finish();
        finished_ = true;
      }
    }
  }

  // A new stream, after TLS or authentication: a new document, from here on.
  void restart() {
    parser_ = chevron::parser();
    finished_ = false;
  }

 private:
  I at_;
  S end_;
  chevron::parser parser_;
  bool finished_ = false;
};

inline std::string escaped(std::string_view text) {
  std::string out;
  for (const char one : text) {
    if (one == '&') out += "&amp;";
    else if (one == '<') out += "&lt;";
    else if (one == '\'') out += "&apos;";
    else if (one == '"') out += "&quot;";
    else out += one;
  }
  return out;
}

}  // namespace tern::detail

export namespace tern {

// Why a request came to nothing: the stream failed; the server or the peer
// answered with an error, kept whole in reply; or the answer was not the type
// asked for.
enum class request_code { connection, error_reply, bad_answer };

struct request_error {
  request_code code;
  std::optional<connect_error> connection;
  std::optional<iq> reply;
};

// A stream that is authenticated and bound: stanzas in, stanzas out.
template <class I, class S, class Out>
class session {
 public:
  session(I at, S end, Out out) : source_(std::move(at), std::move(end)), out_(std::move(out)) {}

  // The full JID the server bound.
  const std::string& jid() const noexcept { return jid_; }

  // The next stanza, as it arrives; nothing where the stream has ended
  // cleanly; or the error.
  std::expected<std::optional<stanza>, connect_error> receive() {
    // What arrived while a request waited for its answer, first.
    if (!pending_.empty()) {
      stanza one = std::move(pending_.front());
      pending_.pop_front();
      return std::optional<stanza>(std::move(one));
    }
    for (;;) {
      if (reading_) {
        if (!yield_)
          return std::unexpected(connect_error{connect_code::xml, "read while a request reads", std::nullopt});
        yield_();
        if (!pending_.empty()) {
          stanza one = std::move(pending_.front());
          pending_.pop_front();
          return std::optional<stanza>(std::move(one));
        }
        continue;
      }
      auto one = read_locked();
      if (!one || !*one)
        return one;
      if (!claimed(**one))
        return one;
    }
  }

  // An iq sent, and its answer awaited: the result or the error with the same
  // id, from the address asked (RFC 6120, 8.2.3). Whatever else arrives in the
  // meantime is kept, and handed out by receive() and stanzas() afterwards, in
  // order. An id is made up where the iq has none.
  std::expected<iq, request_error> request(iq question) {
    if (question.id.empty())
      question.id = "tern-" + std::to_string(++last_id_);
    const std::string id = question.id;
    waiting_[id] = slot{question.to, std::nullopt};
    send(question);
    for (;;) {
      if (auto found = waiting_.find(id); found->second.answer) {
        iq answer = std::move(*found->second.answer);
        waiting_.erase(found);
        if (answer.type == "error")
          return std::unexpected(request_error{request_code::error_reply, std::nullopt, std::move(answer)});
        return answer;
      }
      if (failed_) {
        waiting_.erase(id);
        return std::unexpected(request_error{request_code::connection, *failed_, std::nullopt});
      }
      // Another request is reading: its reading may bring this answer too.
      if (reading_) {
        if (!yield_) {
          waiting_.erase(id);
          return std::unexpected(request_error{
              request_code::connection,
              connect_error{connect_code::xml, "a second request in flight, and no yield", std::nullopt},
              std::nullopt});
        }
        yield_();
        continue;
      }
      auto one = read_locked();
      if (!one || !*one) {
        waiting_.erase(id);
        return std::unexpected(request_error{request_code::connection, *failed_, std::nullopt});
      }
      if (!claimed(**one))
        pending_.push_back(std::move(**one));
    }
  }

  // The same, typed: the payload written from a type with a chevron schema,
  // the answer's first child read into another.
  template <chevron::described Answer, chevron::described Payload>
  std::expected<Answer, request_error> request(std::string_view type, const Payload& payload,
                                               std::optional<std::string> to = std::nullopt) {
    iq question{.to = std::move(to), .type = std::string(type), .payload = {chevron::to_any(payload)}};
    auto answer = request(std::move(question));
    if (!answer)
      return std::unexpected(std::move(answer).error());
    if (answer->payload.empty())
      return std::unexpected(request_error{request_code::bad_answer, std::nullopt, std::move(*answer)});
    auto typed = chevron::from_any<Answer>(answer->payload.front());
    if (!typed)
      return std::unexpected(request_error{request_code::bad_answer, std::nullopt, std::move(*answer)});
    return std::move(*typed);
  }

  // For connect(): how a waiting request lets others run.
  void yield_with(std::function<void()> yield) { yield_ = std::move(yield); }

 private:
  // One reader at a time; a failure is everyone's.
  std::expected<std::optional<stanza>, connect_error> read_locked() {
    reading_ = true;
    auto one = read_stanza();
    reading_ = false;
    if (!one)
      failed_ = one.error();
    else if (!*one)
      failed_ = connect_error{connect_code::closed, "", std::nullopt};
    return one;
  }

  // An answer to a request in flight goes to it: the result or the error with
  // its id, from the address it asked (RFC 6120, 8.2.3).
  bool claimed(stanza& one) {
    auto* answer = std::get_if<iq>(&one);
    if (!answer || (answer->type != "result" && answer->type != "error"))
      return false;
    const auto found = waiting_.find(answer->id);
    if (found == waiting_.end() || found->second.answer)
      return false;
    if (found->second.to && answer->from != found->second.to)
      return false;
    found->second.answer = std::move(*answer);
    return true;
  }

  std::expected<std::optional<stanza>, connect_error> read_stanza() {
    auto one = chevron::read_one_of<message, presence, iq>(source_);
    if (one)
      return std::visit([](auto&& value) { return std::optional<stanza>(stanza(std::move(value))); }, std::move(*one));
    const chevron::read_error& error = one.error();
    // The server's </stream:stream>: the end, and a clean one.
    if (error.code == chevron::read_code::unexpected_element && error.where.empty())
      return std::nullopt;
    if (error.code == chevron::read_code::incomplete ||
        (error.parse_error && error.parse_error->code == chevron::error_code::unexpected_end))
      return std::unexpected(connect_error{connect_code::closed, "", std::nullopt});
    return std::unexpected(connect_error{connect_code::xml, error.where, std::nullopt});
  }

 public:
  class stanza_view;

  // The stanzas as they arrive, for a range-based for loop: each a
  // std::expected<stanza, connect_error>. The view ends where the server ends
  // the stream, or just after an error.
  stanza_view stanzas() { return stanza_view(*this); }

  // A stanza, written to the output.
  template <class Stanza>
  void send(const Stanza& one) {
    out_ = chevron::write(std::move(out_), one);
  }

  // Ends the stream.
  void close() {
    out_ = std::ranges::copy(std::string_view("</stream:stream>"), std::move(out_)).out;
  }

  // For connect(): the reading and writing it sets up, and the JID it bound.
  detail::source<I, S>& source() { return source_; }
  void bound_to(std::string jid) { jid_ = std::move(jid); }
  Out& out() { return out_; }

 private:
  detail::source<I, S> source_;
  Out out_;
  std::string jid_;
  std::deque<stanza> pending_;
  std::size_t last_id_ = 0;
  // The requests in flight, by id: whom the answer must come from, and the
  // answer once somebody has read it.
  struct slot {
    std::optional<std::string> to;
    std::optional<iq> answer;
  };
  std::map<std::string, slot> waiting_;
  bool reading_ = false;
  std::optional<connect_error> failed_;
  std::function<void()> yield_;
};

template <class I, class S, class Out>
class session<I, S, Out>::stanza_view : public std::ranges::view_interface<stanza_view> {
 public:
  class iterator {
   public:
    using value_type = std::expected<stanza, connect_error>;
    using difference_type = std::ptrdiff_t;
    using iterator_concept = std::input_iterator_tag;

    iterator() = default;
    explicit iterator(stanza_view* view) : view_(view) { view_->advance(); }
    iterator(iterator&&) = default;
    iterator& operator=(iterator&&) = default;

    value_type& operator*() const { return *view_->current_; }
    iterator& operator++() {
      view_->advance();
      return *this;
    }
    void operator++(int) { ++*this; }
    friend bool operator==(const iterator& one, std::default_sentinel_t) { return !one.view_->current_; }

   private:
    stanza_view* view_ = nullptr;
  };

  explicit stanza_view(session& s) : session_(&s) {}
  iterator begin() { return iterator(this); }
  std::default_sentinel_t end() const noexcept { return {}; }

 private:
  void advance() {
    if (failed_) {
      current_.reset();
      return;
    }
    auto next = session_->receive();
    if (!next) {
      current_.emplace(std::unexpected(next.error()));
      failed_ = true;
    } else if (*next) {
      current_.emplace(std::move(**next));
    } else {
      current_.reset();
    }
  }

  session* session_;
  std::optional<std::expected<stanza, connect_error>> current_;
  bool failed_ = false;
};

}  // namespace tern

namespace tern::detail {

template <class Session>
class negotiation {
 public:
  negotiation(Session& s, const options& o) : s_(s), o_(o) {}

  std::expected<void, connect_error> run() {
    bool secured = false;
    for (;;) {
      if (auto opened = open(); !opened)
        return opened;
      auto offered = chevron::read<features>(s_.source());
      if (!offered)
        return fail(connect_code::xml, "stream features: " + offered.error().where);
      if (offered->starttls && !secured) {
        if (!o_.start_tls) {
          if (offered->starttls->required())
            return fail(connect_code::tls_required, "");
        } else {
          write("<starttls xmlns='" + std::string(tls_namespace) + "'/>");
          auto answer = read_nonza();
          if (!answer)
            return std::unexpected(answer.error());
          if (answer->local != "proceed")
            return fail(connect_code::tls_refused, answer->local);
          o_.start_tls();
          secured = true;
          s_.source().restart();
          continue;
        }
      }
      if (!authenticated_) {
        if (!offered->mechanisms)
          return fail(connect_code::no_mechanism, "none offered");
        if (auto done = authenticate(offered->mechanisms->mechanism, secured); !done)
          return done;
        authenticated_ = true;
        s_.source().restart();
        continue;
      }
      if (!offered->bind)
        return fail(connect_code::bind_refused, "no bind offered");
      return bind();
    }
  }

  std::string jid;

 private:
  std::unexpected<connect_error> fail(connect_code code, std::string detail) const {
    return std::unexpected(connect_error{code, std::move(detail), std::nullopt});
  }

  void write(std::string_view text) { s_.out() = std::ranges::copy(text, std::move(s_.out())).out; }

  // Our stream header, then the server's.
  std::expected<void, connect_error> open() {
    write("<?xml version='1.0'?><stream:stream to='" + escaped(o_.domain) + "' from='" +
          escaped(o_.username + "@" + o_.domain) + "' version='1.0' xmlns='" + std::string(client_namespace) +
          "' xmlns:stream='" + std::string(stream_namespace) + "'>");
    auto header = s_.source().next();
    if (!header)
      return fail(connect_code::xml, "stream header");
    if (!*header)
      return fail(connect_code::closed, "before the stream header");
    const auto* start = std::get_if<chevron::start_element>(&**header);
    if (!start || start->name.uri != stream_namespace || start->name.local != "stream")
      return fail(connect_code::xml, "not a stream header");
    return {};
  }

  // An element answering negotiation: its name, and its text.
  std::expected<nonza, connect_error> read_nonza() {
    auto first = s_.source().next();
    if (!first || !*first)
      return fail(connect_code::closed, "while negotiating");
    const auto* start = std::get_if<chevron::start_element>(&**first);
    if (!start)
      return fail(connect_code::xml, "while negotiating");
    nonza out{std::string(start->name.uri), std::string(start->name.local), {}};
    if (out.uri == stream_namespace && out.local == "error")
      return fail(connect_code::stream_error, "");
    for (std::size_t depth = 1; depth > 0;) {
      auto next = s_.source().next();
      if (!next || !*next)
        return fail(connect_code::closed, "while negotiating");
      if (std::holds_alternative<chevron::start_element>(**next))
        ++depth;
      else if (std::holds_alternative<chevron::end_element>(**next))
        --depth;
      else if (depth == 1)
        out.text += std::get<chevron::text>(**next).content;
    }
    return out;
  }

  std::expected<void, connect_error> authenticate(const std::vector<std::string>& offered, bool secured) {
    const auto has = [&](std::string_view name) { return std::ranges::find(offered, name) != offered.end(); };
    const std::string nonce = o_.nonce.empty() ? sasl::random_nonce() : o_.nonce;
    if (has("SCRAM-SHA-256"))
      return scram<sasl::scram_sha256>("SCRAM-SHA-256", nonce);
    if (has("SCRAM-SHA-1"))
      return scram<sasl::scram_sha1>("SCRAM-SHA-1", nonce);
    if (has("PLAIN") && (secured || o_.plain_without_tls)) {
      auth("PLAIN", sasl::plain(o_.username, o_.password));
      auto answer = read_nonza();
      if (!answer)
        return std::unexpected(answer.error());
      if (answer->local != "success")
        return fail(connect_code::not_authorized, answer->text);
      return {};
    }
    return fail(connect_code::no_mechanism, "");
  }

  void auth(std::string_view mechanism, std::string_view initial) {
    write("<auth xmlns='" + std::string(sasl_namespace) + "' mechanism='" + std::string(mechanism) + "'>" +
          crypto::base64_encode(crypto::to_bytes(initial)) + "</auth>");
  }

  static std::string text_of(std::string_view base64) {
    const auto decoded = crypto::base64_decode(base64);
    return decoded ? std::string(decoded->begin(), decoded->end()) : std::string();
  }

  template <class Scram>
  std::expected<void, connect_error> scram(std::string_view mechanism, const std::string& nonce) {
    Scram client(o_.username, o_.password, nonce, o_.minimum_iterations);
    auth(mechanism, client.first());
    auto challenge = read_nonza();
    if (!challenge)
      return std::unexpected(challenge.error());
    if (challenge->local != "challenge")
      return fail(connect_code::not_authorized, challenge->local);
    auto reply = client.answer(text_of(challenge->text));
    if (!reply)
      return std::unexpected(connect_error{connect_code::authentication, reply.error().detail, reply.error()});
    write("<response xmlns='" + std::string(sasl_namespace) + "'>" +
          crypto::base64_encode(crypto::to_bytes(*reply)) + "</response>");
    auto outcome = read_nonza();
    if (!outcome)
      return std::unexpected(outcome.error());
    if (outcome->local != "success")
      return fail(connect_code::not_authorized, outcome->local);
    if (auto proved = client.verify(text_of(outcome->text)); !proved)
      return std::unexpected(connect_error{connect_code::authentication, proved.error().detail, proved.error()});
    return {};
  }

  std::expected<void, connect_error> bind() {
    std::string request = "<iq type='set' id='bind_1'><bind xmlns='" + std::string(bind_namespace) + "'>";
    if (o_.resource)
      request += "<resource>" + escaped(*o_.resource) + "</resource>";
    write(request + "</bind></iq>");
    auto answer = chevron::read<iq>(s_.source());
    if (!answer)
      return fail(connect_code::xml, "bind: " + answer.error().where);
    if (answer->type != "result" || answer->id != "bind_1")
      return fail(connect_code::bind_refused, answer->type);
    for (const chevron::any& one : answer->payload)
      if (one.uri == bind_namespace && one.local == "bind")
        for (const chevron::any_node& child : one.children)
          if (const auto* element = std::get_if<chevron::any>(&child.value); element && element->local == "jid")
            for (const chevron::any_node& text : element->children)
              if (const auto* piece = std::get_if<std::string>(&text.value))
                jid += *piece;
    if (jid.empty())
      return fail(connect_code::bind_refused, "no JID in the answer");
    return {};
  }

  Session& s_;
  const options& o_;
  bool authenticated_ = false;
};

}  // namespace tern::detail

export namespace tern {

// Connects over `input`, a range of bytes read as far as each step needs, and
// `output`, an output iterator of char: stream, STARTTLS if a hook is given,
// SCRAM-SHA-256, SCRAM-SHA-1 or PLAIN, and resource binding. The session, a
// plain value, keeps `input`'s iterator and the output iterator; the range
// has to outlive it.
template <std::ranges::input_range Input, std::output_iterator<char> Out>
std::expected<session<std::ranges::iterator_t<Input>, std::ranges::sentinel_t<Input>, Out>, connect_error>
connect(Input& input, Out output, const options& how) {
  using result = session<std::ranges::iterator_t<Input>, std::ranges::sentinel_t<Input>, Out>;
  result s(std::ranges::begin(input), std::ranges::end(input), std::move(output));
  detail::negotiation<result> steps(s, how);
  if (auto done = steps.run(); !done)
    return std::unexpected(done.error());
  s.bound_to(std::move(steps.jid));
  s.yield_with(how.yield);
  return s;
}

}  // namespace tern
