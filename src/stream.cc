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
inline constexpr std::string_view stanza_errors_namespace = "urn:ietf:params:xml:ns:xmpp-stanzas";

// What a stanza of the error kind says went wrong (RFC 6120, 8.3): what to do
// about it, and the condition -- an element of the stanza-errors namespace,
// whose name condition() gives.
namespace error_types {
struct cancel { static constexpr std::string_view xml_value = "cancel"; };
struct continue_ { static constexpr std::string_view xml_value = "continue"; };
struct modify { static constexpr std::string_view xml_value = "modify"; };
struct auth { static constexpr std::string_view xml_value = "auth"; };
struct wait { static constexpr std::string_view xml_value = "wait"; };
}  // namespace error_types

struct stanza_error {
  std::optional<std::variant<error_types::cancel, error_types::continue_, error_types::modify,
                             error_types::auth, error_types::wait>> type;
  std::vector<chevron::any> details;

  std::string_view condition() const {
    for (const chevron::any& one : details)
      if (one.uri == "urn:ietf:params:xml:ns:xmpp-stanzas" && one.local != "text")
        return one.local;
    return {};
  }
};

constexpr auto xml_schema(chevron::type<stanza_error>) {
  using namespace chevron::members;
  return chevron::schema<stanza_error>()
      .name(client_namespace, "error")
      .members(attribute(), unknown_children());
}

// The stanzas, a type for each kind: what the kind can carry and nothing
// else. What they carry beyond what is named is kept whole, in payload.
namespace message {
struct normal {
  std::optional<std::string> to, from, id, lang, body;
  std::vector<chevron::any> payload;
};
struct chat {
  std::optional<std::string> to, from, id, lang, body;
  std::vector<chevron::any> payload;
};
struct groupchat {
  std::optional<std::string> to, from, id, lang, body;
  std::vector<chevron::any> payload;
};
struct headline {
  std::optional<std::string> to, from, id, lang, body;
  std::vector<chevron::any> payload;
};
struct error {
  std::optional<std::string> to, from, id, lang, body;
  stanza_error reason;  // the <error/>
  std::vector<chevron::any> payload;
};
}  // namespace message

namespace presence {
struct available {
  std::optional<std::string> to, from, id, lang, show, status;
  std::optional<int> priority;
  std::vector<chevron::any> payload;
};
struct unavailable {
  std::optional<std::string> to, from, id, lang, status;
  std::vector<chevron::any> payload;
};
struct subscribe {
  std::optional<std::string> to, from, id, lang;
  std::vector<chevron::any> payload;
};
struct subscribed {
  std::optional<std::string> to, from, id, lang;
  std::vector<chevron::any> payload;
};
struct unsubscribe {
  std::optional<std::string> to, from, id, lang;
  std::vector<chevron::any> payload;
};
struct unsubscribed {
  std::optional<std::string> to, from, id, lang;
  std::vector<chevron::any> payload;
};
struct probe {
  std::optional<std::string> to, from, id, lang;
  std::vector<chevron::any> payload;
};
struct error {
  std::optional<std::string> to, from, id, lang;
  stanza_error reason;
  std::vector<chevron::any> payload;
};
}  // namespace presence

namespace iq {
struct get {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  std::vector<chevron::any> payload;
};
struct set {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  std::vector<chevron::any> payload;
};
struct result {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  std::vector<chevron::any> payload;
};
struct error {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  stanza_error reason;
  std::vector<chevron::any> payload;
};
}  // namespace iq

// The schema every stanza shares: its element, the four attributes, the
// <error/> where the kind has one, and the rest kept.
template <class T>
constexpr auto stanza_schema(std::string_view element) {
  using namespace chevron::members;
  auto made = chevron::schema<T>()
                  .name(client_namespace, element)
                  .template member<"to">(attribute())
                  .template member<"from">(attribute())
                  .template member<"id">(attribute())
                  .template member<"lang">(attribute("lang", xml_namespace))
                  .template member<"payload">(unknown_children());
  if constexpr (requires(T one) { one.reason; })
    return made.template member<"reason">(child("error"));
  else
    return made;
}

namespace message {
constexpr auto xml_schema(chevron::type<normal>) {
  return stanza_schema<normal>("message").when<"type">("normal", chevron::or_absent);
}
constexpr auto xml_schema(chevron::type<chat>) { return stanza_schema<chat>("message").when<"type">("chat"); }
constexpr auto xml_schema(chevron::type<groupchat>) {
  return stanza_schema<groupchat>("message").when<"type">("groupchat");
}
constexpr auto xml_schema(chevron::type<headline>) {
  return stanza_schema<headline>("message").when<"type">("headline");
}
constexpr auto xml_schema(chevron::type<error>) { return stanza_schema<error>("message").when<"type">("error"); }
}  // namespace message

namespace presence {
constexpr auto xml_schema(chevron::type<available>) {
  return stanza_schema<available>("presence").when<"type">("", chevron::or_absent);
}
constexpr auto xml_schema(chevron::type<unavailable>) {
  return stanza_schema<unavailable>("presence").when<"type">("unavailable");
}
constexpr auto xml_schema(chevron::type<subscribe>) {
  return stanza_schema<subscribe>("presence").when<"type">("subscribe");
}
constexpr auto xml_schema(chevron::type<subscribed>) {
  return stanza_schema<subscribed>("presence").when<"type">("subscribed");
}
constexpr auto xml_schema(chevron::type<unsubscribe>) {
  return stanza_schema<unsubscribe>("presence").when<"type">("unsubscribe");
}
constexpr auto xml_schema(chevron::type<unsubscribed>) {
  return stanza_schema<unsubscribed>("presence").when<"type">("unsubscribed");
}
constexpr auto xml_schema(chevron::type<probe>) { return stanza_schema<probe>("presence").when<"type">("probe"); }
constexpr auto xml_schema(chevron::type<error>) { return stanza_schema<error>("presence").when<"type">("error"); }
}  // namespace presence

namespace iq {
constexpr auto xml_schema(chevron::type<get>) { return stanza_schema<get>("iq").when<"type">("get"); }
constexpr auto xml_schema(chevron::type<set>) { return stanza_schema<set>("iq").when<"type">("set"); }
constexpr auto xml_schema(chevron::type<result>) { return stanza_schema<result>("iq").when<"type">("result"); }
constexpr auto xml_schema(chevron::type<error>) { return stanza_schema<error>("iq").when<"type">("error"); }
}  // namespace iq

// A stream error (RFC 6120, 4.9): the server ends the stream, and says why.
struct stream_error {
  std::vector<chevron::any> details;

  // The condition: an element of the stream-errors namespace, by its name.
  std::string_view condition() const {
    for (const chevron::any& one : details)
      if (one.uri == "urn:ietf:params:xml:ns:xmpp-streams" && one.local != "text")
        return one.local;
    return {};
  }
};

constexpr auto xml_schema(chevron::type<stream_error>) {
  using namespace chevron::members;
  return chevron::schema<stream_error>().name(stream_namespace, "error").members(unknown_children());
}

using message_t = std::variant<message::normal, message::chat, message::groupchat, message::headline, message::error>;
using presence_t = std::variant<presence::available, presence::unavailable, presence::subscribe,
                                presence::subscribed, presence::unsubscribe, presence::unsubscribed, presence::probe,
                                presence::error>;
using iq_t = std::variant<iq::get, iq::set, iq::result, iq::error>;
using stanza_t = std::variant<message_t, presence_t, iq_t>;

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
  // A get or a set nobody handles is answered with service-unavailable, as
  // RFC 6120, 8.2.3 requires a reply; with this, it is handed out by
  // receive() and stanzas() instead, and answering it is the caller's.
  bool deliver_unhandled = false;
};

// Thrown by a request handler: the request is answered with this error.
struct refusal {
  std::string condition = "service-unavailable";
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
  std::optional<iq::error> reply;  // or the answer that was not the type asked for, as its payload
};

// The same failures, thrown by the calls that do not hand them back.
struct connect_failure : std::runtime_error {
  explicit connect_failure(connect_error what)
      : std::runtime_error("tern: the stream failed" + (what.detail.empty() ? std::string() : ": " + what.detail)),
        error(std::move(what)) {}
  connect_error error;
};

struct request_failure : std::runtime_error {
  explicit request_failure(request_error what)
      : std::runtime_error(what.code == request_code::connection    ? "tern: the stream failed during a request"
                           : what.code == request_code::error_reply ? "tern: the request was answered with an error"
                                                                    : "tern: the answer was not what was asked for"),
        error(std::move(what)) {}
  request_error error;
};

// A query: a payload that says what kind of request carries it and what the
// answer is read into.
//   struct version_query { using kind = tern::iq::get; using answer = server_version; };
template <class Q>
concept query = chevron::described<Q> && chevron::described<typename Q::answer> &&
                (std::same_as<typename Q::kind, iq::get> || std::same_as<typename Q::kind, iq::set>);

// A typed request: whom to ask, and the query itself.
template <class Query>
struct asking {
  std::optional<std::string> to;
  std::optional<std::string> lang;
  Query query{};
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
  std::expected<std::optional<stanza_t>, connect_error> try_receive() {
    // What arrived while a request waited for its answer, first.
    if (!pending_.empty()) {
      stanza_t one = std::move(pending_.front());
      pending_.pop_front();
      return std::optional<stanza_t>(std::move(one));
    }
    for (;;) {
      if (reading_) {
        if (!yield_)
          return std::unexpected(connect_error{connect_code::xml, "read while a request reads", std::nullopt});
        yield_();
        if (!pending_.empty()) {
          stanza_t one = std::move(pending_.front());
          pending_.pop_front();
          return std::optional<stanza_t>(std::move(one));
        }
        continue;
      }
      auto one = read_locked();
      if (!one || !*one)
        return one;
      if (claimed(**one) || dispatched(**one))
        continue;
      return one;
    }
  }

  // Requests carrying a Query, handled: the query read, the handler's answer
  // sent back as the result -- an Answer with a chevron schema, or nothing
  // for an empty result; a tern::refusal thrown sends the error instead.
  template <chevron::described Query, class Handler>
  void handle(Handler handler) {
    constexpr auto schema = xml_schema(chevron::type<Query>{});
    handlers_[{std::string(schema.uri), std::string(schema.local)}] =
        [handler = std::move(handler)](const chevron::any& payload) -> std::vector<chevron::any> {
          auto query = chevron::from_any<Query>(payload);
          if (!query)
            throw refusal{"bad-request"};
          if constexpr (std::is_void_v<decltype(handler(*query))>) {
            handler(*query);
            return {};
          } else {
            return {chevron::to_any(handler(*query))};
          }
        };
  }

  // A request answered: the result, to whom it came from, with its id.
  template <class Question>
    requires(std::same_as<Question, iq::get> || std::same_as<Question, iq::set>)
  void answer(const Question& question, std::vector<chevron::any> payload = {}) {
    send(iq::result{.to = question.from, .id = question.id, .payload = std::move(payload)});
  }

  template <class Question, chevron::described Payload>
    requires(std::same_as<Question, iq::get> || std::same_as<Question, iq::set>)
  void answer(const Question& question, const Payload& payload) {
    answer(question, std::vector<chevron::any>{chevron::to_any(payload)});
  }

  // A request refused: the error, of type cancel, with a condition of the
  // stanza-errors namespace (RFC 6120, 8.3.3).
  template <class Question>
    requires(std::same_as<Question, iq::get> || std::same_as<Question, iq::set>)
  void refuse(const Question& question, std::string_view condition = "service-unavailable") {
    chevron::any said{std::string(stanza_errors_namespace), std::string(condition), {}, {}};
    send(iq::error{.to = question.from,
                   .id = question.id,
                   .reason = stanza_error{error_types::cancel{}, {std::move(said)}}});
  }

  // A get or a set sent, and its answer awaited: the result, or the error,
  // with the same id, from the address asked (RFC 6120, 8.2.3). Whatever else
  // arrives in the meantime is kept, and handed out by receive() and stanzas()
  // afterwards, in order. An id is made up where the request has none.
  template <class Question>
    requires(std::same_as<Question, iq::get> || std::same_as<Question, iq::set>)
  std::expected<iq::result, request_error> try_request(Question question) {
    if (question.id.empty())
      question.id = "tern-" + std::to_string(++last_id_);
    const std::string id = question.id;
    waiting_[id] = slot{question.to, std::nullopt};
    send(question);
    for (;;) {
      if (auto found = waiting_.find(id); found->second.answer) {
        auto answer = std::move(*found->second.answer);
        waiting_.erase(found);
        if (auto* refused = std::get_if<iq::error>(&answer))
          return std::unexpected(request_error{request_code::error_reply, std::nullopt, std::move(*refused)});
        return std::get<iq::result>(std::move(answer));
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
      if (!claimed(**one) && !dispatched(**one))
        pending_.push_back(std::move(**one));
    }
  }

  // The same, typed: a query that says what kind of request it is and what
  // comes back -- using kind = tern::iq::get; using answer = the type -- asked
  // of whom the request says:
  //   session.request<version_query>({.to = "romeo@example.net/orchard"})
  template <query Query>
  std::expected<typename Query::answer, request_error> try_request(asking<Query> question = {}) {
    typename Query::kind sent{.to = std::move(question.to), .lang = std::move(question.lang),
                              .payload = {chevron::to_any(question.query)}};
    auto answer = try_request(std::move(sent));
    if (!answer)
      return std::unexpected(std::move(answer).error());
    std::optional<typename Query::answer> typed;
    if (!answer->payload.empty()) {
      if (auto read = chevron::from_any<typename Query::answer>(answer->payload.front()))
        typed = std::move(*read);
    }
    if (!typed)
      return std::unexpected(request_error{
          request_code::bad_answer, std::nullopt,
          iq::error{answer->to, answer->from, answer->id, answer->lang, {}, std::move(answer->payload)}});
    return std::move(*typed);
  }

  // The same, throwing: the answer, or a tern::request_failure.
  template <class Question>
    requires(std::same_as<Question, iq::get> || std::same_as<Question, iq::set>)
  iq::result request(Question question) {
    auto answer = try_request(std::move(question));
    if (!answer)
      throw request_failure(std::move(answer).error());
    return std::move(*answer);
  }

  template <query Query>
  typename Query::answer request(asking<Query> question = {}) {
    auto answer = try_request<Query>(std::move(question));
    if (!answer)
      throw request_failure(std::move(answer).error());
    return std::move(*answer);
  }

  // The next stanza, or nothing where the stream has ended cleanly; a failure
  // is thrown, a tern::connect_failure.
  std::optional<stanza_t> receive() {
    auto one = try_receive();
    if (!one)
      throw connect_failure(std::move(one).error());
    return std::move(*one);
  }

  // For connect(): how a waiting request lets others run, and whether
  // requests nobody handles are handed out.
  void yield_with(std::function<void()> yield) { yield_ = std::move(yield); }
  void deliver_unhandled(bool deliver) { deliver_unhandled_ = deliver; }

 private:
  // One reader at a time; a failure is everyone's.
  std::expected<std::optional<stanza_t>, connect_error> read_locked() {
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
  // A get or a set that arrived: to its handler, or refused -- every one gets
  // a reply -- unless requests nobody handles are handed out.
  bool dispatched(stanza_t& one) {
    auto* kind = std::get_if<iq_t>(&one);
    if (!kind)
      return false;
    return std::visit(
        [&](auto& question) {
          using type = std::remove_cvref_t<decltype(question)>;
          if constexpr (std::same_as<type, iq::get> || std::same_as<type, iq::set>) {
            if (!question.payload.empty()) {
              const auto found = handlers_.find({question.payload.front().uri, question.payload.front().local});
              if (found != handlers_.end()) {
                try {
                  answer(question, found->second(question.payload.front()));
                } catch (const refusal& refused) {
                  refuse(question, refused.condition);
                }
                return true;
              }
            }
            if (deliver_unhandled_)
              return false;
            refuse(question, "service-unavailable");
            return true;
          } else {
            return false;
          }
        },
        *kind);
  }

  bool claimed(stanza_t& one) {
    auto* kind = std::get_if<iq_t>(&one);
    if (!kind)
      return false;
    return std::visit(
        [&](auto& answer) {
          using type = std::remove_cvref_t<decltype(answer)>;
          if constexpr (std::same_as<type, iq::result> || std::same_as<type, iq::error>) {
            const auto found = waiting_.find(answer.id);
            if (found == waiting_.end() || found->second.answer)
              return false;
            if (found->second.to && answer.from != found->second.to)
              return false;
            found->second.answer.emplace(std::move(answer));
            return true;
          } else {
            return false;
          }
        },
        *kind);
  }

  std::expected<std::optional<stanza_t>, connect_error> read_stanza() {
    auto one = chevron::read_one_of<message::normal, message::chat, message::groupchat, message::headline,
                                    message::error, presence::available, presence::unavailable, presence::subscribe,
                                    presence::subscribed, presence::unsubscribe, presence::unsubscribed,
                                    presence::probe, presence::error, iq::get, iq::set, iq::result, iq::error,
                                    stream_error>(source_);
    // A stream error ends the stream: its condition is the failure.
    if (one) {
      if (const auto* ended = std::get_if<stream_error>(&*one))
        return std::unexpected(connect_error{connect_code::stream_error, std::string(ended->condition()), std::nullopt});
    }
    if (one)
      return std::visit(
          [](auto&& value) {
            using type = std::remove_cvref_t<decltype(value)>;
            if constexpr (std::same_as<type, stream_error>)
              return std::optional<stanza_t>();
            else if constexpr (requires { message_t(std::move(value)); } && !requires { presence_t(std::move(value)); })
              return std::optional<stanza_t>(stanza_t(message_t(std::move(value))));
            else if constexpr (requires { presence_t(std::move(value)); } && !requires { iq_t(std::move(value)); })
              return std::optional<stanza_t>(stanza_t(presence_t(std::move(value))));
            else
              return std::optional<stanza_t>(stanza_t(iq_t(std::move(value))));
          },
          std::move(*one));
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
  // std::expected<stanza_t, connect_error>. The view ends where the server ends
  // the stream, or just after an error.
  stanza_view stanzas() { return stanza_view(*this); }

  // A stanza, written to the output.
  template <class Stanza>
  void send(const Stanza& one) {
    out_ = chevron::write(std::move(out_), one);
  }

  // Ends the stream.
  // Ends the stream from this side (RFC 6120, 4.4). What the server sends
  // before its own closing tag still arrives: go on reading stanzas() until
  // it ends, and only then close the connection.
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
  std::deque<stanza_t> pending_;
  std::size_t last_id_ = 0;
  // The requests in flight, by id: whom the answer must come from, and the
  // answer once somebody has read it.
  struct slot {
    std::optional<std::string> to;
    std::optional<std::variant<iq::result, iq::error>> answer;
  };
  std::map<std::string, slot> waiting_;
  bool reading_ = false;
  std::optional<connect_error> failed_;
  std::function<void()> yield_;
  bool deliver_unhandled_ = false;
  std::map<std::pair<std::string, std::string>, std::function<std::vector<chevron::any>(const chevron::any&)>>
      handlers_;
};

template <class I, class S, class Out>
class session<I, S, Out>::stanza_view : public std::ranges::view_interface<stanza_view> {
 public:
  class iterator {
   public:
    using value_type = std::expected<stanza_t, connect_error>;
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
    auto next = session_->try_receive();
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
  std::optional<std::expected<stanza_t, connect_error>> current_;
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
    auto read = chevron::read_one_of<iq::result, iq::error>(s_.source());
    if (!read)
      return fail(connect_code::xml, "bind: " + read.error().where);
    if (const auto* refused = std::get_if<iq::error>(&*read))
      return fail(connect_code::bind_refused, std::string(refused->reason.condition()));
    auto* answer = &std::get<iq::result>(*read);
    if (answer->id != "bind_1")
      return fail(connect_code::bind_refused, "not the answer to the bind");
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
try_connect(Input& input, Out output, const options& how) {
  using result = session<std::ranges::iterator_t<Input>, std::ranges::sentinel_t<Input>, Out>;
  result s(std::ranges::begin(input), std::ranges::end(input), std::move(output));
  detail::negotiation<result> steps(s, how);
  if (auto done = steps.run(); !done)
    return std::unexpected(done.error());
  s.bound_to(std::move(steps.jid));
  s.yield_with(how.yield);
  s.deliver_unhandled(how.deliver_unhandled);
  return s;
}

// The same, throwing: the session, or a tern::connect_failure.
template <std::ranges::input_range Input, std::output_iterator<char> Out>
session<std::ranges::iterator_t<Input>, std::ranges::sentinel_t<Input>, Out>
connect(Input& input, Out output, const options& how) {
  auto made = try_connect(input, std::move(output), how);
  if (!made)
    throw connect_failure(std::move(made).error());
  return std::move(*made);
}

}  // namespace tern
