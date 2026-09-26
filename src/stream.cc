// A client's stream: connecting, securing, authenticating and binding a
// resource (RFC 6120), then stanzas in and out (RFC 6121) -- over a transport
// of the caller's, whose abilities (STARTTLS, channel binding) are found at
// compile time, with nothing erased and nothing of its own running.
//
// Stanzas are read straight into their types. What a stanza carries is a
// chevron::tagged of the types the session's protocol<> names, chosen by the
// element's name and read directly; only what the protocol does not name is
// kept as a tree, a chevron::any.
//
// The input is read only as far as the next thing needs, and never ahead:
// at <proceed/> nothing more is asked of it until the transport has put TLS
// underneath.
export module tern.stream;

import std;
import chevron;
import tern.jid;
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
inline constexpr std::string_view roster_namespace = "jabber:iq:roster";

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

// A defined condition (RFC 6120, 8.3.3 for stanzas, 4.9.3 for streams): an
// element of its namespace, by name, read as a type of its own. gone,
// redirect and see-other-host say where, as their text.
template <chevron::fixed_string Namespace, chevron::fixed_string Name>
struct condition {
  std::optional<std::string> value;
};

template <chevron::fixed_string Namespace, chevron::fixed_string Name>
constexpr auto xml_schema(chevron::type<condition<Namespace, Name>>) {
  using namespace chevron::members;
  return chevron::schema<condition<Namespace, Name>>().name(Namespace.view(), Name.view()).members(text());
}

// The <text/> an error may have, in its language.
template <chevron::fixed_string Namespace>
struct error_text {
  std::optional<std::string> lang;
  std::string content;
};

template <chevron::fixed_string Namespace>
constexpr auto xml_schema(chevron::type<error_text<Namespace>>) {
  using namespace chevron::members;
  return chevron::schema<error_text<Namespace>>()
      .name(Namespace.view(), "text")
      .members(attribute("lang", xml_namespace), text());
}

template <chevron::fixed_string Name>
using stanza_condition = condition<"urn:ietf:params:xml:ns:xmpp-stanzas", Name>;
template <chevron::fixed_string Name>
using stream_condition = condition<"urn:ietf:params:xml:ns:xmpp-streams", Name>;

namespace conditions {
using bad_request = stanza_condition<"bad-request">;
using conflict = stanza_condition<"conflict">;
using feature_not_implemented = stanza_condition<"feature-not-implemented">;
using forbidden = stanza_condition<"forbidden">;
using gone = stanza_condition<"gone">;
using internal_server_error = stanza_condition<"internal-server-error">;
using item_not_found = stanza_condition<"item-not-found">;
using jid_malformed = stanza_condition<"jid-malformed">;
using not_acceptable = stanza_condition<"not-acceptable">;
using not_allowed = stanza_condition<"not-allowed">;
using not_authorized = stanza_condition<"not-authorized">;
using policy_violation = stanza_condition<"policy-violation">;
using recipient_unavailable = stanza_condition<"recipient-unavailable">;
using redirect = stanza_condition<"redirect">;
using registration_required = stanza_condition<"registration-required">;
using remote_server_not_found = stanza_condition<"remote-server-not-found">;
using remote_server_timeout = stanza_condition<"remote-server-timeout">;
using resource_constraint = stanza_condition<"resource-constraint">;
using service_unavailable = stanza_condition<"service-unavailable">;
using subscription_required = stanza_condition<"subscription-required">;
using undefined_condition = stanza_condition<"undefined-condition">;
using unexpected_request = stanza_condition<"unexpected-request">;
}  // namespace conditions

namespace stream_conditions {
using bad_format = stream_condition<"bad-format">;
using bad_namespace_prefix = stream_condition<"bad-namespace-prefix">;
using conflict = stream_condition<"conflict">;
using connection_timeout = stream_condition<"connection-timeout">;
using host_gone = stream_condition<"host-gone">;
using host_unknown = stream_condition<"host-unknown">;
using improper_addressing = stream_condition<"improper-addressing">;
using internal_server_error = stream_condition<"internal-server-error">;
using invalid_from = stream_condition<"invalid-from">;
using invalid_namespace = stream_condition<"invalid-namespace">;
using invalid_xml = stream_condition<"invalid-xml">;
using not_authorized = stream_condition<"not-authorized">;
using not_well_formed = stream_condition<"not-well-formed">;
using policy_violation = stream_condition<"policy-violation">;
using remote_connection_failed = stream_condition<"remote-connection-failed">;
using reset = stream_condition<"reset">;
using resource_constraint = stream_condition<"resource-constraint">;
using restricted_xml = stream_condition<"restricted-xml">;
using see_other_host = stream_condition<"see-other-host">;
using system_shutdown = stream_condition<"system-shutdown">;
using undefined_condition = stream_condition<"undefined-condition">;
using unsupported_encoding = stream_condition<"unsupported-encoding">;
using unsupported_feature = stream_condition<"unsupported-feature">;
using unsupported_stanza_type = stream_condition<"unsupported-stanza-type">;
using unsupported_version = stream_condition<"unsupported-version">;
}  // namespace stream_conditions

using stanza_condition_t = chevron::tagged<
    conditions::bad_request, conditions::conflict, conditions::feature_not_implemented, conditions::forbidden,
    conditions::gone, conditions::internal_server_error, conditions::item_not_found, conditions::jid_malformed,
    conditions::not_acceptable, conditions::not_allowed, conditions::not_authorized, conditions::policy_violation,
    conditions::recipient_unavailable, conditions::redirect, conditions::registration_required,
    conditions::remote_server_not_found, conditions::remote_server_timeout, conditions::resource_constraint,
    conditions::service_unavailable, conditions::subscription_required, conditions::undefined_condition,
    conditions::unexpected_request>;

using stream_condition_t = chevron::tagged<
    stream_conditions::bad_format, stream_conditions::bad_namespace_prefix, stream_conditions::conflict,
    stream_conditions::connection_timeout, stream_conditions::host_gone, stream_conditions::host_unknown,
    stream_conditions::improper_addressing, stream_conditions::internal_server_error,
    stream_conditions::invalid_from, stream_conditions::invalid_namespace, stream_conditions::invalid_xml,
    stream_conditions::not_authorized, stream_conditions::not_well_formed, stream_conditions::policy_violation,
    stream_conditions::remote_connection_failed, stream_conditions::reset, stream_conditions::resource_constraint,
    stream_conditions::restricted_xml, stream_conditions::see_other_host, stream_conditions::system_shutdown,
    stream_conditions::undefined_condition, stream_conditions::unsupported_encoding,
    stream_conditions::unsupported_feature, stream_conditions::unsupported_stanza_type,
    stream_conditions::unsupported_version>;

// The name of the condition a tagged holds.
template <class Tagged>
constexpr std::string_view condition_name(const Tagged& held) {
  return std::visit([]<class C>(const C&) { return std::string_view(xml_schema(chevron::type<C>{}).local); },
                    held.data());
}

// The condition of that name, where one of Tagged's has it.
template <class Tagged>
constexpr std::optional<Tagged> condition_named(std::string_view name) {
  std::optional<Tagged> out;
  [&]<class... C>(std::type_identity<chevron::tagged<C...>>) {
    ((void)(!out && std::string_view(xml_schema(chevron::type<C>{}).local) == name && (out.emplace(C{}), true)), ...);
  }(std::type_identity<Tagged>{});
  return out;
}

struct stanza_error {
  std::optional<std::variant<error_types::cancel, error_types::continue_, error_types::modify,
                             error_types::auth, error_types::wait>> type;
  std::optional<std::string> by;
  std::optional<stanza_condition_t> what;  // the defined condition
  std::optional<error_text<"urn:ietf:params:xml:ns:xmpp-stanzas">> text;
  std::vector<chevron::any> application;  // an application-specific condition, of the application's

  std::string_view condition() const { return what ? condition_name(*what) : std::string_view(); }
};

constexpr auto xml_schema(chevron::type<stanza_error>) {
  using namespace chevron::members;
  return chevron::schema<stanza_error>()
      .name(client_namespace, "error")
      .members(attribute(), attribute(), _, _, unknown_children());
}

// A stream error (RFC 6120, 4.9): the server ends the stream, and says why.
struct stream_error {
  std::optional<stream_condition_t> what;
  std::optional<error_text<"urn:ietf:params:xml:ns:xmpp-streams">> text;
  std::vector<chevron::any> application;

  std::string_view condition() const { return what ? condition_name(*what) : std::string_view(); }

  // For see-other-host (4.9.3.19): the host, and port, to connect to instead.
  std::optional<std::string> other_host() const {
    if (what)
      if (const auto* other = what->get_if<stream_conditions::see_other_host>())
        return other->value.value_or("");
    return std::nullopt;
  }
};

constexpr auto xml_schema(chevron::type<stream_error>) {
  using namespace chevron::members;
  return chevron::schema<stream_error>().name(stream_namespace, "error").members(_, _, unknown_children());
}

// A conversation a message belongs to (RFC 6121, 5.2.5): its identifier,
// and the thread it was spun off from.
struct thread {
  std::string id;
  std::optional<std::string> parent;
};

constexpr auto xml_schema(chevron::type<thread>) {
  using namespace chevron::members;
  return chevron::schema<thread>().name(client_namespace, "thread").members(text(), attribute());
}

// The roster (RFC 6121, 2): the contacts, as the server keeps them.
namespace subscription {
struct none { static constexpr std::string_view xml_value = "none"; };
struct to { static constexpr std::string_view xml_value = "to"; };
struct from { static constexpr std::string_view xml_value = "from"; };
struct both { static constexpr std::string_view xml_value = "both"; };
struct remove { static constexpr std::string_view xml_value = "remove"; };
}  // namespace subscription

struct subscribe_pending { static constexpr std::string_view xml_value = "subscribe"; };

struct roster_item {
  std::string jid;
  std::optional<std::string> name;
  std::optional<std::variant<tern::subscription::none, tern::subscription::to, tern::subscription::from,
                             tern::subscription::both, tern::subscription::remove>> subscription;
  std::optional<std::variant<subscribe_pending>> ask;
  std::vector<std::string> group;
};

constexpr auto xml_schema(chevron::type<roster_item>) {
  using namespace chevron::members;
  return chevron::schema<roster_item>()
      .name(roster_namespace, "item")
      .members(attribute(), attribute(), attribute(), attribute(), child_text());
}

// The roster as a result, or as a push (2.1.6).
struct roster {
  std::optional<std::string> ver;
  std::vector<roster_item> items;
};

constexpr auto xml_schema(chevron::type<roster>) {
  using namespace chevron::members;
  return chevron::schema<roster>().name(roster_namespace, "query").members(attribute(), child("item"));
}

// An entity's software (XEP-0092), as it answers; each part may be missing,
// so that an answer short of one is still read.
struct version {
  std::optional<std::string> name;
  std::optional<std::string> version;
  std::optional<std::string> os;
};

constexpr auto xml_schema(chevron::type<version>) {
  return chevron::schema<version>().name("jabber:iq:version", "query");
}

// What kind of request a query goes in: using kind = tern::get; or tern::set.
struct get {};
struct set {};

// The queries: each says its kind and what its answer is read into -- a type
// of the protocol's answers<>, or void for an empty result.
namespace query {

// The roster asked for (RFC 6121, 2.1.3), from the version given where there
// is one (2.6).
struct roster {
  using kind = tern::get;
  using answer = tern::roster;
  std::optional<std::string> ver;
};

constexpr auto xml_schema(chevron::type<roster>) {
  using namespace chevron::members;
  return chevron::schema<roster>().name(roster_namespace, "query").members(attribute());
}

// XEP-0092: an entity's software.
struct version {
  using kind = tern::get;
  using answer = tern::version;
};

constexpr auto xml_schema(chevron::type<version>) {
  return chevron::schema<version>().name("jabber:iq:version", "query");
}

// XEP-0199: a ping, answered by an empty result.
struct ping {
  using kind = tern::get;
  using answer = void;
};

constexpr auto xml_schema(chevron::type<ping>) { return chevron::schema<ping>().name("urn:xmpp:ping", "ping"); }

}  // namespace query

// The stanzas, a type for each kind, over what they carry: X, a
// chevron::tagged of the types a protocol names. Each is read straight into
// its type; what is not named is kept, as a chevron::any.
namespace basic {

template <class X>
struct message_normal {
  std::optional<std::string> to, from, id, lang, subject, body;
  std::optional<tern::thread> thread;
  std::vector<X> payload;
};
template <class X>
struct message_chat {
  std::optional<std::string> to, from, id, lang, subject, body;
  std::optional<tern::thread> thread;
  std::vector<X> payload;
};
template <class X>
struct message_groupchat {
  std::optional<std::string> to, from, id, lang, subject, body;
  std::optional<tern::thread> thread;
  std::vector<X> payload;
};
template <class X>
struct message_headline {
  std::optional<std::string> to, from, id, lang, subject, body;
  std::optional<tern::thread> thread;
  std::vector<X> payload;
};
template <class X>
struct message_error {
  std::optional<std::string> to, from, id, lang, subject, body;
  std::optional<tern::thread> thread;
  stanza_error reason;  // the <error/>
  std::vector<X> payload;
};

template <class X>
struct presence_available {
  std::optional<std::string> to, from, id, lang, show, status;
  std::optional<int> priority;
  std::vector<X> payload;
};
template <class X>
struct presence_unavailable {
  std::optional<std::string> to, from, id, lang, status;
  std::vector<X> payload;
};
template <class X>
struct presence_subscribe {
  std::optional<std::string> to, from, id, lang;
  std::vector<X> payload;
};
template <class X>
struct presence_subscribed {
  std::optional<std::string> to, from, id, lang;
  std::vector<X> payload;
};
template <class X>
struct presence_unsubscribe {
  std::optional<std::string> to, from, id, lang;
  std::vector<X> payload;
};
template <class X>
struct presence_unsubscribed {
  std::optional<std::string> to, from, id, lang;
  std::vector<X> payload;
};
template <class X>
struct presence_probe {
  std::optional<std::string> to, from, id, lang;
  std::vector<X> payload;
};
template <class X>
struct presence_error {
  std::optional<std::string> to, from, id, lang;
  stanza_error reason;
  std::vector<X> payload;
};

template <class X>
struct iq_get {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  std::vector<X> payload;
};
template <class X>
struct iq_set {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  std::vector<X> payload;
};
template <class X>
struct iq_result {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  std::vector<X> payload;
};
template <class X>
struct iq_error {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  stanza_error reason;
  std::vector<X> payload;
};

}  // namespace basic

// The schema every stanza shares: its element, the four attributes, the
// <error/> where the kind has one; what it carries is its payload, a tagged.
template <class T>
constexpr auto stanza_schema(std::string_view element) {
  using namespace chevron::members;
  auto made = chevron::schema<T>()
                  .name(client_namespace, element)
                  .template member<"to">(attribute())
                  .template member<"from">(attribute())
                  .template member<"id">(attribute())
                  .template member<"lang">(attribute("lang", xml_namespace));
  if constexpr (requires(T one) { one.reason; })
    return made.template member<"reason">(child("error"));
  else
    return made;
}

namespace basic {

template <class X>
constexpr auto xml_schema(chevron::type<message_normal<X>>) {
  return stanza_schema<message_normal<X>>("message").template when<"type">("normal", chevron::or_absent);
}
template <class X>
constexpr auto xml_schema(chevron::type<message_chat<X>>) {
  return stanza_schema<message_chat<X>>("message").template when<"type">("chat");
}
template <class X>
constexpr auto xml_schema(chevron::type<message_groupchat<X>>) {
  return stanza_schema<message_groupchat<X>>("message").template when<"type">("groupchat");
}
template <class X>
constexpr auto xml_schema(chevron::type<message_headline<X>>) {
  return stanza_schema<message_headline<X>>("message").template when<"type">("headline");
}
template <class X>
constexpr auto xml_schema(chevron::type<message_error<X>>) {
  return stanza_schema<message_error<X>>("message").template when<"type">("error");
}

template <class X>
constexpr auto xml_schema(chevron::type<presence_available<X>>) {
  return stanza_schema<presence_available<X>>("presence").template when<"type">("", chevron::or_absent);
}
template <class X>
constexpr auto xml_schema(chevron::type<presence_unavailable<X>>) {
  return stanza_schema<presence_unavailable<X>>("presence").template when<"type">("unavailable");
}
template <class X>
constexpr auto xml_schema(chevron::type<presence_subscribe<X>>) {
  return stanza_schema<presence_subscribe<X>>("presence").template when<"type">("subscribe");
}
template <class X>
constexpr auto xml_schema(chevron::type<presence_subscribed<X>>) {
  return stanza_schema<presence_subscribed<X>>("presence").template when<"type">("subscribed");
}
template <class X>
constexpr auto xml_schema(chevron::type<presence_unsubscribe<X>>) {
  return stanza_schema<presence_unsubscribe<X>>("presence").template when<"type">("unsubscribe");
}
template <class X>
constexpr auto xml_schema(chevron::type<presence_unsubscribed<X>>) {
  return stanza_schema<presence_unsubscribed<X>>("presence").template when<"type">("unsubscribed");
}
template <class X>
constexpr auto xml_schema(chevron::type<presence_probe<X>>) {
  return stanza_schema<presence_probe<X>>("presence").template when<"type">("probe");
}
template <class X>
constexpr auto xml_schema(chevron::type<presence_error<X>>) {
  return stanza_schema<presence_error<X>>("presence").template when<"type">("error");
}

template <class X>
constexpr auto xml_schema(chevron::type<iq_get<X>>) {
  return stanza_schema<iq_get<X>>("iq").template when<"type">("get");
}
template <class X>
constexpr auto xml_schema(chevron::type<iq_set<X>>) {
  return stanza_schema<iq_set<X>>("iq").template when<"type">("set");
}
template <class X>
constexpr auto xml_schema(chevron::type<iq_result<X>>) {
  return stanza_schema<iq_result<X>>("iq").template when<"type">("result");
}
template <class X>
constexpr auto xml_schema(chevron::type<iq_error<X>>) {
  return stanza_schema<iq_error<X>>("iq").template when<"type">("error");
}

}  // namespace basic

// A protocol: the types a session reads what it receives into. queries<> for
// what gets and sets carry, answers<> for what results carry, extensions<>
// for what messages and presence carry.
template <class... T>
struct queries {};
template <class... T>
struct answers {};
template <class... T>
struct extensions {};

template <class Queries = queries<>, class Answers = answers<>, class Extensions = extensions<>>
struct protocol;

template <class... Q, class... A, class... E>
struct protocol<queries<Q...>, answers<A...>, extensions<E...>> {
  using query_payload = chevron::tagged<Q..., chevron::any>;
  using answer_payload = chevron::tagged<A..., chevron::any>;
  using extension = chevron::tagged<E..., chevron::any>;
  using error_payload = chevron::tagged<chevron::any>;

  struct message {
    using normal = basic::message_normal<extension>;
    using chat = basic::message_chat<extension>;
    using groupchat = basic::message_groupchat<extension>;
    using headline = basic::message_headline<extension>;
    using error = basic::message_error<extension>;
  };
  struct presence {
    using available = basic::presence_available<extension>;
    using unavailable = basic::presence_unavailable<extension>;
    using subscribe = basic::presence_subscribe<extension>;
    using subscribed = basic::presence_subscribed<extension>;
    using unsubscribe = basic::presence_unsubscribe<extension>;
    using unsubscribed = basic::presence_unsubscribed<extension>;
    using probe = basic::presence_probe<extension>;
    using error = basic::presence_error<extension>;
  };
  struct iq {
    using get = basic::iq_get<query_payload>;
    using set = basic::iq_set<query_payload>;
    using result = basic::iq_result<answer_payload>;
    using error = basic::iq_error<error_payload>;
  };

  using message_t = std::variant<typename message::normal, typename message::chat, typename message::groupchat,
                                 typename message::headline, typename message::error>;
  using presence_t =
      std::variant<typename presence::available, typename presence::unavailable, typename presence::subscribe,
                   typename presence::subscribed, typename presence::unsubscribe, typename presence::unsubscribed,
                   typename presence::probe, typename presence::error>;
  using iq_t = std::variant<typename iq::get, typename iq::set, typename iq::result, typename iq::error>;
  using stanza_t = std::variant<message_t, presence_t, iq_t>;

  template <class T>
  static constexpr bool answers_with = (std::same_as<T, A> || ...);

  // One stanza, or the stream's error, read as the type its name says.
  template <class Source>
  static auto read_one(Source& source) {
    return chevron::read_one_of<typename message::normal, typename message::chat, typename message::groupchat,
                                typename message::headline, typename message::error, typename presence::available,
                                typename presence::unavailable, typename presence::subscribe,
                                typename presence::subscribed, typename presence::unsubscribe,
                                typename presence::unsubscribed, typename presence::probe,
                                typename presence::error, typename iq::get, typename iq::set, typename iq::result,
                                typename iq::error, stream_error>(source);
  }
};

// What RFC 6120 and 6121 need, and the version and ping every client is
// asked: roster pushes, version and ping as queries; the roster and versions
// as answers.
using standard = protocol<queries<roster, query::version, query::ping>, answers<roster, version>, extensions<>>;

// The standard protocol's stanzas, by their plain names.
namespace message {
using normal = standard::message::normal;
using chat = standard::message::chat;
using groupchat = standard::message::groupchat;
using headline = standard::message::headline;
using error = standard::message::error;
}  // namespace message

namespace presence {
using available = standard::presence::available;
using unavailable = standard::presence::unavailable;
using subscribe = standard::presence::subscribe;
using subscribed = standard::presence::subscribed;
using unsubscribe = standard::presence::unsubscribe;
using unsubscribed = standard::presence::unsubscribed;
using probe = standard::presence::probe;
using error = standard::presence::error;
}  // namespace presence

namespace iq {
using get = standard::iq::get;
using set = standard::iq::set;
using result = standard::iq::result;
using error = standard::iq::error;
}  // namespace iq

using message_t = standard::message_t;
using presence_t = standard::presence_t;
using iq_t = standard::iq_t;
using stanza_t = standard::stanza_t;

// A roster kept between sessions (RFC 6121, 2.6): what the caller stores --
// the version it is at, and the items by JID -- and gives back to sync().
struct roster_cache {
  std::optional<std::string> ver;
  std::flat_map<std::string, roster_item> items;

  // A whole roster: what was kept is replaced.
  void replace(roster whole) {
    items.clear();
    for (roster_item& one : whole.items) {
      std::string key = one.jid;
      items.insert_or_assign(std::move(key), std::move(one));
    }
    ver = std::move(whole.ver);
  }

  // A push (2.1.6, 2.6.3): each item added or changed, or with subscription
  // remove dropped; and the version it brings.
  void apply(roster push) {
    for (roster_item& one : push.items) {
      if (one.subscription && std::holds_alternative<tern::subscription::remove>(*one.subscription)) {
        items.erase(one.jid);
      } else {
        std::string key = one.jid;
        items.insert_or_assign(std::move(key), std::move(one));
      }
    }
    if (push.ver)
      ver = std::move(push.ver);
  }

  // The same, from the stanza: false where it is not a roster push.
  template <class X>
  bool apply(const basic::iq_set<X>& push) {
    if constexpr (X::template can_hold<roster>) {
      if (!push.payload.empty())
        if (const roster* got = push.payload.front().template get_if<roster>()) {
          apply(*got);
          return true;
        }
    }
    return false;
  }
};

}  // namespace tern

namespace tern::detail {

// What negotiation reads: the stream's features, each a type -- what no
// member names is passed over -- and the answers to it.
struct tls_required {};
struct starttls_feature {
  std::optional<tls_required> mandatory;

  bool required() const { return mandatory.has_value(); }
};
struct mechanisms_feature {
  std::vector<std::string> mechanism;
};
struct bind_feature {};
struct rosterver_feature {};
struct features {
  std::optional<starttls_feature> starttls;
  std::optional<mechanisms_feature> mechanisms;
  std::optional<bind_feature> bind;
  std::optional<rosterver_feature> ver;
};

constexpr auto xml_schema(chevron::type<tls_required>) {
  return chevron::schema<tls_required>().name(tls_namespace, "required");
}
constexpr auto xml_schema(chevron::type<starttls_feature>) {
  return chevron::schema<starttls_feature>().name(tls_namespace, "starttls");
}
constexpr auto xml_schema(chevron::type<mechanisms_feature>) {
  return chevron::schema<mechanisms_feature>().name(sasl_namespace, "mechanisms");
}
constexpr auto xml_schema(chevron::type<bind_feature>) {
  return chevron::schema<bind_feature>().name(bind_namespace, "bind");
}
constexpr auto xml_schema(chevron::type<rosterver_feature>) {
  return chevron::schema<rosterver_feature>().name("urn:xmpp:features:rosterver", "ver");
}
constexpr auto xml_schema(chevron::type<features>) {
  return chevron::schema<features>().name(stream_namespace, "features");
}

// The answer to binding: the full JID.
struct bind_result {
  std::optional<std::string> jid;
};
constexpr auto xml_schema(chevron::type<bind_result>) {
  return chevron::schema<bind_result>().name(bind_namespace, "bind");
}

// <proceed/>, <failure/>, <challenge>, <success> and the rest: an element's
// name and its text, which is all negotiation needs of them.
struct nonza {
  std::string uri, local, text;
  std::string first_child;  // the name of its first child element: a failure's condition
};

template <class T> struct is_iq_get : std::false_type {};
template <class X> struct is_iq_get<basic::iq_get<X>> : std::true_type {};
template <class T> struct is_iq_set : std::false_type {};
template <class X> struct is_iq_set<basic::iq_set<X>> : std::true_type {};

}  // namespace tern::detail

export namespace tern {

enum class connect_code : std::uint8_t {
  xml,               // the stream was not well-formed, or not what was asked
  closed,            // the input ended
  stream_error,      // the server ended the stream with an error
  tls_required,      // the server wants TLS and the transport cannot start it
  tls_refused,       // the server refused STARTTLS
  no_mechanism,      // nothing both sides can authenticate with
  not_authorized,    // the server refused the credentials
  authentication,    // SCRAM went wrong: see sasl
  bind_refused,      // the server refused the resource
  tls_failed,        // the transport could not start TLS
};

struct connect_error {
  connect_code code;
  std::string detail;
  std::optional<sasl::failure> sasl;
  // With the stream error see-other-host (RFC 6120, 4.9.3.19): where the
  // server sends the client instead -- a host, an IPv4 address or an IPv6
  // one in brackets, and perhaps a port. The caller reconnects there.
  std::optional<std::string> other_host{};
  // Where the server refused binding (RFC 6120, 7.6.2.2): its <error/> --
  // the condition (conflict, not-allowed, resource-constraint), the type and
  // any text -- whole.
  std::optional<stanza_error> stanza{};
};

// What the TLS layer gives for channel binding: the type and its data.
struct channel_binding {
  std::string type;  // "tls-exporter", "tls-server-end-point"
  crypto::bytes data;
};

// A transport: bytes in, as an input range -- of bytes, or of chunks, each a
// range of bytes as one read brought them -- and bytes out, written and then
// flushed where a unit ends. input() is a reference to a range the transport
// keeps; after start_tls() it is taken again.
template <class T>
concept transport = requires(T& t, std::string_view bytes) {
  requires std::is_lvalue_reference_v<decltype(t.input())>;
  requires std::ranges::input_range<std::remove_reference_t<decltype(t.input())>>;
  t.write(bytes);
  t.flush();
};

// One that can start TLS at <proceed/> (RFC 6120, 5.4.3.3): true where the
// handshake succeeded, the server's name given for checking its certificate.
template <class T>
concept tls_transport = transport<T> && requires(T& t, std::string_view host) {
  { t.start_tls(host) } -> std::convertible_to<bool>;
};

// One that can say it is secured -- by TLS started, or from the start, as
// with direct TLS (XEP-0368) -- and so allow PLAIN and channel binding.
template <class T>
concept secured_transport = transport<T> && requires(const T& t) {
  { t.secured() } -> std::convertible_to<bool>;
};

// One whose TLS gives channel-binding data (RFC 9266, tls-exporter; or
// tls-server-end-point): with it SCRAM-SHA-256-PLUS or SCRAM-SHA-1-PLUS is
// used where offered, and the absence of an offer is said to the server.
template <class T>
concept binding_transport = transport<T> && requires(T& t) {
  { t.channel_binding() } -> std::same_as<std::optional<channel_binding>>;
};

// A range read and an output iterator written: a transport without TLS.
template <std::ranges::input_range Input, std::output_iterator<char> Out>
class range_transport {
 public:
  range_transport(Input& input, Out output) : input_(&input), output_(std::move(output)) {}
  Input& input() { return *input_; }
  void write(std::string_view bytes) { output_ = std::ranges::copy(bytes, std::move(output_)).out; }
  void flush() {}

 private:
  Input* input_;
  Out output_;
};

struct options {
  std::string username;  // the localpart, prepared
  std::string domain;
  std::string password;
  std::optional<std::string> resource;
  // PLAIN sends the password itself: only over TLS, unless this says so.
  bool plain_without_tls = false;
  std::uint32_t minimum_iterations = 4096;
  std::string nonce = {};  // for SCRAM; random where empty
  // A get or a set nobody handles is answered with service-unavailable, as
  // RFC 6120, 8.2.3 requires a reply; with this, it is handed out by
  // receive() and stanzas() instead, and answering it is the caller's.
  bool deliver_unhandled = false;
};

// The handlers of incoming queries, given at connect(): each a callable
// taking a query type of the protocol's queries<>, and returning its answer
// -- a type with a chevron schema, or void for an empty result. The first
// that takes the query is called; one that throws tern::refusal sends the
// error instead.
//   tern::answering{[](const tern::query::version&) { return tern::version{"tern", "0.1"}; },
//                   [](const tern::query::ping&) {}}
template <class... Handlers>
class answering {
 public:
  constexpr answering(Handlers... handlers) : handlers(std::move(handlers)...) {}
  std::tuple<Handlers...> handlers;
};
template <class... Handlers>
answering(Handlers...) -> answering<Handlers...>;

// Thrown by a handler: the request is answered with this error.
struct refusal {
  std::string condition = "service-unavailable";
};

// How a request waits while another one reads the stream: suspend and let
// the others run -- a coroutine's yield, or a wait on a condition with
// threads. no_yield: only one request in flight at a time.
struct no_yield {
  void operator()() const noexcept {}
};

}  // namespace tern

namespace tern::detail {

// A transport's input read for chevron: bytes fed to a parser only as far as
// the next event needs -- up to a '>' or a '<', where an event can end -- and
// never further. Or a range of chunks, each fed whole.
template <class R>
class source {
  using iterator = std::ranges::iterator_t<R>;
  using sentinel = std::ranges::sentinel_t<R>;
  static constexpr bool chunks = std::ranges::input_range<std::iter_reference_t<iterator>>;

 public:
  // The input, from where it is now: at the start, and again after TLS.
  void start(R& range) {
    at_.reset();
    end_.reset();
    at_.emplace(std::ranges::begin(range));
    end_.emplace(std::ranges::end(range));
    parser_ = chevron::parser();
    finished_ = false;
  }

  std::expected<std::optional<chevron::event>, chevron::error> next() {
    for (;;) {
      auto one = parser_.next();
      if (!one || *one)
        return one;
      if (finished_)
        return one;
      if constexpr (chunks) {
        // A chunk -- what a read of a socket brought -- fed whole.
        if (*at_ == *end_) {
          parser_.finish();
          finished_ = true;
        } else {
          parser_.feed(**at_);
          ++*at_;
        }
      } else {
        // The end is asked about only where a byte is needed: over a socket,
        // asking is waiting for the peer, and after the '>' that ends a
        // stanza there may be nothing more for a long while.
        std::string piece;
        bool ended = false;
        for (;;) {
          if (*at_ == *end_) {
            ended = true;
            break;
          }
          const char unit = static_cast<char>(**at_);
          ++*at_;
          piece.push_back(unit);
          if (unit == '>' || unit == '<')
            break;
        }
        parser_.feed(piece);
        if (ended && piece.empty()) {
          parser_.finish();
          finished_ = true;
        }
      }
    }
  }

  // A new stream after authentication: a new document, from here on. What
  // came after the old document in the same chunk belongs to the new.
  void restart() {
    const std::string rest(parser_.unread());
    parser_ = chevron::parser();
    parser_.feed(rest);
    finished_ = false;
  }

 private:
  std::optional<iterator> at_;
  std::optional<sentinel> end_;
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
// answered with an error, its <error/> in reply; or the answer was not the
// type asked for.
enum class request_code { connection, error_reply, bad_answer };

struct request_error {
  request_code code;
  std::optional<connect_error> connection;
  std::optional<stanza_error> reply;
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

// A query: a payload that says what kind of request carries it -- tern::get
// or tern::set -- and what its answer is read into, or void.
template <class K>
inline constexpr bool is_get_kind = std::same_as<K, get> || detail::is_iq_get<K>::value;
template <class K>
inline constexpr bool is_set_kind = std::same_as<K, set> || detail::is_iq_set<K>::value;

template <class Q>
concept is_query = chevron::described<Q> && (is_get_kind<typename Q::kind> || is_set_kind<typename Q::kind>) &&
                   (std::is_void_v<typename Q::answer> || chevron::described<typename Q::answer>);

// A typed request: whom to ask, and the query itself.
template <class Query>
struct asking {
  std::optional<std::string> to;
  std::optional<std::string> lang;
  Query query{};
};

// A get or a set, of any protocol.
template <class Q>
concept iq_request = detail::is_iq_get<Q>::value || detail::is_iq_set<Q>::value;

// A stream that is authenticated and bound: stanzas in, stanzas out. T is the
// transport, or a reference to the caller's; P the protocol; Handlers the
// answering<> of incoming queries; Yield how a request waits.
template <class T, class P = standard, class Handlers = answering<>, class Yield = no_yield>
class session {
 public:
  using protocol_type = P;
  using transport_type = std::remove_reference_t<T>;
  using message_t = typename P::message_t;
  using presence_t = typename P::presence_t;
  using iq_t = typename P::iq_t;
  using stanza_t = typename P::stanza_t;
  using result = typename P::iq::result;
  using error = typename P::iq::error;

  session(T transport, Handlers handlers, Yield yield)
      : transport_(static_cast<T&&>(transport)), handlers_(std::move(handlers)), yield_(std::move(yield)) {
    source_.start(transport_.input());
  }

  // The full JID the server bound.
  const std::string& jid() const noexcept { return jid_; }

  // Whether the server said it versions rosters (RFC 6121, 2.6.1).
  bool roster_versioning() const noexcept { return roster_versioning_; }

  // The next stanza, as it arrives; nothing where the stream has ended
  // cleanly; or the error.
  std::expected<std::optional<stanza_t>, connect_error> try_receive() {
    // What arrived while a request waited for its answer, first.
    if (!pending_.empty())
      return take_pending();
    for (;;) {
      if (reading_) {
        if constexpr (can_yield) {
          yield_();
          if (!pending_.empty())
            return take_pending();
          continue;
        } else {
          return std::unexpected(connect_error{connect_code::xml, "read while a request reads", std::nullopt});
        }
      }
      auto one = read_locked();
      if (!one || !*one)
        return one;
      if (claimed(**one) || dispatched(**one))
        continue;
      return one;
    }
  }

  // The next stanza, or nothing where the stream has ended cleanly; a failure
  // is thrown, a tern::connect_failure.
  std::optional<stanza_t> receive() {
    auto one = try_receive();
    if (!one)
      throw connect_failure(std::move(one).error());
    return std::move(*one);
  }

  // A get or a set sent, and its answer awaited: the result, or the error,
  // with the same id, from the address asked (RFC 6120, 8.2.3). Whatever else
  // arrives in the meantime is kept, and handed out by receive() and stanzas()
  // afterwards, in order. An id is made up where the request has none.
  template <iq_request Question>
  std::expected<result, request_error> try_request(Question question) {
    if (question.id.empty())
      question.id = "tern-" + std::to_string(++last_id_);
    const std::string id = question.id;
    waiting_[id] = slot{question.to, std::nullopt};
    send(question);
    for (;;) {
      if (auto found = waiting_.find(id); found->second.answer) {
        auto answer = std::move(*found->second.answer);
        waiting_.erase(found);
        if (auto* refused = std::get_if<error>(&answer))
          return std::unexpected(request_error{request_code::error_reply, std::nullopt, std::move(refused->reason)});
        return std::get<result>(std::move(answer));
      }
      if (failed_) {
        waiting_.erase(id);
        return std::unexpected(request_error{request_code::connection, *failed_, std::nullopt});
      }
      // Another request is reading: its reading may bring this answer too.
      if (reading_) {
        if constexpr (can_yield) {
          yield_();
          continue;
        } else {
          waiting_.erase(id);
          return std::unexpected(request_error{
              request_code::connection,
              connect_error{connect_code::xml, "a second request in flight, and no yield", std::nullopt},
              std::nullopt});
        }
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
  // comes back, asked of whom the request says:
  //   session.request<tern::query::version>({.to = "romeo@example.net/orchard"})
  // The answer is read straight into its type -- one of the protocol's
  // answers<> -- as the result arrives; void for an empty result.
  template <is_query Query>
  std::expected<typename Query::answer, request_error> try_request(asking<Query> question = {}) {
    using carried = chevron::tagged<Query>;
    using sent_type =
        std::conditional_t<is_get_kind<typename Query::kind>, basic::iq_get<carried>, basic::iq_set<carried>>;
    sent_type sent{.to = std::move(question.to), .lang = std::move(question.lang)};
    sent.payload.emplace_back(std::move(question.query));
    auto answer = try_request(std::move(sent));
    if (!answer)
      return std::unexpected(std::move(answer).error());
    if constexpr (std::is_void_v<typename Query::answer>) {
      return {};
    } else {
      static_assert(P::template answers_with<typename Query::answer>,
                    "tern: the query's answer type is not among the protocol's answers<>");
      if (!answer->payload.empty())
        if (auto* typed = answer->payload.front().template get_if<typename Query::answer>())
          return std::move(*typed);
      return std::unexpected(request_error{request_code::bad_answer, std::nullopt, std::nullopt});
    }
  }

  // The same, throwing: the answer, or a tern::request_failure.
  template <iq_request Question>
  result request(Question question) {
    auto answer = try_request(std::move(question));
    if (!answer)
      throw request_failure(std::move(answer).error());
    return std::move(*answer);
  }

  template <is_query Query>
  typename Query::answer request(asking<Query> question = {}) {
    auto answer = try_request<Query>(std::move(question));
    if (!answer)
      throw request_failure(std::move(answer).error());
    if constexpr (!std::is_void_v<typename Query::answer>)
      return std::move(*answer);
  }

  // A request answered: an empty result, or one carrying the answer given.
  template <iq_request Question>
  void answer(const Question& question) {
    send(basic::iq_result<chevron::tagged<chevron::any>>{.to = question.from, .id = question.id});
  }

  template <iq_request Question, chevron::described Answer>
  void answer(const Question& question, Answer carried) {
    basic::iq_result<chevron::tagged<Answer>> out{.to = question.from, .id = question.id};
    out.payload.emplace_back(std::move(carried));
    send(out);
  }

  // A request refused: the error, of type cancel, with a condition of the
  // stanza-errors namespace (RFC 6120, 8.3.3).
  template <iq_request Question>
  void refuse(const Question& question, std::string_view condition = "service-unavailable") {
    send(basic::iq_error<chevron::tagged<chevron::any>>{
        .to = question.from,
        .id = question.id,
        .reason = stanza_error{.type = error_types::cancel{},
                               .what = condition_named<stanza_condition_t>(condition).value_or(
                                   stanza_condition_t(conditions::undefined_condition{}))}});
  }

  class stanza_view;

  // The stanzas as they arrive, for a range-based for loop: each a
  // std::expected<stanza_t, connect_error>. The view ends where the server ends
  // the stream, or just after an error.
  stanza_view stanzas() { return stanza_view(*this); }

  // A stanza, written to the transport, and flushed.
  template <chevron::described Stanza>
  void send(const Stanza& one) {
    out_.clear();
    chevron::write(std::back_inserter(out_), one);
    transport_.write(out_);
    transport_.flush();
  }

  // Ends the stream from this side (RFC 6120, 4.4). What the server sends
  // before its own closing tag still arrives: go on reading stanzas() until
  // it ends, and only then close the connection.
  void close() {
    // RFC 6121, 4.5: unavailable presence before the stream ends, where
    // presence was sent.
    if (announced_) {
      send(typename P::presence::unavailable{});
      announced_ = false;
    }
    transport_.write("</stream:stream>");
    transport_.flush();
  }

  // Presence (RFC 6121, 4): available -- the initial presence after the
  // roster, or a change of it -- and, to one address, directed.
  void available(typename P::presence::available said = {}) {
    if (!said.to)
      announced_ = true;
    send(said);
  }

  // Subscriptions (RFC 6121, 3), each to a bare JID as 3.1.1 wants: asking
  // for someone's presence, approving or denying their asking, and taking
  // one's own back. An address that is not one is an error, not sent.
  std::expected<void, jid_error> subscribe(std::string_view to) {
    return to_bare<typename P::presence::subscribe>(to);
  }
  std::expected<void, jid_error> approve(std::string_view to) {
    return to_bare<typename P::presence::subscribed>(to);
  }
  std::expected<void, jid_error> deny(std::string_view to) {
    return to_bare<typename P::presence::unsubscribed>(to);
  }
  std::expected<void, jid_error> unsubscribe(std::string_view to) {
    return to_bare<typename P::presence::unsubscribe>(to);
  }

  // The roster brought up to date (RFC 6121, 2.6). Where the server versions
  // rosters it is asked for from the version kept -- ver='' where there is
  // none -- and an empty answer leaves the cache as it is: nothing changed,
  // or the changes follow as pushes, for cache.apply(). Otherwise, and
  // wherever the whole roster comes, it replaces what was kept.
  std::expected<void, request_error> try_sync(roster_cache& cache) {
    static_assert(P::template answers_with<roster>, "tern: sync() needs tern::roster among the protocol's answers<>");
    query::roster asked;
    if (roster_versioning_)
      asked.ver = cache.ver.value_or("");
    basic::iq_get<chevron::tagged<query::roster>> sent;
    sent.payload.emplace_back(std::move(asked));
    auto answer = try_request(std::move(sent));
    if (!answer)
      return std::unexpected(std::move(answer).error());
    if (answer->payload.empty())
      return {};
    if (auto* whole = answer->payload.front().template get_if<roster>()) {
      cache.replace(std::move(*whole));
      return {};
    }
    return std::unexpected(request_error{request_code::bad_answer, std::nullopt, std::nullopt});
  }

  // The same, throwing a tern::request_failure.
  void sync(roster_cache& cache) {
    if (auto done = try_sync(cache); !done)
      throw request_failure(std::move(done).error());
  }

  // For connect(): the transport, the reading it sets up, and what
  // negotiation found.
  transport_type& transport() noexcept { return transport_; }
  detail::source<std::remove_reference_t<decltype(std::declval<transport_type&>().input())>>& source() {
    return source_;
  }
  void bound_to(std::string jid) { jid_ = std::move(jid); }
  void versions_rosters(bool on) { roster_versioning_ = on; }
  void deliver_unhandled(bool deliver) { deliver_unhandled_ = deliver; }

 private:
  static constexpr bool can_yield = !std::same_as<Yield, no_yield>;

  std::expected<std::optional<stanza_t>, connect_error> take_pending() {
    stanza_t one = std::move(pending_.front());
    pending_.pop_front();
    return std::optional<stanza_t>(std::move(one));
  }

  template <class Presence>
  std::expected<void, jid_error> to_bare(std::string_view to) {
    auto address = jid::parse(to);
    if (!address)
      return std::unexpected(address.error());
    send(Presence{.to = address->bare().str()});
    return {};
  }

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

  // A query given to the first handler that takes its type; false where none
  // does.
  template <class Question, class Query>
  bool handled(const Question& question, const Query& query) {
    bool done = false;
    std::apply(
        [&](auto&... handler) {
          const auto try_one = [&](auto& one) {
            using held = std::remove_reference_t<decltype(one)>;
            if constexpr (std::invocable<held&, const Query&>) {
              if (done)
                return;
              done = true;
              try {
                if constexpr (std::is_void_v<std::invoke_result_t<held&, const Query&>>) {
                  one(query);
                  answer(question);
                } else {
                  answer(question, one(query));
                }
              } catch (const refusal& refused) {
                refuse(question, refused.condition);
              }
            }
          };
          (try_one(handler), ...);
        },
        handlers_.handlers);
    return done;
  }

  // A get or a set that arrived: to its handler, or refused -- every one gets
  // a reply -- unless requests nobody handles are handed out.
  bool dispatched(stanza_t& one) {
    auto* kind = std::get_if<iq_t>(&one);
    if (!kind)
      return false;
    return std::visit(
        [&](auto& question) {
          using type = std::remove_cvref_t<decltype(question)>;
          if constexpr (std::same_as<type, typename P::iq::get> || std::same_as<type, typename P::iq::set>) {
            if constexpr (std::same_as<type, typename P::iq::set> &&
                          P::query_payload::template can_hold<roster>) {
              if (!question.payload.empty())
                if (const roster* push = question.payload.front().template get_if<roster>()) {
                  // RFC 6121, 2.1.6: a push is from the account itself -- no
                  // from, or the bare JID -- or it is ignored, not answered.
                  const std::string bare = jid_.substr(0, jid_.find('/'));
                  if (question.from && *question.from != bare)
                    return true;
                  if (handled(question, *push))
                    return true;
                  // Nobody handles it: answered all the same, and handed out.
                  answer(question);
                  return false;
                }
            }
            if (!question.payload.empty()) {
              const bool taken = std::visit(
                  [&]<class Query>(const Query& query) {
                    if constexpr (std::same_as<Query, chevron::any>)
                      return false;
                    else
                      return handled(question, query);
                  },
                  question.payload.front().data());
              if (taken)
                return true;
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

  // An answer to a request in flight goes to it: the result or the error with
  // its id, from the address it asked (RFC 6120, 8.2.3).
  bool claimed(stanza_t& one) {
    auto* kind = std::get_if<iq_t>(&one);
    if (!kind)
      return false;
    return std::visit(
        [&](auto& answer) {
          using type = std::remove_cvref_t<decltype(answer)>;
          if constexpr (std::same_as<type, result> || std::same_as<type, error>) {
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
    auto one = P::read_one(source_);
    // A stream error ends the stream: its condition is the failure.
    if (one) {
      if (const auto* ended = std::get_if<stream_error>(&*one))
        return std::unexpected(connect_error{connect_code::stream_error, std::string(ended->condition()),
                                             std::nullopt, ended->other_host()});
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
    }
    const chevron::read_error& failure = one.error();
    // The server's </stream:stream>: the end, and a clean one.
    if (failure.code == chevron::read_code::unexpected_element && failure.where.empty())
      return std::nullopt;
    if (failure.code == chevron::read_code::incomplete ||
        (failure.parse_error && failure.parse_error->code == chevron::error_code::unexpected_end))
      return std::unexpected(connect_error{connect_code::closed, "", std::nullopt});
    return std::unexpected(connect_error{connect_code::xml, failure.where, std::nullopt});
  }

  T transport_;
  Handlers handlers_;
  Yield yield_;
  detail::source<std::remove_reference_t<decltype(std::declval<transport_type&>().input())>> source_;
  std::string out_;
  std::string jid_;
  bool roster_versioning_ = false;
  std::deque<stanza_t> pending_;
  std::size_t last_id_ = 0;
  // The requests in flight, by id: whom the answer must come from, and the
  // answer once somebody has read it.
  struct slot {
    std::optional<std::string> to;
    std::optional<std::variant<result, error>> answer;
  };
  std::map<std::string, slot> waiting_;
  bool reading_ = false;
  std::optional<connect_error> failed_;
  bool deliver_unhandled_ = false;
  bool announced_ = false;
};

template <class T, class P, class Handlers, class Yield>
class session<T, P, Handlers, Yield>::stanza_view : public std::ranges::view_interface<stanza_view> {
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
  using transport_type = typename Session::transport_type;

 public:
  negotiation(Session& s, const options& o) : s_(s), o_(o) {}

  std::expected<void, connect_error> run() {
    bool secured = false;
    if constexpr (secured_transport<transport_type>)
      secured = s_.transport().secured();
    for (;;) {
      if (auto opened = open(); !opened)
        return opened;
      auto next = chevron::read_one_of<features, stream_error>(s_.source());
      if (!next)
        return fail(connect_code::xml, "stream features: " + next.error().where);
      if (const auto* ended = std::get_if<stream_error>(&*next))
        return std::unexpected(connect_error{connect_code::stream_error, std::string(ended->condition()),
                                             std::nullopt, ended->other_host()});
      const features* offered = &std::get<features>(*next);
      if (offered->starttls && !secured) {
        if constexpr (tls_transport<transport_type>) {
          write("<starttls xmlns='" + std::string(tls_namespace) + "'/>");
          auto answer = read_nonza();
          if (!answer)
            return std::unexpected(answer.error());
          if (answer->local != "proceed") {
            write("</stream:stream>");
            return fail(connect_code::tls_refused, answer->local);
          }
          if (!s_.transport().start_tls(o_.domain))
            return fail(connect_code::tls_failed, "");
          secured = true;
          s_.source().start(s_.transport().input());
          continue;
        } else {
          if (offered->starttls->required())
            return fail(connect_code::tls_required, "");
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
      roster_versioning = offered->ver.has_value();
      return bind();
    }
  }

  std::string jid;
  bool roster_versioning = false;

 private:
  std::unexpected<connect_error> fail(connect_code code, std::string detail) const {
    return std::unexpected(connect_error{code, std::move(detail), std::nullopt});
  }

  void write(std::string_view text) {
    s_.transport().write(text);
    s_.transport().flush();
  }

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
    // A stream error may come here too (4.9): its condition is its first
    // child, and see-other-host's text is the host.
    const bool ended = out.uri == stream_namespace && out.local == "error";
    std::string first_text;
    std::size_t children = 0;
    for (std::size_t depth = 1; depth > 0;) {
      auto next = s_.source().next();
      if (!next || !*next)
        return fail(connect_code::closed, "while negotiating");
      if (const auto* inner = std::get_if<chevron::start_element>(&**next)) {
        if (depth == 1) {
          ++children;
          if (out.first_child.empty())
            out.first_child = std::string(inner->name.local);
        }
        ++depth;
      } else if (std::holds_alternative<chevron::end_element>(**next)) {
        --depth;
      } else if (depth == 1) {
        out.text += std::get<chevron::text>(**next).content;
      } else if (depth == 2 && children == 1) {
        first_text += std::get<chevron::text>(**next).content;
      }
    }
    if (ended) {
      std::optional<std::string> other;
      if (out.first_child == "see-other-host")
        other = std::move(first_text);
      return std::unexpected(
          connect_error{connect_code::stream_error, out.first_child, std::nullopt, std::move(other)});
    }
    return out;
  }

  std::expected<void, connect_error> authenticate(const std::vector<std::string>& offered, bool secured) {
    const auto has = [&](std::string_view name) { return std::ranges::find(offered, name) != offered.end(); };
    const std::string nonce = o_.nonce.empty() ? sasl::random_nonce() : o_.nonce;
    std::optional<channel_binding> binding;
    if constexpr (binding_transport<transport_type>) {
      if (secured)
        binding = s_.transport().channel_binding();
    }
    if (binding && has("SCRAM-SHA-256-PLUS"))
      return scram<sasl::scram_sha256>("SCRAM-SHA-256-PLUS", nonce, &*binding, true);
    if (binding && has("SCRAM-SHA-1-PLUS"))
      return scram<sasl::scram_sha1>("SCRAM-SHA-1-PLUS", nonce, &*binding, true);
    if (has("SCRAM-SHA-256"))
      return scram<sasl::scram_sha256>("SCRAM-SHA-256", nonce, binding ? &*binding : nullptr, false);
    if (has("SCRAM-SHA-1"))
      return scram<sasl::scram_sha1>("SCRAM-SHA-1", nonce, binding ? &*binding : nullptr, false);
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
  std::expected<void, connect_error> scram(std::string_view mechanism, const std::string& nonce,
                                           const channel_binding* binding, bool plus) {
    Scram client(o_.username, o_.password, nonce, o_.minimum_iterations);
    if (binding && plus)
      client.bind_channel(binding->type, binding->data);
    else if (binding)
      client.could_bind();
    auth(mechanism, client.first());
    auto challenge = read_nonza();
    if (!challenge)
      return std::unexpected(challenge.error());
    if (challenge->local != "challenge")
      return fail(connect_code::not_authorized,
                  challenge->local == "failure" ? challenge->first_child : challenge->local);
    auto reply = client.answer(text_of(challenge->text));
    if (!reply) {
      write("<abort xmlns='" + std::string(sasl_namespace) + "'/>");
      (void)read_nonza();  // <failure><aborted/></failure>, or the end
      return std::unexpected(connect_error{connect_code::authentication, reply.error().detail, reply.error()});
    }
    write("<response xmlns='" + std::string(sasl_namespace) + "'>" +
          crypto::base64_encode(crypto::to_bytes(*reply)) + "</response>");
    auto outcome = read_nonza();
    if (!outcome)
      return std::unexpected(outcome.error());
    if (outcome->local != "success")
      return fail(connect_code::not_authorized,
                  outcome->local == "failure" ? outcome->first_child : outcome->local);
    if (auto proved = client.verify(text_of(outcome->text)); !proved)
      return std::unexpected(connect_error{connect_code::authentication, proved.error().detail, proved.error()});
    return {};
  }

  // The answer read straight into its type: the JID bound, or the error.
  std::expected<void, connect_error> bind() {
    std::string request = "<iq type='set' id='bind_1'><bind xmlns='" + std::string(bind_namespace) + "'>";
    if (o_.resource)
      request += "<resource>" + escaped(*o_.resource) + "</resource>";
    write(request + "</bind></iq>");
    auto read = chevron::read_one_of<basic::iq_result<chevron::tagged<bind_result, chevron::any>>,
                                     basic::iq_error<chevron::tagged<chevron::any>>>(s_.source());
    if (!read)
      return fail(connect_code::xml, "bind: " + read.error().where);
    if (const auto* refused = std::get_if<1>(&*read))
      return std::unexpected(connect_error{connect_code::bind_refused, std::string(refused->reason.condition()),
                                           std::nullopt, std::nullopt, refused->reason});
    const auto& answer = std::get<0>(*read);
    if (answer.id != "bind_1")
      return fail(connect_code::bind_refused, "not the answer to the bind");
    if (!answer.payload.empty())
      if (const bind_result* bound = answer.payload.front().template get_if<bind_result>())
        jid = bound->jid.value_or("");
    if (jid.empty())
      return fail(connect_code::bind_refused, "no JID in the answer");
    return {};
  }

  Session& s_;
  const options& o_;
  bool authenticated_ = false;
};

template <class Session>
std::expected<Session, connect_error> establish(Session s, const options& how) {
  negotiation<Session> steps(s, how);
  if (auto done = steps.run(); !done)
    return std::unexpected(done.error());
  s.bound_to(std::move(steps.jid));
  s.versions_rosters(steps.roster_versioning);
  s.deliver_unhandled(how.deliver_unhandled);
  return s;
}

}  // namespace tern::detail

export namespace tern {

// Connects over the caller's transport -- kept by reference, so it has to
// outlive the session: stream, STARTTLS where the transport can start TLS,
// SCRAM (-PLUS where it gives channel binding) or PLAIN, and resource
// binding. P, given first, is the protocol:
//   auto s = tern::connect<my_protocol>(socket, how, tern::answering{...});
template <class P = standard, transport T, class Handlers = answering<>, class Yield = no_yield>
std::expected<session<T&, P, Handlers, Yield>, connect_error>
try_connect(T& transport, const options& how, Handlers handlers = {}, Yield yield = {}) {
  return detail::establish(session<T&, P, Handlers, Yield>(transport, std::move(handlers), std::move(yield)), how);
}

// The same over a range of bytes (or of chunks), read as far as each step
// needs, and an output iterator of char: no TLS. The range has to outlive
// the session.
template <class P = standard, std::ranges::input_range Input, std::output_iterator<char> Out,
          class Handlers = answering<>, class Yield = no_yield>
std::expected<session<range_transport<Input, Out>, P, Handlers, Yield>, connect_error>
try_connect(Input& input, Out output, const options& how, Handlers handlers = {}, Yield yield = {}) {
  return detail::establish(session<range_transport<Input, Out>, P, Handlers, Yield>(
                               range_transport<Input, Out>(input, std::move(output)), std::move(handlers),
                               std::move(yield)),
                           how);
}

// The same, throwing: the session, or a tern::connect_failure.
template <class P = standard, transport T, class Handlers = answering<>, class Yield = no_yield>
session<T&, P, Handlers, Yield> connect(T& transport, const options& how, Handlers handlers = {},
                                        Yield yield = {}) {
  auto made = try_connect<P>(transport, how, std::move(handlers), std::move(yield));
  if (!made)
    throw connect_failure(std::move(made).error());
  return std::move(*made);
}

template <class P = standard, std::ranges::input_range Input, std::output_iterator<char> Out,
          class Handlers = answering<>, class Yield = no_yield>
session<range_transport<Input, Out>, P, Handlers, Yield> connect(Input& input, Out output, const options& how,
                                                                 Handlers handlers = {}, Yield yield = {}) {
  auto made = try_connect<P>(input, std::move(output), how, std::move(handlers), std::move(yield));
  if (!made)
    throw connect_failure(std::move(made).error());
  return std::move(*made);
}

}  // namespace tern
