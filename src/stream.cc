// SPDX-License-Identifier: AGPL-3.0-only
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
import splice;
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

// The names of a tagged's conditions, in order; the name of the one it holds
// read by its index.
template <class Tagged>
struct condition_names;
template <class... C>
struct condition_names<chevron::tagged<C...>> {
  static constexpr std::array<std::string_view, sizeof...(C)> names{
      std::string_view(xml_schema(chevron::type<C>{}).local)...};
};

template <class Tagged>
constexpr std::string_view condition_name(const Tagged& held) {
  return condition_names<Tagged>::names[held.data().index()];
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

using error_type_t = spl::variant<error_types::cancel, error_types::continue_, error_types::modify,
                                  error_types::auth, error_types::wait>;

namespace basic {

// A stanza's <error/> (RFC 6120, 8.3): its type, the defined condition, its
// text, and an application-specific condition (8.3.2) -- A, a tagged of the
// types the protocol's errors<> names, read straight into them; one it does
// not name is passed over. void where it names none.
template <class A>
struct stanza_error {
  std::optional<error_type_t> type;
  std::optional<std::string> by;
  std::optional<stanza_condition_t> what;  // the defined condition
  std::optional<error_text<"urn:ietf:params:xml:ns:xmpp-stanzas">> text;
  std::optional<A> application;

  constexpr std::string_view condition() const { return what ? condition_name(*what) : std::string_view(); }
};

template <>
struct stanza_error<void> {
  std::optional<error_type_t> type;
  std::optional<std::string> by;
  std::optional<stanza_condition_t> what;
  std::optional<error_text<"urn:ietf:params:xml:ns:xmpp-stanzas">> text;

  constexpr std::string_view condition() const { return what ? condition_name(*what) : std::string_view(); }
};

template <class A>
constexpr auto xml_schema(chevron::type<stanza_error<A>>) {
  using namespace chevron::members;
  if constexpr (std::is_void_v<A>)
    return chevron::schema<stanza_error<A>>().name(client_namespace, "error").members(attribute(), attribute(), _, _);
  else
    return chevron::schema<stanza_error<A>>()
        .name(client_namespace, "error")
        .members(attribute(), attribute(), _, _, _);
}

}  // namespace basic

// The <error/> of a protocol that names no application conditions.
using stanza_error = basic::stanza_error<void>;

// A stream error (RFC 6120, 4.9): the server ends the stream, and says why.
// An application's own condition (4.9.4) is passed over.
struct stream_error {
  std::optional<stream_condition_t> what;
  std::optional<error_text<"urn:ietf:params:xml:ns:xmpp-streams">> text;

  constexpr std::string_view condition() const { return what ? condition_name(*what) : std::string_view(); }

  // For see-other-host (4.9.3.19): the host, and port, to connect to instead.
  constexpr std::optional<std::string> other_host() const {
    if (what)
      if (const auto* other = what->get_if<stream_conditions::see_other_host>())
        return other->value.value_or("");
    return std::nullopt;
  }
};

constexpr auto xml_schema(chevron::type<stream_error>) {
  using namespace chevron::members;
  return chevron::schema<stream_error>().name(stream_namespace, "error");
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
  std::optional<spl::variant<tern::subscription::none, tern::subscription::to, tern::subscription::from,
                             tern::subscription::both, tern::subscription::remove>> subscription;
  std::optional<spl::variant<subscribe_pending>> ask;
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

// A contact added or changed (RFC 6121, 2.3, 2.4), or with subscription
// remove taken out (2.5): one item a set.
struct roster_set {
  using kind = tern::set;
  using answer = void;
  std::vector<roster_item> items;
};

constexpr auto xml_schema(chevron::type<roster_set>) {
  using namespace chevron::members;
  return chevron::schema<roster_set>().name(roster_namespace, "query").members(child("item"));
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
template <class X, class R = tern::stanza_error>
struct message_error {
  std::optional<std::string> to, from, id, lang, subject, body;
  std::optional<tern::thread> thread;
  R reason;  // the <error/>
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
template <class X, class R = tern::stanza_error>
struct presence_error {
  std::optional<std::string> to, from, id, lang;
  R reason;
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
template <class X, class R = tern::stanza_error>
struct iq_error {
  std::optional<std::string> to, from;
  std::string id;
  std::optional<std::string> lang;
  R reason;
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
template <class X, class R>
constexpr auto xml_schema(chevron::type<message_error<X, R>>) {
  return stanza_schema<message_error<X, R>>("message").template when<"type">("error");
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
template <class X, class R>
constexpr auto xml_schema(chevron::type<presence_error<X, R>>) {
  return stanza_schema<presence_error<X, R>>("presence").template when<"type">("error");
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
template <class X, class R>
constexpr auto xml_schema(chevron::type<iq_error<X, R>>) {
  return stanza_schema<iq_error<X, R>>("iq").template when<"type">("error");
}

}  // namespace basic

// XEP-0203: when a stanza was first sent, and where it was held.
struct delay {
  std::string stamp;
  std::optional<std::string> from;
  std::optional<std::string> reason;
};
constexpr auto xml_schema(chevron::type<delay>) {
  using namespace chevron::members;
  return chevron::schema<delay>().name("urn:xmpp:delay", "delay").members(attribute(), attribute(), text());
}

// XEP-0297: a message forwarded, and when it was sent. What the message
// carries is kept as it came.
namespace forward {
using plain = chevron::tagged<chevron::any>;
using message = chevron::tagged<basic::message_normal<plain>, basic::message_chat<plain>,
                                basic::message_groupchat<plain>, basic::message_headline<plain>,
                                basic::message_error<plain>>;
struct forwarded {
  std::optional<tern::delay> delay;
  std::optional<forward::message> message;
};
constexpr auto xml_schema(chevron::type<forwarded>) {
  return chevron::schema<forwarded>().name("urn:xmpp:forward:0", "forwarded");
}
}  // namespace forward

// XEP-0280: copies of one's messages sent and received by one's other
// resources.
namespace carbons {
inline constexpr std::string_view carbons_namespace = "urn:xmpp:carbons:2";
struct received {
  forward::forwarded forwarded;
};
struct sent {
  forward::forwarded forwarded;
};
// In a message: no copies of it.
struct private_ {};
constexpr auto xml_schema(chevron::type<received>) {
  return chevron::schema<received>().name(carbons_namespace, "received");
}
constexpr auto xml_schema(chevron::type<sent>) { return chevron::schema<sent>().name(carbons_namespace, "sent"); }
constexpr auto xml_schema(chevron::type<private_>) {
  return chevron::schema<private_>().name(carbons_namespace, "private");
}
}  // namespace carbons

// XEP-0045: multi-user chat -- joining a room, and who is in it.
namespace muc {
inline constexpr std::string_view muc_namespace = "http://jabber.org/protocol/muc";
inline constexpr std::string_view user_namespace = "http://jabber.org/protocol/muc#user";

// How much of the room's past to be sent on joining.
struct history {
  std::optional<std::string> maxstanzas;
  std::optional<std::string> seconds;
};
constexpr auto xml_schema(chevron::type<history>) {
  using namespace chevron::members;
  return chevron::schema<history>().name(muc_namespace, "history").members(attribute(), attribute());
}

// What a presence to room@service/nick carries to join the room.
struct join {
  std::optional<muc::history> history;
  std::optional<std::string> password;
};
constexpr auto xml_schema(chevron::type<join>) {
  using namespace chevron::members;
  return chevron::schema<join>().name(muc_namespace, "x").members(child("history"), child_text());
}

// An occupant, as a room's presence says: its affiliation (owner, admin,
// member, outcast, none), its role (moderator, participant, visitor, none),
// its real JID where the room shows it, and its nick where it changes.
struct item {
  std::optional<std::string> affiliation;
  std::optional<std::string> role;
  std::optional<std::string> jid;
  std::optional<std::string> nick;
};
constexpr auto xml_schema(chevron::type<item>) {
  using namespace chevron::members;
  return chevron::schema<item>().name(user_namespace, "item").members(attribute(), attribute(), attribute(),
                                                                      attribute());
}

// A status code: 110 is the presence of oneself, 201 a room just made.
struct status {
  std::string code;
};
constexpr auto xml_schema(chevron::type<status>) {
  using namespace chevron::members;
  return chevron::schema<status>().name(user_namespace, "status").members(attribute());
}

// What a room's presences carry about the occupant.
struct user {
  std::vector<muc::item> items;
  std::vector<muc::status> statuses;
};
constexpr auto xml_schema(chevron::type<user>) {
  using namespace chevron::members;
  return chevron::schema<user>().name(user_namespace, "x").members(child("item"), child("status"));
}
}  // namespace muc

// XEP-0402: the rooms one keeps, as PEP items of urn:xmpp:bookmarks:1, each
// item's id the room's JID.
namespace bookmarks {
inline constexpr std::string_view bookmarks_namespace = "urn:xmpp:bookmarks:1";
inline constexpr std::string_view pubsub_namespace = "http://jabber.org/protocol/pubsub";

struct conference {
  std::optional<std::string> name;
  std::optional<std::string> autojoin;  // "true" or "1" to join on connecting
  std::optional<std::string> nick;
  std::optional<std::string> password;
};
constexpr auto xml_schema(chevron::type<conference>) {
  using namespace chevron::members;
  return chevron::schema<conference>()
      .name(bookmarks_namespace, "conference")
      .members(attribute(), attribute(), child_text(), child_text());
}

struct item {
  std::string id;
  std::optional<bookmarks::conference> conference;
};
constexpr auto xml_schema(chevron::type<item>) {
  using namespace chevron::members;
  return chevron::schema<item>().name(pubsub_namespace, "item").members(attribute(), child("conference"));
}

struct item_list {
  std::string node;
  std::vector<bookmarks::item> items;
};
constexpr auto xml_schema(chevron::type<item_list>) {
  using namespace chevron::members;
  return chevron::schema<item_list>().name(pubsub_namespace, "items").members(attribute(), child("item"));
}

// The answer: the bookmarks node's items.
struct pubsub {
  std::optional<bookmarks::item_list> items;
};
constexpr auto xml_schema(chevron::type<pubsub>) {
  using namespace chevron::members;
  return chevron::schema<pubsub>().name(pubsub_namespace, "pubsub").members(child("items"));
}

// Whether a bookmark says to join its room on connecting.
constexpr bool autojoins(const conference& one) {
  return one.autojoin && (*one.autojoin == "true" || *one.autojoin == "1");
}
}  // namespace bookmarks

// XEP-0333: chat markers -- a message marked as one to be marked, and a
// marker saying one was displayed.
namespace markers {
inline constexpr std::string_view markers_namespace = "urn:xmpp:chat-markers:0";
struct markable {};
constexpr auto xml_schema(chevron::type<markable>) {
  return chevron::schema<markable>().name(markers_namespace, "markable");
}
struct displayed {
  std::string id;
};
constexpr auto xml_schema(chevron::type<displayed>) {
  using namespace chevron::members;
  return chevron::schema<displayed>().name(markers_namespace, "displayed").members(attribute());
}
}  // namespace markers

// XEP-0308: a message correcting an earlier one of the same sender.
namespace corrections {
struct replace {
  std::string id;
};
constexpr auto xml_schema(chevron::type<replace>) {
  using namespace chevron::members;
  return chevron::schema<replace>().name("urn:xmpp:message-correct:0", "replace").members(attribute());
}
}  // namespace corrections

// XEP-0424: a message taken back by its sender.
namespace retractions {
struct retract {
  std::string id;
};
constexpr auto xml_schema(chevron::type<retract>) {
  using namespace chevron::members;
  return chevron::schema<retract>().name("urn:xmpp:message-retract:1", "retract").members(attribute());
}
}  // namespace retractions

// XEP-0461: a message answering another: whose it was, and its id.
namespace replies {
struct reply {
  std::optional<std::string> to;
  std::string id;
};
constexpr auto xml_schema(chevron::type<reply>) {
  using namespace chevron::members;
  return chevron::schema<reply>().name("urn:xmpp:reply:0", "reply").members(attribute(), attribute());
}
}  // namespace replies

// XEP-0059: a page of a result set.
namespace rsm {
struct set {
  std::optional<int> max;
  std::optional<std::string> after, before, first, last;
  std::optional<int> count;
};
constexpr auto xml_schema(chevron::type<set>) {
  return chevron::schema<set>().name("http://jabber.org/protocol/rsm", "set");
}
}  // namespace rsm

// XEP-0004: a data form -- a query's filter, and what a server asks, as
// registering (XEP-0077) does.
namespace data_form {
inline constexpr std::string_view form_namespace = "jabber:x:data";
inline constexpr std::string_view media_namespace = "urn:xmpp:media-element";
struct required_flag {};
constexpr auto xml_schema(chevron::type<required_flag>) {
  return chevron::schema<required_flag>().name(form_namespace, "required");
}
// One of a list's choices: what it says, and what it sends.
struct option {
  std::optional<std::string> label;
  std::string value;
};
constexpr auto xml_schema(chevron::type<option>) {
  using namespace chevron::members;
  return chevron::schema<option>().name(form_namespace, "option").members(attribute(), child_text());
}
// XEP-0221: where a field's picture or sound is -- a cid: of XEP-0231's
// data sent with the form, or an address -- and of what type.
struct uri {
  std::string type;
  std::string location;
};
constexpr auto xml_schema(chevron::type<uri>) {
  using namespace chevron::members;
  return chevron::schema<uri>().name(media_namespace, "uri").members(attribute(), text());
}
struct media {
  std::vector<data_form::uri> uri;
};
constexpr auto xml_schema(chevron::type<media>) {
  using namespace chevron::members;
  return chevron::schema<media>().name(media_namespace, "media").members(child("uri", media_namespace));
}
struct field {
  std::optional<std::string> var;
  std::optional<std::string> type;
  std::vector<std::string> value;
  std::optional<std::string> label = {};
  std::optional<std::string> desc = {};
  std::optional<required_flag> required = {};
  std::vector<data_form::option> options = {};
  std::optional<data_form::media> media = {};
};
constexpr auto xml_schema(chevron::type<field>) {
  using namespace chevron::members;
  return chevron::schema<field>()
      .name(form_namespace, "field")
      .members(attribute(), attribute(), child_text(), attribute(), child_text(), child("required"), child("option"),
               child("media", media_namespace));
}
struct form {
  std::string type;
  std::vector<data_form::field> fields;
  std::optional<std::string> title = {};
  std::vector<std::string> instructions = {};
};
constexpr auto xml_schema(chevron::type<form>) {
  using namespace chevron::members;
  return chevron::schema<form>()
      .name(form_namespace, "x")
      .members(attribute(), child("field"), child_text(), child_text());
}
}  // namespace data_form

// XEP-0231: data sent along, named by its cid -- a captcha's picture.
namespace bob {
struct data {
  std::string cid;
  std::optional<std::string> type;
  std::string base64;
};
constexpr auto xml_schema(chevron::type<data>) {
  using namespace chevron::members;
  return chevron::schema<data>().name("urn:xmpp:bob", "data").members(attribute(), attribute(), text());
}
}  // namespace bob

// XEP-0077: an account made on the stream, before signing in with it --
// what the server asks for: the old fields, or a form (XEP-0004, with a
// captcha as XEP-0158 has it), or a page to make it on (XEP-0066).
namespace registration {
inline constexpr std::string_view register_namespace = "jabber:iq:register";
struct registered_flag {};
constexpr auto xml_schema(chevron::type<registered_flag>) {
  return chevron::schema<registered_flag>().name(register_namespace, "registered");
}
struct page {
  std::optional<std::string> url;
  std::optional<std::string> desc;
};
constexpr auto xml_schema(chevron::type<page>) {
  using namespace chevron::members;
  return chevron::schema<page>().name("jabber:x:oob", "x").members(child_text(), child_text());
}
struct asked {
  std::optional<std::string> instructions;
  std::optional<registered_flag> registered;
  // The old fields, each asked where present; email the one beyond the
  // account's own two that servers ask most.
  std::optional<std::string> username;
  std::optional<std::string> password;
  std::optional<std::string> email;
  std::optional<data_form::form> form;
  std::optional<registration::page> page;
  std::vector<bob::data> data;
};
constexpr auto xml_schema(chevron::type<asked>) {
  using namespace chevron::members;
  return chevron::schema<asked>()
      .name(register_namespace, "query")
      .members(child_text(), child("registered"), child_text(), child_text(), child_text(),
               child("x", data_form::form_namespace), child("x", "jabber:x:oob"), child("data", "urn:xmpp:bob"));
}
// The answers to what a server asks beyond the username and the password:
// each a field's var -- an old field's name -- and its value.
struct answer {
  std::string var;
  std::string value;
};
}  // namespace registration

// XEP-0313: the archive of one's messages, asked for a page at a time.
namespace mam {
inline constexpr std::string_view mam_namespace = "urn:xmpp:mam:2";
struct fin {
  std::optional<bool> complete;
  std::optional<rsm::set> page;
};
constexpr auto xml_schema(chevron::type<fin>) {
  using namespace chevron::members;
  return chevron::schema<fin>().name(mam_namespace, "fin").members(attribute(), _);
}
// One archived message, in a message of its own before the answer.
struct result {
  std::optional<std::string> queryid;
  std::string id;
  forward::forwarded forwarded;
};
constexpr auto xml_schema(chevron::type<result>) {
  using namespace chevron::members;
  return chevron::schema<result>().name(mam_namespace, "result").members(attribute(), attribute(), _);
}
struct query {
  using kind = tern::set;
  using answer = mam::fin;
  std::optional<std::string> queryid;
  std::optional<data_form::form> filter;
  std::optional<rsm::set> page;
};
constexpr auto xml_schema(chevron::type<query>) {
  using namespace chevron::members;
  return chevron::schema<query>().name(mam_namespace, "query").members(attribute(), _, _);
}
// The filter of 4.1: whose messages, from when, until when.
constexpr data_form::form filter(std::optional<std::string> with, std::optional<std::string> start = {},
                              std::optional<std::string> end = {}) {
  data_form::form out{.type = "submit"};
  out.fields.push_back({.var = "FORM_TYPE", .type = "hidden", .value = {std::string(mam_namespace)}});
  if (with)
    out.fields.push_back({.var = "with", .value = {std::move(*with)}});
  if (start)
    out.fields.push_back({.var = "start", .value = {std::move(*start)}});
  if (end)
    out.fields.push_back({.var = "end", .value = {std::move(*end)}});
  return out;
}
}  // namespace mam

// XEP-0030: what an entity is and what it does, and the items it has.
namespace disco {
inline constexpr std::string_view info_namespace = "http://jabber.org/protocol/disco#info";
inline constexpr std::string_view items_namespace = "http://jabber.org/protocol/disco#items";
struct identity {
  std::string category, type;
  std::optional<std::string> lang, name;
};
constexpr auto xml_schema(chevron::type<identity>) {
  using namespace chevron::members;
  return chevron::schema<identity>()
      .name(info_namespace, "identity")
      .members(attribute(), attribute(), attribute("lang", xml_namespace), attribute());
}
struct feature {
  std::string var;
};
constexpr auto xml_schema(chevron::type<feature>) {
  using namespace chevron::members;
  return chevron::schema<feature>().name(info_namespace, "feature").members(attribute());
}
struct info {
  std::optional<std::string> node;
  std::vector<disco::identity> identities;
  std::vector<disco::feature> features;
};
constexpr auto xml_schema(chevron::type<info>) {
  using namespace chevron::members;
  return chevron::schema<info>().name(info_namespace, "query").members(attribute(), child("identity"), child("feature"));
}
struct item {
  std::string jid;
  std::optional<std::string> node, name;
};
constexpr auto xml_schema(chevron::type<item>) {
  using namespace chevron::members;
  return chevron::schema<item>().name(items_namespace, "item").members(attribute(), attribute(), attribute());
}
struct items {
  std::optional<std::string> node;
  std::vector<disco::item> list;
};
constexpr auto xml_schema(chevron::type<items>) {
  using namespace chevron::members;
  return chevron::schema<items>().name(items_namespace, "query").members(attribute(), child("item"));
}
}  // namespace disco

// XEP-0115: what an entity can do, in its presence, as a hash of its info.
namespace caps {
inline constexpr std::string_view caps_namespace = "http://jabber.org/protocol/caps";
struct c {
  std::string hash, node, ver;
  std::optional<std::string> ext;
};
constexpr auto xml_schema(chevron::type<c>) {
  using namespace chevron::members;
  return chevron::schema<c>().name(caps_namespace, "c").members(attribute(), attribute(), attribute(), attribute());
}
// 5.1: the verification string of an entity's info, with SHA-1.
constexpr std::string ver_of(const disco::info& info) {
  std::vector<std::string> identities, features;
  for (const disco::identity& one : info.identities)
    identities.push_back(one.category + "/" + one.type + "/" + one.lang.value_or("") + "/" + one.name.value_or(""));
  for (const disco::feature& one : info.features)
    features.push_back(one.var);
  std::ranges::sort(identities);
  std::ranges::sort(features);
  std::string text;
  for (const std::string& one : identities)
    text += one + "<";
  for (const std::string& one : features)
    text += one + "<";
  return crypto::base64_encode(crypto::sha1::digest(crypto::to_bytes(text)));
}
}  // namespace caps

// XEP-0198: stanzas acknowledged, and a stream resumed where it broke.
namespace sm {
inline constexpr std::string_view sm_namespace = "urn:xmpp:sm:3";
struct feature {};
struct r {};
struct a {
  std::uint32_t h = 0;
};
struct enabled {
  std::optional<std::string> id;
  std::optional<bool> resume;
  std::optional<std::string> location;
  std::optional<std::uint32_t> max;
};
struct resumed {
  std::uint32_t h = 0;
  std::string previd;
};
struct failed {
  std::optional<std::uint32_t> h;
  std::optional<stanza_condition_t> what;
};
constexpr auto xml_schema(chevron::type<feature>) { return chevron::schema<feature>().name(sm_namespace, "sm"); }
constexpr auto xml_schema(chevron::type<r>) { return chevron::schema<r>().name(sm_namespace, "r"); }
constexpr auto xml_schema(chevron::type<a>) {
  using namespace chevron::members;
  return chevron::schema<a>().name(sm_namespace, "a").members(attribute());
}
constexpr auto xml_schema(chevron::type<enabled>) {
  using namespace chevron::members;
  return chevron::schema<enabled>()
      .name(sm_namespace, "enabled")
      .members(attribute(), attribute(), attribute(), attribute());
}
constexpr auto xml_schema(chevron::type<resumed>) {
  using namespace chevron::members;
  return chevron::schema<resumed>().name(sm_namespace, "resumed").members(attribute(), attribute());
}
constexpr auto xml_schema(chevron::type<failed>) {
  using namespace chevron::members;
  return chevron::schema<failed>().name(sm_namespace, "failed").members(attribute(), _);
}
}  // namespace sm

// What a stream to resume needs: kept by the caller from session.sm().
struct sm_state {
  std::string id;
  std::string jid;
  std::uint32_t inbound = 0;
  std::uint32_t acked = 0;
  std::vector<std::string> unacked;  // the stanzas the server has not acknowledged, as written
};

namespace query {
// XEP-0030.
struct disco_info {
  using kind = tern::get;
  using answer = tern::disco::info;
  std::optional<std::string> node;
};
constexpr auto xml_schema(chevron::type<disco_info>) {
  using namespace chevron::members;
  return chevron::schema<disco_info>().name(disco::info_namespace, "query").members(attribute());
}
struct disco_items {
  using kind = tern::get;
  using answer = tern::disco::items;
  std::optional<std::string> node;
};
constexpr auto xml_schema(chevron::type<disco_items>) {
  using namespace chevron::members;
  return chevron::schema<disco_items>().name(disco::items_namespace, "query").members(attribute());
}
// XEP-0280.
struct carbons_enable {
  using kind = tern::set;
  using answer = void;
};
constexpr auto xml_schema(chevron::type<carbons_enable>) {
  return chevron::schema<carbons_enable>().name(carbons::carbons_namespace, "enable");
}
struct carbons_disable {
  using kind = tern::set;
  using answer = void;
};
constexpr auto xml_schema(chevron::type<carbons_disable>) {
  return chevron::schema<carbons_disable>().name(carbons::carbons_namespace, "disable");
}
// XEP-0402: one's bookmarks, the items of the bookmarks node.
struct bookmarks_items {
  std::string node{tern::bookmarks::bookmarks_namespace};
};
constexpr auto xml_schema(chevron::type<bookmarks_items>) {
  using namespace chevron::members;
  return chevron::schema<bookmarks_items>().name(tern::bookmarks::pubsub_namespace, "items").members(attribute());
}
struct bookmarks {
  using kind = tern::get;
  using answer = tern::bookmarks::pubsub;
  bookmarks_items items;
};
constexpr auto xml_schema(chevron::type<bookmarks>) {
  using namespace chevron::members;
  return chevron::schema<bookmarks>().name(tern::bookmarks::pubsub_namespace, "pubsub").members(child("items"));
}

}  // namespace query

// A page of the archive (XEP-0313): the messages, and how the page ends.
struct archive_page {
  std::vector<mam::result> results;
  mam::fin fin;
};

// A protocol: the types a session reads what it receives into. queries<> for
// what gets and sets carry, answers<> for what results carry, extensions<>
// for what messages and presence carry.
template <class... T>
struct queries {};
template <class... T>
struct answers {};
template <class... T>
struct extensions {};
// Application-specific error conditions (RFC 6120, 8.3.2).
template <class... T>
struct errors {};

// What a session does with an element no type of its protocol names: keeps
// it as it came, a chevron::any -- the one tree there is -- or passes over
// it, so that no tree is ever made.
struct keep_unknown {};
struct drop_unknown {};

namespace detail {
// A type no element is read into: the one alternative of a payload whose
// protocol names nothing there and drops the unknown.
struct nothing {};
constexpr auto xml_schema(chevron::type<nothing>) { return chevron::schema<nothing>().name("urn:tern:nothing", ""); }

template <class Unknown, class... T>
struct payload_of;
template <class... T>
struct payload_of<keep_unknown, T...> {
  using type = chevron::tagged<T..., chevron::any>;
};
template <class... T>
struct payload_of<drop_unknown, T...> {
  using type = chevron::tagged<T...>;
};
template <>
struct payload_of<drop_unknown> {
  using type = chevron::tagged<nothing>;
};

template <class... R>
struct application_of {
  using type = chevron::tagged<R...>;
};
template <>
struct application_of<> {
  using type = void;
};
}  // namespace detail

template <class Queries = queries<>, class Answers = answers<>, class Extensions = extensions<>,
          class Errors = errors<>, class Unknown = keep_unknown>
struct protocol;

template <class... Q, class... A, class... E, class... R, class Unknown>
struct protocol<queries<Q...>, answers<A...>, extensions<E...>, errors<R...>, Unknown> {
  static_assert(std::same_as<Unknown, keep_unknown> || std::same_as<Unknown, drop_unknown>,
                "tern: a protocol's last parameter is tern::keep_unknown or tern::drop_unknown");
  using query_payload = typename detail::payload_of<Unknown, Q...>::type;
  using answer_payload = typename detail::payload_of<Unknown, A...>::type;
  using extension = typename detail::payload_of<Unknown, E...>::type;
  using error_payload = typename detail::payload_of<Unknown>::type;
  using stanza_error = basic::stanza_error<typename detail::application_of<R...>::type>;

  struct message {
    using normal = basic::message_normal<extension>;
    using chat = basic::message_chat<extension>;
    using groupchat = basic::message_groupchat<extension>;
    using headline = basic::message_headline<extension>;
    using error = basic::message_error<extension, stanza_error>;
  };
  struct presence {
    using available = basic::presence_available<extension>;
    using unavailable = basic::presence_unavailable<extension>;
    using subscribe = basic::presence_subscribe<extension>;
    using subscribed = basic::presence_subscribed<extension>;
    using unsubscribe = basic::presence_unsubscribe<extension>;
    using unsubscribed = basic::presence_unsubscribed<extension>;
    using probe = basic::presence_probe<extension>;
    using error = basic::presence_error<extension, stanza_error>;
  };
  struct iq {
    using get = basic::iq_get<query_payload>;
    using set = basic::iq_set<query_payload>;
    using result = basic::iq_result<answer_payload>;
    using error = basic::iq_error<error_payload, stanza_error>;
  };

  using message_t = spl::variant<typename message::normal, typename message::chat, typename message::groupchat,
                                 typename message::headline, typename message::error>;
  using presence_t =
      spl::variant<typename presence::available, typename presence::unavailable, typename presence::subscribe,
                   typename presence::subscribed, typename presence::unsubscribe, typename presence::unsubscribed,
                   typename presence::probe, typename presence::error>;
  using iq_t = spl::variant<typename iq::get, typename iq::set, typename iq::result, typename iq::error>;
  using stanza_t = spl::variant<message_t, presence_t, iq_t>;

  template <class T>
  static constexpr bool answers_with = (std::same_as<T, A> || ...);

  // One stanza, or the stream's error, read as the type its name says.
  template <class Source>
  static constexpr auto read_one(Source& source) {
    return chevron::read_one_of<typename message::normal, typename message::chat, typename message::groupchat,
                                typename message::headline, typename message::error, typename presence::available,
                                typename presence::unavailable, typename presence::subscribe,
                                typename presence::subscribed, typename presence::unsubscribe,
                                typename presence::unsubscribed, typename presence::probe,
                                typename presence::error, typename iq::get, typename iq::set, typename iq::result,
                                typename iq::error, stream_error, sm::r, sm::a>(source);
  }
};

// What RFC 6120 and 6121 need, and what every client is asked and uses:
// roster pushes, version, ping and disco as queries; the roster, versions,
// disco and the archive's end as answers; delay, caps, carbons and archived
// messages as extensions.
using standard = protocol<queries<roster, query::version, query::ping, query::disco_info, query::disco_items>,
                          answers<roster, version, disco::info, disco::items, mam::fin>,
                          extensions<delay, caps::c, carbons::received, carbons::sent, mam::result>>;

// What a chat client also uses: rooms (XEP-0045), bookmarks (XEP-0402),
// chat markers (XEP-0333), corrections (XEP-0308), retractions (XEP-0424)
// and replies (XEP-0461), on top of the standard protocol.
using client = protocol<queries<roster, query::version, query::ping, query::disco_info, query::disco_items>,
                        answers<roster, version, disco::info, disco::items, mam::fin, bookmarks::pubsub>,
                        extensions<delay, caps::c, carbons::received, carbons::sent, mam::result, muc::join,
                                   muc::user, markers::markable, markers::displayed, corrections::replace,
                                   retractions::retract, replies::reply>>;

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
  constexpr void replace(roster whole) {
    items.clear();
    for (roster_item& one : whole.items) {
      std::string key = one.jid;
      items.insert_or_assign(std::move(key), std::move(one));
    }
    ver = std::move(whole.ver);
  }

  // A push (2.1.6, 2.6.3): each item added or changed, or with subscription
  // remove dropped; and the version it brings.
  constexpr void apply(roster push) {
    for (roster_item& one : push.items) {
      if (one.subscription && spl::holds_alternative<tern::subscription::remove>(*one.subscription)) {
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
  constexpr bool apply(const basic::iq_set<X>& push) {
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

  constexpr bool required() const { return mandatory.has_value(); }
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
  std::optional<sm::feature> sm;
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
  malformed_stanza,  // a stanza did not fit its type: passed over, and the stream goes on
  resume_failed,     // the server would not resume the stream (XEP-0198)
  resource_limit,    // a configured session buffer limit was reached
  request_conflict,  // an id is already in flight or awaiting a late reply
  invalid_ack,       // acknowledgment exceeds the stanzas sent
  registration_asks,     // the server asks more than was answered: see registration
  registration_refused,  // the server would not make the account: see stanza
};

// A stanza that could not be read into its type: what it was, whose, and
// why. The stream goes on after it.
struct malformed_stanza {
  std::string element, type, id;
  std::optional<std::string> from;
  chevron::read_error why;
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
  // With malformed_stanza: the stanza, which the stream has gone on after.
  std::optional<malformed_stanza> malformed{};
  // With registration_asks: what the server asks, whole -- its form, the
  // pictures it names, the page to make the account on. Connecting again
  // with the answers, by the form's vars, makes it; a captcha's challenge,
  // a hidden field, is answered with this one's where it is given.
  std::optional<registration::asked> registration{};
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
  constexpr range_transport(Input& input, Out output) : input_(&input), output_(std::move(output)) {}
  constexpr Input& input() { return *input_; }
  constexpr void write(std::string_view bytes) { output_ = std::ranges::copy(bytes, std::move(output_)).out; }
  constexpr void flush() {}

 private:
  Input* input_;
  Out output_;
};

// Counts of retained values, plus a byte bound on serialized retransmissions.
// Zero allows no entries in that buffer. Raise these explicitly for workloads
// needing more; a slow consumer must not retain an unbounded session history.
struct buffer_limits {
  std::size_t pending_stanzas = 1024;
  std::size_t inbox_stanzas = 4096;
  std::size_t requests = 256;
  std::size_t abandoned_requests = 1024;
  std::size_t unacked_stanzas = 1024;
  std::size_t unacked_bytes = 16 * 1024 * 1024;
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
  // XEP-0198: acknowledge stanzas, and make the stream resumable, where the
  // server offers it.
  bool stream_management = false;
  // XEP-0030 and XEP-0115: what this client says it is. tern adds what it
  // does itself: disco, caps, ping.
  disco::info self = {.identities = {{.category = "client", .type = "pc", .name = "tern"}}};
  std::string caps_node = "https://github.com/j4niwzis/tern";
  // A get or a set nobody handles is answered with service-unavailable, as
  // RFC 6120, 8.2.3 requires a reply; with this, it is handed out by
  // receive() and stanzas() instead, and answering it is the caller's.
  bool deliver_unhandled = false;
  // The language of what this client says (RFC 6120, 4.7.4), on its stream.
  std::string lang = "en";
  buffer_limits buffers{};
  // XEP-0077: make the account first, with the username and the password,
  // and these answers to what else the server asks.
  std::optional<std::vector<registration::answer>> create = {};
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

// The caller's coroutines -- fibers, or threads -- as a session sees them:
// the one running, parking it until it is woken, and waking one. A
// request from a coroutine that is not the reader parks; the reader wakes
// it with its answer. Nothing is erased: the scheduler is a type of the
// session.
template <class S>
concept scheduler = std::equality_comparable<typename S::handle> && requires(S& s, typename S::handle h) {
  { s.current() } -> std::convertible_to<typename S::handle>;
  s.park();
  s.wake(h);
};

// One coroutine: a request reads for itself.
struct no_scheduler {
  using handle = int;
};

// Threads as the coroutines, running at once: the session is held by one of
// them at a time -- a turn, taken again by the one that has it -- and let go
// of while the reader waits for bytes, and while a request is parked. With
// the standard library only.
class thread_scheduler {
  struct turn {
    std::mutex lock;
    std::atomic<std::thread::id> owner{};
    int depth = 0;

    void enter() {
      if (owner.load() == std::this_thread::get_id()) {
        ++depth;
        return;
      }
      lock.lock();
      owner = std::this_thread::get_id();
      depth = 1;
    }
    void leave() {
      if (--depth == 0) {
        owner = std::thread::id();
        lock.unlock();
      }
    }
    int leave_all() {
      const int held = depth;
      depth = 0;
      owner = std::thread::id();
      lock.unlock();
      return held;
    }
    void resume(int held) {
      lock.lock();
      owner = std::this_thread::get_id();
      depth = held;
    }
  };

 public:
  using handle = std::binary_semaphore*;

  // The turn, while it lives.
  class held {
   public:
    explicit held(turn* t) : turn_(t) { turn_->enter(); }
    held(const held&) = delete;
    held& operator=(const held&) = delete;
    ~held() { turn_->leave(); }

   private:
    turn* turn_;
  };

  // The turn let go of, while it lives.
  class released {
   public:
    explicit released(turn* t) : turn_(t), depth_(t->leave_all()) {}
    released(const released&) = delete;
    released& operator=(const released&) = delete;
    ~released() { turn_->resume(depth_); }

   private:
    turn* turn_;
    int depth_;
  };

  held hold() const { return held(turn_.get()); }
  released release() const { return released(turn_.get()); }
  handle current() const { return &mine(); }
  void park() const {
    released away(turn_.get());
    mine().acquire();
  }
  void wake(handle one) const { one->release(); }

 private:
  static std::binary_semaphore& mine() {
    thread_local std::binary_semaphore self{0};
    return self;
  }
  std::shared_ptr<turn> turn_ = std::make_shared<turn>();
};

}  // namespace tern

namespace tern::detail {

// A number as decimal digits, in constant evaluation too.
template <std::integral N>
constexpr std::string decimal(N n) {
  char digits[24];
  char* end = std::to_chars(digits, digits + 24, n).ptr;
  return std::string(digits, end);
}

// What an inbox takes when it is not told what to take: everything.
struct everything {
  constexpr bool operator()(const auto&) const noexcept { return true; }
};

// A queue: std::deque at run time; a std::vector while the compiler
// evaluates, where deque cannot be used. Which is chosen when it is made,
// so the program runs on the deque as before.
//
// Each element is kept in a slot of its own. A container compares its own
// iterators, and when the element is a std::expected, expected is a template
// argument of the iterator type, so argument-dependent lookup finds
// expected's operator==(const expected&, const T2&) there too; libc++ 21 and
// 22 then check its constraint, *x == v, by asking the same question again,
// and stop with "satisfaction of constraint depends on itself". A class
// nested in this one is not a template argument of anything the containers
// compare.
template <class T>
class queue {
 public:
  constexpr queue() {
    if consteval {
      std::construct_at(&vector_);
      in_vector_ = true;
    } else {
      std::construct_at(&deque_);
    }
  }
  constexpr queue(queue&& other) : in_vector_(other.in_vector_) {
    if (in_vector_)
      std::construct_at(&vector_, std::move(other.vector_));
    else
      std::construct_at(&deque_, std::move(other.deque_));
  }
  queue(const queue&) = delete;
  queue& operator=(const queue&) = delete;
  queue& operator=(queue&&) = delete;
  constexpr ~queue() {
    if (in_vector_)
      std::destroy_at(&vector_);
    else
      std::destroy_at(&deque_);
  }

  constexpr bool empty() const { return in_vector_ ? vector_.empty() : deque_.empty(); }
  constexpr std::size_t size() const { return in_vector_ ? vector_.size() : deque_.size(); }
  constexpr T& front() { return in_vector_ ? vector_.front().value : deque_.front().value; }
  constexpr T& at(std::size_t i) { return in_vector_ ? vector_[i].value : deque_[i].value; }
  constexpr void pop_front() {
    if (in_vector_)
      vector_.erase(vector_.begin());
    else
      deque_.pop_front();
  }
  constexpr void push_back(T one) {
    if (in_vector_)
      vector_.push_back(slot{std::move(one)});
    else
      deque_.push_back(slot{std::move(one)});
  }
  // Each element given to pred once, in order; those it says so of taken out.
  template <class Pred>
  constexpr void remove_if(Pred pred) {
    auto of_value = [&pred](auto& one) { return pred(one.value); };
    if (in_vector_)
      std::erase_if(vector_, of_value);
    else
      std::erase_if(deque_, of_value);
  }
  template <class F>
  constexpr void for_each(F f) const {
    if (in_vector_)
      for (const slot& one : vector_)
        f(one.value);
    else
      for (const slot& one : deque_)
        f(one.value);
  }
  constexpr void assign(const std::vector<T>& from) {
    if (in_vector_)
      vector_.clear();
    else
      deque_.clear();
    for (const T& one : from)
      push_back(one);
  }
  constexpr std::vector<T> to_vector() const {
    std::vector<T> out;
    for_each([&](const T& one) { out.push_back(one); });
    return out;
  }

 private:
  struct slot {
    T value;
  };
  union {
    std::deque<slot> deque_;
    std::vector<slot> vector_;
  };
  bool in_vector_ = false;
};

// Runs at the end of its scope, however it ends: returned from, or unwound
// -- a coroutine killed where it waited included.
template <class F>
struct on_exit {
  F run;
  constexpr ~on_exit() { run(); }
};
template <class F>
on_exit(F) -> on_exit<F>;

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
  constexpr void start(R& range) {
    at_.reset();
    end_.reset();
    at_.emplace(std::ranges::begin(range));
    end_.emplace(std::ranges::end(range));
    parser_ = chevron::parser();
    finished_ = false;
    chunk_fed_ = false;
    depth_ = 0;
    piece_.clear();
  }

  // The stanza being read: its element and what says whose it is.
  struct top {
    std::string element, type, id;
    std::optional<std::string> from;
  };
  constexpr const top& current() const noexcept { return current_; }
  constexpr std::size_t depth() const noexcept { return depth_; }

  // After a stanza that could not be read: the rest of it passed over, back
  // to the stream's level.
  constexpr std::expected<void, chevron::error> skip_to_stream_level() {
    while (depth_ > 1) {
      auto one = next();
      if (!one)
        return std::unexpected(one.error());
      if (!*one)
        return {};
    }
    return {};
  }

  constexpr std::expected<std::optional<chevron::event>, chevron::error> next() {
    for (;;) {
      auto one = parser_.next();
      if (one && *one)
        track(**one);
      if (!one || *one)
        return one;
      if (finished_)
        return one;
      if constexpr (chunks) {
        // Incrementing an input iterator may fetch the next chunk. Defer
        // it until the parser needs more bytes, so control replies and TLS
        // upgrades happen before that fetch can block.
        if (chunk_fed_) { ++*at_; chunk_fed_ = false; }
        if (*at_ == *end_) {
          parser_.finish();
          finished_ = true;
        } else {
          parser_.feed(**at_);
          chunk_fed_ = true;
        }
      } else {
        // The end is asked about only where a byte is needed: over a socket,
        // asking is waiting for the peer, and after the '>' that ends a
        // stanza there may be nothing more for a long while.
        // What is taken is kept here, not on the stack: taking it may be cut
        // short, and what was taken is not lost.
        bool ended = false;
        for (;;) {
          if (*at_ == *end_) {
            ended = true;
            break;
          }
          const char unit = static_cast<char>(**at_);
          piece_.push_back(unit);
          ++*at_;
          if (unit == '>' || unit == '<')
            break;
        }
        const bool nothing = piece_.empty();
        parser_.feed(piece_);
        piece_.clear();
        if (ended && nothing) {
          parser_.finish();
          finished_ = true;
        }
      }
    }
  }

  // A new stream after authentication: a new document, from here on. What
  // came after the old document in the same chunk belongs to the new.
  constexpr void restart() {
    const std::string rest(parser_.unread());
    parser_ = chevron::parser();
    parser_.feed(rest);
    finished_ = false;
    depth_ = 0;
  }

 private:
  constexpr void track(const chevron::event& one) {
    if (const auto* start = spl::get_if<chevron::start_element>(&one)) {
      if (++depth_ == 2) {
        current_ = top{std::string(start->name.local), {}, {}, std::nullopt};
        for (const auto& attribute : start->attributes) {
          if (!attribute.name.uri.empty())
            continue;
          if (attribute.name.local == "type")
            current_.type = std::string(attribute.value);
          else if (attribute.name.local == "id")
            current_.id = std::string(attribute.value);
          else if (attribute.name.local == "from")
            current_.from = std::string(attribute.value);
        }
      }
    } else if (spl::holds_alternative<chevron::end_element>(one) && depth_ > 0) {
      --depth_;
    }
  }

  std::size_t depth_ = 0;
  top current_;
  std::string piece_;
  std::optional<iterator> at_;
  std::optional<sentinel> end_;
  chevron::parser parser_;
  bool finished_ = false;
  bool chunk_fed_ = false;
};

constexpr std::string escaped(std::string_view text) {
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

template <class E>
struct basic_request_error {
  request_code code;
  std::optional<connect_error> connection;
  std::optional<E> reply;
  // With bad_answer: the answer that did not fit its type, where it did not.
  std::optional<malformed_stanza> malformed{};
};
using request_error = basic_request_error<stanza_error>;

// The same failures, thrown by the calls that do not hand them back.
struct connect_failure : std::runtime_error {
  explicit connect_failure(connect_error what)
      : std::runtime_error("tern: the stream failed" + (what.detail.empty() ? std::string() : ": " + what.detail)),
        error(std::move(what)) {}
  connect_error error;
};

template <class E>
struct basic_request_failure : std::runtime_error {
  explicit basic_request_failure(basic_request_error<E> what)
      : std::runtime_error(what.code == request_code::connection    ? "tern: the stream failed during a request"
                           : what.code == request_code::error_reply ? "tern: the request was answered with an error"
                                                                    : "tern: the answer was not what was asked for"),
        error(std::move(what)) {}
  basic_request_error<E> error;
};
using request_failure = basic_request_failure<stanza_error>;

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
// answering<> of incoming queries; Scheduler the caller's coroutines.
template <class T, class P = standard, class Handlers = answering<>, class Scheduler = no_scheduler>
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
  // A request's failure, with the protocol's <error/>.
  using request_error = basic_request_error<typename P::stanza_error>;
  using request_failure = basic_request_failure<typename P::stanza_error>;

  constexpr session(T transport, Handlers handlers, Scheduler scheduler, buffer_limits limits = {})
      : transport_(static_cast<T&&>(transport)), handlers_(std::move(handlers)), scheduler_(std::move(scheduler)),
        limits_(limits) {
    source_.start(transport_.input());
  }

  // The full JID the server bound.
  constexpr const std::string& jid() const noexcept { return jid_; }

  // Whether the server said it versions rosters (RFC 6121, 2.6.1).
  constexpr bool roster_versioning() const noexcept { return roster_versioning_; }

  // XEP-0198: what resuming this stream needs, where it can be resumed.
  constexpr std::optional<sm_state> sm() const {
    [[maybe_unused]] auto held = hold();
    if (!sm_enabled_ || sm_id_.empty())
      return std::nullopt;
    return sm_state{sm_id_, jid_, inbound_, acked_, unacked_.to_vector()};
  }

  // XEP-0198: the server asked to say how many stanzas it has handled.
  constexpr void request_ack() {
    [[maybe_unused]] auto held = hold();
    if (sm_enabled_)
      write_raw("<r xmlns='urn:xmpp:sm:3'/>");
  }

  // XEP-0313: a page of the archive -- the messages that answer the query,
  // read straight into their types, and how the page ends.
  constexpr std::expected<archive_page, request_error> try_archive(mam::query query, std::optional<std::string> to = {}) {
    [[maybe_unused]] auto held = hold();
    static_assert(P::template answers_with<mam::fin> && P::extension::template can_hold<mam::result>,
                  "tern: archive() needs mam::fin among the answers<> and mam::result among the extensions<>");
    if (!query.queryid)
      query.queryid = "tern-mam-" + detail::decimal(++last_id_);
    const std::string queryid = *query.queryid;
    ++archiving_;
    detail::on_exit archived{[this] { --archiving_; }};
    auto fin = try_request<mam::query>({.to = std::move(to), .query = std::move(query)});
    if (!fin)
      return std::unexpected(std::move(fin).error());
    archive_page page{.fin = std::move(*fin)};
    // The results came as messages before the answer, and wait to be taken.
    pending_.remove_if([&](std::expected<stanza_t, connect_error>& entry) {
      bool taken = false;
      if (entry)
        if (auto* message = spl::get_if<message_t>(&*entry))
          spl::visit(
              [&](auto& one) {
                for (auto& carried : one.payload)
                  if (auto* result = carried.template get_if<mam::result>(); result && result->queryid == queryid) {
                    page.results.push_back(std::move(*result));
                    taken = true;
                  }
              },
              *message);
      return taken;
    });
    return page;
  }

  constexpr archive_page archive(mam::query query, std::optional<std::string> to = {}) {
    auto page = try_archive(std::move(query), std::move(to));
    if (!page)
      throw request_failure(std::move(page).error());
    return std::move(*page);
  }

  // The next stanza, as it arrives; nothing where the stream has ended
  // cleanly; or the error. Whoever calls this is the reader: an answer to a
  // request goes to it -- the coroutine parked on it woken -- a query to its
  // handler, and the rest comes out here.
  constexpr std::expected<std::optional<stanza_t>, connect_error> try_receive() {
    [[maybe_unused]] auto held = hold();
    if constexpr (concurrent)
      reader_ = scheduler_.current();
    receiving_ = true;
    // Whoever waits next reads, once this one is done.
    detail::on_exit over{[this] { hand_over(); }};
    for (;;) {
      if (!pending_.empty())
        return take_pending();
      if (failed_) {
        if (ended_)
          return std::optional<stanza_t>();
        return std::unexpected(*failed_);
      }
      if (reading_) {
        if constexpr (concurrent) {
          // An inbox's coroutine reads: woken when it hands out.
          receiver_waiting_ = scheduler_.current();
          detail::on_exit forget{[this] { receiver_waiting_.reset(); }};
          scheduler_.park();
          continue;
        } else {
          return std::unexpected(connect_error{connect_code::xml, "read while another reads", std::nullopt});
        }
      }
      read_and_route();
    }
  }

  // The next stanza, or nothing where the stream has ended cleanly; a failure
  // is thrown, a tern::connect_failure.
  constexpr std::optional<stanza_t> receive() {
    auto one = try_receive();
    if (!one)
      throw connect_failure(std::move(one).error());
    return std::move(*one);
  }

  // What a request comes to.
  using outcome = std::expected<result, request_error>;

  // A get or a set sent, and its answer awaited: the result, or the error,
  // with the same id, from the address asked (RFC 6120, 8.2.3). Whatever else
  // arrives in the meantime is kept, and handed out by receive() and stanzas()
  // afterwards, in order. An id is made up where the request has none.
  //
  // With a scheduler, a request from a coroutine other than the reader --
  // the one that connected, or last called receive() -- never reads: it
  // parks, and the reader wakes it when its answer comes, or the stream is
  // over. A coroutine killed while it is parked leaves nothing behind: its
  // answer is dropped when it comes. Timeouts and giving up are the
  // caller's; surviving them is the session's.
  template <iq_request Question>
  constexpr outcome try_request(Question question) {
    [[maybe_unused]] auto held = hold();
    auto started = start(std::move(question));
    if (!started)
      return std::unexpected(request_error{request_code::connection, std::move(started).error(), std::nullopt});
    const std::string id = std::move(*started);
    detail::on_exit forget{[this, &id] { abandon(id); }};
    for (;;) {
      if (auto done = finished(id))
        return std::move(*done);
      if constexpr (concurrent) {
        if (!reader_ || !(*reader_ == scheduler_.current())) {
          waiting_.at(id).waiter = scheduler_.current();
          scheduler_.park();
          continue;
        }
      }
      if (reading_) {
        waiting_.erase(id);
        return std::unexpected(request_error{
            request_code::connection,
            connect_error{connect_code::xml, "a request reading while another reads", std::nullopt},
            std::nullopt});
      }
      read_and_route();
    }
  }

  // The same, typed: a query that says what kind of request it is and what
  // comes back, asked of whom the request says:
  //   session.request<tern::query::version>({.to = "romeo@example.net/orchard"})
  // The answer is read straight into its type -- one of the protocol's
  // answers<> -- as the result arrives; void for an empty result.
  template <is_query Query>
  constexpr std::expected<typename Query::answer, request_error> try_request(asking<Query> question = {}) {
    return typed<Query>(try_request(sent_for(std::move(question))));
  }

  // The same, throwing: the answer, or a tern::request_failure.
  template <iq_request Question>
  constexpr result request(Question question) {
    auto answer = try_request(std::move(question));
    if (!answer)
      throw request_failure(std::move(answer).error());
    return std::move(*answer);
  }

  template <is_query Query>
  constexpr typename Query::answer request(asking<Query> question = {}) {
    auto answer = try_request<Query>(std::move(question));
    if (!answer)
      throw request_failure(std::move(answer).error());
    if constexpr (!std::is_void_v<typename Query::answer>)
      return std::move(*answer);
  }

  // A request answered: an empty result, or one carrying the answer given.
  template <iq_request Question>
  constexpr void answer(const Question& question) {
    send(basic::iq_result<chevron::tagged<chevron::any>>{.to = question.from, .id = question.id});
  }

  template <iq_request Question, chevron::described Answer>
  constexpr void answer(const Question& question, Answer carried) {
    basic::iq_result<chevron::tagged<Answer>> out{.to = question.from, .id = question.id};
    out.payload.emplace_back(std::move(carried));
    send(out);
  }

  // A request refused: the error, of type cancel, with a condition of the
  // stanza-errors namespace (RFC 6120, 8.3.3).
  template <iq_request Question>
  constexpr void refuse(const Question& question, std::string_view condition = "service-unavailable") {
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
  constexpr stanza_view stanzas() { return stanza_view(*this); }

  class inbox;

  // An inbox of one's own: every stanza that arrives while it is open, the
  // ones receive() would hand out -- messages, presences, requests nobody
  // handles -- in order, and taken out of it alone. Each coroutine that waits
  // for something opens one, and what one takes the others still have:
  //   auto from_romeo = session.open_inbox("romeo@example.net");
  //   const tern::stanza_t* one = from_romeo.next();   // parks till one comes
  // Given an address, only what comes from that bare JID is let in -- and
  // only that wakes a coroutine parked on it; next() may be told more
  // (next(is_chat), a lambda). A stanza that could not be read goes to
  // receive() only.
  constexpr inbox open_inbox(std::optional<std::string> from = {}) { return inbox(*this, std::move(from)); }

  // Each chunk is consumed by write() before it returns; flush() ends the
  // stanza. Stream management retains one encoded copy for retransmission.
  // Capacity errors happen before writing any part of that managed stanza.
  template <chevron::described Stanza>
  constexpr std::expected<void, connect_error> try_send(const Stanza& one) {
    [[maybe_unused]] auto held = hold();
    if (failed_) return std::unexpected(*failed_);
    auto xml = chevron::to_xml(one);
    if (!sm_enabled_) {
      // Coalesce markup and escape fragments without buffering the stanza.
      // Large borrowed runs go straight to the transport.
      std::array<char, 4096> buffer{};
      std::size_t used = 0;
      const auto flush = [&] {
        if (used) transport_.write(std::string_view(buffer.data(), std::exchange(used, 0)));
      };
      for (const auto chunk : xml.chunks()) {
        if (chunk.size() >= buffer.size()) {
          flush();
          transport_.write(chunk);
        } else {
          if (chunk.size() > buffer.size() - used) flush();
          std::ranges::copy(chunk, buffer.begin() + used);
          used += chunk.size();
        }
      }
      flush();
    } else {
      if (unacked_.size() >= limits_.unacked_stanzas)
        return capacity("unacknowledged stanzas");
      const std::size_t available = limits_.unacked_bytes - unacked_bytes_;
      out_.clear();
      for (const auto chunk : xml.chunks()) {
        if (chunk.size() > available - out_.size()) {
          out_.clear();
          return capacity("unacknowledged bytes");
        }
        out_.append(chunk);
      }
      unacked_.push_back(out_);
      unacked_bytes_ += out_.size();
      transport_.write(out_);
    }
    transport_.flush();
    return {};
  }

  template <chevron::described Stanza>
  constexpr void send(const Stanza& one) {
    if (auto sent = try_send(one); !sent) throw connect_failure(std::move(sent).error());
  }

  // Ends the stream from this side (RFC 6120, 4.4). What the server sends
  // before its own closing tag still arrives: go on reading stanzas() until
  // it ends, and only then close the connection.
  constexpr void close() {
    [[maybe_unused]] auto held = hold();
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
  // Broadcast, it says what this client can do (XEP-0115), where the
  // protocol's extensions have caps.
  constexpr void available(typename P::presence::available said = {}) {
    [[maybe_unused]] auto held = hold();
    if (!said.to) {
      announced_ = true;
      if constexpr (P::extension::template can_hold<caps::c>)
        said.payload.push_back(caps::c{.hash = "sha-1", .node = caps_node_, .ver = caps::ver_of(self_)});
    }
    send(said);
  }

  // Subscriptions (RFC 6121, 3), each to a bare JID as 3.1.1 wants: asking
  // for someone's presence, approving or denying their asking, and taking
  // one's own back. An address that is not one is an error, not sent.
  constexpr std::expected<void, jid_error> subscribe(std::string_view to) {
    return to_bare<typename P::presence::subscribe>(to);
  }
  constexpr std::expected<void, jid_error> approve(std::string_view to) {
    return to_bare<typename P::presence::subscribed>(to);
  }
  constexpr std::expected<void, jid_error> deny(std::string_view to) {
    return to_bare<typename P::presence::unsubscribed>(to);
  }
  constexpr std::expected<void, jid_error> unsubscribe(std::string_view to) {
    return to_bare<typename P::presence::unsubscribe>(to);
  }

  // The roster brought up to date (RFC 6121, 2.6). Where the server versions
  // rosters it is asked for from the version kept -- ver='' where there is
  // none -- and an empty answer leaves the cache as it is: nothing changed,
  // or the changes follow as pushes, for cache.apply(). Otherwise, and
  // wherever the whole roster comes, it replaces what was kept.
  constexpr std::expected<void, request_error> try_sync(roster_cache& cache) {
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

  // A contact added, or changed -- its name, its groups (RFC 6121, 2.3,
  // 2.4) -- by its bare JID; the server pushes the change after.
  constexpr std::expected<void, request_error> try_update_contact(roster_item item) {
    item.subscription.reset();  // the client does not set it (2.1.2.5), but for remove
    item.ask.reset();
    return try_request<query::roster_set>({.query = {.items = {std::move(item)}}});
  }
  constexpr void update_contact(roster_item item) {
    if (auto done = try_update_contact(std::move(item)); !done)
      throw request_failure(std::move(done).error());
  }

  // A contact taken out of the roster (2.5), subscriptions both ways ended.
  constexpr std::expected<void, request_error> try_remove_contact(std::string_view jid) {
    roster_item item{.jid = std::string(jid), .subscription = tern::subscription::remove{}};
    return try_request<query::roster_set>({.query = {.items = {std::move(item)}}});
  }
  constexpr void remove_contact(std::string_view jid) {
    if (auto done = try_remove_contact(jid); !done)
      throw request_failure(std::move(done).error());
  }

  // The same, throwing a tern::request_failure.
  constexpr void sync(roster_cache& cache) {
    if (auto done = try_sync(cache); !done)
      throw request_failure(std::move(done).error());
  }

  // For connect(): the transport, the reading it sets up, and what
  // negotiation found.
  constexpr transport_type& transport() noexcept { return transport_; }
  constexpr detail::source<std::remove_reference_t<decltype(std::declval<transport_type&>().input())>>& source() {
    return source_;
  }
  constexpr void bound_to(std::string jid) { jid_ = std::move(jid); }
  constexpr void versions_rosters(bool on) { roster_versioning_ = on; }
  constexpr void deliver_unhandled(bool deliver) { deliver_unhandled_ = deliver; }
  // The coroutine that connects reads, until another calls receive().
  constexpr void adopt_reader() {
    if constexpr (concurrent)
      reader_ = scheduler_.current();
  }
  constexpr void describes_itself(const options& how) {
    self_ = how.self;
    for (std::string_view var : {disco::info_namespace, caps::caps_namespace, std::string_view("urn:xmpp:ping")})
      if (std::ranges::find(self_.features, var, &disco::feature::var) == self_.features.end())
        self_.features.push_back({std::string(var)});
    caps_node_ = how.caps_node;
  }
  constexpr void stream_managed(const sm::enabled& enabled) {
    sm_enabled_ = true;
    if (enabled.resume.value_or(false))
      sm_id_ = enabled.id.value_or("");
  }
  // A stream resumed: the old one's count, and what it had not had
  // acknowledged sent again.
  constexpr std::expected<void, connect_error> resumed_from(const sm_state& state, std::uint32_t h) {
    const auto handled = static_cast<std::uint32_t>(h - state.acked);
    if (handled > state.unacked.size())
      return std::unexpected(connect_error{connect_code::invalid_ack, "resume acknowledgment", std::nullopt});
    if (state.unacked.size() - handled > limits_.unacked_stanzas)
      return capacity("unacknowledged stanzas");
    std::size_t bytes = 0;
    for (std::size_t i = handled; i < state.unacked.size(); ++i) {
      if (state.unacked[i].size() > limits_.unacked_bytes - bytes)
        return capacity("unacknowledged bytes");
      bytes += state.unacked[i].size();
    }
    sm_enabled_ = true;
    sm_id_ = state.id;
    inbound_ = state.inbound;
    acked_ = h;
    unacked_bytes_ = bytes;
    for (std::size_t i = handled; i < state.unacked.size(); ++i) unacked_.push_back(state.unacked[i]);
    unacked_.for_each([&](const std::string& again) { transport_.write(again); });
    transport_.flush();
    return {};
  }

 private:
  static constexpr bool concurrent = scheduler<Scheduler>;

  constexpr void write_raw(std::string_view text) {
    transport_.write(text);
    transport_.flush();
  }

  // The server has handled h stanzas of ours: those are dropped.
  constexpr void acknowledged(std::uint32_t h) {
    const auto count = static_cast<std::uint32_t>(h - acked_);
    if (count > unacked_.size()) {
      fail_session({connect_code::invalid_ack, "acknowledgment exceeds sent stanzas", std::nullopt});
      return;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
      unacked_bytes_ -= unacked_.front().size();
      unacked_.pop_front();
    }
    acked_ = h;
  }

  static constexpr std::unexpected<connect_error> capacity(std::string_view buffer) {
    return std::unexpected(connect_error{connect_code::resource_limit, std::string(buffer), std::nullopt});
  }

  // Incoming data cannot be silently discarded and then acknowledged on
  // resume. Preserve queued values, stop routing, and wake every waiter.
  constexpr void fail_session(connect_error error) {
    if (!failed_) failed_ = std::move(error);
    if (failed_->code == connect_code::resource_limit || failed_->code == connect_code::invalid_ack)
      sm_id_.clear();
    for (auto& entry : waiting_) wake(entry.second);
    if constexpr (concurrent) {
      for (inbox* one : inboxes_)
        if (one->waiter_) scheduler_.wake(*std::exchange(one->waiter_, std::nullopt));
      if (receiver_waiting_) scheduler_.wake(*std::exchange(receiver_waiting_, std::nullopt));
    }
  }

  constexpr void queue_pending(std::expected<stanza_t, connect_error> one) {
    if (pending_.size() >= limits_.pending_stanzas) {
      fail_session(capacity("pending stanzas").error());
      return;
    }
    pending_.push_back(std::move(one));
  }


  // What tern answers itself, where no handler took the query: disco (with
  // this client's info, for its caps node too), and ping.
  template <class Question, class Query>
  constexpr bool answered_by_tern(const Question& question, const Query& query) {
    if constexpr (std::same_as<Query, query::disco_info>) {
      disco::info out = self_;
      out.node = query.node;
      answer(question, std::move(out));
      return true;
    } else if constexpr (std::same_as<Query, query::disco_items>) {
      answer(question, disco::items{.node = query.node});
      return true;
    } else if constexpr (std::same_as<Query, query::ping>) {
      answer(question);
      return true;
    } else {
      return false;
    }
  }

  // A request sent, and its slot made: its id.
  template <iq_request Question>
  constexpr std::expected<std::string, connect_error> start(Question question) {
    if (failed_) return std::unexpected(*failed_);
    if (waiting_.size() >= limits_.requests) return capacity("requests in flight");
    const auto occupied = [&](const std::string& id) {
      bool abandoned = false;
      abandoned_.for_each([&](const std::string& old) { abandoned |= old == id; });
      return waiting_.contains(id) || abandoned;
    };
    if (question.id.empty()) {
      do { question.id = "tern-" + detail::decimal(++last_id_); } while (occupied(question.id));
    } else if (occupied(question.id)) {
      return std::unexpected(connect_error{connect_code::request_conflict, question.id, std::nullopt});
    }
    std::string id = question.id;
    waiting_.emplace(id, slot{question.to, std::nullopt});
    bool sent = false;
    detail::on_exit rollback{[&] { if (!sent) waiting_.erase(id); }};
    if (auto written = try_send(question); !written) return std::unexpected(std::move(written).error());
    sent = true;
    return id;
  }

  // Keep a bounded history of cancellations. A reply older than this window
  // is an unsolicited stanza, rather than retaining tombstones forever.
  constexpr void abandon(const std::string& id) {
    if (waiting_.erase(id) == 0 || limits_.abandoned_requests == 0) return;
    if (abandoned_.size() >= limits_.abandoned_requests) abandoned_.pop_front();
    abandoned_.push_back(id);
  }
  constexpr bool drop_abandoned(const std::string& id) {
    bool found = false;
    abandoned_.remove_if([&](const std::string& old) {
      if (old != id) return false;
      found = true;
      return true;
    });
    return found;
  }

  // What the request came to, where it has come to something; its slot
  // freed then.
  constexpr std::optional<outcome> finished(const std::string& id) {
    const auto found = waiting_.find(id);
    if (found == waiting_.end())
      return std::nullopt;
    if (found->second.answer) {
      auto answer = std::move(*found->second.answer);
      waiting_.erase(found);
      if (auto* refused = spl::get_if<error>(&answer))
        return outcome(std::unexpected(request_error{request_code::error_reply, std::nullopt, std::move(refused->reason)}));
      return outcome(spl::get<result>(std::move(answer)));
    }
    if (found->second.malformed) {
      auto bad = std::move(*found->second.malformed);
      waiting_.erase(found);
      return outcome(std::unexpected(request_error{request_code::bad_answer, std::nullopt, std::nullopt, std::move(bad)}));
    }
    if (failed_) {
      waiting_.erase(found);
      return outcome(std::unexpected(request_error{request_code::connection, *failed_, std::nullopt}));
    }
    return std::nullopt;
  }

  // A query's iq.
  template <is_query Query>
  static constexpr auto sent_for(asking<Query> question) {
    using carried = chevron::tagged<Query>;
    using sent_type =
        std::conditional_t<is_get_kind<typename Query::kind>, basic::iq_get<carried>, basic::iq_set<carried>>;
    sent_type sent{.to = std::move(question.to), .lang = std::move(question.lang)};
    sent.payload.emplace_back(std::move(question.query));
    return sent;
  }

  // A result as the query's answer, read straight into its type.
  template <class Query>
  static constexpr std::expected<typename Query::answer, request_error> typed(outcome answer) {
    if (!answer)
      return std::unexpected(std::move(answer).error());
    if constexpr (std::is_void_v<typename Query::answer>) {
      return {};
    } else {
      static_assert(P::template answers_with<typename Query::answer>,
                    "tern: the query's answer type is not among the protocol's answers<>");
      if (!answer->payload.empty())
        if (auto* got = answer->payload.front().template get_if<typename Query::answer>())
          return std::move(*got);
      return std::unexpected(request_error{request_code::bad_answer, std::nullopt, std::nullopt});
    }
  }

  // One stanza read and sent where it goes: an answer to its request, a
  // query to its handler, the rest kept to hand out.
  constexpr void read_and_route() {
    auto one = read_locked();
    if (!one) {
      if (one.error().code == connect_code::malformed_stanza && !settled(*one.error().malformed))
        queue_pending(std::unexpected(one.error()));
    } else if (*one) {
      try {
        if (!claimed(**one) && !dispatched(**one)) hand_out(std::move(**one));
      } catch (const connect_failure& failed) {
        // An automatic reply can hit the outgoing limit too. Report it
        // through try_receive/try_request and wake their other waiters.
        fail_session(failed.error);
      }
    }
  }

  // A stanza for whoever takes stanzas: receive(), where anyone receives, or
  // nobody has opened an inbox -- or an archive query waits for it -- and
  // each inbox open. Copied only where both want it.
  constexpr void hand_out(stanza_t one) {
    const bool to_receive = inboxes_.empty() || receiving_ || archiving_ > 0;
    if ((to_receive && pending_.size() >= limits_.pending_stanzas) ||
        (!inboxes_.empty() && log_.size() >= limits_.inbox_stanzas)) {
      fail_session(capacity(to_receive && pending_.size() >= limits_.pending_stanzas
                                ? "pending stanzas" : "inbox stanzas").error());
      return;
    }
    if (!inboxes_.empty()) {
      logged entry{.seq = next_seq_++, .from = {}, .stanza = nullptr};
      if (const auto from = from_of(one))
        entry.from = bare_of(*from);
      entry.stanza = to_receive ? std::make_unique<stanza_t>(one) : std::make_unique<stanza_t>(std::move(one));
      log_.push_back(std::move(entry));
      wake_inboxes(log_.at(log_.size() - 1).from);
    }
    if (to_receive) {
      pending_.push_back(std::move(one));
      if constexpr (concurrent)
        if (receiver_waiting_)
          scheduler_.wake(*std::exchange(receiver_waiting_, std::nullopt));
    }
  }

  // Whom a stanza is from, as it says.
  static constexpr std::optional<std::string_view> from_of(const stanza_t& one) {
    return spl::visit(
        [](const auto& kind) {
          return spl::visit(
              [](const auto& stanza) -> std::optional<std::string_view> {
                if constexpr (requires { stanza.from; })
                  if (stanza.from)
                    return std::string_view(*stanza.from);
                return std::nullopt;
              },
              kind);
        },
        one);
  }

  // An address's bare JID, prepared as RFC 7622 says, so that two ways of
  // writing one address are one; while the compiler evaluates, where the
  // preparation cannot run, as it is written.
  static constexpr std::string bare_of(std::string_view address) {
    if !consteval {
      if (auto parsed = jid::parse(address))
        return parsed->bare().str();
    }
    return std::string(address.substr(0, address.find('/')));
  }

  // The coroutines parked on an inbox that lets this in, woken.
  constexpr void wake_inboxes([[maybe_unused]] const std::string& from) {
    if constexpr (concurrent)
      for (inbox* one : inboxes_)
        if (one->waiter_ && (!one->from_ || *one->from_ == from))
          scheduler_.wake(*std::exchange(one->waiter_, std::nullopt));
  }

  // Nobody reads, and somebody waits: the first of them woken, to read.
  constexpr void hand_over() {
    if constexpr (concurrent) {
      if (reading_)
        return;
      for (inbox* one : inboxes_)
        if (one->waiter_) {
          scheduler_.wake(*std::exchange(one->waiter_, std::nullopt));
          return;
        }
      if (receiver_waiting_)
        scheduler_.wake(*std::exchange(receiver_waiting_, std::nullopt));
    }
  }

  // What every inbox has taken, or has not been open for, let go of.
  constexpr void trim_log() {
    std::uint64_t kept = next_seq_;
    for (const inbox* one : inboxes_)
      kept = std::min(kept, one->held_ ? one->at_ - 1 : one->at_);
    while (!log_.empty() && log_.front().seq < kept)
      log_.pop_front();
  }

  constexpr std::expected<std::optional<stanza_t>, connect_error> take_pending() {
    auto one = std::move(pending_.front());
    pending_.pop_front();
    if (!one)
      return std::unexpected(std::move(one).error());
    return std::optional<stanza_t>(std::move(*one));
  }

  // A stanza that could not be read, where it belongs: an answer to the
  // request it answers -- by id, from the address asked -- and a request
  // refused with bad-request, as every request gets a reply (RFC 6120,
  // 8.2.3). True where it has been given to a request; otherwise it is the
  // caller's to hear of.
  constexpr bool settled(const malformed_stanza& bad) {
    if (bad.element != "iq")
      return false;
    if (bad.type == "result" || bad.type == "error") {
      const auto found = waiting_.find(bad.id);
      if (found == waiting_.end())
        return drop_abandoned(bad.id);  // its request is gone: dropped
      if (found->second.answer || found->second.malformed)
        return false;
      if (found->second.to && bad.from != found->second.to)
        return false;
      found->second.malformed = bad;
      wake(found->second);
      return true;
    }
    if (bad.type == "get" || bad.type == "set")
      send(basic::iq_error<chevron::tagged<chevron::any>>{
          .to = bad.from,
          .id = bad.id,
          .reason = stanza_error{.type = error_types::modify{}, .what = stanza_condition_t(conditions::bad_request{})}});
    return false;
  }

  template <class Presence>
  constexpr std::expected<void, jid_error> to_bare(std::string_view to) {
    auto address = jid::parse(to);
    if (!address)
      return std::unexpected(address.error());
    send(Presence{.to = address->bare().str()});
    return {};
  }

  // One reader at a time; a failure is everyone's.
  constexpr std::expected<std::optional<stanza_t>, connect_error> read_locked() {
    reading_ = true;
    detail::on_exit done_reading{[this] { reading_ = false; }};
    std::expected<std::optional<stanza_t>, connect_error> one;
    for (;;) {
      {
        [[maybe_unused]] auto away = release();  // others send while this waits for bytes
        one = read_one_stanza();
      }
      const bool control = std::exchange(acks_read_, false);
      apply_acks();  // under the turn, before waiting for another byte
      if (failed_) return std::unexpected(*failed_);
      if (!control) break;
    }
    if (sm_enabled_ && ((one && *one) || (!one && one.error().code == connect_code::malformed_stanza)))
      ++inbound_;
    if (!one && one.error().code != connect_code::malformed_stanza) {
      fail_session(one.error());
    } else if (one && !*one) {
      ended_ = true;
      fail_session({connect_code::closed, "", std::nullopt});
    }
    return one;
  }

  // A query given to the first handler that takes its type; false where none
  // does.
  template <class Question, class Query>
  constexpr bool handled(const Question& question, const Query& query) {
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
  constexpr bool dispatched(stanza_t& one) {
    auto* kind = spl::get_if<iq_t>(&one);
    if (!kind)
      return false;
    return spl::visit(
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
              bool taken = false;
              std::as_const(question.payload.front()).with([&]<class Query>(const Query& query) {
                if constexpr (!std::same_as<Query, chevron::any>)
                  taken = handled(question, query) || answered_by_tern(question, query);
              });
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
  constexpr bool claimed(stanza_t& one) {
    auto* kind = spl::get_if<iq_t>(&one);
    if (!kind)
      return false;
    return spl::visit(
        [&](auto& answer) {
          using type = std::remove_cvref_t<decltype(answer)>;
          if constexpr (std::same_as<type, result> || std::same_as<type, error>) {
            const auto found = waiting_.find(answer.id);
            if (found == waiting_.end())
              return drop_abandoned(answer.id);  // its request is gone: dropped
            if (found->second.answer || found->second.malformed)
              return false;
            if (found->second.to && answer.from != found->second.to)
              return false;
            found->second.answer.emplace(std::move(answer));
            wake(found->second);
            return true;
          } else {
            return false;
          }
        },
        *kind);
  }

  // One stanza; XEP-0198's <r/> answered and <a/> taken on the way, and each
  // stanza read, fitting its type or not, counted.
  constexpr std::expected<std::optional<stanza_t>, connect_error> read_one_stanza() {
    auto one = P::read_one(source_);
    if (one) {
      if (spl::holds_alternative<sm::r>(*one)) {
        ++acks_asked_;
        acks_read_ = true;
        return std::nullopt;
      }
      if (const auto* ack = spl::get_if<sm::a>(&*one)) {
        acked_h_ = ack->h;
        acks_read_ = true;
        return std::nullopt;
      }
    }
    // A stream error ends the stream: its condition is the failure.
    if (one) {
      if (const auto* ended = spl::get_if<stream_error>(&*one))
        return std::unexpected(connect_error{connect_code::stream_error, std::string(ended->condition()),
                                             std::nullopt, ended->other_host()});
      return spl::visit(
          [](auto&& value) {
            using type = std::remove_cvref_t<decltype(value)>;
            if constexpr (std::same_as<type, stream_error> || std::same_as<type, sm::r> || std::same_as<type, sm::a>)
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
    // XML that is not well-formed ends the stream; a stanza that is, but does
    // not fit its type, is passed over, and the stream goes on.
    if (failure.parse_error || source_.depth() < 2)
      return std::unexpected(connect_error{connect_code::xml, failure.where, std::nullopt});
    const auto stanza = source_.current();
    if (auto skipped = source_.skip_to_stream_level(); !skipped)
      return std::unexpected(connect_error{connect_code::xml, failure.where, std::nullopt});
    return std::unexpected(
        connect_error{connect_code::malformed_stanza, failure.where, std::nullopt, std::nullopt, std::nullopt,
                      malformed_stanza{stanza.element, stanza.type, stanza.id, stanza.from, failure}});
  }

  T transport_;
  Handlers handlers_;
  mutable Scheduler scheduler_;
  detail::source<std::remove_reference_t<decltype(std::declval<transport_type&>().input())>> source_;
  buffer_limits limits_{};
  std::string out_;
  std::string jid_;
  bool roster_versioning_ = false;
  detail::queue<std::expected<stanza_t, connect_error>> pending_;
  std::size_t last_id_ = 0;
  // The requests in flight, by id: whom the answer must come from, and the
  // answer once somebody has read it.
  struct slot {
    std::optional<std::string> to;
    std::optional<spl::variant<result, error>> answer;
    std::optional<malformed_stanza> malformed{};
    std::optional<typename Scheduler::handle> waiter{};  // the coroutine parked on it
  };

  // The scheduler's turn, where it has one, while what is returned lives;
  // and the turn let go of.
  constexpr auto hold() const {
    if constexpr (requires { scheduler_.hold(); })
      return scheduler_.hold();
    else
      return 0;
  }
  constexpr auto release() const {
    if constexpr (requires { scheduler_.release(); })
      return scheduler_.release();
    else
      return 0;
  }

  // What XEP-0198 asked while the turn was let go of, done with it back.
  constexpr void apply_acks() {
    if (acked_h_)
      acknowledged(*std::exchange(acked_h_, std::nullopt));
    for (; acks_asked_ > 0; --acks_asked_)
      if (sm_enabled_ && !failed_)
        write_raw("<a xmlns='urn:xmpp:sm:3' h='" + detail::decimal(inbound_) + "'/>");
  }

  // The coroutine parked on a request, where there is one, to run again.
  constexpr void wake(slot& waiting) {
    if constexpr (concurrent)
      if (waiting.waiter)
        scheduler_.wake(*std::exchange(waiting.waiter, std::nullopt));
  }
  std::map<std::string, slot> waiting_;
  // The inboxes' log: what arrived since the oldest place one of them is at,
  // each stanza once, where it stays while an inbox holds it.
  struct logged {
    std::uint64_t seq;
    std::string from;  // its bare JID, prepared
    std::unique_ptr<stanza_t> stanza;
  };
  detail::queue<logged> log_;
  std::uint64_t next_seq_ = 0;
  std::vector<inbox*> inboxes_;
  bool receiving_ = false;         // somebody has called receive()
  std::size_t archiving_ = 0;      // archive queries waiting for their results
  std::optional<typename Scheduler::handle> receiver_waiting_;
  bool reading_ = false;
  std::optional<connect_error> failed_;
  bool deliver_unhandled_ = false;
  bool announced_ = false;
  bool acks_read_ = false;
  bool ended_ = false;
  std::optional<std::uint32_t> acked_h_;
  std::uint32_t acks_asked_ = 0;
  detail::queue<std::string> abandoned_;  // bounded cancellation history
  std::optional<typename Scheduler::handle> reader_;  // the coroutine that reads
  disco::info self_;
  std::string caps_node_;
  bool sm_enabled_ = false;
  std::string sm_id_;
  std::uint32_t inbound_ = 0;
  std::uint32_t acked_ = 0;
  detail::queue<std::string> unacked_;
  std::size_t unacked_bytes_ = 0;
};

template <class T, class P, class Handlers, class Scheduler>
class session<T, P, Handlers, Scheduler>::stanza_view : public std::ranges::view_interface<stanza_view> {
 public:
  class iterator {
   public:
    using value_type = std::expected<stanza_t, connect_error>;
    using difference_type = std::ptrdiff_t;
    using iterator_concept = std::input_iterator_tag;

    iterator() = default;
    constexpr explicit iterator(stanza_view* view) : view_(view) { view_->advance(); }
    iterator(iterator&&) = default;
    iterator& operator=(iterator&&) = default;

    constexpr value_type& operator*() const { return *view_->current_; }
    constexpr iterator& operator++() {
      view_->advance();
      return *this;
    }
    constexpr void operator++(int) { ++*this; }
    friend constexpr bool operator==(const iterator& one, std::default_sentinel_t) { return !one.view_->current_; }

   private:
    stanza_view* view_ = nullptr;
  };

  constexpr explicit stanza_view(session& s) : session_(&s) {}
  constexpr iterator begin() { return iterator(this); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }

 private:
  constexpr void advance() {
    if (failed_) {
      current_.reset();
      return;
    }
    auto next = session_->try_receive();
    if (!next) {
      // A stanza passed over is reported, and the stanzas go on.
      failed_ = next.error().code != connect_code::malformed_stanza;
      current_.emplace(std::unexpected(next.error()));
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

template <class T, class P, class Handlers, class Scheduler>
class session<T, P, Handlers, Scheduler>::inbox {
 public:
  // Open from now on: what arrived before is not in it.
  constexpr inbox(session& s, std::optional<std::string> from) : session_(&s) {
    [[maybe_unused]] auto held = s.hold();
    if (from)
      from_ = session::bare_of(*from);
    at_ = s.next_seq_;
    s.inboxes_.push_back(this);
  }
  inbox(const inbox&) = delete;
  inbox& operator=(const inbox&) = delete;

  constexpr ~inbox() {
    [[maybe_unused]] auto held = session_->hold();
    std::erase(session_->inboxes_, this);
    session_->trim_log();
    session_->hand_over();
  }

  // The next stanza in it that filter takes -- the rest passed over, for
  // this inbox only -- kept for the caller until the next call, or the
  // inbox's end; nullptr where the stream has ended cleanly; or the error.
  // Where nothing has come, it reads, or parks while another coroutine does.
  template <class Filter = detail::everything>
    requires std::predicate<Filter&, const stanza_t&>
  constexpr std::expected<const stanza_t*, connect_error> try_next(Filter filter = {}) {
    session& s = *session_;
    [[maybe_unused]] auto held = s.hold();
    held_ = false;
    detail::on_exit over{[&s] {
      s.trim_log();
      s.hand_over();
    }};
    for (;;) {
      while (at_ < s.next_seq_) {
        auto& entry = s.log_.at(static_cast<std::size_t>(at_ - s.log_.front().seq));
        ++at_;
        if ((!from_ || *from_ == entry.from) && std::invoke(filter, std::as_const(*entry.stanza))) {
          held_ = true;
          return entry.stanza.get();
        }
      }
      s.trim_log();
      if (s.failed_) {
        if (s.ended_)
          return nullptr;
        return std::unexpected(*s.failed_);
      }
      if (s.reading_) {
        if constexpr (concurrent) {
          waiter_ = s.scheduler_.current();
          detail::on_exit forget{[this] { waiter_.reset(); }};
          s.scheduler_.park();
          continue;
        } else {
          return std::unexpected(connect_error{connect_code::xml, "read while another reads", std::nullopt});
        }
      }
      s.read_and_route();
    }
  }

  // The same, throwing a tern::connect_failure.
  template <class Filter = detail::everything>
    requires std::predicate<Filter&, const stanza_t&>
  constexpr const stanza_t* next(Filter filter = {}) {
    auto one = try_next(std::move(filter));
    if (!one)
      throw connect_failure(std::move(one).error());
    return *one;
  }

  // The bare JID it lets in, where it was given one.
  constexpr const std::optional<std::string>& from() const noexcept { return from_; }

 private:
  friend class session;
  session* session_;
  std::optional<std::string> from_;
  std::uint64_t at_ = 0;      // the place of the next stanza for it
  bool held_ = false;         // the one before at_ is the caller's still
  std::optional<typename Scheduler::handle> waiter_{};
};

}  // namespace tern

namespace tern::detail {

template <class Session>
class negotiation {
  using transport_type = typename Session::transport_type;

 public:
  constexpr negotiation(Session& s, const options& o, const sm_state* resume = nullptr) : s_(s), o_(o), resume_(resume) {}

  constexpr std::expected<void, connect_error> run() {
    bool secured = false;
    if constexpr (secured_transport<transport_type>)
      secured = s_.transport().secured();
    for (;;) {
      if (auto opened = open(); !opened)
        return opened;
      auto next = chevron::read_one_of<features, stream_error>(s_.source());
      if (!next)
        return fail(connect_code::xml, "stream features: " + next.error().where);
      if (const auto* ended = spl::get_if<stream_error>(&*next))
        return std::unexpected(connect_error{connect_code::stream_error, std::string(ended->condition()),
                                             std::nullopt, ended->other_host()});
      const features* offered = &spl::get<features>(*next);
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
      // Over a transport that can speak TLS, nothing goes on without it --
      // not even SCRAM -- unless plain was chosen: a server, or anyone on the
      // way, that leaves <starttls/> out of its features would otherwise have
      // the login and the whole session in the clear (STARTTLS stripping).
      if constexpr (tls_transport<transport_type>) {
        if (!secured && !o_.plain_without_tls)
          return fail(connect_code::tls_required, "the server offered no TLS");
      }
      if (o_.create && !registered_) {
        if (!secured && !o_.plain_without_tls)
          return fail(connect_code::tls_required, "to register");
        if (auto made = register_account(*o_.create); !made)
          return made;
        registered_ = true;
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
      roster_versioning = offered->ver.has_value();
      if (resume_)
        return resume();
      if (!offered->bind)
        return fail(connect_code::bind_refused, "no bind offered");
      if (auto bound = bind(); !bound)
        return bound;
      if (o_.stream_management && offered->sm) {
        write("<enable xmlns='urn:xmpp:sm:3' resume='true'/>");
        auto answer = chevron::read_one_of<sm::enabled, sm::failed>(s_.source());
        if (!answer)
          return fail(connect_code::xml, "stream management: " + answer.error().where);
        if (const auto* on = spl::get_if<sm::enabled>(&*answer))
          enabled = *on;
      }
      return {};
    }
  }

  std::string jid;
  bool roster_versioning = false;
  std::optional<sm::enabled> enabled;  // XEP-0198, where it was enabled
  std::uint32_t resumed_h = 0;         // where resumed: what the server had handled

 private:
  constexpr std::unexpected<connect_error> fail(connect_code code, std::string detail) const {
    return std::unexpected(connect_error{code, std::move(detail), std::nullopt});
  }

  constexpr void write(std::string_view text) {
    s_.transport().write(text);
    s_.transport().flush();
  }

  // Our stream header, then the server's.
  constexpr std::expected<void, connect_error> open() {
    write("<?xml version='1.0'?><stream:stream to='" + escaped(o_.domain) + "' from='" +
          escaped(o_.username + "@" + o_.domain) + "' version='1.0' xml:lang='" + escaped(o_.lang) + "' xmlns='" +
          std::string(client_namespace) +
          "' xmlns:stream='" + std::string(stream_namespace) + "'>");
    auto header = s_.source().next();
    if (!header)
      return fail(connect_code::xml, "stream header");
    if (!*header)
      return fail(connect_code::closed, "before the stream header");
    const auto* start = spl::get_if<chevron::start_element>(&**header);
    if (!start || start->name.uri != stream_namespace || start->name.local != "stream")
      return fail(connect_code::xml, "not a stream header");
    return {};
  }

  // An element answering negotiation: its name, and its text.
  constexpr std::expected<nonza, connect_error> read_nonza() {
    auto first = s_.source().next();
    if (!first || !*first)
      return fail(connect_code::closed, "while negotiating");
    const auto* start = spl::get_if<chevron::start_element>(&**first);
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
      if (const auto* inner = spl::get_if<chevron::start_element>(&**next)) {
        if (depth == 1) {
          ++children;
          if (out.first_child.empty())
            out.first_child = std::string(inner->name.local);
        }
        ++depth;
      } else if (spl::holds_alternative<chevron::end_element>(**next)) {
        --depth;
      } else if (depth == 1) {
        out.text += spl::get<chevron::text>(**next).content;
      } else if (depth == 2 && children == 1) {
        first_text += spl::get<chevron::text>(**next).content;
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

  constexpr std::expected<void, connect_error> authenticate(const std::vector<std::string>& offered, bool secured) {
    const auto has = [&](std::string_view name) { return std::ranges::find(offered, name) != offered.end(); };
    // A random nonce where none is given -- but for the compiler, which has
    // no randomness, and runs the session only to test it.
    std::string nonce = o_.nonce;
    if (nonce.empty()) {
      if consteval {
        nonce = "tern-constant-evaluation";
      } else {
        nonce = sasl::random_nonce();
      }
    }
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

  constexpr void auth(std::string_view mechanism, std::string_view initial) {
    write("<auth xmlns='" + std::string(sasl_namespace) + "' mechanism='" + std::string(mechanism) + "'>" +
          crypto::base64_encode(crypto::to_bytes(initial)) + "</auth>");
  }

  static constexpr std::string text_of(std::string_view base64) {
    const auto decoded = crypto::base64_decode(base64);
    return decoded ? std::string(decoded->begin(), decoded->end()) : std::string();
  }

  template <class Scram>
  constexpr std::expected<void, connect_error> scram(std::string_view mechanism, const std::string& nonce,
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

  // XEP-0198, 5: the old stream taken up again, instead of binding.
  constexpr std::expected<void, connect_error> resume() {
    write("<resume xmlns='urn:xmpp:sm:3' h='" + detail::decimal(resume_->inbound) + "' previd='" +
          escaped(resume_->id) + "'/>");
    auto answer = chevron::read_one_of<sm::resumed, sm::failed>(s_.source());
    if (!answer)
      return fail(connect_code::xml, "resume: " + answer.error().where);
    if (const auto* refused = spl::get_if<sm::failed>(&*answer))
      return fail(connect_code::resume_failed,
                  refused->what ? std::string(condition_name(*refused->what)) : std::string());
    resumed_h = spl::get<sm::resumed>(*answer).h;
    jid = resume_->jid;
    return {};
  }

  // The answer read straight into its type: the JID bound, or the error.
  constexpr std::expected<void, connect_error> bind() {
    std::string request = "<iq type='set' id='bind_1'><bind xmlns='" + std::string(bind_namespace) + "'>";
    if (o_.resource)
      request += "<resource>" + escaped(*o_.resource) + "</resource>";
    write(request + "</bind></iq>");
    auto read = chevron::read_one_of<basic::iq_result<chevron::tagged<bind_result, chevron::any>>,
                                     basic::iq_error<chevron::tagged<chevron::any>, stanza_error>>(s_.source());
    if (!read)
      return fail(connect_code::xml, "bind: " + read.error().where);
    if (const auto* refused = spl::get_if<1>(&*read))
      return std::unexpected(connect_error{connect_code::bind_refused, std::string(refused->reason.condition()),
                                           std::nullopt, std::nullopt, refused->reason});
    const auto& answer = spl::get<0>(*read);
    if (answer.id != "bind_1")
      return fail(connect_code::bind_refused, "not the answer to the bind");
    if (!answer.payload.empty())
      if (const bind_result* bound = answer.payload.front().template get_if<bind_result>())
        jid = bound->jid.value_or("");
    if (jid.empty())
      return fail(connect_code::bind_refused, "no JID in the answer");
    return {};
  }

  // XEP-0077, 3.1: what the server asks, then the answers -- the form's
  // fields filled where it sent one, else the old fields.
  constexpr std::expected<void, connect_error> register_account(const std::vector<registration::answer>& answers) {
    write("<iq type='get' id='register_1'><query xmlns='" + std::string(registration::register_namespace) +
          "'/></iq>");
    auto read = chevron::read_one_of<basic::iq_result<chevron::tagged<registration::asked, chevron::any>>,
                                     basic::iq_error<chevron::tagged<chevron::any>, stanza_error>>(s_.source());
    if (!read)
      return fail(connect_code::xml, "register: " + read.error().where);
    if (const auto* refused = spl::get_if<1>(&*read))
      return refusal(refused->reason);
    const auto& answer = spl::get<0>(*read);
    const registration::asked* asked =
        answer.payload.empty() ? nullptr : answer.payload.front().template get_if<registration::asked>();
    if (!asked)
      return fail(connect_code::registration_refused, "no registration offered");
    const auto given = [&](std::string_view var) -> std::optional<std::string> {
      if (var == "username")
        return o_.username;
      if (var == "password")
        return o_.password;
      const auto found = std::ranges::find(answers, var, &registration::answer::var);
      if (found == answers.end())
        return std::nullopt;
      return found->value;
    };
    const auto asks_more = [&] {
      return std::unexpected(connect_error{.code = connect_code::registration_asks,
                                           .detail = asked->instructions.value_or(""),
                                           .sasl = std::nullopt,
                                           .registration = *asked});
    };
    std::string request;
    if (asked->form) {
      // Each field with a var sent back: its answer, else what the form
      // holds; one required and left empty is asked of the caller.
      const auto filled = [&](const data_form::field& one) {
        return given(*one.var).transform([](std::string value) { return std::vector{std::move(value)}; })
            .value_or(one.value);
      };
      // Not const: a filter is walked through itself, which keeps where it begins.
      auto sent = asked->form->fields |
                        std::views::filter([](const data_form::field& one) {
                          return one.var.has_value() && one.type != std::optional<std::string>("fixed");
                        });
      const bool missing = std::ranges::any_of(sent, [&](const data_form::field& one) {
        return one.required && std::ranges::all_of(filled(one), [](const std::string& value) { return value.empty(); });
      });
      if (missing)
        return asks_more();
      const auto field_sent = [&](const data_form::field& one) {
        return "<field var='" + escaped(*one.var) + "'>" +
               (filled(one) |
                std::views::transform([](const std::string& value) { return "<value>" + escaped(value) + "</value>"; }) |
                std::views::join | std::ranges::to<std::string>()) +
               "</field>";
      };
      request = "<x xmlns='" + std::string(data_form::form_namespace) + "' type='submit'>" +
                (sent | std::views::transform(field_sent) | std::views::join | std::ranges::to<std::string>()) + "</x>";
    } else if (asked->username || asked->password) {
      // The old fields: each one listed is required (3.1).
      const auto old_field = [&](std::string_view name, const std::optional<std::string>& listed)
          -> std::optional<std::string> {
        if (!listed)
          return std::string();
        return given(name).transform(
            [&](const std::string& value) { return "<" + std::string(name) + ">" + escaped(value) + "</" + std::string(name) + ">"; });
      };
      const std::array fields{old_field("username", asked->username), old_field("password", asked->password),
                              old_field("email", asked->email)};
      if (std::ranges::any_of(fields, [](const auto& one) { return !one.has_value(); }))
        return asks_more();
      request = fields | std::views::transform([](const auto& one) -> const std::string& { return *one; }) |
                std::views::join | std::ranges::to<std::string>();
    } else {
      // Nothing to fill: a page to make the account on, or nothing at all.
      return asks_more();
    }
    write("<iq type='set' id='register_2'><query xmlns='" + std::string(registration::register_namespace) + "'>" +
          request + "</query></iq>");
    auto made = chevron::read_one_of<basic::iq_result<chevron::tagged<chevron::any>>,
                                     basic::iq_error<chevron::tagged<chevron::any>, stanza_error>>(s_.source());
    if (!made)
      return fail(connect_code::xml, "register: " + made.error().where);
    if (const auto* refused = spl::get_if<1>(&*made))
      return refusal(refused->reason);
    return {};
  }

  constexpr std::unexpected<connect_error> refusal(const stanza_error& reason) const {
    return std::unexpected(connect_error{connect_code::registration_refused, std::string(reason.condition()),
                                         std::nullopt, std::nullopt, reason});
  }

  Session& s_;
  const options& o_;
  const sm_state* resume_;
  bool authenticated_ = false;
  bool registered_ = false;
};

template <class Session>
constexpr std::expected<Session, connect_error> establish(Session s, const options& how, const sm_state* resume = nullptr) {
  negotiation<Session> steps(s, how, resume);
  if (auto done = steps.run(); !done)
    return std::unexpected(done.error());
  s.bound_to(std::move(steps.jid));
  s.versions_rosters(steps.roster_versioning);
  s.deliver_unhandled(how.deliver_unhandled);
  s.describes_itself(how);
  s.adopt_reader();
  if (resume) {
    if (auto restored = s.resumed_from(*resume, steps.resumed_h); !restored)
      return std::unexpected(std::move(restored).error());
  } else if (steps.enabled)
    s.stream_managed(*steps.enabled);
  return s;
}

}  // namespace tern::detail

export namespace tern {

// Connects over the caller's transport -- kept by reference, so it has to
// outlive the session: stream, STARTTLS where the transport can start TLS,
// SCRAM (-PLUS where it gives channel binding) or PLAIN, and resource
// binding. P, given first, is the protocol:
//   auto s = tern::connect<my_protocol>(socket, how, tern::answering{...});
template <class P = standard, transport T, class Handlers = answering<>, class Scheduler = no_scheduler>
constexpr std::expected<session<T&, P, Handlers, Scheduler>, connect_error>
try_connect(T& transport, const options& how, Handlers handlers = {}, Scheduler scheduler = {}) {
  return detail::establish(
      session<T&, P, Handlers, Scheduler>(transport, std::move(handlers), std::move(scheduler), how.buffers), how);
}

// XEP-0198: a stream taken up again over a new transport, from what
// session.sm() gave: authenticated, then resumed instead of bound, and what
// the server had not acknowledged sent again.
template <class P = standard, transport T, class Handlers = answering<>, class Scheduler = no_scheduler>
constexpr std::expected<session<T&, P, Handlers, Scheduler>, connect_error>
try_resume(T& transport, const options& how, const sm_state& state, Handlers handlers = {}, Scheduler scheduler = {}) {
  return detail::establish(
      session<T&, P, Handlers, Scheduler>(transport, std::move(handlers), std::move(scheduler), how.buffers), how, &state);
}

// The same over a range of bytes (or of chunks), read as far as each step
// needs, and an output iterator of char: no TLS. The range has to outlive
// the session.
template <class P = standard, std::ranges::input_range Input, std::output_iterator<char> Out,
          class Handlers = answering<>, class Scheduler = no_scheduler>
constexpr std::expected<session<range_transport<Input, Out>, P, Handlers, Scheduler>, connect_error>
try_connect(Input& input, Out output, const options& how, Handlers handlers = {}, Scheduler scheduler = {}) {
  return detail::establish(session<range_transport<Input, Out>, P, Handlers, Scheduler>(
                               range_transport<Input, Out>(input, std::move(output)), std::move(handlers),
                               std::move(scheduler), how.buffers),
                           how);
}

// The same, throwing: the session, or a tern::connect_failure.
template <class P = standard, transport T, class Handlers = answering<>, class Scheduler = no_scheduler>
constexpr session<T&, P, Handlers, Scheduler> connect(T& transport, const options& how, Handlers handlers = {},
                                        Scheduler scheduler = {}) {
  auto made = try_connect<P>(transport, how, std::move(handlers), std::move(scheduler));
  if (!made)
    throw connect_failure(std::move(made).error());
  return std::move(*made);
}

template <class P = standard, std::ranges::input_range Input, std::output_iterator<char> Out,
          class Handlers = answering<>, class Scheduler = no_scheduler>
constexpr session<range_transport<Input, Out>, P, Handlers, Scheduler> connect(Input& input, Out output, const options& how,
                                                                 Handlers handlers = {}, Scheduler scheduler = {}) {
  auto made = try_connect<P>(input, std::move(output), how, std::move(handlers), std::move(scheduler));
  if (!made)
    throw connect_failure(std::move(made).error());
  return std::move(*made);
}

}  // namespace tern

export namespace tern {

namespace detail {
template <class K, class V>
inline constexpr bool in_variant = false;
template <class K, class... A>
inline constexpr bool in_variant<K, spl::variant<A...>> = (std::same_as<K, A> || ...);
}  // namespace detail

// What was received, without nesting std::visit: f called with the kind of
// stanza itself -- message::chat, presence::subscribe, iq::result... -- of
// any protocol's stanza_t.
template <class F, class... Families>
constexpr decltype(auto) visit(F&& f, const spl::variant<Families...>& stanza) {
  return spl::visit([&](const auto& family) -> decltype(auto) { return spl::visit(f, family); }, stanza);
}
template <class F, class... Families>
constexpr decltype(auto) visit(F&& f, spl::variant<Families...>& stanza) {
  return spl::visit([&](auto& family) -> decltype(auto) { return spl::visit(f, family); }, stanza);
}

// The stanza as that kind, where it is one; nothing otherwise.
//   if (const auto* chat = tern::get_if<tern::message::chat>(one)) ...
template <class Kind, class... Families>
constexpr const Kind* get_if(const spl::variant<Families...>& stanza) {
  const Kind* out = nullptr;
  (
      [&] {
        if constexpr (detail::in_variant<Kind, Families>)
          if (const auto* family = spl::get_if<Families>(&stanza))
            out = spl::get_if<Kind>(family);
      }(),
      ...);
  return out;
}

// What a stanza carries, of that type, where it carries one: the first.
//   if (const auto* copy = tern::find<tern::carbons::received>(*message)) ...
template <class T, class Stanza>
  requires requires(const Stanza& one) { one.payload; }
constexpr const T* find(const Stanza& one) {
  for (const auto& carried : one.payload) {
    if constexpr (std::remove_cvref_t<decltype(carried)>::template can_hold<T>)
      if (const T* got = carried.template get_if<T>())
        return got;
  }
  return nullptr;
}

// The same through a stanza_t, whatever its kind.
template <class T, class... Families>
constexpr const T* find(const spl::variant<Families...>& stanza) {
  return tern::visit([](const auto& kind) { return tern::find<T>(kind); }, stanza);
}

}  // namespace tern
