# tern

An XMPP client library for C++26, as modules. It speaks over a transport of
the caller's -- a type, with nothing erased: what it can do is found by
concepts at compile time -- and runs nothing of its own: with a blocking
socket in a thread, or with coroutines that suspend inside the transport, the
control flow is the caller's.

```cpp
my_socket wire = …;                                   // a tern::transport, below
auto session = tern::connect(wire, {
    .username = "juliet", .domain = "example.com", .password = "…",
    .resource = "balcony",
});  // throws tern::connect_failure; try_connect hands a std::expected back instead
for (auto&& stanza : session.stanzas()) {     // ends where the server ends the stream
  if (!stanza) {
    report(stanza.error());
    break;
  }
  splice::visit(handle, *stanza);               // message, presence or iq
}
session.send(tern::message::chat{.to = "romeo@example.net", .body = "hi"});
```

- **Negotiation** (RFC 6120): the stream, STARTTLS where the transport can
  start TLS -- nothing past `<proceed/>` is read before it has -- SASL, and
  resource binding.
- **Authentication**: SCRAM-SHA-256 and SCRAM-SHA-1 (RFC 5802, RFC 7677), their
  -PLUS forms where the transport gives channel binding (RFC 9266), and PLAIN
  (RFC 4616) only over TLS unless asked otherwise. SHA-1, SHA-256, HMAC,
  PBKDF2 and Base64 are the library's own, constexpr, checked against the
  standard vectors.
- **Stanzas read straight into their types**: no tree on the way for what the
  protocol names; below.
- **Input read as far as needed**: a range of bytes up to the next `<` or `>`
  at a time, or a range of chunks a chunk at a time, and never ahead, which is
  what makes the TLS upgrade and coroutines work.

Built on [chevron](https://github.com/j4niwzis/chevron), the XML of streams, and
[alef](https://github.com/j4niwzis/alef) for addresses (PRECIS, IDNA). Both
come through cmake-everywhere, pinned to commits; both are private, so git has
to be able to authenticate to fetch them. To build against local checkouts
instead: `-DCPM_chevron_SOURCE=<path> -DCPM_alef_SOURCE=<path>`.

## Transports

```cpp
struct my_socket {
  chunks& input();                         // an input range the transport keeps: of bytes,
                                           // or of chunks, each a range of bytes one read brought
  void write(std::string_view bytes);
  void flush();                            // where tern ends a unit: a stanza, a nonza
  bool start_tls(std::string_view host);   // optional: tern::tls_transport
  bool secured() const;                    // optional: tern::secured_transport (direct TLS too)
  std::optional<tern::channel_binding> channel_binding();  // optional: tern::binding_transport
};
```

`tern::transport` is the first three; each optional member is a concept of
its own, and negotiation asks for it with `if constexpr`: STARTTLS only where
the transport can start TLS (a server that requires it is an error
otherwise), SCRAM -PLUS only where it gives binding data. After `start_tls()`
the input is taken again. The session keeps a reference to the transport,
which has to outlive it.

`tern::connect(input, output_iterator, how)` is the same over a range of
bytes (or of chunks) and an output iterator: a `tern::range_transport`,
without TLS.

`examples/live.cc` is a transport over a socket, or over `openssl s_client`
for TLS, whose input is the chunks each `read()` brings; it has been run
against ejabberd 26.07 and Prosody 13.

## What a stanza carries: protocols

Each kind of stanza is a type of its own, with what that kind can carry:
`tern::message::chat`, `tern::message::groupchat`, … `tern::presence::subscribe`,
… `tern::iq::get`, `tern::iq::set`, `tern::iq::result`, `tern::iq::error`.
`tern::message_t`, `tern::presence_t` and `tern::iq_t` are the variants of
each, `tern::stanza_t` the variant of those, and `splice::visit` tells them
apart. The error kinds carry their `<error/>` parsed, as `reason`: its type
(cancel, continue, modify, auth, wait), its condition as a type of its own
(`what`, a `chevron::tagged` of `tern::conditions::service_unavailable` and the
other 21 of RFC 6120, 8.3.3; `condition()` gives its name), its `text`, and an
application's own condition kept as it came. Stream errors the same, with the
25 conditions of 4.9.3 in `tern::stream_conditions`.

What a stanza carries, `payload`, is a vector of `chevron::tagged` of the
types a protocol names -- chosen by the element's name and read straight into
that type -- and `chevron::any` for what it does not name, the only tree:

```cpp
using my_protocol = tern::protocol<
    tern::queries<tern::roster, tern::query::version, tern::query::ping, my_query>,  // in gets and sets
    tern::answers<tern::roster, tern::version, my_answer>,                         // in results
    tern::extensions<delay, chat_state>>;                                          // in messages and presence
auto session = tern::connect<my_protocol>(wire, how);
my_protocol::message::chat …;  // the stanza types, over the protocol
```

A fifth parameter says what becomes of an element no listed type names:
`tern::keep_unknown`, the default, keeps it as a `chevron::any`;
`tern::drop_unknown` passes over it, and then no tree is ever made. A
fourth, `tern::errors<…>`, names the application-specific error conditions
(RFC 6120, 8.3.2) read into the `<error/>`'s `application`; one not named is
passed over.

The stanzas are `tern::basic::message_chat<X>` and the like; a protocol's
`message::chat` is one over its extensions. `tern::standard`, the default,
names what RFC 6120 and 6121 need and what every client is asked: the roster
(`tern::roster`, result and push), and XEP-0092's version and XEP-0199's ping.

## Requests

```cpp
tern::version v = session.request<tern::query::version>({.to = "example.com"});  // read straight into it
session.request<tern::query::ping>({.to = "example.com"});                        // void: an empty result
auto maybe = session.try_request<my_query>({.to = "romeo@example.net/orchard"});   // std::expected instead
tern::iq::result raw = session.request(tern::iq::get{.payload = {…}});
```

A query says its kind and its answer: `using kind = tern::get;` (or
`tern::set`) and `using answer = …;` -- a type of the protocol's
`answers<>`, checked at compile time, or `void`. An iq is sent -- with an id
made up where it has none -- and its answer awaited: the result, or the
error, thrown as a `tern::request_failure` (or handed back by `try_request`)
with the `<error/>` kept. Whatever else arrives in the meantime is kept for
`receive()` and `stanzas()`, in order.

Several requests may be in flight at once, from coroutines of any kind --
fibers, or threads taking turns. One coroutine reads: the one that connected,
or whoever last called `receive()` or `stanzas()`. A request from any other
never reads: it parks, and the reader wakes it with its answer, typed, or
with the error where the stream ends. The coroutines are the caller's; the
session sees them through a scheduler, a type with three operations --
`current()`, `park()`, `wake(handle)` -- given to `connect`
(`tern::no_scheduler`, the default: one coroutine, whose requests read for
themselves). A coroutine killed while it is parked leaves nothing behind: its
answer is dropped when it comes. Timeouts and giving up are the caller's.

Several coroutines may also each wait for stanzas of their own, without
taking them from one another: an inbox holds every stanza that arrives while
it is open -- what `receive()` would hand out -- and taking one out of one
inbox leaves it in every other.

```cpp
auto from_romeo = session.open_inbox("romeo@example.net");  // a bare JID, or nothing: everything
while (const tern::stanza_t* one = from_romeo.next())         // parks till one comes; nullptr at the end
  handle(*one);
```

Each stanza is kept once, in a log the inboxes read at their own places,
and let go of when every inbox has passed it; the one `next()` returned is
the caller's until the next call. The address is a filter the session knows
(prepared as RFC 7622 says, so `Romeo@Example.NET` is Romeo), so only what
it lets in wakes a parked coroutine; `next()` takes any predicate besides,
run in the waiting coroutine -- nothing stored, no type erasure. Whoever
waits and finds nobody reading reads, and hands over to the next waiter when
it has its stanza: no coroutine has to be the reader. While inboxes are open
and nobody calls `receive()`, nothing is kept for it. A stanza that could
not be read goes to `receive()` only.

Requests coming in are answered by handlers given at `connect`, a static
pack -- no map, no type erasure:

```cpp
auto session = tern::connect(wire, how, tern::answering{
    [](const tern::query::version&) { return tern::version{"tern", "0.1", {}}; },
    [](const tern::query::ping&) {},                     // void: an empty result
});
```

The first handler that takes the query's type is called; one that throws
`tern::refusal` sends that error. Every get and set gets one reply: a
query no handler takes is refused with service-unavailable (RFC 6120,
8.2.3), unless `options::deliver_unhandled` hands it out instead.

Every call that can fail comes in two forms, as in scan: `connect`, `receive`
and `request` throw; `try_connect`, `try_receive` and `try_request` hand a
`std::expected` back.

## Streaming writes and buffer limits

`session.try_send(stanza)` returns `std::expected<void, connect_error>`;
`send(stanza)` throws `connect_failure` on the same errors. Without stream
management, XML is written incrementally: small markup and escape fragments
share a 4 KiB buffer, while large text runs are borrowed directly. With stream
management, the encoded stanza is retained until acknowledged. A transport's
`write(string_view)` must consume or copy the bytes before returning;
`flush()` is called once at the end of the stanza.

`options::buffers` configures retained state, with these defaults:

| Buffer | Default |
| --- | ---: |
| Pending stanzas for `receive()` | 1,024 |
| Shared inbox log, including values currently held by inboxes | 4,096 |
| Requests in flight | 256 |
| Recent cancelled request IDs | 1,024 |
| Unacknowledged outgoing stanzas | 1,024 |
| Encoded bytes of unacknowledged outgoing stanzas | 16 MiB |

Zero permits no entries in that buffer. These are counts of values except
for the explicit byte limit; they do not bound the size of an individual
incoming stanza or the allocator's overhead.

A full outgoing buffer returns `connect_code::resource_limit` before any
part of that stanza is written. Read acknowledgments and retry. A full
request table likewise rejects the new request without sending it. IDs
already in flight or retained as cancellations return `request_conflict`.
Cancellation history evicts the oldest IDs when full; replies older than
that window are delivered as unsolicited stanzas.

An incoming stanza that exceeds a pending or inbox limit stops the session
with `resource_limit` and wakes its waiters. Already queued values remain
available before that error is returned. The session is no longer resumable,
because the stanza that did not fit must not be acknowledged as handled.
An acknowledgment beyond the sent stanza count is `invalid_ack` and also
disables resumption. Valid control elements are processed before waiting
for more input, including when the peer sends `<r/>` and waits for `<a/>`.

## The roster

`session.sync(cache)` brings a `tern::roster_cache` up to date (RFC 6121,
2.6), from its version where the server versions rosters; `cache.apply(push)`
takes a push. Subscriptions: `subscribe`, `approve`, `deny`, `unsubscribe`,
each to a bare JID; `available()` and `close()` send presence.

## Constant evaluation

The session is `constexpr` along its whole path -- negotiation, SASL, the
typed reading, requests and their routing -- so the compiler can run it, and
must refuse any undefined behaviour on the way. A `std::deque`, which cannot
be used there, is a `std::vector` while the compiler evaluates and a deque
when the program runs (a union, chosen with `if consteval`): nothing is
slower for it. Threads (`thread_scheduler`) and transports that read
sockets are the program's alone.

`test/constexpr_test.cc` holds `CONSTEXPR_TEST`s, as alef's: each runs when
the program runs, and -- with `-DTERN_CONSTEXPR_TESTS=ON`, as CI builds --
while it is compiled as well, a whole session over a script among them. One
that is not a constant expression fails when it runs, and compiles itself
alone (`tern-constexpr-Suite.Name`) so that the compiler says why.

## Licence

GNU Affero General Public License, version 3 only (`AGPL-3.0-only`) -- the
text is in `LICENSE`. A program that uses this library is a work based on
it; whoever interacts with such a program over a network is offered its
source, as the licence's section 13 says.
