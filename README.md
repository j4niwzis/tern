# tern

An XMPP client library for C++23, as modules. It reads from any input range
of bytes and writes to any output iterator of chars, and runs nothing of its
own: with a blocking socket in a thread, or with stackful coroutines that
suspend inside the range, the control flow is the caller's.

```cpp
std::string written;
auto session = tern::connect(socket_bytes, socket_writer, {
    .username = "juliet", .domain = "example.com", .password = "…",
    .resource = "balcony",
    .start_tls = [&] { /* put TLS under the input and the output */ },
});  // throws tern::connect_failure; try_connect hands a std::expected back instead
for (auto&& stanza : session.stanzas()) {     // ends where the server ends the stream
  if (!stanza) {
    report(stanza.error());
    break;
  }
  std::visit(handle, *stanza);                  // message, presence or iq
}
session.send(tern::message::chat{.to = "romeo@example.net", .body = "hi"});
```

- **Negotiation** (RFC 6120): the stream, STARTTLS through a hook the caller
  gives -- nothing past `<proceed/>` is read before it has run -- SASL, and
  resource binding.
- **Authentication**: SCRAM-SHA-256 and SCRAM-SHA-1 (RFC 5802, RFC 7677), and
  PLAIN (RFC 4616) only over TLS unless asked otherwise. SHA-1, SHA-256,
  HMAC, PBKDF2 and Base64 are the library's own, constexpr, checked against
  the standard vectors.
- **Stanzas**: `tern::message`, `tern::presence` and `tern::iq` are plain
  structs, read and written by chevron; what they carry beyond the named
  fields is kept whole.
- **Input read as far as needed**: up to the next `<` or `>` at a time, and
  never ahead, which is what makes the TLS upgrade and coroutines work.

Built on [chevron](https://github.com/j4niwzis/chevron), the XML of streams, and
[alef](https://github.com/j4niwzis/alef) for addresses (PRECIS, IDNA). Both
come through cmake-everywhere, pinned to commits; both are private, so git has
to be able to authenticate to fetch them. To build against local checkouts
instead: `-DCPM_chevron_SOURCE=<path> -DCPM_alef_SOURCE=<path>`.

## Requests

```cpp
tern::iq::result answer = session.request(tern::iq::get{.payload = {chevron::to_any(ping{})}});
server_version version = session.request<version_query>();   // version_query: using kind = tern::iq::get; using answer = server_version;
auto maybe = session.try_request<version_query>({.to = "romeo@example.net/orchard"});  // std::expected instead
```

An iq is sent -- with an id made up where it has none -- and its answer
awaited: the result, or the error, which is thrown as a `tern::request_failure`
(or handed back by `try_request`) with the error iq kept whole. Whatever else
arrives in the meantime is kept for `receive()` and `stanzas()`, in order.
Several requests may be in flight at once, from coroutines or threads: each
answer goes to the request it belongs to, one of them reads the stream at a
time, and the others wait in `options::yield`.

Every call that can fail comes in two forms, as in scan: `connect`, `receive`
and `request` throw; `try_connect`, `try_receive` and `try_request` hand a
`std::expected` back.

## Kinds

Each kind of stanza is a type of its own, with what that kind can carry:
`tern::message::chat`, `tern::message::groupchat`, … `tern::presence::subscribe`,
… `tern::iq::get`, `tern::iq::set`, `tern::iq::result`, `tern::iq::error`.
`tern::message_t`, `tern::presence_t` and `tern::iq_t` are the variants of
each, `tern::stanza_t` the variant of those, and `std::visit` tells them
apart. The error kinds carry their `<error/>` parsed, as `reason`: its type
(cancel, continue, modify, auth, wait) and `condition()`. Requests take a get
or a set and give a result, or throw the error.
