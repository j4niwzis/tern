# Compliance

What RFC 6120 (XMPP Core), RFC 6121 (XMPP IM) and RFC 7622 (addresses)
require of a client, a row each, and where tern stands. **done** has a test
beside it; **partial** says what is missing; **not yet** is not there at all.
What the RFCs require only of servers is left out.

## RFC 6120: XMPP Core

| § | Requirement | Status | Test |
| --- | --- | --- | --- |
| 4.2 | The initiating entity opens the stream with `to` (the server's domain) and `version='1.0'` | done | `Stream.ScramBindAndStanzas` |
| 4.3.2 | The stream is restarted, with a new header, after TLS and after SASL success | done | `Stream.StartTlsThenPlain`, `Stream.ScramBindAndStanzas` |
| 4.4 | Closing: `</stream:stream>` sent, and the peer's closing tag waited for before the connection is closed | done: `close()` sends it, and `stanzas()` goes on until the peer's; the connection is the caller's to close after that | `Stream.StreamErrorAndClosing` |
| 4.6 | Whitespace keepalives are accepted between stanzas | done | `Stream.FailureConditionAndKeepalives` |
| 3.2.1 | The service located by DNS SRV (`_xmpp-client._tcp`), tried by priority and weight (RFC 2782); the domain at 5222 where there is none | done: `tern::srv` -- the query, the answer read, the order; sending it is the transport's, as in `examples/live.cc` | `Srv.Query`, `Srv.Answers`, `Srv.Order` |
| 4.7.4 | `xml:lang` on the initiating entity's stream header | done: `options::lang`, "en" by default | every negotiation test |
| 4.9 | Stream errors: `<stream:error/>` parsed, its condition reported, the stream closed | done, during negotiation and after it (`connect_code::stream_error`, the condition as detail) | `Stream.StreamErrorAndClosing`, `Stream.SeeOtherHost` |
| 4.9.3.19 | `see-other-host`: reconnect to the host given | done: the host (and port) in `connect_error::other_host`; tern owns no socket, so the caller reconnects | `Stream.SeeOtherHost` |
| 5.3.1 | STARTTLS used where offered; a server that requires it and a client that cannot is an error | done | `Stream.StartTlsThenPlain`, `Stream.WhatStopsIt` |
| 5.4.3.3 | After `<proceed/>`, nothing is read or written before TLS is in place | done: the hook runs before anything past `<proceed/>` is read | `Stream.StartTlsThenPlain` |
| 5.4.3.3 | After `<failure/>` for STARTTLS the stream is closed | done: `</stream:stream>` written, `tls_refused` reported | `Stream.NegotiationErrors` |
| 6.3.3 | Mechanisms chosen by the client's preference among those offered | done: SCRAM-SHA-256, then SCRAM-SHA-1, then PLAIN | `Stream.ScramBindAndStanzas` |
| 6.3.10 | PLAIN not used without TLS unless explicitly allowed | done | `Stream.WhatStopsIt` |
| 6.4.2 | SCRAM as RFC 5802/7677: nonce, salted password, proofs, the server's signature verified | done | `Sasl.*`, `Stream.ScramBindAndStanzas` |
| 6.4.3 | Channel binding (the -PLUS mechanisms) | done: SCRAM-SHA-256-PLUS and SCRAM-SHA-1-PLUS with the data the TLS layer gives (`options::channel_binding`), `y,,` where none is offered | `Stream.ChannelBinding` |
| 6.4.5 | SASL `<failure/>`: its condition reported | done: `connect_code::not_authorized`, the condition as detail | `Stream.FailureConditionAndKeepalives` |
| 6.4.1, 6.4.5 | `<abort/>` to give up an exchange | done: a challenge SCRAM cannot take is answered with `<abort/>`, and the `<failure><aborted/></failure>` read | `Stream.SaslAbort` |
| 7.4 | Resource binding requested, with or without a resource | done | `Stream.ScramBindAndStanzas` |
| 7.6.2 | The resource the server assigned is the one used | done: the JID from the result | `Stream.ScramBindAndStanzas` |
| 7.6.2.2 | A `conflict` or other error to binding reported | done: `bind_refused`, the condition as detail and the whole `<error/>` in `connect_error::stanza` | `Stream.NegotiationErrors` |
| 8.1 | Stanzas have exactly `to`, `from`, `id`, `type`, `xml:lang` as attributes | done | `Stream.RequestAndAnswer` |
| 8.1.3 | An `id` on every iq | done: made up where the request has none | `Stream.RequestAndAnswer` |
| 8.2.3 | Every iq get or set gets exactly one result or error | done: handlers, else `service-unavailable` | `Stream.EveryRequestIsAnswered` |
| 8.2.3 | A result or error matched to the request by id and by who sent it | done | `Stream.RequestAndAnswer`, `Stream.TwoRequestsInFlight` |
| 8.3 | Stanza errors: `<error/>` with a type and a condition in the stanza-errors namespace, parsed and written | done | `Stream.RequestAndAnswer`, `Stream.EveryRequestIsAnswered` |
| 8.4 | Extended content: child elements in other namespaces kept and passed on | done: `payload` | `Stream.RequestAndAnswer` |
| 11.1 | XML restrictions: no comments, processing instructions, DTDs, entity references beyond the five | done: chevron refuses them | chevron `Parser.*` |
| 11.6 | UTF-8, and characters that are XML characters | done: chevron checks them | chevron `Parser.LongTextChecked` |
| 13.9 | Limits against resource exhaustion: depth, token size, attributes | done: chevron's limits | chevron `Parser.*` |

## RFC 7622: addresses

| § | Requirement | Status | Test |
| --- | --- | --- | --- |
| 3.2 | Domainpart prepared as an IDNA2008 domain name, a trailing dot dropped, IP literals kept | done: `tern::jid`, with alef | `Jid.ValidExamples`, `Jid.NotAddresses` |
| 3.3 | Localpart prepared with the UsernameCaseMapped profile of PRECIS, and `" & ' / : < > @` refused | done | `Jid.ValidExamples`, `Jid.NotAddresses` |
| 3.4 | Resourcepart prepared with the OpaqueString profile of PRECIS | done | `Jid.ValidExamples` |
| 3.x | Each part at most 1023 octets after preparation | done | `Jid.NotAddresses` |

## RFC 6121: XMPP IM

| § | Requirement | Status | Test |
| --- | --- | --- | --- |
| 2.1.3 | Roster get | done: `request<tern::query::roster>()` | `Stream.RosterAndPushes` |
| 2.1.6 | Roster push: answered with a result, from the client's own account only | done: answered, and handed out or to its handler; a push from anyone else ignored | `Stream.RosterAndPushes` |
| 2.3-2.5 | Roster set: a contact added or changed, one item a set, no subscription but remove; and removed | done: `update_contact()`, `remove_contact()`, `query::roster_set` | `Stream.RosterChanges` |
| 2.6 | Roster versioning | done: the `rosterver` feature seen; `tern::roster_cache` kept by the caller; `sync()` asks from its version (`ver=''` with none), keeps it on an empty answer, replaces it on a whole roster; `apply()` for pushes | `Stream.RosterVersioning` |
| 3 | Subscription requests, approval, cancellation, unsubscribing, each to a bare JID | done: `subscribe`, `approve`, `deny`, `unsubscribe`; the state is the server's | `Stream.PresenceAndSubscriptions` |
| 4.2 | Initial presence after the roster | done: `available()`; asking for the roster first is the caller's | `Stream.PresenceAndSubscriptions` |
| 4.5 | Unavailable presence before closing the stream | done: `close()` sends it where presence was sent | `Stream.PresenceAndSubscriptions` |
| 5.2.2 | Message types: chat, groupchat, headline, normal, error | done | `Stream.ScramBindAndStanzas` |
| 5.2.3, 5.2.5 | `<subject/>` and `<thread/>` (with `parent`) | done: members `subject` and `thread` of every message type | `Stream.SubjectAndThread` |

## XEP-0077: In-Band Registration

| § | Requirement | Status | Test |
| --- | --- | --- | --- |
| 3.1 | The fields asked for with a get, before authentication, and answered with a set | done: `options::create`, after TLS and before SASL; over plain text only with `plain_without_tls` | `Stream.RegistrationAnswered` |
| 3.1 | The old fields: each one listed is required | done: username and password from the options, any other from the answers | |
| 4 | A data form (XEP-0004) in place of the old fields | done: every field with a var sent back, answered or as the form held it; one required and left empty hands the form back (`connect_code::registration_asks`, `connect_error::registration`) | `Stream.RegistrationAsksMore` |
| 5 | A page to register on (XEP-0066) | done: handed back in `registration::asked::page` | |
| 3.1 | Errors: conflict, not-acceptable and the rest | done: `connect_code::registration_refused`, the stanza error whole | |

XEP-0158 (CAPTCHA forms), XEP-0221 (media) and XEP-0231 (bits of binary): the form's fields keep their labels, descriptions, options and media, and the data sent with the form is kept by its cid, so whatever kind of captcha the server uses is shown by the caller and answered as a field.
