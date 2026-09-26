// What the stream tests share: a scripted server's pieces, the options of
// RFC 7677's example, transports over scripts, and the test's own types.
// Included by each stream test file after its imports.

namespace {

std::string b64(std::string_view text) { return tern::crypto::base64_encode(tern::crypto::to_bytes(text)); }

const std::string header =
    "<?xml version='1.0'?><stream:stream to='example.com' from='user@example.com' version='1.0' xml:lang='en' "
    "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";

std::string server_header(std::string_view id) {
  return "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' "
         "id='" + std::string(id) + "' from='example.com' version='1.0'>";
}

const std::string bind_features =
    "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";
const std::string bind_result =
    "<iq type='result' id='bind_1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
    "<jid>user@example.com/tern</jid></bind></iq>";
const std::string bind_request =
    "<iq type='set' id='bind_1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>tern</resource></bind></iq>";

// A transport over a script: what the server says, read as far as asked,
// and what the client writes. TLS "starts" where the client asks for it,
// and the script goes on from there.
struct scripted {
  std::string_view data;
  std::size_t at = 0;
  std::string written;
  std::optional<tern::channel_binding> binding;
  bool tls = false;
  std::size_t read_at_tls = 0;

  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    scripted* s = nullptr;
    char operator*() const { return s->data[s->at]; }
    iterator& operator++() {
      ++s->at;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(std::default_sentinel_t) const { return s->at == s->data.size(); }
  };
  struct range {
    scripted* s = nullptr;
    iterator begin() const { return {s}; }
    std::default_sentinel_t end() const { return {}; }
  };
  range view;

  range& input() {
    view.s = this;
    return view;
  }
  void write(std::string_view bytes) { written.append(bytes); }
  void flush() {}
  bool start_tls(std::string_view) {
    read_at_tls = at;
    tls = true;
    return true;
  }
  bool secured() const { return tls; }
  std::optional<tern::channel_binding> channel_binding() const { return binding; }
};

tern::options rfc7677() {
  return {.username = "user", .domain = "example.com", .password = "pencil", .resource = "tern",
          .nonce = "rOprNGfwEbeRWgbNEkqO"};
}

}  // namespace




namespace {

struct ping {};
constexpr auto xml_schema(chevron::type<ping>) {
  return chevron::schema<ping>().name("urn:xmpp:ping", "ping");
}

struct version {
  std::optional<std::string> name, version;
};
constexpr auto xml_schema(chevron::type<version>) {
  return chevron::schema<version>().name("jabber:iq:version", "query");
}

struct version_query {
  using kind = tern::get;
  using answer = version;
};
constexpr auto xml_schema(chevron::type<version_query>) {
  return chevron::schema<version_query>().name("jabber:iq:version", "query");
}

// The test's own version, asked and answered: read straight into its types.
using test_protocol = tern::protocol<tern::queries<tern::roster, version_query>, tern::answers<tern::roster, version>>;

}  // namespace


namespace {

// Characters of a string, one at a time; at one place, the reader is
// suspended and the other side runs -- a stackful coroutine, made of two
// threads that never run at once.
struct baton {
  std::binary_semaphore first{0}, second{0};
};

struct suspending_input {
  std::string_view text;
  std::size_t at_which;
  baton* pass;
  bool* passed;

  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    const suspending_input* in = nullptr;
    std::size_t at = 0;
    char operator*() const {
      if (at == in->at_which && !*in->passed) {
        *in->passed = true;
        in->pass->second.release();  // the other one runs...
        in->pass->first.acquire();   // ...until it lets this one go on
      }
      return in->text[at];
    }
    iterator& operator++() {
      ++at;
      return *this;
    }
    void operator++(int) { ++at; }
    friend bool operator==(const iterator& one, std::default_sentinel_t) {
      return one.at == one.in->text.size();
    }
  };
  iterator begin() const { return {this, 0}; }
  std::default_sentinel_t end() const { return {}; }
};

}  // namespace








// Input as a socket gives it: asking whether it has ended waits for the
// peer. What a request needs is read, and nothing is asked past it.
struct live_input {
  std::string_view data;
  std::size_t at = 0;
  bool asked_past = false;

  struct iterator {
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    live_input* in = nullptr;
    char operator*() const { return in->data[in->at]; }
    iterator& operator++() {
      ++in->at;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(std::default_sentinel_t) const {
      if (in->at == in->data.size())
        in->asked_past = true;
      return in->at == in->data.size();
    }
  };
  iterator begin() { return {this}; }
  std::default_sentinel_t end() const { return {}; }
};
