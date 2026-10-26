# CoT Relay

A small, self-contained bridge between independently-administered TAK
servers (GoATAK and compatible - see the protocol notes below). It
connects as a client over mTLS to several servers, merges the incoming
CoT streams into a single state, filters out noise, and forwards
significant changes onward per configurable routing rules - with a web
panel to manage servers, routing rules, and watch what's actually
flowing through it, live.

**Not affiliated with TAK Product Center or the GoATAK project.** Built
against the publicly documented Cursor-on-Target (CoT) protocol and
tested against GoATAK; "TAK" and related marks belong to their
respective owners.

**Origin:** this started as a piece of a computer-vision project that
needed to publish detections to a TAK server as CoT markers - the
server-bridging part turned out to be useful on its own, so it was
pulled out into this standalone tool.

**Development:** architecture, requirements, and testing by the author;
implementation built with AI pair-programming (Claude). Issues and
protocol-correctness questions are welcome either way - see
CONTRIBUTING.md.

## What this is (and isn't)

The MVP scope below is deliberate, not a to-do list someone forgot to
finish - see "Deliberate MVP limitations" for what's intentionally out of
scope and why.

## Structure

- `cot.py` — incremental parser for the CoT stream (`<event>...</event>`
  boundaries), parses the fields that are needed, and does a surgical
  `uid` substitution in the opening tag without rebuilding the whole event.
- `connection.py` — Connection Manager: mTLS connection to one server,
  auto-reconnect, keep-alive, outbound queue with uid-coalescing.
- `state.py` — State Store: namespace merge (`<source>-<uid>`) + filter
  for significant changes (distance / heartbeat / type-callsign change).
- `router.py` — `from -> [to, ...]` rules with filters and a loop-guard.
- `relay.py` — the orchestrator wiring everything together.
- `main.py` — entry point, config, graceful shutdown on Ctrl+C.

## Running it

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
# put client.pem / client.key / ca.pem for each server under certs/<name>/
# and edit config.yaml with your host/port/certificates
python main.py --config config.yaml --verbose
```

Stop with `Ctrl+C` (graceful shutdown, closes the connections).

## Deliberate MVP limitations

- **TAK protocol v1 only (plain XML)**, no protobuf v2. Most self-hosted
  servers (GoATAK, FreeTAKServer) work fine over XML; protobuf can be
  added as a follow-up step.
- **No Data Package / Mission syncing** — like official federation, the
  relay only works with the CoT event stream.
- **In-memory state**, no persistence across restarts — on restart the
  State Store is rebuilt from the live stream.
- **Single process, no HA** — if the relay goes down, federated
  visibility disappears until the process comes back up and reconnects.
- **Merge-by-uid is the default, not spatial dedup** — objects from
  different servers sharing a uid are merged into one (matches how ATAK
  itself behaves - see "uid trust" below); the relay doesn't try to infer
  "these are probably the same object" from position/callsign when uids
  differ. If a genuinely single real-world object ends up under two
  different uids (e.g. it re-enrolled and got a new device id), it'll
  still show up twice - that inference is out of scope for now.
- **No filter for private/addressed messages** (`dest`/`marti`) — if a
  server honors `dest` when broadcasting, the relay physically never sees
  private 1:1 messages (the server won't send them to it in the first
  place). But if a given server doesn't honor that and sends everything
  into the shared scope stream, the relay currently forwards it like
  anything else. Worth checking empirically against your server, and if
  needed, add a check in `cot.py`/`state.py` for `<marti><dest .../></marti>`
  before treating an event as "significant" for forwarding.
- **TLS**: `verify_ca: true` requires a real server CA file (saved during
  enrollment) — without it, the remote server isn't authenticated, only
  you are authenticated to it. For servers you don't administer yourself,
  always use `verify_ca: true` with their CA.

## uid trust and merging (`trust_uid`)

**Default changed:** earlier versions always namespaced every source's
uid (`<source>-<uid>`), unconditionally. As of this version, the default
is `trust_uid: true` per server — objects are merged by their raw uid
across sources, matching how a real ATAK client behaves (it merges by
uid regardless of which server told it, and treats uid as the identity
of the object, not the transport). **If you're upgrading an existing
deployment**, this is a behavior change: two servers that previously
showed the same real object as two separate entries will now show it as
one, merged. If any of your sources use a predictable/generated uid
scheme (sensor feeds, detection pipelines, anything that isn't a human
carrying an ATAK-family device) where a coincidental collision with
another source's uid is plausible, set `trust_uid: false` on that
server's config (or the matching toggle in the panel) - its uid gets
namespaced as before, so it can never silently merge with or overwrite
an unrelated object from elsewhere.

What `trust_uid: false` costs: the same real object reported by two
untrusted-per-relay sources under the same uid will show up as two
separate entries rather than merging - there's no dedup logic beyond raw
uid matching. Mixed setups (some servers trusted, others not) work fine;
the setting is independent per source.

## Echo suppression (bidirectional routing safety)

If server A and server B route to each other (`A -> B` and `B -> A`) and
a server broadcasts to its whole scope without excluding the sender, the
relay's own forwarded write comes straight back to it on the same
connection's inbound side. Without a guard, the relay would treat that
as new traffic from B, re-namespace the already-namespaced uid (growing
another `<name>-` prefix), and route it onward again — not just a
duplicate-looking marker, but an unbounded prefix chain in any
bidirectional setup.

Each `ServerConnection` now keeps a short-lived record of uids it just
sent out on that specific connection. Anything received back on the same
connection matching a recently-sent uid is dropped before it ever
reaches the State Store — it never becomes a tracked object, never shows
up in Live Feed/Map, and never gets routed further. A genuinely new
object from that server (different uid) is unaffected.

**Window sizing matters more than it looks.** The window scales with
`filter.heartbeat_interval_s` (3x it, floored at 180s) instead of a fixed
constant. An earlier version used a flat 20s window, which was shorter
than the default 60s heartbeat interval — meaning the "recently sent"
record for an unchanged object could expire in the 40-second gap
*between our own re-sends*, and a server-side event landing in that gap
(a periodic full-resync, for instance — some TAK-adjacent server
implementations do this on a ~30s cadence) would slip past the check and
get re-namespaced under a second name, silently defeating the very thing
this section is describing. If you configure a much longer
`heartbeat_interval_s`, the window scales with it automatically.

## Authenticating to servers

Both approaches already used in vision-agent are supported:

- **An existing certificate** (PEM or PKCS#12 `.p12`/`.pfx`) — in the
  panel, this is the "Already have a certificate" mode: upload the file
  directly, the panel saves it under `certs/<name>/client.<ext>` (and
  `truststore.<ext>` for the CA) on its own — you never type or see a
  file path. In `config.yaml` directly, set `cert`/`key`/`ca` as paths;
  for `.p12` also set `cert_password`/`ca_password` if the container is
  password-protected. No separate key file/field is needed for `.p12` —
  it's already inside; plain PEM works too as long as the key is embedded
  in the same file (a separate `.key` file can still be used via
  `config.yaml`, just not through the upload UI).
- **Auto-enroll** (domain + login/password) — the relay generates its own
  key+CSR and gets a signed certificate + CA from the server
  (`/Marti/api/tls/signClient/v2`, the standard GoATAK/TAK Server flow).
  In the panel this is the "Get via login/password" mode in the add-server
  form; the result is saved under `certs/<name>/` and the server then
  lives on like any regular PEM-based server. The username is saved in
  `config.yaml` (not a secret, kept for convenience so it's pre-filled
  next time you re-enroll) - the password is never saved anywhere, at
  any point; it's used once for the request and discarded.

## Web panel

`web_dashboard.py` + `dashboard.html` (same folder) — a Flask layer on top of
the same relay core: server cards with live connection status,
enabling/disabling a server without deleting its config, adding/editing
servers and routing rules right from the browser. Changes apply via
hot-reload (the whole Relay is rebuilt and restarted, like
`rebuild_multisender()` in vision-agent) and are saved back to
`config.yaml`. A language toggle (EN/RU) in the top-right corner switches
every panel string on the fly, without a page reload; the choice is saved
in the browser (`localStorage`) so it persists across visits. This only
covers the panel's own UI text — Python code comments/logs and CoT payload
content are unaffected and stay in English.

```bash
pip install -r requirements.txt   # now includes flask
python web_dashboard.py
# open http://localhost:5077
```

If `config.yaml` doesn't exist yet next to it — the panel creates an
empty one itself the first time you save a server through the UI.

## Panel access (login/password)

Managed from inside the panel itself now — click **Panel access** next to
the language toggle. First time: just set a username/password (no
current credentials needed, since none exist yet). After that: changing
it requires the current username/password to be entered correctly first.
The password is stored in `config.yaml` as a salted hash
(`werkzeug.security.generate_password_hash`) — never in plain text,
and never visible again after you set it.

`RELAY_WEB_USER`/`RELAY_WEB_PASS` environment variables still work as a
bootstrap/automation option, but only take effect if nothing has been set
via the panel yet — once you set credentials through **Panel access**,
that takes over and the env vars are ignored from then on.

If the panel is reachable beyond localhost, also turn on
`RELAY_WEB_TLS=1` (see below) — Basic Auth sends credentials in the clear
over plain HTTP, so without TLS anyone on the network path can read them.

## Port

Defaults to `5077` (not 5000 — so it doesn't collide with other services
of yours on that port). Change it with an environment variable:

```bash
RELAY_WEB_PORT=8090 python web_dashboard.py
```

## Encrypting the panel itself (optional)

By default the panel serves plain HTTP - if it's reachable beyond
localhost, enroll credentials (and everything else) travel unencrypted
between your browser and it. Turn on a self-signed HTTPS listener:

```bash
pip install -r requirements.txt   # now includes pyopenssl
RELAY_WEB_TLS=1 python web_dashboard.py
# open https://localhost:5077 - the browser will warn about the
# self-signed certificate, that's expected, accept it to proceed
```

This doesn't give you a trusted certificate (browsers will always warn),
it just stops credentials from going out in the clear on the local/
tactical network between your browser and the panel.

**Security.** Basic Auth is optional (see above), off by default. If you
don't turn it on, don't expose the panel to the internet directly —
localhost/VPN only, or behind a reverse proxy.

## Self-presence (relay visibility on the server)

The relay periodically sends a CoT event about itself to each connected
server: uid `relay-<server name from the config>`, callsign
`<prefix> (<name>)` (default `CoT-Relay (server_a)`), with a full set of
detail fields (contact, takv, `__group`, status, track) — the same set a
real ATAK client sends. Sent right after the handshake and refreshed
every ~45 seconds. Configurable via the `identity` section in
`config.yaml`.

**Known limitation:** on GoATAK this doesn't guarantee fixing an "empty
Units/Dashboard list" — the available source confirms the server receives
and processes the event (`app.NewCotMessage` doesn't filter by uid), but
the exact logic for what actually lands in the web panel's
Units/Dashboard list (as opposed to the Devices list, which is about
something else entirely — certificates/logins, not CoT) wasn't
conclusively found in the open-source code. If the marker still isn't
visible after this change, check: (1) whether the scope of the login the
relay connects with matches the scope the Dashboard is viewed under; (2)
GoATAK's own built-in CoT log (the docs claim this capability) — whether
`uid relay-<name>` shows up there at all, which separates "the relay
didn't send it" from "the server received it but didn't display it".

## Live objects (what the relay is actually pulling from the servers)

Routing rules can now be edited in place (not just added/deleted) - click
**Edit** on a row in the Servers tab's routing table. The rule form now
uses checkboxes for "To" (pick from your configured servers, instead of
typing comma-separated names) and a dropdown for the CoT type filter with
readable, affiliation-colored labels (🔵 friendly / 🔴 hostile / 🟢
neutral / 🟡 unknown) instead of raw type strings - "Custom…" still lets
you type an exact prefix for anything not in the curated list. This isn't
full MIL-STD-2525 iconography (that needs a symbol-rendering library and
a real SIDC mapping), just a readable picker for the common cases.

Also fixed: the "From" dropdown used to get silently reset back to the
first server every ~4 seconds while the Add/Edit rule modal was open,
because the background poll that refreshes server status was rebuilding
that `<select>` from scratch without preserving the current selection.

Each server card (Servers tab) now also shows which servers it routes
data to/from (`→`/`←`, color-coded to match the Live Feed/Map/Chat tabs),
computed from the current routing rules - including a red warning if a
server's direction allows sending but no rule actually routes anything
out of it.

Cards also show **which identity the connection is actually using**
("Connected as: <CN>") - read straight from the certificate's Common
Name field, not from anything typed into the panel. This matters because
you can point several server-entries at the same physical host with
different certificates/logins, and without this there was no way to
tell, from the card alone, which one is which. Works for any cert
(enrolled, uploaded p12, uploaded PEM) since it reads the actual
certificate file, not a remembered username - shows nothing if the file
can't be parsed (wrong password, missing file) rather than erroring.

**Can a routing rule target the same server it came from (`mesh -> mesh`)?**
No - blocked at two levels: the "To" checkbox list excludes whichever
server is selected as "From", so you can't even pick it in the UI; and
`Router.targets_for()` unconditionally discards the origin server from
the computed target set as a loop-guard, so even a self-referencing rule
added by hand in `config.yaml` is silently a no-op.

The panel now has four tabs:

- **Servers** — server cards, add/edit/enroll, and the routing rules table
  (unchanged from before).
- **Live Feed** — a card per source server (address, live item count);
  click one to filter the table below to just that server's markers,
  click again to go back to all. This is the old flat "Live objects"
  table, restructured so it stays readable once several servers and many
  objects are in play.
- **Chat** — GeoChat messages (CoT type `b-t-f`, exact match only —
  `b-t-f-d`/`b-t-f-r` delivery/read receipts are excluded, they carry no
  message text) seen across all connections: time, source server, room,
  sender, message text. Chat messages still get forwarded through the
  normal routing pipeline like any other CoT event (per your `routes`),
  they're just displayed separately here since a message isn't a
  position — they're deliberately excluded from Live Feed and the Map so
  they don't show up as fake 0,0-coordinate objects there. Same caveat as
  before applies here too: whether private 1:1 chats reach the relay at
  all depends on whether the source server honors `dest`/`marti`
  addressing (see the private-message note in the limitations above) -
  group/room chat should always arrive.
- **Map** — every tracked object plotted on a Leaflet map, color-coded by
  source server, with checkboxes above the map to show/hide markers per
  server. This shows something no single ATAK/WinTAK/GoATAK client can:
  the fused picture across every federated server at once. Uses public
  OpenStreetMap tiles for the base map — that needs internet access on
  the machine running the panel; markers still plot at the correct
  coordinates without it, only the background imagery is affected.

Refreshes every 3 seconds. Colors are assigned deterministically per
server name, so the same server keeps the same color across the Live
Feed cards, the table, and the map.

## Next steps

1. Run it against a couple of test servers and watch the logs
   (`--verbose` on `main.py`, or the `web_dashboard.py` console) — confirm
   events are actually arriving and being filtered sensibly.
2. If needed — protobuf v2, spatial deduplication, state persistence,
   metrics/alerts.

## Known issue: a server's stream stops after connecting

If you see a CoT event with `uid="protouid"` and `type="t-x-takp-v"`
arriving right after connecting — that's the server's TAK protocol
version-negotiation control message, not real traffic. The relay now
filters these out of the State Store and routing (they were previously
polluting the Live Feed and Map with fake 0,0-coordinate entries).

That fix stops the pollution, but if a server's actual traffic (positions,
tracks) genuinely stops arriving afterward and doesn't come back, the
likely cause is different and NOT fixed by the filter: some TAK-family
servers may expect a client to reply to that negotiation message and
could change what they send over the plain-XML channel if no reply comes.
(For the record: this was initially suspected to be official-TAK-Server-
specific behavior "unlike GoATAK," based only on a domain name -
`takserver.ru` turned out to be GoATAK's own public community test
server, confirmed in GoATAK's own README, not official TAK Server. So
this remains an open question for GoATAK too, not something confirmed to
be TAK-Server-specific.) The relay currently
speaks TAK protocol v1 (plain XML) only and doesn't implement this
handshake at all (see the v1-only limitation above) - if this turns out
to be the actual cause, implementing the negotiation reply (or protobuf
v2 support) would need to be the next real step, not a cosmetic filter.
First checks to tell these apart: (1) the Servers tab - is the connection
still shown as connected; (2) run with `--verbose` and watch whether
*anything* keeps arriving from that source after the `protouid` message,
even non-significant updates.

**Bridging official TAK Server and GoATAK specifically:** untested. Both
should support the same baseline plain-XML CoT-over-TLS mode the relay
speaks (GoATAK documents it explicitly; official TAK Server needs it for
backward compatibility with older ATAK versions), so it should work in
principle the same way it already works between two GoATAK instances -
but this hasn't been verified against a real official TAK Server, which
is normally restricted-access (.mil/.gov/approved coalition partners)
rather than something with a public test instance the way GoATAK offers.
If you get access to test this, the things most likely to differ are:
whether the server insists on a reply to `t-x-takp-v` before continuing
in XML, and whether it expects a periodic `t-x-c-t` (ping) message from
the client to consider the session alive, beyond just having the TCP/TLS
connection open.
