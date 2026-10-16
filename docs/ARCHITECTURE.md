# LANyard (后院联机) — Architecture

LANyard lets 2–8 friends play Minecraft Java Edition together over the internet
**without any server operated by the project**. Two copies of the app connect
to each other directly (IPv6, a router port mapping, or UDP hole punching) and
then act as a transparent TCP pipe between the guest's Minecraft and the host's
"Open to LAN" world.

This file describes how the pieces fit together. Decisions that were not fixed
by the original specification are recorded in [DECISIONS.md](DECISIONS.md).

## Processes

```
 ┌───────────────────────┐   HTTP+JSON on 127.0.0.1,   ┌─────────────────────────┐
 │ GUI (Wails, gui/)     │──── bearer token from ─────▶│ core (internal/engine)  │
 │  Host / Join / Diag   │     per-user core.json      │  networking, sessions   │
 └───────────────────────┘                             └──────────┬──────────────┘
 ┌───────────────────────┐            same API                    │ QUIC over UDP
 │ future Fabric mod (v2)│───────────────────────────────▶        ▼
 └───────────────────────┘                              the friend's core
```

* **Core** — all networking lives in the core. It runs as a separate
  background process: `LANyard.exe --core` (the GUI binary re-executes itself)
  or the standalone `lanyard-core` binary (headless; also contains a small
  `ctl` CLI client). The GUI and the future mod are just clients.
* **Discovery / single instance** — the core takes an exclusive OS file lock
  on `<config>/core.lock` (flock / LockFileEx). Holding the lock means "I am
  the core". It then writes `<config>/core.json` (`0600`) with
  `{pid, addr, token, version, apiVersion}` (`addr` is the API's
  `127.0.0.1:port`). A client:
  1. reads `core.json`, calls `GET /v1/hello` with the token;
  2. if that answers with a compatible `apiVersion`, reuses that core;
  3. if a core answers with another `apiVersion` (left running across an
     update), asks it to shut down (`POST /v1/shutdown`) and waits for the
     lock to be free;
  4. starts a core and polls `core.json` until it answers.
  A second core started by a race fails to take the lock and exits with a
  distinctive code, so two clients starting at once still end up sharing one
  core. The GUI starts its core with `-idle 60s`: it exits after 60 s with no
  API traffic and no active session. Sessions keep it running while clients
  are around; the GUI sends a heartbeat every 20 s, and sessions that no
  client has touched for 10 minutes (the GUI crashed) are ended too, so a
  crashed GUI never leaves the core running forever. The standalone
  `lanyard-core` never exits on its own unless started with `-idle`.
* **Control API security** — listens on `127.0.0.1` only, on a random port.
  Every request needs `Authorization: Bearer <token>`; the token is 256 random
  bits regenerated each start and only readable by the user (the config
  directory is mode `0700`; on Windows its permissions are replaced with the
  current user and SYSTEM only, since Unix modes mean nothing there). Requests whose
  `Host` header is not a loopback address are rejected (DNS-rebinding guard),
  and no CORS headers are ever sent.

## Package layout

| Path | Purpose |
|---|---|
| `internal/brand` | Product name/ID/version — single source in `brand.json` |
| `internal/i18n` | Translation catalogs (`locales/en.json`, `locales/zh-CN.json`) shared by core and GUI |
| `internal/config` | Per-user paths and `settings.json` |
| `internal/joincode` | `LY1-…` invite and `LY1R-…` reply codes, `lanyard://join/…` links |
| `internal/transport` | QUIC endpoints (`quic.Transport` per UDP socket), host certificate + fingerprint pinning, authentication handshake, stream types, punch packets, `Relay` extension point |
| `internal/stunx` | STUN client multiplexed on the QUIC socket, RFC 5780 NAT behaviour probes, test STUN server |
| `internal/portmap` | UPnP-IGD (goupnp), NAT-PMP (go-nat-pmp) and PCP (built-in, RFC 6887) mappings, raced in parallel |
| `internal/netinfo` | Interface enumeration, IPv6 global address discovery, CGNAT heuristics |
| `internal/connect` | Candidate gathering, happy-eyeballs dialer, hole punching, attempt log, failure diagnosis rules |
| `internal/mclan` | "Open to LAN" announcement parsing, listener (host side) and announcer (guest side) |
| `internal/proxy` | TCP ⇄ QUIC stream pipes with half-close |
| `internal/engine` | Host and join sessions, state, approvals, idle shutdown |
| `internal/api` | Control API server, client, discovery/lock |
| `internal/update` | Signed manifest fetch + minisign verification |
| `internal/sysinfo` | OS-specific bits (firewall-rule check, detached process start) behind build tags |
| `internal/logbuf` | slog handler with ring buffer + rotating file, log export |
| `cmd/lanyard-core` | Headless core + `ctl` client |
| `cmd/lanyard-release` | Release tooling: key generation, manifest creation + signing |
| `cmd/stuncheck` | Probes the default STUN server list (run in CI) |
| `gui/` | Wails v2 application (separate Go module so the core builds without cgo/webview) |
| `test/natlab` | Network-namespace NAT matrix integration tests (Linux, root) |
| `tools/brandsync` | Propagates `brand.json` into `gui/wails.json` |

## Connection model

### Sockets
Each side opens one UDP socket per address family (IPv4, IPv6) and wraps it in
a `quic.Transport`. The *same* socket is used for STUN, hole-punch packets and
QUIC, which is what makes hole punching work: the NAT mapping discovered by
STUN is the one QUIC later uses. Non-QUIC datagrams (STUN, punch) are read via
`Transport.ReadNonQUICPacket` and dispatched by a demultiplexer.

The host is always the QUIC server; guests are always QUIC clients.

### Host start
In parallel, with a short overall budget (~3 s):
* enumerate global IPv6 addresses (IPv6 direct candidate);
* request a port mapping via UPnP-IGD, NAT-PMP and PCP at once — first wins;
* query all configured STUN servers in parallel (server-reflexive IPv4
  candidate; comparing results from different servers yields the NAT mapping
  behaviour);
* one LAN IPv4 address (for friends on the same network).

The candidates, a random 80-bit secret, a 96-bit truncated SHA-256 fingerprint
of the host's self-signed certificate, the expiry and NAT summary flags are
packed into the invite code.

### Join (happy eyeballs)
The guest decodes the code and dials **all candidates in parallel**, staggered
slightly in the order *IPv6 direct → port-mapped → STUN reflexive → LAN*.
The first QUIC handshake that passes certificate pinning *and* the secret
check wins; the others are cancelled. Every attempt is logged with start
time, duration and outcome.

If nothing connects within ~6 s the guest app switches to the **reply-code
exchange** (while continuing to try). It shows a reply code containing its own
candidates plus an HMAC proof that it knows the host's secret. The host pastes
it; the host then sends authenticated punch packets to the guest's candidates
from its QUIC socket while the guest keeps re-dialing — the classic
simultaneous-open hole punch. A valid punch packet arriving at the guest also
reveals the host's *peer-reflexive* address (useful when the host is behind a
symmetric NAT) and is added as a new candidate.

| Host NAT \ Guest NAT | full cone | addr-restricted | port-restricted | symmetric |
|---|---|---|---|---|
| full cone / UPnP / open IPv6 | one-way | one-way | one-way | one-way |
| address-restricted | reply | reply | reply | reply |
| port-restricted | reply | reply | reply | **fails** |
| symmetric | reply (prflx) | reply (prflx) | **fails** | **fails** |

"Fails" cases need the v1.1 self-hosted relay or IPv6. The NAT lab
(`test/natlab`) checks a representative part of this table: a cell from every
row and both sides of each "fails" boundary (7 cells), plus UPnP, CGNAT and
IPv6-only scenarios. The remaining cells follow from the same rules.

### Security
* QUIC/TLS 1.3 with ALPN `lanyard/1`. The guest pins the host certificate by
  the fingerprint from the code; a mismatching host is rejected before any
  data flows.
* The first stream on every connection is the control stream. The guest sends
  the secret; the host rejects unknown, revoked or expired secrets
  (constant-time comparison) and closes the connection.
* "New code" revokes the old secret. Optional per-join approval makes the host
  user click Allow/Deny before the guest is admitted.
* Punch packets and reply codes carry truncated HMAC-SHA256 tags keyed by the
  secret, so strangers can't make a host spray packets at arbitrary
  addresses.
* LANyard never inspects or modifies Minecraft traffic. Authentication
  (online mode) is enforced, or not, by the host's game exactly as on a LAN.

### Streams
After authentication each TCP connection accepted on the guest's local
listener becomes one bidirectional QUIC stream (type byte `0x02`). The host
dials the selected Minecraft port on its machine and pipes bytes both ways,
propagating half-closes. Server-list pings and game sessions are just more
streams.

### Minecraft LAN integration
* **Host**: joins multicast group `224.0.2.60:4445` on all interfaces and
  parses `[MOTD]…[/MOTD][AD]port[/AD]`. Worlds seen in the last few seconds are
  listed; the most recent local one is used automatically and its port is
  followed when it changes. A manual port (default 25565) supports dedicated
  servers.
* **Guest**: listens on `127.0.0.1:<port>` and announces
  `[MOTD]<host motd> (via LANyard)[/MOTD][AD]<port>[/AD]` every 1.5 s via
  loopback multicast (plus unicast to `127.0.0.1:4445` as a fallback) so the
  world shows up in Multiplayer → LAN. The core ignores its own announcements
  when detecting worlds.

### Relay extension point (v1.1)
`transport.Relay` is an interface returning a `net.PacketConn` that tunnels
datagrams through a user-run relay. Because QUIC runs end-to-end over that
PacketConn, pinning and authentication are unchanged; the relay only sees
encrypted packets. In v1.1 `connect` will treat it as one more strategy in
the happy eyeballs race. v1 ships only the interface and `transport.NoRelay`
(which never allocates); nothing in `connect` uses it yet, and the relay
address setting is stored but not shown.

## GUI
Wails v2 with a plain TypeScript frontend (Vite). It calls Go bindings in
`gui/app.go`, which forward to the core API client. It polls `/v1/state`
once a second. Clipboard detection runs when the window gains focus. The
Windows firewall-rule check and illustrated "Allow access" guide live in the
GUI. `lanyard://join/<code>` arrives as a command-line argument (single
instance lock forwards it to the running window).

## Updates
Check-and-notify only. `manifest.json` + `manifest.json.minisig` are fetched
from GitHub Releases (3 s timeout), then from the maintainer's mirror. The
signature is verified with the Ed25519 minisign public key embedded at build
time before anything is shown. No telemetry; "Export logs" creates a zip the
user can attach to a bug report.
