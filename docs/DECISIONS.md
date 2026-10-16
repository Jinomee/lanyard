# Decisions

Choices the original specification left open, with the reasoning. Newest at
the bottom of each section.

## Naming and prior art (Step 0, 2026-10-16)

* **Name check.** Modrinth: the slug `lanyard` is taken by an unrelated
  cosmetic mod ("Customizable lanyards for in-game events", ~1.5k
  downloads), so the v2 mod needs a different slug (e.g. `lanyard-link`).
  CurseForge: no Minecraft project named Lanyard found. GitHub: the best-known
  "lanyard" is a Discord-presence API, unrelated to Minecraft. None of these
  were judged serious, so the name stays. It is defined once in
  `internal/brand/brand.json`.
* **Prior art reviewed.** lanlink (Rust/iroh: very similar feature set, but
  uses third-party relays/discovery by default), Terracotta 陶瓦联机 and
  mc_network (EasyTier-based virtual LANs with public nodes),
  MinecraftConnectTool, MCLink, P2WLAN, e4mc / World Host / PeerCraft (mods
  with project-run relay or rendezvous servers). LANyard's distinguishing
  constraint is that it needs **no** server at all: signalling is done by
  people copy-pasting codes.

## Protocol

* **Code alphabet.** Crockford base32 (case-insensitive, no I/L/O/U) so codes
  survive being read aloud, retyped, or auto-capitalised by chat apps.
  Decoders ignore whitespace and `-` after the prefix, and map I/L→1, O→0.
* **Prefixes.** Invites use `LY1-`, guest replies `LY1R-`. The type is also
  inside the payload; distinct prefixes let the UI tell users "this is a reply
  code — paste it in the Host screen" instead of a generic error. The prefix
  is a protocol constant, deliberately *not* derived from the brand name, so
  renaming the product doesn't break compatibility.
* **Sizes.** Secret: 80 bits. Certificate fingerprint: first 96 bits of
  SHA-256(cert DER) — a second-preimage attack on 96 bits is infeasible.
  Checksum: CRC-32 (typo/truncation detection; security comes from TLS
  pinning and the secret, not the checksum). Expiry: Unix seconds (uint32).
  Default invite lifetime: 24 h; reply codes: 10 min.
* **Candidate limits.** At most 2 IPv6 addresses (stable ones preferred over
  temporary), 1 mapped, 1 reflexive and 1 LAN IPv4 in an invite, to keep codes
  around 100 characters.
* **ALPN** `lanyard/1`; first stream = control (JSON lines), MC proxy streams
  start with byte `0x02`.
* **Host is always the QUIC server.** Simplifies pinning (only the host has a
  certificate that matters) and lets the one-way code work without any reply.
* **Host certificate** is ECDSA P-256, self-signed, persisted in the config
  directory and reused across sessions, so a reused code still matches. A
  "reset identity" setting regenerates it.
* **PCP** is implemented in-tree (≈150 lines, MAP opcode only) because no
  maintained, dependency-light Go PCP client exists; UPnP uses
  `huin/goupnp`, NAT-PMP uses `jackpal/go-nat-pmp`.
* **NAT filtering detection** uses RFC 5780 CHANGE-REQUEST where the STUN
  server supports it (it advertises OTHER-ADDRESS); otherwise filtering is
  reported as "unknown". Mapping behaviour is always inferred by comparing
  the reflexive address returned by different STUN servers to the same
  socket.
* **Max players.** 7 guests per host (8 players total), per the target
  audience; the host rejects further joins with a clear reason.

## Process model

* The GUI binary re-executes itself with `--core` instead of embedding the
  core, so the core outlives a GUI restart and a future mod can share it. A
  standalone `lanyard-core` binary is also built for headless use.
* The core exits after 60 s with no API calls and no active sessions.
* GUI state updates by polling `/v1/state` every second (simplest robust
  option; an event stream can be added later without breaking clients).
* The GUI lives in a separate Go module (`gui/go.mod`) so that `go build ./...`
  of the core module works on every OS without cgo or WebView headers.

## UX

* Guest display name defaults to the OS user name; it is only ever sent to the
  host the guest is joining and can be changed in Settings.
* Language "Auto" follows the WebView's `navigator.language` (which follows
  the OS); anything starting with `zh` selects Simplified Chinese.
* Host approval is off by default (spec), and when on, a pending guest waits up
  to 2 minutes.

## Connectivity details (learned while building the NAT lab)

* **Default STUN list** was checked from a GitHub-hosted runner (US) on
  2026-10-16 with `cmd/stuncheck` (CI job `stun-check` runs it on every
  push): `stun.miwifi.com` (RFC 5780), `stun.chat.bilibili.com`,
  `stun.douyucdn.cn:18000` (RFC 5780), `stun.cdnbye.com`,
  `stun.cloudflare.com`, `stun.l.google.com:19302`, `stun.nextcloud.com`
  (RFC 5780) and `stun.freeswitch.org` (RFC 5780) answered.
  `stun.hitv.com`, `stun.qq.com` and `stun.syncthing.net` did not and were
  dropped or never added. Reachability *from inside mainland China* could not
  be verified from CI; it is part of docs/MANUAL_TEST.md.
* **Port mappings are not cleaned up after losing the race** (except a UPnP
  rule on a *different* external port). miniupnpd, which most consumer
  routers run, keeps one rule per port for UPnP, NAT-PMP and PCP, so deleting
  the "loser" deleted the winner. The lab caught this. Losing NAT-PMP/PCP
  mappings expire by themselves (2 h).
* **CGNAT detection** uses, in order: a CGNAT (100.64/10) address on this PC;
  the router *refusing* a mapping because its own WAN address is private
  (modern miniupnpd: UPnP error 501, NAT-PMP result 3); a mapped external
  address that isn't public; the router's external address differing from the
  STUN-observed one.
* **A host punch also nudges known paths.** When a valid punch arrives from an
  address the guest is already dialing, that path retries immediately. Only a
  *new* address becomes a separate "peer-reflexive" path.
* **Attempt phase** is the phase in which a try *ended*, so a dial that
  completes after the host's punches is reported as "reply code".
* **LANyard's own LAN announcements carry a trailing `[LY]` marker** (after
  `[/AD]`; Minecraft ignores it). Detectors skip marked packets, so one core
  never re-hosts another core's relayed world (found when two cores ran on one
  machine). Same-process ports are also ignored explicitly.
* **The host keeps serving the chosen world** while it is announced, even if
  another world opens later. If the world disappears (closed or reopened on a
  new port), it follows the most recently opened local world.
* **Guest LAN announcement** is a unicast datagram to `127.0.0.1:4445` plus
  multicast on the loopback interface, both from `127.0.0.1`. Minecraft's
  socket is bound to the wildcard address, so the unicast reaches it, and the
  world is listed as `127.0.0.1:<port>`, reachable only from that PC. We
  deliberately don't announce on the LAN interface: the tunnel would then be
  offered to everyone on the guest's network.
* **Lab realism:** emulated routers drop unsolicited WAN input (like every
  real router). Without that, Linux conntrack confirms an entry for the peer's
  early probe, and the PC's later outbound punch gets a different source port
  (SNAT tuple clash), so hole punching fails in a way real routers don't.
  "Address-restricted" filtering is emulated per mapping (remote address +
  port), as RFC 4787 defines it.

## Packaging

* **v1 ships unsigned.** SignPath Foundation asks for an established project
  first, and paid options were deferred. The README explains SmartScreen's
  "Run anyway" and how to check SHA-256 hashes. `docs/RELEASING.md` has the
  per-release antivirus false-positive checklist and the signing options for
  later.

* The installer is per-machine (needs admin anyway for the firewall rule) and
  creates an inbound rule for the executable on **all profiles**: many home
  networks are marked "Public" on Windows.
* The installer stops running `LANyard.exe` processes (GUI and background
  core are the same executable) before replacing files.
* The firewall check uses PowerShell's NetSecurity module. It reports
  *blocked* separately because clicking "Cancel" on the Windows prompt creates
  block rules, which is the most common silent failure.
* Update manifests are signed by a dedicated release key. `lanyard-release
  verify` runs in the release workflow against the key **embedded in the app**,
  so a release can never be published with a signature that installed
  clients would reject.
