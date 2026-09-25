# goproxy — encrypted, DPI-obfuscating layer-3 tunnel

A single Go binary that builds encrypted, obfuscated tunnels between **nodes**.
Every instance is a node: it accepts peers, connects to peers, or both. The
same binary therefore serves as an exit server, as a client, or as a site in a
mesh of data centers. It operates at layer 3 (a TUN device), so **TCP, UDP and
ICMP are all carried transparently** — there is no per-protocol proxy.

```
  exit server + clients                         site mesh + road warriors

  laptop ──▶ goproxy ═══════▶ goproxy ──▶ internet     10.1.0.0/16    10.2.0.0/16
  (client node)        (exit node, NAT)                   DC1 ════════════ DC2
                                                            ╲             ╱
                                                             ╲═══ DC3 ═══╱   ◀── laptop
                                                                10.3.0.0/16
```

**All runtime configuration comes from environment variables** — there are no
config files. Run `goproxy env` for the full list.

## How it works

- **Transport** between two nodes — set by the listening node's
  `GOPROXY_TRANSPORT` (the connecting side uses the same):
  - `aead` — a raw TCP connection carrying a ChaCha20-Poly1305 record stream with
    encrypted lengths and random padding. On the wire it is indistinguishable
    from random bytes: no TLS, no fixed headers, nothing static for DPI to match.
  - `tls` — a genuine TLS connection (real ClientHello, SNI, certificate) so the
    traffic looks like ordinary HTTPS. Best against DPI that blocks *unknown*
    protocols.
  - `udp` — a datagram tunnel (one inner packet per UDP datagram, WireGuard-style
    counter nonce + anti-replay window). No TCP-over-TCP head-of-line blocking,
    tolerates loss/reordering. Uses the same obfuscated, Elligator2 handshake.

  The handshake ephemeral keys are encoded with **Elligator2**, so they appear as
  uniform-random bytes rather than recognisable X25519 points (as obfs4 does).
- **Handshake / auth** — `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, the same
  construction WireGuard uses: mutual authentication with static X25519 keys,
  forward secrecy from ephemeral keys, plus an optional pre-shared key. A peer is
  admitted **iff** its public key is listed as a peer.
- **Routing** — every packet the node reads from its TUN goes to the peer whose
  routes contain the destination (longest prefix wins); a packet from a peer is
  accepted only if its source is routed to that peer. Packets no peer routes are
  **blocked**.
- **Host networking is yours** — goproxy creates and addresses its TUN; on
  request it also routes the peers' prefixes into it
  ([`GOPROXY_PUSH_ROUTES`](#pushing-routes)) and NATs its TUN network to the
  internet (`GOPROXY_MASQUERADE`). It never changes sysctls; the commands a
  host needs are given with each scenario below.

Linux only. Requires root (or `CAP_NET_ADMIN`) for the TUN.

## Build

```bash
go build -o goproxy .
```

Or take a release: every `v*` tag builds static Linux binaries (`amd64`,
`arm64`, `armv7`, with `SHA256SUMS`) attached to the GitHub release, and a
multi-arch image `crashntech/go-proxy:<tag>` (plus `latest` unless the tag is a
pre-release such as `v0.2.0-rc1`). See
[`.github/workflows/release.yml`](.github/workflows/release.yml); it needs the
repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (and optionally
the variable `DOCKER_IMAGE` for another image name).

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Keys

Every node has its own static key pair; each node lists the **public** keys of
its peers.

```bash
goproxy keypair                  # a fresh private + public pair
# or
goproxy genkey > node.key
goproxy pubkey < node.key        # its public key, for the peers' config
```

With Docker (no local Go toolchain), key generation needs no privileges:

```bash
docker build -t goproxy:latest .
docker run --rm goproxy:latest keypair
```

## Nodes and peers

A node is configured with its identity and TUN, an optional listener, and its
peers:

```bash
GOPROXY_PRIVATE_KEY=...              # this node's private key
GOPROXY_TUN_ADDRESS=10.8.0.1/24      # TUN address (default 10.255.255.1/32)
GOPROXY_LISTEN=0.0.0.0:443           # accept peers (optional)
GOPROXY_TRANSPORT=tls                # listener transport, default for connecting
GOPROXY_PSK=a-long-shared-secret     # default PSK for all peers

GOPROXY_PEER_<NAME>=<public key>     # declares a peer
```

Per-peer settings (`GOPROXY_PEER_<NAME>_<FIELD>`):

| field       | meaning |
|-------------|---------|
| `ROUTES`    | IPv4 CIDRs behind the peer: packets to them are sent to it, and it may only send from them. `0.0.0.0/0` = everything. |
| `IP`        | a tunnel IP handed to the peer when it connects; the peer translates its TUN address to it. For clients — see below. Implies a `/32` route. |
| `ENDPOINT`  | `host:port` to connect to. Without it the node only waits for the peer to connect. |
| `NAT`       | `true`: traffic of this node's clients sent to the peer leaves with the node's own address (see [NAT for clients](#nat-for-clients)), so the peer needs no routes for them. |
| `TRANSPORT`, `PSK`, `SNI`, `INSECURE`, `KEEPALIVE` | overrides of `GOPROXY_TRANSPORT`, `GOPROXY_PSK`, `GOPROXY_TLS_SNI`, `GOPROXY_TLS_INSECURE`, `GOPROXY_KEEPALIVE`. |

Every peer needs `ROUTES` and/or `IP`, and a prefix may belong to one peer only.
A pair of nodes needs a connection in one direction only — either side may set
the other's `ENDPOINT`; if both do, both connections are kept and either carries
the traffic.

**Address translation for clients.** When a peer has an `IP`, it is told that IP
during the handshake and rewrites its own TUN address to it on the way out and
back on the way in (stateless, with checksum fix-up). A client can thus use
several servers at once, each handing it a different IP from its own range,
with one TUN. Only traffic whose source is the TUN address is translated —
traffic leaving the host with another source (e.g. a LAN host's) keeps it,
unless the peer has `NAT` (below).

### NAT for clients

With `GOPROXY_PEER_<NAME>_NAT=true` the node source-NATs its **clients'**
traffic sent to that peer — LAN devices it forwards for, road warriors
connected to it — to its own TUN address (and from there to the IP the peer
handed out, if any), and translates the replies back. The peer then needs no
route back to the clients: a home gateway needs no `MASQUERADE`, and a site can
let its road warriors reach another site that has no route to them.

- Done inside the node, no iptables: TCP and UDP are mapped by port, ICMP echo
  by identifier; ICMP errors about a mapped flow are translated too (embedded
  header included), so path-MTU discovery keeps working.
- Mappings are endpoint-dependent: replies are accepted only from the address
  and port the flow was opened to. Connections the peer side opens *to* a
  client are left untranslated, replies included (the client stays reachable
  by its real address wherever the peer can route to it).
- Translated ports lie outside the host's `ip_local_port_range`
  (61000–65535 by default), so they never clash with the node's own sockets.
  Idle mappings expire (TCP 1 h, 1 min after FIN/RST; UDP 3 min; ICMP 30 s).
- The node's own traffic is never translated. Other protocols and non-first
  IP fragments pass unchanged.

Other node settings: `GOPROXY_IFNAME` (TUN name, `goproxy0`), `GOPROXY_MTU`
(1320), `GOPROXY_FWMARK` (`0x676f`, the `SO_MARK` put on the node's own
connections to peers and their DNS lookups, so host policy routing can keep them
out of the TUN), `GOPROXY_PUSH_ROUTES` (below), `GOPROXY_MASQUERADE` (an
interface to NAT the TUN network out of, see the [exit host
setup](#exit-host-setup)), plus the obfuscation and fallback settings.

### Pushing routes

By default (`GOPROXY_PUSH_ROUTES=false`) the node leaves host routing alone:
you decide what enters the TUN (see each scenario). Otherwise it routes its
peers' prefixes (`_ROUTES` and `_IP`) into the TUN itself and removes those
routes and rules again on exit. Either for everyone on the host, or only for
the clients it forwards traffic for:

**`GOPROXY_PUSH_ROUTES=true`** — the host itself and its clients, the way
`wg-quick` does it:

- a specific prefix becomes `ip route add <prefix> dev goproxy0`. If the host
  already has a route for exactly that prefix, it is left alone (with a
  warning in the log);
- `0.0.0.0/0` becomes a default route in table `GOPROXY_FWMARK` (26479) plus the
  rules of the [client host setup](#client-host-setup) (`pref 1001`, `1002`,
  IPv4 and IPv6) — everything except directly connected networks and the node's
  own connections goes into the TUN. With a strict `rp_filter` this needs the
  CONNMARK lines; the node warns if they are missing.

**`GOPROXY_PUSH_ROUTES=clients`** — only forwarded traffic (LAN devices using
the node as their gateway, road warriors arriving through the tunnel); the
host's own traffic keeps its normal routes and never enters the TUN:

```bash
# what the node sets up (table = GOPROXY_FWMARK)
ip route add 10.2.0.0/16 dev goproxy0 table 26479           # every peer prefix, 0.0.0.0/0 as "default"
ip rule add lookup main suppress_prefixlength 0 pref 1001   # connected networks still win
ip rule add not iif lo lookup 26479 pref 1002               # "not from this host"
```

- a forwarded destination no peer routes is passed on by the host's normal
  routes. To block it instead, add one rule yourself:
  `ip rule add not iif lo prohibit pref 1003`;
- works with a strict `rp_filter` as is: for forwarded packets the kernel's
  reverse-path check matches the same rule;
- the host is then not reachable from the peers' networks through the tunnel
  (its replies follow the normal routes) — except from the TUN's own network,
  e.g. the road-warrior pool;
- if the host has its own route for exactly a peer's prefix, that route wins
  for the clients too (with a warning in the log).

Both leave sysctls and iptables alone: bypass rules (`pref 1000`), forwarding
and NAT stay yours. Unlike a persistent TUN with your own routes, pushed routes
disappear while the node is stopped, so traffic is not blocked then.

## Scenario 1: exit server and clients

### Exit node

```bash
export GOPROXY_PRIVATE_KEY="$(cat exit.key)"
export GOPROXY_LISTEN=0.0.0.0:443
export GOPROXY_TRANSPORT=tls
export GOPROXY_TLS_HOST=www.microsoft.com          # for the self-signed cert
export GOPROXY_PSK="a-long-shared-secret"
export GOPROXY_TUN_ADDRESS=10.8.0.1/24             # the clients' network

export GOPROXY_PEER_LAPTOP="PUB_OF_LAPTOP"
export GOPROXY_PEER_LAPTOP_IP=10.8.0.2
export GOPROXY_PEER_OFFICE="PUB_OF_OFFICE"
export GOPROXY_PEER_OFFICE_IP=10.8.0.3
export GOPROXY_PEER_OFFICE_ROUTES=192.168.50.0/24  # a LAN behind that client (optional)

sudo -E goproxy node
```

For `tls` you can leave `GOPROXY_TLS_CERT`/`GOPROXY_TLS_KEY` empty to
auto-generate a self-signed certificate (clients set `GOPROXY_TLS_INSECURE=true`),
or point them at a real certificate for a fully legitimate-looking endpoint.

#### Exit host setup

The node hands decrypted packets to its TUN; the host forwards them and NATs
them to the internet (`eth0` = the egress interface). Enable forwarding:

```bash
sysctl -w net.ipv4.ip_forward=1
```

and either set `GOPROXY_MASQUERADE=eth0` — the node then adds the rules below
for its TUN network on start and removes them on exit (an identical rule
already present is taken over) — or add them yourself:

```bash
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
# only needed if the FORWARD policy is DROP (e.g. docker or ufw installed):
iptables -A FORWARD -s 10.8.0.0/24 -o eth0 -j ACCEPT
iptables -A FORWARD -d 10.8.0.0/24 -i eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

Routes a client brings along (`192.168.50.0/24` above) also need a route into the
TUN: `ip route add 192.168.50.0/24 dev goproxy0` (with a persistent TUN, see
below, so the route survives restarts).

### Client node

```bash
export GOPROXY_PRIVATE_KEY="$(cat laptop.key)"
export GOPROXY_PSK="a-long-shared-secret"
export GOPROXY_TLS_INSECURE=true                   # accept the self-signed cert

export GOPROXY_PEER_EXIT="PUB_OF_EXIT"
export GOPROXY_PEER_EXIT_ENDPOINT=EXIT_PUBLIC_IP:443
export GOPROXY_PEER_EXIT_TRANSPORT=tls
export GOPROXY_PEER_EXIT_ROUTES=0.0.0.0/0

sudo -E goproxy node
```

Several exits split by destination are just several peers — the more specific
route wins, and different exits may use different transports:

```bash
GOPROXY_PEER_DE=... GOPROXY_PEER_DE_ENDPOINT=de.example:443 GOPROXY_PEER_DE_ROUTES=0.0.0.0/0
GOPROXY_PEER_JP=... GOPROXY_PEER_JP_ENDPOINT=jp.example:443 GOPROXY_PEER_JP_TRANSPORT=udp \
GOPROXY_PEER_JP_ROUTES="203.0.113.0/24 198.51.100.7/32"
```

Drop DE's `0.0.0.0/0` and only the JP prefixes work at all — the rest of what
enters the TUN is blocked.

#### Client host setup

*Which* traffic enters the TUN is up to the host. The recipe below sends
everything into it except directly connected networks, the bypass list and the
node's own (marked) connections — the same scheme `wg-quick` uses.
[`GOPROXY_PUSH_ROUTES=true`](#pushing-routes) does the table and the
`pref 1001`/`1002` rules for you; the bypass rules and the CONNMARK lines stay
yours either way:

```bash
TUN=goproxy0 MARK=0x676f TABLE=26479          # GOPROXY_IFNAME, GOPROXY_FWMARK, any free table id

# A persistent TUN: goproxy attaches to it, the routes below survive goproxy
# restarts, and while goproxy is down the traffic is dropped instead of leaking.
# (Without it goproxy creates the TUN itself; then add the routes after each start.)
ip tuntap add dev $TUN mode tun
ip link set $TUN up

# A table whose default route is the TUN.
ip route add default dev $TUN table $TABLE
ip -6 route add default dev $TUN table $TABLE

# Bypass: destinations sent directly via the host's normal routes (one rule each).
ip rule add to 192.168.0.0/16 lookup main pref 1000

# Non-default routes of the main table (connected subnets, docker bridges) still apply...
ip rule add lookup main suppress_prefixlength 0 pref 1001
ip -6 rule add lookup main suppress_prefixlength 0 pref 1001
# ...everything else goes to the TUN, except goproxy's own marked sockets.
ip rule add not fwmark $MARK lookup $TABLE pref 1002
ip -6 rule add not fwmark $MARK lookup $TABLE pref 1002
```

If `net.ipv4.conf.all.rp_filter` is `1` (strict; the default on RHEL-like
systems), the peers' replies would fail the reverse-path check, since an
unmarked lookup of a peer's address points into the TUN. Either relax it to `2`,
or carry the mark over to the replies:

```bash
sysctl -w net.ipv4.conf.all.src_valid_mark=1
iptables -t mangle -A OUTPUT -m mark --mark $MARK -j CONNMARK --save-mark
iptables -t mangle -A PREROUTING -m connmark --mark $MARK -j CONNMARK --restore-mark
```

Notes:

- Whatever the rules send into the TUN and no peer routes is blocked, so with
  this recipe "not bypassed and not routed" means blocked. To leave some traffic
  alone instead, bypass it.
- The IPv6 lines capture IPv6 only to block it (peers carry IPv4); skip them if
  the host has IPv6 disabled, or bypass IPv6 prefixes with `ip -6 rule add to ...`.
- For a split tunnel instead, skip the table and rules and route only what the
  peers cover: `ip route add 203.0.113.0/24 dev goproxy0`.
- To undo: `ip link del $TUN` (drops the table's routes) and
  `ip [-6] rule del pref 1000|1001|1002` for each rule added.

#### Gateway for other devices

To route other devices through the client (e.g. your home router points at it),
enable forwarding and let the node translate their traffic to the IP the exit
handed out — set `GOPROXY_PEER_EXIT_NAT=true`:

```bash
sysctl -w net.ipv4.ip_forward=1
# only needed if the FORWARD policy is DROP:
iptables -A FORWARD -o goproxy0 -j ACCEPT
iptables -A FORWARD -i goproxy0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

(Instead of `_NAT`, `iptables -t nat -A POSTROUTING -o goproxy0 -j MASQUERADE`
does the same in the kernel.)

Forwarded traffic follows the same rules as the host's: bypassed destinations
go out directly, the rest into the TUN. To tunnel only the devices and keep the
gateway's own traffic direct, use `GOPROXY_PUSH_ROUTES=clients` instead of the
[client host setup](#client-host-setup).

## Scenario 2: site mesh with road warriors

Three data centers on public IPs, each with its own network, linked
full-mesh; a laptop connected to **any one** of them reaches all three.

| site | public address   | network       | TUN address (road-warrior pool) |
|------|------------------|---------------|---------------------------------|
| DC1  | `dc1.example`    | `10.1.0.0/16` | `10.1.254.1/24`                 |
| DC2  | `dc2.example`    | `10.2.0.0/16` | `10.2.254.1/24`                 |
| DC3  | `dc3.example`    | `10.3.0.0/16` | `10.3.254.1/24`                 |

Each site's TUN address comes from its own network, so the node's own traffic
and its road warriors are reachable from the other sites without any NAT. Site
traffic keeps its real addresses end to end.

### Site nodes

Each pair needs one connection: DC1 connects to DC2 and DC3, DC2 connects to
DC3. (Setting the endpoint on both sides of a pair is fine too — then either
side can re-establish the link.)

```bash
# --- DC1 ---
GOPROXY_PRIVATE_KEY=<DC1 private>
GOPROXY_LISTEN=0.0.0.0:443
GOPROXY_TRANSPORT=tls
GOPROXY_TLS_INSECURE=true
GOPROXY_PSK=a-long-shared-secret
GOPROXY_TUN_ADDRESS=10.1.254.1/24

GOPROXY_PEER_DC2=<DC2 public>
GOPROXY_PEER_DC2_ENDPOINT=dc2.example:443
GOPROXY_PEER_DC2_ROUTES=10.2.0.0/16
GOPROXY_PEER_DC3=<DC3 public>
GOPROXY_PEER_DC3_ENDPOINT=dc3.example:443
GOPROXY_PEER_DC3_ROUTES=10.3.0.0/16

GOPROXY_PEER_LAPTOP=<laptop public>
GOPROXY_PEER_LAPTOP_IP=10.1.254.10

# --- DC2 --- (same common part, TUN 10.2.254.1/24)
GOPROXY_PEER_DC1=<DC1 public>
GOPROXY_PEER_DC1_ROUTES=10.1.0.0/16                # DC1 connects to us
GOPROXY_PEER_DC3=<DC3 public>
GOPROXY_PEER_DC3_ENDPOINT=dc3.example:443
GOPROXY_PEER_DC3_ROUTES=10.3.0.0/16
GOPROXY_PEER_LAPTOP=<laptop public>
GOPROXY_PEER_LAPTOP_IP=10.2.254.10

# --- DC3 --- (same common part, TUN 10.3.254.1/24)
GOPROXY_PEER_DC1=<DC1 public>
GOPROXY_PEER_DC1_ROUTES=10.1.0.0/16
GOPROXY_PEER_DC2=<DC2 public>
GOPROXY_PEER_DC2_ROUTES=10.2.0.0/16
GOPROXY_PEER_LAPTOP=<laptop public>
GOPROXY_PEER_LAPTOP_IP=10.3.254.10
```

#### Site host setup

On each site node (shown for DC1):

```bash
sysctl -w net.ipv4.ip_forward=1               # forward between the LAN and the tunnel

# Routes to the other sites: set GOPROXY_PUSH_ROUTES=true (or =clients, if the
# site node itself should not use them), or yourself:
ip tuntap add dev goproxy0 mode tun           # persistent, so the routes survive restarts
ip link set goproxy0 up
ip route add 10.2.0.0/16 dev goproxy0
ip route add 10.3.0.0/16 dev goproxy0
```

The site's LAN must send the other sites' networks to the node: either the node
is the LAN's gateway, or the LAN router gets
`10.2.0.0/16, 10.3.0.0/16 and 10.1.254.0/24 via <node's LAN address>`.
Keep the road-warrior pool (`10.1.254.0/24`) off any on-link LAN segment —
otherwise LAN hosts would ARP for the laptops instead of routing to the node.

Traffic between sites is not NATed — do not masquerade `-o goproxy0`. (If a
site cannot route back to another site's clients, e.g. a partner network, set
`GOPROXY_PEER_<NAME>_NAT=true` for that peer: they then appear there as the
node's TUN address.) If the road warriors should reach the internet through
the site as well, set `GOPROXY_MASQUERADE=eth0` on the site node: it NATs only
its TUN network (the pool, `10.1.254.0/24`) out of `eth0`, so traffic between
sites keeps its addresses.

### Road warrior

The laptop connects to one site and routes all three networks through it:

```bash
GOPROXY_PRIVATE_KEY=<laptop private>
GOPROXY_PSK=a-long-shared-secret
GOPROXY_TLS_INSECURE=true
GOPROXY_PEER_DC2=<DC2 public>
GOPROXY_PEER_DC2_ENDPOINT=dc2.example:443
GOPROXY_PEER_DC2_TRANSPORT=tls
GOPROXY_PEER_DC2_ROUTES=10.1.0.0/16 10.2.0.0/16 10.3.0.0/16
```

On the laptop host, set `GOPROXY_PUSH_ROUTES=true`, or route the three
networks into the TUN yourself — after starting goproxy, or beforehand with a
persistent TUN:

```bash
for net in 10.1.0.0/16 10.2.0.0/16 10.3.0.0/16; do ip route add $net dev goproxy0; done
```

Or use the full [client host setup](#client-host-setup) with `0.0.0.0/0` in
`_ROUTES` to also use the site as an internet exit.

The site hands the laptop an address from its own pool (`10.2.254.10` at DC2),
so the other sites route replies back through DC2 on their own. To use DC1
instead, point the peer at DC1 (its public key and endpoint) — nothing else
changes. Alternatively the laptop may connect to all three sites at once, each
peer routing only its own site's network.

## Running under systemd

Everything is environment-driven, so a unit just points at an
`EnvironmentFile=`; put the host setup in a script run before it:

```ini
[Unit]
Description=goproxy node
After=network-online.target

[Service]
EnvironmentFile=/etc/goproxy/node.env
# host setup of your scenario (see above), e.g. a script of those commands:
# ExecStartPre=/usr/local/sbin/goproxy-net-up
ExecStart=/usr/local/bin/goproxy node
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Docker

A multi-stage [`Dockerfile`](Dockerfile) builds a small static image (Alpine +
`iptables`/`iproute2`). Ready-to-edit compose files for scenario 1 live under
[`deploy/`](deploy). The container needs `NET_ADMIN` and the `/dev/net/tun`
device. The compose files do the host setup inside the container's own network
namespace (the exit via `GOPROXY_MASQUERADE=eth0`, the client via a few
commands before starting goproxy), so the real host is not touched.

Exit node:

```bash
cd deploy
cp server.env.example server.env      # fill in keys / psk / peers
docker compose -f docker-compose.server.yml up -d --build
```

Client node:

```bash
cd deploy
cp client.env.example client.env      # fill in keys / psk / peers
docker compose -f docker-compose.client.yml up -d --build
```

Notes:

- In the default (bridge) client setup the container tunnels its **own** network
  namespace. Other containers can route through it with
  `network_mode: "service:goproxy-client"` (see the commented `app` service in
  the client compose).
- With `network_mode: host` (site nodes, a LAN gateway, or NAT via the real host
  interface) the setup commands would change the host itself — run them on the
  host instead and keep the container's command plain `node`.

## Command reference

```
goproxy genkey                          print a new base64 X25519 private key
goproxy pubkey  < private.key           derive the public key
goproxy keypair                         print a fresh private + public pair
goproxy gencert -host H -cert C -key K  write a self-signed TLS cert/key
goproxy env                             list all recognised environment variables
goproxy node                            run a node (configured via env)
```

## Traffic obfuscation (aead)

The `aead` transport is designed to resist traffic-analysis. What it does:

- **Encrypted record lengths.** Every record's length is itself encrypted (as in
  shadowsocks AEAD), so an observer sees only an opaque byte stream — no
  plaintext length fields.
- **Variable record sizes.** Each data record gets 0–`GOPROXY_OBFS_MAX_PAD`
  (default 255) random padding bytes; the receiver recovers the real packet from
  the inner IP header and drops the padding.
- **Randomised cover traffic.** Both ends emit variable-size junk records at
  randomised intervals (`GOPROXY_OBFS_COVER`, default on). This masks whether the
  tunnel is idle or busy and replaces the fixed keepalive heartbeat with
  irregular timing. Observed on the wire, idle traffic looks like:

  ```
  +0.63s len=322   +1.56s len=691   +2.59s len=456   +1.16s len=1038  ...
  ```

- **No static signature.** There is no TLS, no SNI, no fixed header — the first
  bytes are an **Elligator2**-encoded ephemeral key (indistinguishable from
  uniform random) followed by ciphertext.
- **In-order transport doesn't reorder; use `udp` if you need that.** The `aead`
  transport is a single TCP stream (in-order by definition). The `udp` transport
  carries each inner packet in its own datagram, so it tolerates loss and
  reordering and has no TCP-over-TCP head-of-line blocking.

Honest limitations (not yet addressed):

- **Handshake length prefix.** In `aead` mode the handshake messages still carry
  a 2-byte plaintext length prefix (the ephemeral key itself is now uniform via
  Elligator2). A high-end DPI could use the length framing; removing it needs a
  self-delimiting handshake.
- **Per-packet timing** of real traffic is passed through unchanged (only cover
  traffic timing is randomised); full inter-arrival-time shaping is not done.

Tuning knobs: `GOPROXY_OBFS_MAX_PAD`, `GOPROXY_OBFS_COVER` (see `goproxy env`).
Both apply to `aead` and `udp`.

## Fallback (anti-probing)

Censorship systems often confirm a suspected proxy by **actively probing** it —
connecting themselves and seeing whether it behaves like a real server. A port
that hangs, resets, or speaks an unknown protocol to everyone but your peers is
a tell.

A listening node can hand any connection that fails the handshake (scanners,
probes, wrong keys) to a **fallback** that makes the endpoint look like an
ordinary web server. Bytes already read during the failed handshake are
replayed, so a reverse-proxy backend sees the original request intact. This runs
above the transport, so it works for both `aead` and `tls`.

Modes (`GOPROXY_FALLBACK_MODE`):

- `off` (default) — just close the connection.
- `status` — return a fixed HTTP status (`GOPROXY_FALLBACK_STATUS`, default 403),
  rendered as an nginx-style page.
- `redirect` — 302 to `GOPROXY_FALLBACK_URL`.
- `proxy` — transparently reverse-proxy to `GOPROXY_FALLBACK_TARGET`
  (`host:port`). **Strongest camouflage**: point it at a local `nginx` serving a
  real-looking site, or at a real website's `host:port`, and to a prober the
  endpoint is indistinguishable from that site.

```bash
# Anything that isn't an authenticated peer is served your decoy site:
export GOPROXY_FALLBACK_MODE=proxy
export GOPROXY_FALLBACK_TARGET=127.0.0.1:8080     # a local nginx, say
```

Valid peers continue to tunnel on the same port at the same time.

Note: with `aead` the outer connection is not TLS, so a fallback HTTP response is
plaintext (the endpoint looks like a plain HTTP service). To present a proper
HTTPS decoy to TLS probes, use `GOPROXY_TRANSPORT=tls` together with the
fallback.

## Security model

- Only nodes whose **public key** is listed as a `GOPROXY_PEER_<NAME>` can
  complete the handshake — that is the authorization. Remove a peer to revoke it.
- The optional **PSK** adds a shared secret; with the `aead` transport it also
  means a prober without the PSK cannot even elicit a valid response.
- Forward secrecy: session keys come from ephemeral X25519 and are discarded when
  the connection ends.
- Anti-replay: the connecting side's handshake carries a timestamp checked within
  a 90 s window.
- Anti-spoofing: a node accepts from a peer only packets whose source is routed
  to that peer (plus ICMP errors, for path-MTU discovery), so a peer cannot pose
  as another site or as a destination routed elsewhere.
- Fail-closed: packets in the TUN that no peer routes are blocked, and traffic
  for a disconnected peer is dropped rather than leaked around the tunnel (with
  a persistent TUN, also while goproxy is not running).

This is a practical obfuscation + encryption tool, not a formally audited VPN.
Use real certificates and a strong PSK for anything important.

## Troubleshooting

- **`open /dev/net/tun` fails** — run as root and ensure the `tun` module is
  loaded (`modprobe tun`).
- **ICMP/UDP work but TCP to :80/:443 fails from behind the tunnel** — something
  on the *exit host* is intercepting forwarded TCP (a transparent proxy such as
  `redsocks`, or a restrictive `FORWARD` policy). Check
  `iptables -t nat -S PREROUTING` for `REDIRECT`/`DNAT` on ports 80/443 and
  `iptables -S FORWARD` for a `DROP` policy ahead of the MASQUERADE rules.
- **No connectivity at all** — verify the [exit host setup](#exit-host-setup)
  (`net.ipv4.ip_forward` is 1, MASQUERADE on the right egress interface) and
  that the peers' keys and PSK match.
- **Connected, but nothing goes through** — check that the traffic reaches the
  TUN (`ip route get <dst>`; for the capture recipe `ip rule` and
  `ip route show table 26479`), `rp_filter` (a strict value needs the CONNMARK
  lines), and that the destination is in a peer's `_ROUTES` and the source in
  the other side's `_ROUTES` for this node. With `GOPROXY_PUSH_ROUTES`, look for
  "already exists" warnings — such a prefix keeps the host's existing route.
- **Connecting to a peer times out, but only with a captured default route** —
  strict `rp_filter` drops the peer's replies (`nstat -az TcpExtIPReversePathFilter`
  counts them); relax it to `2` or add the CONNMARK lines.
- **A site pair stays down for a while after a restart** — reconnects back off
  up to 30 s; setting the endpoint on both sides lets either one re-establish
  the link.

## Notes & limitations

- **MTU is handled automatically.** The inner MTU defaults to 1320, per-packet
  padding is bounded so wrapped packets never exceed it, and the outer TCP MSS is
  clamped (1360) — so pages don't "load halfway" on reduced or tunneled paths.
  If a very small-MTU path still stalls, lower `GOPROXY_MTU` on both sides.
- `aead` runs over TCP, so a lossy path incurs TCP-over-TCP behaviour. For most
  browsing this is fine; `tls` has the same property. `udp` avoids it.
- Peer routes are IPv4-only; IPv6 reaching the TUN is blocked.
- Routes are static: a prefix belongs to one peer, so there is no automatic
  failover to another site.
- Per-peer `NAT` translates TCP, UDP and ICMP echo only; other protocols and
  non-first fragments of large datagrams pass untranslated.
