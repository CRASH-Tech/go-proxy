# goproxy — encrypted, DPI-obfuscating layer-3 tunnel

A single Go binary that runs as either a **client** or a **server** and builds an
encrypted, obfuscated tunnel between them. It operates at layer 3 (a TUN
device), so **TCP, UDP and ICMP are all carried transparently** — there is no
per-protocol proxy.

```
  LAN devices          client VM                         server VPS                internet
 ┌───────────┐   ┌────────────────────┐          ┌────────────────────────┐    ┌──────────┐
 │ phone/PC  │──▶│ tun0  goproxy client│═════════▶│ goproxy server  tun0   │──▶ │  8.8.8.8 │
 │ (default  │   │  (encrypt + obfusc.)│  TCP/TLS │ (decrypt, NAT to world)│    │  google  │
 │  route)   │◀──│                     │◀═════════│                        │◀── │   ...    │
 └───────────┘   └────────────────────┘  internet└────────────────────────┘    └──────────┘
```

**All runtime configuration comes from environment variables** — there are no
config files. Run `goproxy env` for the full list.

## How it works

- **Transport** (client ⇄ server), pick one via `GOPROXY_TRANSPORT`:
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
  forward secrecy from ephemeral keys, plus an optional pre-shared key. A client
  is authorized **iff** its public key is listed on the server. Multiple clients
  are supported, each pinned to a tunnel IP.
- **Forwarding** — the server writes decrypted packets to its TUN and the Linux
  kernel NATs (MASQUERADEs) them to the internet; return traffic is routed back
  to the owning client by tunnel IP.

Linux only (client and server). Requires root (for `/dev/net/tun`, iptables and
routes).

## Build

```bash
go build -o goproxy .
```

## 1. Generate keys

On each side generate a static key pair. Give each peer the *other* side's
**public** key.

```bash
goproxy genkey > server.key
goproxy pubkey < server.key      # server public key (goes in the client env)

goproxy genkey > client.key
goproxy pubkey < client.key      # client public key (goes in the server env)
```

(`goproxy keypair` prints a fresh private+public pair in one go.)

### With Docker (no local Go toolchain)

Build the image once, then run the key commands in a throwaway container — key
generation needs no privileges, devices or network:

```bash
docker build -t goproxy:latest .

# a fresh private + public pair
docker run --rm goproxy:latest keypair

# or, matching the file-based flow above (note -i so stdin is passed through):
docker run --rm goproxy:latest genkey > server.key
docker run --rm -i goproxy:latest pubkey < server.key
```

## 2. Server (VPS)

```bash
export GOPROXY_TRANSPORT=tls
export GOPROXY_LISTEN=0.0.0.0:443
export GOPROXY_PRIVATE_KEY="$(cat server.key)"
export GOPROXY_PSK="a-long-shared-secret"
export GOPROXY_TUNNEL_SUBNET=10.8.0.0/24
export GOPROXY_TUNNEL_SERVER_IP=10.8.0.1
export GOPROXY_TLS_HOST=www.microsoft.com          # for the self-signed cert
# authorized clients: one GOPROXY_CLIENT_<NAME> each, value "pubkey,ip[,allowed_ips]"
export GOPROXY_CLIENT_LAPTOP="PUB_OF_CLIENT1,10.8.0.2"
export GOPROXY_CLIENT_PHONE="PUB_OF_CLIENT2,10.8.0.3,192.168.50.0/24"

sudo -E goproxy server
```

With `GOPROXY_AUTO_NAT=true` (the default) the server enables IP forwarding and
installs the MASQUERADE / FORWARD rules automatically, reverting them on a clean
shutdown (Ctrl-C / SIGTERM). To manage NAT yourself set `GOPROXY_AUTO_NAT=false`
and run:

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -s 10.8.0.0/24 -o eth0 -j ACCEPT
iptables -A FORWARD -d 10.8.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

For `GOPROXY_TRANSPORT=tls` you can leave `GOPROXY_TLS_CERT`/`GOPROXY_TLS_KEY`
empty to auto-generate a self-signed certificate (clients set
`GOPROXY_TLS_INSECURE=true`), or point them at a real certificate for a fully
legitimate-looking endpoint.

## 3. Client (VM)

A client connects to **one or more servers**. Each server is declared by
`GOPROXY_SERVER_<NAME>` (its address); per-server settings use
`GOPROXY_SERVER_<NAME>_<FIELD>` and fall back to the global `GOPROXY_*` defaults.
The client runs an independent tunnel (its own TUN, session and routes) per
server. Single-server example:

```bash
export GOPROXY_TRANSPORT=tls
export GOPROXY_PRIVATE_KEY="$(cat client.key)"
export GOPROXY_PSK="a-long-shared-secret"
export GOPROXY_TLS_INSECURE=true                     # accept the self-signed cert

export GOPROXY_SERVER_MAIN=SERVER_PUBLIC_IP:443
export GOPROXY_SERVER_MAIN_PUBLIC_KEY="PUB_OF_SERVER"
export GOPROXY_SERVER_MAIN_DEFAULT=true              # route this host's traffic via it

sudo -E goproxy client
```

The client learns its tunnel IP from the server during the handshake and
configures its TUN automatically. Per-server routing:

- `GOPROXY_SERVER_<NAME>_DEFAULT=true` — route the **host's own** traffic through
  this server (at most one server may set it).
- `GOPROXY_SERVER_<NAME>_ROUTES="203.0.113.0/24 8.8.8.8/32"` — **split tunnel**:
  send only these prefixes through this server.
- `GOPROXY_SERVER_<NAME>_GATEWAY=true` — make the VM a router for **other
  devices**: traffic forwarded out of this TUN is masqueraded to the tunnel IP
  (for the "point my home router at the VM" setup).
- `GOPROXY_SERVER_<NAME>_IFNAME=tun-de` — name the TUN device.

## Multiple servers, split by destination

One client process, several servers, each with its own routes — no manual
`ip route` needed:

```bash
sudo -E env \
  GOPROXY_PRIVATE_KEY="$(cat client.key)" GOPROXY_PSK=secret GOPROXY_TLS_INSECURE=true \
  \
  GOPROXY_SERVER_DE=de.example:443 GOPROXY_SERVER_DE_PUBLIC_KEY="$PUB_DE" \
  GOPROXY_SERVER_DE_TRANSPORT=tls  GOPROXY_SERVER_DE_DEFAULT=true \
  GOPROXY_SERVER_DE_IFNAME=tun-de \
  \
  GOPROXY_SERVER_JP=jp.example:443 GOPROXY_SERVER_JP_PUBLIC_KEY="$PUB_JP" \
  GOPROXY_SERVER_JP_TRANSPORT=udp  GOPROXY_SERVER_JP_ROUTES="203.0.113.0/24 198.51.100.7/32" \
  GOPROXY_SERVER_JP_IFNAME=tun-jp \
  \
  goproxy client
```

Everything goes through Germany by default; the two listed prefixes go through
Japan. Give each server a **different tunnel subnet** (server side) so the TUNs
don't collide, and set `_DEFAULT=true` on **at most one** server. Different
servers may even use different transports (here DE is `tls`, JP is `udp`).

## Running under systemd

Everything is environment-driven, so a unit just sets `Environment=` (or points
at an `EnvironmentFile=`):

```ini
[Unit]
Description=goproxy server
After=network-online.target

[Service]
Environment=GOPROXY_TRANSPORT=tls
Environment=GOPROXY_LISTEN=0.0.0.0:443
Environment=GOPROXY_PRIVATE_KEY=...
Environment=GOPROXY_PSK=a-long-shared-secret
Environment=GOPROXY_CLIENT_LAPTOP=PUB1,10.8.0.2
Environment=GOPROXY_CLIENT_PHONE=PUB2,10.8.0.3
ExecStart=/usr/local/bin/goproxy server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Docker

A multi-stage [`Dockerfile`](Dockerfile) builds a small static image (Alpine +
`iptables`/`iproute2`). Ready-to-edit compose files live under
[`deploy/`](deploy). The container needs `NET_ADMIN`, the `/dev/net/tun` device,
and IP forwarding in its namespace.

Server:

```bash
cd deploy
cp server.env.example server.env      # fill in keys / psk / clients
docker compose -f docker-compose.server.yml up -d --build
```

Client:

```bash
cd deploy
cp client.env.example client.env      # fill in server / keys / psk
docker compose -f docker-compose.client.yml up -d --build
```

Notes:

- In the default (bridge) client setup the container tunnels its **own** network
  namespace. Other containers can route through it with
  `network_mode: "service:goproxy-client"` (see the commented `app` service in
  the client compose).
- For a **LAN gateway** (home router points at this host) or to NAT the server
  via the real host interface, use `network_mode: host` in the compose service
  (commented instructions are in each file), and enable `net.ipv4.ip_forward=1`
  on the host.
- A single client reaches multiple servers at once — declare several
  `GOPROXY_SERVER_<NAME>` with per-server `_ROUTES` (see above).

## Command reference

```
goproxy genkey                          print a new base64 X25519 private key
goproxy pubkey  < private.key           derive the public key
goproxy keypair                         print a fresh private + public pair
goproxy gencert -host H -cert C -key K  write a self-signed TLS cert/key
goproxy env                             list all recognised environment variables
goproxy server                          run as server (configured via env)
goproxy client                          run as client (configured via env)
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
that hangs, resets, or speaks an unknown protocol to everyone but your clients
is a tell.

The server can hand any connection that fails the client handshake (scanners,
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
# Anything that isn't an authenticated client is served your decoy site:
export GOPROXY_FALLBACK_MODE=proxy
export GOPROXY_FALLBACK_TARGET=127.0.0.1:8080     # a local nginx, say
```

Valid clients continue to tunnel on the same port at the same time.

Note: with `aead` the outer connection is not TLS, so a fallback HTTP response is
plaintext (the endpoint looks like a plain HTTP service). To present a proper
HTTPS decoy to TLS probes, use `GOPROXY_TRANSPORT=tls` together with the
fallback.

## Security model

- Only clients whose **public key** is in `GOPROXY_CLIENTS` can complete the
  handshake — that is the authorization. Remove a key to revoke a client.
- The optional **PSK** adds a shared secret; with the `aead` transport it also
  means a prober without the PSK cannot even elicit a valid response.
- Forward secrecy: session keys come from ephemeral X25519 and are discarded when
  the connection ends.
- Anti-replay: the client's handshake carries a timestamp checked within a 90 s
  window.
- Anti-spoofing: the server drops packets whose source is not an address routed
  to that client.

This is a practical obfuscation + encryption tool, not a formally audited VPN.
Use real certificates and a strong PSK for anything important.

## Troubleshooting

- **`open /dev/net/tun` fails** — run as root and ensure the `tun` module is
  loaded (`modprobe tun`).
- **ICMP/UDP work but TCP to :80/:443 fails from behind the tunnel** — something
  on the *server host* is intercepting forwarded TCP (a transparent proxy such
  as `redsocks`, or a restrictive `FORWARD` policy). Check
  `iptables -t nat -S PREROUTING` for `REDIRECT`/`DNAT` on ports 80/443 and
  `iptables -S FORWARD` for a `DROP` policy ahead of the MASQUERADE rules.
- **No connectivity at all** — verify `GOPROXY_EGRESS_INTERFACE`, that
  `net.ipv4.ip_forward` is 1, and that the client's PSK/keys match the server.

## Notes & limitations

- `aead` runs over TCP, so a lossy path incurs TCP-over-TCP behaviour. For most
  browsing this is fine; `tls` has the same property.
- IPv6 packets are carried, but the NAT/route helpers configure IPv4.
- Multi-hop (client → S1 → S2 → world) is not implemented yet; the transport and
  session layers are structured to allow chaining later.
