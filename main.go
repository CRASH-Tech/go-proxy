// Command goproxy builds encrypted, DPI-obfuscating layer-3 tunnels between
// nodes. Every instance is a node: it accepts peers, connects to peers, or
// both, so the same binary serves as an exit server, a client or a site in a
// mesh.
//
// All runtime configuration comes from environment variables (see the README
// or `goproxy env` for the full list). Usage:
//
//	goproxy genkey                       generate a private key (base64)
//	goproxy pubkey < private.key         derive the public key from a private key
//	goproxy keypair                      print a fresh private+public key pair
//	goproxy gencert -host H -cert C -key K   write a self-signed TLS cert/key
//	goproxy node                         run a node     (configured via env)
//	goproxy env                          print all recognised environment variables
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"goproxy/internal/config"
	"goproxy/internal/keys"
	"goproxy/internal/node"
	"goproxy/internal/transport"
	"goproxy/internal/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "genkey":
		cmdGenkey()
	case "pubkey":
		cmdPubkey()
	case "keypair":
		cmdKeypair()
	case "gencert":
		cmdGencert(os.Args[2:])
	case "env":
		fmt.Print(envReference)
	case "node":
		cmdNode()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `goproxy - encrypted, DPI-obfuscating layer-3 tunnel

All runtime configuration is read from environment variables (run 'goproxy env').

commands:
  genkey                         print a new base64 X25519 private key
  pubkey                         read a private key on stdin, print its public key
  keypair                        print a fresh private and public key pair
  gencert -host H -cert C -key K write a self-signed TLS certificate/key
  env                            list all recognised environment variables
  node                           run a node (configured via env)
`)
}

func cmdGenkey() {
	k, err := keys.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("genkey: %v", err)
	}
	fmt.Println(k.String())
}

func cmdPubkey() {
	data, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		log.Fatalf("pubkey: read stdin: %v", err)
	}
	priv, err := keys.ParsePrivateKey(strings.TrimSpace(string(data)))
	if err != nil {
		log.Fatalf("pubkey: %v", err)
	}
	fmt.Println(priv.Public().String())
}

func cmdKeypair() {
	k, err := keys.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("keypair: %v", err)
	}
	fmt.Printf("private: %s\npublic:  %s\n", k.String(), k.Public().String())
}

func cmdGencert(args []string) {
	fs := flag.NewFlagSet("gencert", flag.ExitOnError)
	host := fs.String("host", "www.example.com", "certificate CN/SAN host")
	certPath := fs.String("cert", "cert.pem", "output certificate path")
	keyPath := fs.String("key", "key.pem", "output key path")
	_ = fs.Parse(args)
	if err := transport.WriteSelfSigned(*certPath, *keyPath, *host); err != nil {
		log.Fatalf("gencert: %v", err)
	}
}

func cmdNode() {
	dataDir := os.Getenv("GOPROXY_DATA_DIR")
	pending := config.SettingsPending(dataDir) // settings just changed in the web UI

	// failed handles an error before the node is up: after a settings change
	// in the web UI it restores the previous settings and starts again, so a
	// bad setting cannot lock the UI out.
	failed := func(what string, err error) {
		if pending {
			log.Printf("%s: %v", what, err)
			if rerr := config.RollbackSettings(dataDir); rerr == nil {
				log.Printf("the settings changed in the web UI did not work: restored the previous ones")
				restart()
			}
		}
		log.Fatalf("%s: %v", what, err)
	}

	cfg, err := config.LoadNode()
	if err != nil {
		failed("node", err)
	}
	n, err := node.New(cfg)
	if err != nil {
		failed("node", err)
	}
	n.OnStarted = func() { // called from Run, on this goroutine
		if pending {
			config.ConfirmSettings(dataDir)
			pending = false
			log.Printf("the settings changed in the web UI are in effect")
		}
	}

	stop := make(chan struct{})
	var stopOnce sync.Once
	shutdown := func() { stopOnce.Do(func() { close(stop) }) }
	var restarting atomic.Bool
	go handleSignals(shutdown)

	stopWeb := func() {}
	if cfg.WebListen != "" {
		requestRestart := func() {
			restarting.Store(true)
			shutdown()
		}
		if stopWeb, err = web.Start(cfg, n, requestRestart); err != nil {
			failed("web UI", err)
		}
	}

	runErr := n.Run(stop)
	stopWeb()
	if restarting.Load() {
		log.Printf("restarting to apply the new settings...")
		restart()
	}
	if runErr != nil {
		failed("node", runErr)
	}
	log.Printf("shut down cleanly")
}

// restart replaces this process with a fresh copy of itself (same PID, same
// environment), which reads its configuration again.
func restart() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("restart: %v", err)
	}
	err = syscall.Exec(exe, os.Args, os.Environ())
	log.Fatalf("restart: %v", err)
}

func handleSignals(onSignal func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Printf("signal received, shutting down...")
	onSignal()
}

const envReference = `goproxy environment variables (goproxy node)

node:
  GOPROXY_PRIVATE_KEY        this node's X25519 private key (base64); may be
                             left out with GOPROXY_DATA_DIR (generated and kept
                             there on first start)
  GOPROXY_NAME               this node's name in configs generated for peers
                             (default: the hostname)
  GOPROXY_DATA_DIR           directory for the peers managed in the web UI
                             (peers.json) and a generated key (node.key)
  GOPROXY_IFNAME             TUN device name          (default: goproxy0)
  GOPROXY_TUN_ADDRESS        TUN address; its network is where handed-out peer
                             IPs live               (default: 10.255.255.1/32)
  GOPROXY_MTU                TUN (inner) MTU          (default: 1320)
                             padding is bounded to it and the outer TCP MSS is
                             clamped, so packets fit typical/tunneled paths.
  GOPROXY_FWMARK             SO_MARK set on connections to peers (and their DNS
                             lookups), for host policy routing (default: 0x676f)
  GOPROXY_PUSH_ROUTES        route the peers' prefixes into the TUN on the host
                             (removed on exit): false | true | clients
                             (default: false)
                             true:    for the host and its clients -- prefixes
                                      "ip route add <cidr> dev <tun>", 0.0.0.0/0
                                      via table GOPROXY_FWMARK + ip rules that
                                      exempt the node's own marked connections
                             clients: only for forwarded traffic -- all prefixes
                                      in table GOPROXY_FWMARK, used via
                                      "ip rule ... not iif lo"; the host's own
                                      traffic keeps its routes
  GOPROXY_MASQUERADE         interface to NAT the TUN network out of, e.g. eth0
                             (iptables MASQUERADE + FORWARD accepts, removed on
                             exit; net.ipv4.ip_forward stays yours) (default: off)
  GOPROXY_MASQUERADE_IPS     source CIDRs to NAT out of GOPROXY_MASQUERADE instead
                             of the TUN network, e.g. a LAN whose router sends
                             everything to the node (default: the TUN network)
  GOPROXY_LOG_CONNECTIONS    log one line per new connection through the tunnel:
                             who, where, via/from which peer, or blocked
                             (default: false)
  GOPROXY_OBFS_MAX_PAD       max random padding bytes per record (default: 255)
  GOPROXY_OBFS_COVER         send randomised cover traffic       (default: true)

web UI (optional):
  GOPROXY_WEB_LISTEN         address of the management UI, e.g. 127.0.0.1:8080
  GOPROXY_WEB_PASSWORD       its password                     [required with it]
  GOPROXY_WEB_TLS            serve it over HTTPS with a self-signed certificate
                             (default: false)
  GOPROXY_WEB_PATH           serve it only under this path, e.g. k7Qm2xVd;
                             any other URL is a 404         (default: at /)
  Peers added in the UI are saved in GOPROXY_DATA_DIR and applied at once;
  peers from the environment are shown read-only. These settings can be made
  in the UI too, when the environment leaves them unset: GOPROXY_NAME,
  GOPROXY_LISTEN, GOPROXY_TRANSPORT, GOPROXY_PSK, GOPROXY_TLS_HOST,
  GOPROXY_TUN_ADDRESS, GOPROXY_PUSH_ROUTES, GOPROXY_MASQUERADE,
  GOPROXY_MASQUERADE_IPS, GOPROXY_LOG_CONNECTIONS (kept in settings.json;
  saving restarts the node, which restores the previous ones if it cannot
  start with them). The node's key can be generated or pasted there.

accepting peers (optional):
  GOPROXY_LISTEN             listen address, e.g. 0.0.0.0:443 (default: none)
  GOPROXY_TRANSPORT          aead | tls | udp         (default: aead)
                             aead: raw TCP, obfuscated, Elligator2 handshake
                             tls:  looks like HTTPS
                             udp:  datagram tunnel (no TCP-over-TCP, tolerates
                                   loss/reorder; anti-replay windowed)
                             also the default transport for connecting to peers
  GOPROXY_TLS_CERT           TLS cert path (tls; empty => self-signed)
  GOPROXY_TLS_KEY            TLS key path
  GOPROXY_TLS_HOST           self-signed cert host    (default: www.microsoft.com)
  GOPROXY_FALLBACK_MODE      what to do with connections that fail the
                             handshake (probes/scanners): off (default) |
                             status | redirect | proxy
  GOPROXY_FALLBACK_STATUS    HTTP status for "status" mode      (default: 403)
  GOPROXY_FALLBACK_URL       Location header for "redirect" mode
  GOPROXY_FALLBACK_TARGET    backend host:port for "proxy" mode (transparently
                             reverse-proxied; e.g. a local nginx or a real site)

peers (one or more):
  GOPROXY_PEER_<NAME>_PUBLIC_KEY   peer's X25519 public key (declares a peer)
  GOPROXY_PEER_<NAME>_ROUTES       IPv4 CIDRs behind the peer (comma/space):
                                   packets to them are sent to it, and it may
                                   only send from them. 0.0.0.0/0 = everything
  GOPROXY_PEER_<NAME>_IP           tunnel IP handed to the peer when it connects
                                   (it translates its TUN address to it);
                                   implies a /32 route. For clients.
  GOPROXY_PEER_<NAME>_ENDPOINT     host:port -- connect to the peer (otherwise
                                   only wait for it to connect)
  GOPROXY_PEER_<NAME>_NAT          true: source-NAT this node's clients' traffic
                                   to the peer to the node's own address (TCP,
                                   UDP, ICMP echo; in the node, no iptables)
                                   (default: false)
  GOPROXY_PEER_<NAME>_TRANSPORT    for _ENDPOINT        (default: GOPROXY_TRANSPORT)
  GOPROXY_PEER_<NAME>_PSK          shared secret        (default: GOPROXY_PSK)
  GOPROXY_PEER_<NAME>_SNI          tls SNI              (default: GOPROXY_TLS_SNI)
  GOPROXY_PEER_<NAME>_INSECURE     accept self-signed   (default: GOPROXY_TLS_INSECURE)
  GOPROXY_PEER_<NAME>_KEEPALIVE    cover/keepalive seconds (default: GOPROXY_KEEPALIVE, 25)
  GOPROXY_PEER_<NAME>_DISABLED     true: keep the peer configured but unused; its
                                   routes may then repeat an enabled peer's
  GOPROXY_PEER_<NAME>_INTERFACE    create a TUN of the peer's own with this name
                                   (up to 15 chars): whatever the host routes
                                   into it goes to the peer, and the peer's
                                   traffic comes out of it. _ROUTES then only
                                   limit its source addresses, stay out of the
                                   node TUN and GOPROXY_PUSH_ROUTES, and may
                                   repeat another such peer's

  Each peer needs _ROUTES and/or _IP; a prefix may belong to one peer only
  (peers with an _INTERFACE excepted).
  Every packet entering the TUN goes to the peer with the longest matching
  route; packets matching none (and all IPv6) are BLOCKED (answered with ICMP
  "administratively prohibited"). The node changes no sysctls or iptables,
  and host routes only with GOPROXY_PUSH_ROUTES -- see the README.
  <NAME>: letters, digits, '-' and '_' (e.g. DC2, LAPTOP).

examples:
  exit server:  GOPROXY_LISTEN=0.0.0.0:443 GOPROXY_TUN_ADDRESS=10.8.0.1/24 GOPROXY_MASQUERADE=eth0
                GOPROXY_PEER_LAPTOP_PUBLIC_KEY=<pub> GOPROXY_PEER_LAPTOP_IP=10.8.0.2
  its client:   GOPROXY_PEER_EXIT_PUBLIC_KEY=<pub> GOPROXY_PEER_EXIT_ENDPOINT=exit.example:443
                GOPROXY_PEER_EXIT_ROUTES=0.0.0.0/0
  site mesh:    GOPROXY_LISTEN=0.0.0.0:443 GOPROXY_TUN_ADDRESS=10.1.254.1/24
                GOPROXY_PEER_DC2_PUBLIC_KEY=<pub> GOPROXY_PEER_DC2_ENDPOINT=dc2.example:443
                GOPROXY_PEER_DC2_ROUTES=10.2.0.0/16
`
