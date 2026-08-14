// Command goproxy is a single binary that runs either as a client or a server
// to build an encrypted, DPI-obfuscating layer-3 tunnel over TCP.
//
// All runtime configuration comes from environment variables (see the README
// or `goproxy env` for the full list). Usage:
//
//	goproxy genkey                       generate a private key (base64)
//	goproxy pubkey < private.key         derive the public key from a private key
//	goproxy keypair                      print a fresh private+public key pair
//	goproxy gencert -host H -cert C -key K   write a self-signed TLS cert/key
//	goproxy server                       run as server  (configured via env)
//	goproxy client                       run as client  (configured via env)
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
	"syscall"

	"goproxy/internal/client"
	"goproxy/internal/config"
	"goproxy/internal/keys"
	"goproxy/internal/server"
	"goproxy/internal/transport"
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
	case "server":
		cmdServer()
	case "client":
		cmdClient()
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
  server                         run as server (configured via env)
  client                         run as client (configured via env)
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

func cmdServer() {
	cfg, err := config.LoadServer()
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	go handleSignals(func() { srv.Close() })

	if err := srv.Run(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func cmdClient() {
	cfg, err := config.LoadClient()
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	cl, err := client.New(cfg)
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	stop := make(chan struct{})
	go handleSignals(func() { close(stop) })

	if err := cl.Run(stop); err != nil {
		log.Fatalf("client: %v", err)
	}
	log.Printf("shut down cleanly")
}

func handleSignals(onSignal func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Printf("signal received, shutting down...")
	onSignal()
}

const envReference = `goproxy environment variables

common:
  GOPROXY_TRANSPORT          aead | tls | udp         (default: aead)
                             aead: raw TCP, obfuscated, Elligator2 handshake
                             tls:  looks like HTTPS
                             udp:  datagram tunnel (no TCP-over-TCP, tolerates
                                   loss/reorder; anti-replay windowed)
  GOPROXY_PRIVATE_KEY        this peer's X25519 private key (base64)   [required]
  GOPROXY_PSK                shared secret; must match the peer        (default: none)
  GOPROXY_MTU                tunnel MTU               (default: 1380)
  GOPROXY_IFNAME             TUN device name          (default: kernel-assigned)
  GOPROXY_OBFS_MAX_PAD       max random padding bytes per record (default: 255)
  GOPROXY_OBFS_COVER         send randomised cover traffic       (default: true)

server (goproxy server):
  GOPROXY_LISTEN             listen address, e.g. 0.0.0.0:443          [required]
  GOPROXY_TUNNEL_SUBNET      tunnel subnet            (default: 10.8.0.0/24)
  GOPROXY_TUNNEL_SERVER_IP   server's tunnel IP       (default: 10.8.0.1)
  GOPROXY_AUTO_NAT           enable IP-forward + MASQUERADE (default: true)
  GOPROXY_EGRESS_INTERFACE   NAT egress iface         (default: autodetect)
  GOPROXY_TLS_CERT           TLS cert path (tls mode; empty => self-signed)
  GOPROXY_TLS_KEY            TLS key path
  GOPROXY_TLS_HOST           self-signed cert host    (default: www.microsoft.com)
  GOPROXY_CLIENT_<NAME>      authorize a client (one var each; at least one
                             required). Value: "pubkey,ip[,allowed_ips]" where
                             allowed_ips are space-separated. <NAME> is the label.
                             Example:
                               GOPROXY_CLIENT_LAPTOP=PUBA=,10.8.0.2
                               GOPROXY_CLIENT_PC=PUBB=,10.8.0.3,192.168.50.0/24
  GOPROXY_FALLBACK_MODE      what to do with connections that fail the client
                             handshake (probes/scanners): off (default) |
                             status | redirect | proxy
  GOPROXY_FALLBACK_STATUS    HTTP status for "status" mode      (default: 403)
  GOPROXY_FALLBACK_URL       Location header for "redirect" mode
  GOPROXY_FALLBACK_TARGET    backend host:port for "proxy" mode (transparently
                             reverse-proxied; e.g. a local nginx or a real site)

client (goproxy client) -- one tunnel per server:
  GOPROXY_SERVER_<NAME>            server host:port (declares a server; >=1 required)
  GOPROXY_SERVER_<NAME>_PUBLIC_KEY server's X25519 public key (base64)   [required]
  GOPROXY_SERVER_<NAME>_ROUTES     CIDRs to send via this server (comma/space)
  GOPROXY_SERVER_<NAME>_DEFAULT    route ALL traffic via this server (only one)
  GOPROXY_SERVER_<NAME>_TRANSPORT  aead|tls|udp        (default: GOPROXY_TRANSPORT)
  GOPROXY_SERVER_<NAME>_PSK        override            (default: GOPROXY_PSK)
  GOPROXY_SERVER_<NAME>_PRIVATE_KEY client key         (default: GOPROXY_PRIVATE_KEY)
  GOPROXY_SERVER_<NAME>_SNI        tls SNI             (default: GOPROXY_TLS_SNI)
  GOPROXY_SERVER_<NAME>_INSECURE   accept self-signed  (default: GOPROXY_TLS_INSECURE)
  GOPROXY_SERVER_<NAME>_GATEWAY    masquerade LAN into this tunnel
  GOPROXY_SERVER_<NAME>_IFNAME     TUN device name
  GOPROXY_SERVER_<NAME>_KEEPALIVE  keepalive seconds   (default: GOPROXY_KEEPALIVE)

  <NAME> is any label without '_' (e.g. DE, US). The unsuffixed GOPROXY_PSK,
  GOPROXY_PRIVATE_KEY, GOPROXY_TRANSPORT, GOPROXY_TLS_* act as defaults.
  Example (all traffic via DE, one subnet via US):
    GOPROXY_SERVER_DE=de.example:443   GOPROXY_SERVER_DE_PUBLIC_KEY=... DE_DEFAULT=true
    GOPROXY_SERVER_US=us.example:443   GOPROXY_SERVER_US_PUBLIC_KEY=... US_ROUTES="203.0.113.0/24"
`
