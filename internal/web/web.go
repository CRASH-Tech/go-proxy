// Package web serves the node's management UI (GOPROXY_WEB_LISTEN): the
// status of the node and its peers, adding, changing and removing the peers
// kept in the data directory, key generation, and the connection log.
//
// Access needs the password (GOPROXY_WEB_PASSWORD); a login yields a session
// cookie (HttpOnly, SameSite=Strict), signed with a key derived from the
// password, so it survives a restart of the node and dies with a password
// change. Requests that change something must be JSON with the X-Goproxy
// header, which a cross-site form cannot send.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/keys"
	"goproxy/internal/node"
	"goproxy/internal/transport"
)

//go:embed static
var static embed.FS

const (
	cookieName = "goproxy_session"
	sessionTTL = 12 * time.Hour
)

// Server is the web UI.
type Server struct {
	n        *node.Node
	cfg      *config.NodeConfig
	restart  func() // restarts the node to apply settings; nil = not possible
	passHash [32]byte
	signKey  [32]byte // signs session tokens
	secure   bool     // served over TLS: mark the cookie Secure
	base     string   // GOPROXY_WEB_PATH ("/secret") or ""

	mu      sync.Mutex
	revoked map[string]time.Time // logged-out tokens -> their expiry
	loginMu sync.Mutex           // failed logins are serialised and slowed down
}

// NewServer returns the UI for n (configured by cfg), protected by
// cfg.WebPassword. restart, if not nil, restarts the node to apply settings.
func NewServer(cfg *config.NodeConfig, n *node.Node, restart func()) *Server {
	return &Server{
		n:        n,
		cfg:      cfg,
		restart:  restart,
		passHash: sha256.Sum256([]byte(cfg.WebPassword)),
		signKey:  sha256.Sum256([]byte("goproxy-web-session\x00" + cfg.WebPassword)),
		secure:   cfg.WebTLS,
		base:     cfg.WebPath,
		revoked:  map[string]time.Time{},
	}
}

// Start serves the UI on cfg.WebListen until the returned func is called.
// restart is called (after the response is sent) when settings changed in the
// UI need a restart of the node.
func Start(cfg *config.NodeConfig, n *node.Node, restart func()) (func(), error) {
	ln, err := net.Listen("tcp", cfg.WebListen)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if cfg.WebTLS {
		cert, err := transport.LoadOrCreateCert("", "", "goproxy")
		if err != nil {
			ln.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		scheme = "https"
	}
	srv := &http.Server{
		Handler:           NewServer(cfg, n, restart).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web UI: %v", err)
		}
	}()
	log.Printf("web UI on %s://%s%s/", scheme, cfg.WebListen, cfg.WebPath)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

// Handler returns the UI's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	files, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServerFS(files))

	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	api := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.auth(h)) }
	api("GET /api/state", s.state)
	api("GET /api/settings", s.getSettings)
	api("PUT /api/settings", s.putSettings)
	api("GET /api/connections", s.connections)
	api("GET /api/next-ip", s.nextIP)
	api("POST /api/keypair", s.keypair)
	api("POST /api/node/key", s.nodeKey)
	api("POST /api/peers", s.addPeer)
	api("PUT /api/peers/{name}", s.updatePeer)
	api("DELETE /api/peers/{name}", s.deletePeer)
	if s.base == "" {
		return headers(mux)
	}
	// Only under the base path; anything else is a bare 404, so the UI's
	// existence is not given away.
	inner := http.StripPrefix(s.base, headers(mux))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, s.base+"/"):
			inner.ServeHTTP(w, r)
		case r.URL.Path == s.base:
			http.Redirect(w, r, s.base+"/", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
}

// cookiePath scopes the session cookie to the UI.
func (s *Server) cookiePath() string { return s.base + "/" }

// headers adds security headers to every response.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// auth lets through requests with a valid session; changing requests must
// also carry the X-Goproxy header (CSRF protection).
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.validSession(r) {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Goproxy") != "1" {
			writeError(w, http.StatusForbidden, "missing X-Goproxy header")
			return
		}
		next(w, r)
	})
}

// newToken returns a session token: expiry and a random nonce, signed.
func (s *Server) newToken(exp time.Time) string {
	var body [16]byte
	binary.BigEndian.PutUint64(body[:8], uint64(exp.Unix()))
	_, _ = rand.Read(body[8:])
	mac := hmac.New(sha256.New, s.signKey[:])
	mac.Write(body[:])
	return base64.RawURLEncoding.EncodeToString(append(body[:], mac.Sum(nil)...))
}

// checkToken returns the expiry of a valid token.
func (s *Server) checkToken(tok string) (time.Time, bool) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(b) != 16+sha256.Size {
		return time.Time{}, false
	}
	mac := hmac.New(sha256.New, s.signKey[:])
	mac.Write(b[:16])
	if !hmac.Equal(mac.Sum(nil), b[16:]) {
		return time.Time{}, false
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(b[:8])), 0)
	if time.Now().After(exp) {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, out := s.revoked[tok]; out {
		return time.Time{}, false
	}
	return exp, true
}

func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	_, ok := s.checkToken(c.Value)
	return ok
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Goproxy") != "1" {
		writeError(w, http.StatusForbidden, "missing X-Goproxy header")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	got := sha256.Sum256([]byte(req.Password))
	if subtle.ConstantTimeCompare(got[:], s.passHash[:]) != 1 {
		s.loginMu.Lock()
		time.Sleep(time.Second)
		s.loginMu.Unlock()
		log.Printf("web UI: failed login from %s", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "wrong password")
		return
	}
	token := s.newToken(time.Now().Add(sessionTTL))
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: s.cookiePath(), MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secure,
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		if exp, ok := s.checkToken(c.Value); ok {
			now := time.Now()
			s.mu.Lock()
			for t, e := range s.revoked {
				if now.After(e) {
					delete(s.revoked, t)
				}
			}
			s.revoked[c.Value] = exp
			s.mu.Unlock()
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.cookiePath(), MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secure})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	filePeers := s.n.FilePeers()
	if filePeers == nil {
		filePeers = []config.Peer{}
	}
	// peers: effective configuration and status; file_peers: as stored, for
	// the edit form (empty fields there mean "the node's default").
	writeJSON(w, map[string]any{"node": s.n.Info(), "peers": s.n.Peers(), "file_peers": filePeers})
}

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	enabled, entries := s.n.Connections()
	writeJSON(w, map[string]any{"enabled": enabled, "entries": entries})
}

func (s *Server) nextIP(w http.ResponseWriter, r *http.Request) {
	ip, err := s.n.NextFreeIP()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ip": ip})
}

func (s *Server) keypair(w http.ResponseWriter, r *http.Request) {
	priv, err := keys.GeneratePrivateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]string{"private_key": priv.String(), "public_key": priv.Public().String()})
}

// nodeKey replaces this node's key: with the given private key, or a new one.
func (s *Server) nodeKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrivateKey string `json:"private_key"`
	}
	if r.ContentLength != 0 && !readJSON(w, r, &req) {
		return
	}
	var pub keys.PublicKey
	var err error
	if k := strings.TrimSpace(req.PrivateKey); k != "" {
		priv, perr := keys.ParsePrivateKey(k)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "private key: "+perr.Error())
			return
		}
		pub, err = s.n.SetKey(priv)
	} else {
		pub, err = s.n.RegenerateKey()
	}
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, map[string]string{"public_key": pub.String()})
}

// settingView is one editable setting as the UI shows it.
type settingView struct {
	Key    string `json:"key"`
	Value  string `json:"value"`  // in effect
	Source string `json:"source"` // env (read-only) | settings | default
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	values := s.cfg.SettingValues()
	out := make([]settingView, 0, len(config.EditableSettings))
	for _, k := range config.EditableSettings {
		out = append(out, settingView{Key: k, Value: values[k], Source: s.cfg.Sources[k]})
	}
	writeJSON(w, map[string]any{
		"settings": out,
		"editable": s.cfg.DataDir != "" && s.restart != nil,
	})
}

// putSettings checks and saves settings, then restarts the node to apply
// them. Settings set in the environment cannot be changed here. An empty
// value returns a setting to its default.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DataDir == "" || s.restart == nil {
		writeError(w, http.StatusConflict, "settings can only be changed with GOPROXY_DATA_DIR set")
		return
	}
	var req map[string]string
	if !readJSON(w, r, &req) {
		return
	}
	next, err := config.ReadSettings(s.cfg.DataDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for k, v := range req {
		if !slices.Contains(config.EditableSettings, k) {
			writeError(w, http.StatusBadRequest, k+" cannot be set here")
			return
		}
		if s.cfg.Sources[k] == "env" {
			if strings.TrimSpace(v) != s.cfg.SettingValues()[k] {
				writeError(w, http.StatusBadRequest, k+" is set in the environment")
				return
			}
			continue
		}
		next[k] = strings.TrimSpace(v)
	}
	// Check the result as the node would load it, peers from the UI included.
	cfg, err := config.LoadNodeWith(next)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	peers := append(slices.Clone(cfg.Peers), s.n.FilePeers()...)
	for i := len(cfg.Peers); i < len(peers); i++ {
		cfg.ApplyDefaults(&peers[i])
	}
	if err := config.ValidatePeers(peers); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := config.BeginSettingsChange(s.cfg.DataDir, next); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("saving settings: %v", err))
		return
	}
	log.Printf("web UI: settings changed; restarting to apply them")
	writeJSON(w, map[string]bool{"restarting": true})
	go func() {
		time.Sleep(300 * time.Millisecond) // let the response go out
		s.restart()
	}()
}

func (s *Server) addPeer(w http.ResponseWriter, r *http.Request) {
	var p config.Peer
	if !readJSON(w, r, &p) {
		return
	}
	peers := s.n.FilePeers()
	if slices.ContainsFunc(peers, func(q config.Peer) bool { return q.Name == p.Name }) {
		writeError(w, http.StatusConflict, "a peer named "+p.Name+" exists")
		return
	}
	s.apply(w, append(peers, clean(p)))
}

func (s *Server) updatePeer(w http.ResponseWriter, r *http.Request) {
	var p config.Peer
	if !readJSON(w, r, &p) {
		return
	}
	peers := s.n.FilePeers()
	i := slices.IndexFunc(peers, func(q config.Peer) bool { return q.Name == r.PathValue("name") })
	if i < 0 {
		writeError(w, http.StatusNotFound, "no peer "+r.PathValue("name")+" managed here")
		return
	}
	peers[i] = clean(p)
	s.apply(w, peers)
}

func (s *Server) deletePeer(w http.ResponseWriter, r *http.Request) {
	peers := s.n.FilePeers()
	i := slices.IndexFunc(peers, func(q config.Peer) bool { return q.Name == r.PathValue("name") })
	if i < 0 {
		writeError(w, http.StatusNotFound, "no peer "+r.PathValue("name")+" managed here")
		return
	}
	s.apply(w, slices.Delete(peers, i, i+1))
}

func (s *Server) apply(w http.ResponseWriter, peers []config.Peer) {
	if err := s.n.SetFilePeers(peers); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// clean trims a peer as entered in the UI.
func clean(p config.Peer) config.Peer {
	p.Name = strings.TrimSpace(p.Name)
	p.PublicKey = strings.TrimSpace(p.PublicKey)
	p.IP = strings.TrimSpace(p.IP)
	p.Endpoint = strings.TrimSpace(p.Endpoint)
	p.TLS.SNI = strings.TrimSpace(p.TLS.SNI)
	var routes []string
	for _, r := range p.Routes {
		for _, f := range strings.FieldsFunc(r, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\t' }) {
			routes = append(routes, f)
		}
	}
	p.Routes = routes
	return p
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "JSON expected")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
