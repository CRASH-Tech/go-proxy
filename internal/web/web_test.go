package web

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/keys"
	"goproxy/internal/node"
)

func pub(t *testing.T) string {
	k, _ := keys.GeneratePrivateKey()
	return k.Public().String()
}

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func (c *client) do(method, path, body string, header bool) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if header {
		req.Header.Set("X-Goproxy", "1")
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func setup(t *testing.T) (*client, *node.Node) {
	c, n, _ := setupWith(t, nil)
	return c, n
}

// setupWith starts the UI for a node (not running) whose config is loaded
// from the environment given by env; restarts counts requested restarts.
func setupWith(t *testing.T, restarts *int) (*client, *node.Node, *config.NodeConfig) {
	return setupPath(t, restarts, "")
}

func setupPath(t *testing.T, restarts *int, path string) (*client, *node.Node, *config.NodeConfig) {
	t.Helper()
	cfg := &config.NodeConfig{
		Name: "HOME", DataDir: t.TempDir(), InterfaceName: "goproxy0", Address: "10.8.0.1/24",
		MTU: 1320, Transport: "udp", PushRoutes: "false", FwMark: 0x676f, DefaultKeepalive: 25,
		WebPassword: "s3cret", WebPath: path,
		Sources: map[string]string{"GOPROXY_TUN_ADDRESS": "env"},
	}
	env := config.Peer{Name: "EXIT", PublicKey: pub(t), Routes: []string{"0.0.0.0/0"}}
	cfg.ApplyDefaults(&env)
	cfg.Peers = []config.Peer{env}
	n, err := node.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restart func()
	if restarts != nil {
		restart = func() { *restarts++ }
	}
	srv := httptest.NewServer(NewServer(cfg, n, restart).Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: srv.URL, http: &http.Client{Jar: jar}}, n, cfg
}

func TestAuth(t *testing.T) {
	c, _ := setup(t)
	if code, _ := c.do("GET", "/api/state", "", false); code != http.StatusUnauthorized {
		t.Fatalf("state without login: %d", code)
	}
	if code, _ := c.do("POST", "/api/login", `{"password":"nope"}`, true); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if code, _ := c.do("POST", "/api/login", `{"password":"s3cret"}`, false); code != http.StatusForbidden {
		t.Fatalf("login without X-Goproxy: %d", code)
	}
	if code, _ := c.do("POST", "/api/login", `{"password":"s3cret"}`, true); code != http.StatusOK {
		t.Fatalf("login: %d", code)
	}
	if code, _ := c.do("GET", "/api/state", "", false); code != http.StatusOK {
		t.Fatalf("state after login: %d", code)
	}
	if code, _ := c.do("POST", "/api/keypair", "", false); code != http.StatusForbidden {
		t.Fatalf("change without X-Goproxy (CSRF): %d", code)
	}
	c.do("POST", "/api/logout", "", true)
	if code, _ := c.do("GET", "/api/state", "", false); code != http.StatusUnauthorized {
		t.Fatalf("state after logout: %d", code)
	}
}

func TestCookieAndHeaders(t *testing.T) {
	c, _ := setup(t)
	req, _ := http.NewRequest("POST", c.base+"/api/login", strings.NewReader(`{"password":"s3cret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Goproxy", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	ck := res.Header.Get("Set-Cookie")
	if !strings.Contains(ck, "HttpOnly") || !strings.Contains(ck, "SameSite=Strict") {
		t.Fatalf("cookie %q", ck)
	}
	res, err = http.Get(c.base + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("index: %d, CSP %q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
}

func TestPeerLifecycle(t *testing.T) {
	c, n := setup(t)
	c.do("POST", "/api/login", `{"password":"s3cret"}`, true)

	_, kp := c.do("POST", "/api/keypair", "", true)
	if kp["public_key"] == "" || kp["private_key"] == "" {
		t.Fatalf("keypair = %v", kp)
	}
	_, ip := c.do("GET", "/api/next-ip", "", false)
	if ip["ip"] != "10.8.0.2" {
		t.Fatalf("next ip = %v", ip)
	}
	add := `{"name":"LAPTOP","public_key":"` + kp["public_key"].(string) + `","ip":"10.8.0.2","routes":[],"nat":false,"transport":"","psk":"","tls":{"sni":"","insecure":false},"keepalive":0}`
	if code, out := c.do("POST", "/api/peers", add, true); code != 200 {
		t.Fatalf("add: %d %v", code, out)
	}
	if code, _ := c.do("POST", "/api/peers", add, true); code != http.StatusConflict {
		t.Fatalf("adding it twice: %d", code)
	}
	if got := n.FilePeers(); len(got) != 1 || got[0].IP != "10.8.0.2" {
		t.Fatalf("node file peers = %+v", got)
	}

	upd := strings.Replace(add, `"ip":"10.8.0.2","routes":[]`, `"ip":"10.8.0.5","routes":["192.168.50.0/24, 192.168.60.0/24"]`, 1)
	if code, out := c.do("PUT", "/api/peers/LAPTOP", upd, true); code != 200 {
		t.Fatalf("update: %d %v", code, out)
	}
	if got := n.FilePeers()[0]; got.IP != "10.8.0.5" || len(got.Routes) != 2 {
		t.Fatalf("after update: %+v", got)
	}

	// Invalid changes are refused with the reason, and nothing changes.
	bad := strings.Replace(add, `"routes":[]`, `"routes":["0.0.0.0/0"]`, 1) // EXIT's route
	bad = strings.Replace(bad, `"LAPTOP"`, `"OTHER"`, 1)
	bad = strings.Replace(bad, kp["public_key"].(string), pub(t), 1)
	if code, out := c.do("POST", "/api/peers", bad, true); code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "0.0.0.0/0") {
		t.Fatalf("conflicting route: %d %v", code, out)
	}

	// Peers from the environment cannot be changed here.
	if code, _ := c.do("DELETE", "/api/peers/EXIT", "", true); code != http.StatusNotFound {
		t.Fatalf("deleting an env peer: %d", code)
	}
	if code, _ := c.do("DELETE", "/api/peers/LAPTOP", "", true); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	_, st := c.do("GET", "/api/state", "", false)
	if peers := st["peers"].([]any); len(peers) != 1 {
		t.Fatalf("peers after delete: %v", peers)
	}
}

func TestSessionSurvivesRestart(t *testing.T) {
	c, n, cfg := setupWith(t, nil)
	c.do("POST", "/api/login", `{"password":"s3cret"}`, true)
	// A new server with the same password (the node restarted) accepts the cookie.
	srv2 := httptest.NewServer(NewServer(cfg, n, nil).Handler())
	defer srv2.Close()
	c2 := &client{t: t, base: srv2.URL, http: c.http}
	u, _ := url.Parse(c.base)
	u2, _ := url.Parse(srv2.URL)
	c.http.Jar.SetCookies(u2, c.http.Jar.Cookies(u))
	if code, _ := c2.do("GET", "/api/state", "", false); code != 200 {
		t.Fatalf("session after a restart: %d", code)
	}
	// Another password: sessions are gone.
	cfg2 := *cfg
	cfg2.WebPassword = "changed"
	srv3 := httptest.NewServer(NewServer(&cfg2, n, nil).Handler())
	defer srv3.Close()
	u3, _ := url.Parse(srv3.URL)
	c.http.Jar.SetCookies(u3, c.http.Jar.Cookies(u))
	if code, _ := (&client{t: t, base: srv3.URL, http: c.http}).do("GET", "/api/state", "", false); code != 401 {
		t.Fatalf("session after a password change: %d", code)
	}
}

func TestSettings(t *testing.T) {
	restarts := 0
	c, _, cfg := setupWith(t, &restarts)
	c.do("POST", "/api/login", `{"password":"s3cret"}`, true)

	_, st := c.do("GET", "/api/settings", "", false)
	if st["editable"] != true || len(st["settings"].([]any)) != len(config.EditableSettings) {
		t.Fatalf("settings = %v", st)
	}
	if code, out := c.do("PUT", "/api/settings", `{"GOPROXY_TUN_ADDRESS":"10.9.0.1/24"}`, true); code != 400 || !strings.Contains(out["error"].(string), "environment") {
		t.Fatalf("changing a setting from the environment: %d %v", code, out)
	}
	if code, out := c.do("PUT", "/api/settings", `{"GOPROXY_TRANSPORT":"quic"}`, true); code != 400 {
		t.Fatalf("an invalid setting: %d %v", code, out)
	}
	if code, out := c.do("PUT", "/api/settings", `{"GOPROXY_WEB_PASSWORD":"x"}`, true); code != 400 {
		t.Fatalf("a setting that is not editable: %d %v", code, out)
	}
	if restarts != 0 {
		t.Fatal("restarted for a rejected change")
	}
	t.Setenv("GOPROXY_PRIVATE_KEY", "") // LoadNodeWith reads the environment
	t.Setenv("GOPROXY_DATA_DIR", cfg.DataDir)
	t.Setenv("GOPROXY_WEB_LISTEN", "127.0.0.1:8080")
	t.Setenv("GOPROXY_WEB_PASSWORD", "s3cret")
	if code, out := c.do("PUT", "/api/settings", `{"GOPROXY_LISTEN":"0.0.0.0:443","GOPROXY_LOG_CONNECTIONS":"true"}`, true); code != 200 {
		t.Fatalf("a valid change: %d %v", code, out)
	}
	time.Sleep(500 * time.Millisecond)
	if restarts != 1 {
		t.Fatalf("%d restarts, want 1", restarts)
	}
	saved, _ := config.ReadSettings(cfg.DataDir)
	if saved["GOPROXY_LISTEN"] != "0.0.0.0:443" || !config.SettingsPending(cfg.DataDir) {
		t.Fatalf("saved = %v, pending %v", saved, config.SettingsPending(cfg.DataDir))
	}
	if err := config.RollbackSettings(cfg.DataDir); err != nil {
		t.Fatal(err)
	}
	if saved, _ := config.ReadSettings(cfg.DataDir); len(saved) != 0 || config.SettingsPending(cfg.DataDir) {
		t.Fatalf("after rollback: %v", saved)
	}
}

func TestNodeKey(t *testing.T) {
	c, n := setup(t)
	c.do("POST", "/api/login", `{"password":"s3cret"}`, true)
	if code, _ := c.do("POST", "/api/node/key", `{"private_key":"not a key"}`, true); code != 400 {
		t.Fatalf("a bad key: %d", code)
	}
	k, _ := keys.GeneratePrivateKey()
	code, out := c.do("POST", "/api/node/key", `{"private_key":"`+k.String()+`"}`, true)
	if code != 200 || out["public_key"] != k.Public().String() || n.Info().PublicKey != k.Public().String() {
		t.Fatalf("set key: %d %v", code, out)
	}
	if code, out := c.do("POST", "/api/node/key", "", true); code != 200 || out["public_key"] == k.Public().String() {
		t.Fatalf("generate: %d %v", code, out)
	}
}

func TestWebPath(t *testing.T) {
	c, _, _ := setupPath(t, nil, "/k7Qm")
	root := c.base
	for _, p := range []string{"/", "/index.html", "/app.js", "/api/state", "/k7", "/k7Qmx/", "/x/k7Qm/"} {
		res, err := http.Get(root + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound || res.Header.Get("Content-Security-Policy") != "" {
			t.Fatalf("GET %s: %d, want a bare 404", p, res.StatusCode)
		}
	}
	if code, _ := c.do("POST", "/api/login", `{"password":"s3cret"}`, true); code != http.StatusNotFound {
		t.Fatalf("login outside the path: %d", code)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Get(root + "/k7Qm")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/k7Qm/" {
		t.Fatalf("GET /k7Qm: %d -> %q", res.StatusCode, res.Header.Get("Location"))
	}
	for _, p := range []string{"/k7Qm/", "/k7Qm/app.js"} {
		res, err := http.Get(root + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("GET %s: %d", p, res.StatusCode)
		}
	}

	c.base = root + "/k7Qm"
	req, _ := http.NewRequest("POST", c.base+"/api/login", strings.NewReader(`{"password":"s3cret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Goproxy", "1")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if ck := res.Header.Get("Set-Cookie"); !strings.Contains(ck, "Path=/k7Qm/") {
		t.Fatalf("cookie %q, want Path=/k7Qm/", ck)
	}
	c.do("POST", "/api/login", `{"password":"s3cret"}`, true)
	if code, _ := c.do("GET", "/api/state", "", false); code != http.StatusOK {
		t.Fatalf("state under the path: %d", code)
	}
}
