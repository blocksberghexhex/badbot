package sim

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// Web bedient einen Port fuer die Simulationen http und wordpress. Beide
// teilen sich den Listener; welche Simulation eine Anfrage zaehlt, haengt am
// Pfad und daran, welche auf dem Port eingeschaltet sind.
type Web struct {
	Server    string // Server-Kopfzeile, z. B. nginx/1.18.0
	HTTP      bool
	WordPress bool
	Port      int32
	Melde     func(puffer.Beobachtung)
}

var (
	wpPfad     = regexp.MustCompile(`^/(wp-login\.php|xmlrpc\.php|wp-admin|wp-content|wp-includes|wp-json)`)
	wpPlugin   = regexp.MustCompile(`^/wp-content/plugins/([A-Za-z0-9._-]{1,64})/`)
	xmlMethode = regexp.MustCompile(`<methodName>\s*([A-Za-z0-9._]{1,64})\s*</methodName>`)
)

func (w *Web) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	sim := "http"
	if w.WordPress && (wpPfad.MatchString(r.URL.Path) || !w.HTTP) {
		sim = "wordpress"
	}
	probe := []puffer.Merkmal{
		Text("methode", r.Method, 16),
		Text("pfad", ohnePasswort(r.URL), 200),
		Text("host", r.Host, 100),
		Text("ua", r.UserAgent(), 200),
		Text("kopf", kopfnamen(r.Header), 300),
	}
	if r.TLS != nil && r.TLS.ServerName != "" {
		probe = append(probe, Text("sni", r.TLS.ServerName, 100))
	}
	// Mehr als 16 KiB liest keine Simulation; der Rest bleibt ungelesen.
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	// Ein Formular traegt meist Zugangsdaten: dann nur die Feldnamen, die
	// Anmeldung selbst haelt die Simulation gehasht fest.
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if f, err := url.ParseQuery(string(body)); err == nil && len(f) > 0 {
			probe = append(probe, Text("felder", schluessel(f), 200))
		}
	} else if len(body) > 0 {
		probe = append(probe, Text("body", string(body), 128))
	}

	rw.Header().Set("Server", w.Server)
	var status int
	var antwort string
	if sim == "wordpress" {
		status, antwort, probe = w.wordpress(rw, r, body, probe)
	} else {
		status, antwort, probe = w.http(rw, r, body, probe)
	}
	if q := lauscher.Gegenstelle(addr(r.RemoteAddr)); q.IsValid() {
		w.Melde(puffer.Beobachtung{Quelle: q, Simulation: sim, Port: w.Port, Zeit: time.Now(), Probe: probe})
	}
	if rw.Header().Get("Content-Type") == "" {
		rw.Header().Set("Content-Type", "text/html")
	}
	rw.WriteHeader(status)
	if r.Method != http.MethodHead {
		io.WriteString(rw, antwort)
	}
}

type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }

var passwortFeld = regexp.MustCompile(`(?i)pass|pwd|secret|token`)

// ohnePasswort ersetzt Werte von Parametern, die nach Zugangsdaten heissen.
func ohnePasswort(u *url.URL) string {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || u.RawQuery == "" {
		return u.RequestURI()
	}
	geaendert := false
	for k := range q {
		if passwortFeld.MatchString(k) {
			q[k] = []string{"*"}
			geaendert = true
		}
	}
	if !geaendert {
		return u.RequestURI()
	}
	return u.EscapedPath() + "?" + q.Encode()
}

func schluessel(f url.Values) string {
	n := make([]string, 0, len(f))
	for k := range f {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ",")
}

func kopfnamen(h http.Header) string {
	n := make([]string, 0, len(h))
	for k := range h {
		n = append(n, strings.ToLower(k))
	}
	sort.Strings(n)
	return strings.Join(n, ",")
}

// Feste Antworten. Nichts darin sieht aus wie ein Zugangsdatum, nichts
// verweist auf fremde Dienste.
var koeder = map[string]struct {
	status int
	typ    string
	inhalt string
}{
	"/.env":              {200, "text/plain", "APP_ENV=production\nAPP_DEBUG=false\nLOG_CHANNEL=stack\n"},
	"/.git/config":       {200, "text/plain", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"},
	"/.git/HEAD":         {200, "text/plain", "ref: refs/heads/master\n"},
	"/actuator/env":      {200, "application/json", `{"activeProfiles":[],"propertySources":[]}`},
	"/actuator/health":   {200, "application/json", `{"status":"UP"}`},
	"/server-status":     {403, "", ""},
	"/cgi-bin/":          {403, "", ""},
	"/phpmyadmin/":       {200, "", pmaSeite},
	"/pma/":              {200, "", pmaSeite},
	"/config.php.bak":    {200, "text/plain", ""},
	"/wp-config.php.old": {200, "text/plain", ""},
	"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": {200, "", ""},
}

func (w *Web) http(rw http.ResponseWriter, r *http.Request, body []byte, probe []puffer.Merkmal) (int, string, []puffer.Merkmal) {
	switch r.URL.Path {
	case "/":
		return 200, nginxStart, probe
	case "/phpmyadmin/index.php", "/pma/index.php":
		if r.Method == http.MethodPost {
			werte := formular(body)
			probe = append(probe, Anmeldung(werte.Get("pma_username"), werte.Get("pma_password")))
		}
		return 200, pmaSeite, probe
	}
	k, ok := koeder[r.URL.Path]
	if !ok && strings.HasPrefix(r.URL.Path, "/cgi-bin/") {
		k, ok = koeder["/cgi-bin/"]
	}
	if !ok {
		return 404, w.fehlerseite(404, "Not Found"), probe
	}
	if k.status != 200 {
		return k.status, w.fehlerseite(k.status, http.StatusText(k.status)), probe
	}
	if k.typ != "" {
		rw.Header().Set("Content-Type", k.typ)
	}
	return 200, k.inhalt, probe
}

func (w *Web) wordpress(rw http.ResponseWriter, r *http.Request, body []byte, probe []puffer.Merkmal) (int, string, []puffer.Merkmal) {
	p := r.URL.Path
	switch {
	case p == "/wp-login.php":
		if r.Method == http.MethodPost {
			// Nur Formularfelder lesen -- ParseForm auf dem schon gelesenen Body.
			werte := formular(body)
			probe = append(probe, Anmeldung(werte.Get("log"), werte.Get("pwd")))
			return 200, wpLogin(true), probe
		}
		return 200, wpLogin(false), probe
	case p == "/xmlrpc.php":
		if r.Method != http.MethodPost {
			rw.Header().Set("Content-Type", "text/plain")
			return 405, "XML-RPC server accepts POST requests only.", probe
		}
		for i, m := range xmlMethode.FindAllSubmatch(body, 10) {
			if i >= 5 {
				break
			}
			probe = append(probe, Text("xmlrpc", string(m[1]), 64))
		}
		rw.Header().Set("Content-Type", "text/xml; charset=UTF-8")
		return 200, xmlrpcFehler, probe
	case p == "/wp-admin" || strings.HasPrefix(p, "/wp-admin/"):
		rw.Header().Set("Location", "/wp-login.php?reauth=1")
		return 302, "", probe
	}
	if m := wpPlugin.FindStringSubmatch(p); m != nil {
		probe = append(probe, Text("plugin", m[1], 64))
		return 200, "", probe
	}
	return 404, w.fehlerseite(404, "Not Found"), probe
}

func formular(body []byte) interface{ Get(string) string } {
	r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	return r.PostForm
}

func (w *Web) fehlerseite(code int, text string) string {
	t := itoa(code) + " " + text
	return "<html>\r\n<head><title>" + t + "</title></head>\r\n<body>\r\n<center><h1>" + t +
		"</h1></center>\r\n<hr><center>" + w.Server + "</center>\r\n</body>\r\n</html>\r\n"
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

const nginxStart = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
</body>
</html>
`

const pmaSeite = `<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head>
<body><form method="post" action="index.php">
<input type="text" name="pma_username"><input type="password" name="pma_password">
<input type="submit" value="Go"></form></body></html>
`

func wpLogin(fehler bool) string {
	meldung := ""
	if fehler {
		meldung = `<div id="login_error"><strong>Error:</strong> The username or password you entered is incorrect.</div>`
	}
	return `<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title></head>
<body class="login"><div id="login">` + meldung + `
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
</form></div></body></html>
`
}

const xmlrpcFehler = `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct></value></fault></methodResponse>
`

// Bedienen startet den HTTP-Server auf ln. Ob eine Verbindung TLS spricht,
// entscheidet das erste Byte (0x16 = TLS-Handshake) -- so beantwortet jeder
// Port beides, wie es Scanner auf 8080 und 8443 gleichermassen erwarten.
func (w *Web) Bedienen(ln net.Listener, zert *tls.Certificate) *http.Server {
	srv := &http.Server{
		Handler:           w,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    8 << 10,
		// Scanner erzeugen massenhaft Protokollfehler; die sind kein Betriebsereignis.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{*zert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS10}
	go srv.Serve(&tlsWeiche{Listener: ln, cfg: cfg, fertig: make(chan net.Conn), ende: make(chan struct{})})
	return srv
}

// tlsWeiche liest das erste Byte jeder Verbindung in einer eigenen Goroutine,
// damit eine stumme Verbindung das Annehmen der anderen nicht aufhaelt.
type tlsWeiche struct {
	net.Listener
	cfg    *tls.Config
	fertig chan net.Conn
	ende   chan struct{}
	start  sync.Once
	fehler error
}

func (t *tlsWeiche) Accept() (net.Conn, error) {
	t.start.Do(func() { go t.annehmen() })
	select {
	case c := <-t.fertig:
		return c, nil
	case <-t.ende:
		return nil, t.fehler
	}
}

func (t *tlsWeiche) annehmen() {
	for {
		c, err := t.Listener.Accept()
		if err != nil {
			t.fehler = err
			close(t.ende)
			return
		}
		go func() {
			r := bufio.NewReaderSize(c, 16)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			b, err := r.Peek(1)
			c.SetReadDeadline(time.Time{})
			if err != nil {
				c.Close()
				return
			}
			var v net.Conn = &gepuffert{Conn: c, r: r}
			if b[0] == 0x16 {
				v = tls.Server(v, t.cfg)
			}
			select {
			case t.fertig <- v:
			case <-t.ende:
				v.Close()
			}
		}()
	}
}

type gepuffert struct {
	net.Conn
	r *bufio.Reader
}

func (g *gepuffert) Read(b []byte) (int, error) { return g.r.Read(b) }

// ZertifikatLaden liest das selbst signierte Zertifikat oder erzeugt es
// einmal. Es traegt keinen Namen: Ein Name verriete, wem der Collector gehoert.
func ZertifikatLaden(pfad string) (*tls.Certificate, error) {
	if roh, err := os.ReadFile(pfad); err == nil {
		z, err := tls.X509KeyPair(roh, roh)
		return &z, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	nr, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	beginn := time.Now().Add(-time.Duration(nr.Int64()%(400*24)) * time.Hour)
	vorlage := &x509.Certificate{
		SerialNumber:          nr,
		Subject:               pkix.Name{},
		NotBefore:             beginn,
		NotAfter:              beginn.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, vorlage, vorlage, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	roh := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})...)
	if err := os.WriteFile(pfad, roh, 0o600); err != nil {
		return nil, err
	}
	z, err := tls.X509KeyPair(roh, roh)
	return &z, err
}
