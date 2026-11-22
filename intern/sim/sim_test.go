package sim

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
	"golang.org/x/crypto/ssh"
)

const geheim = "Sommer2026!geheim"

type sammler chan puffer.Beobachtung

func neuerLauscher(t *testing.T) (*lauscher.Lauscher, sammler) {
	s := make(sammler, 100)
	l := lauscher.Neu(lauscher.Vorgabe, func(b puffer.Beobachtung) { s <- b }, slog.New(slog.DiscardHandler))
	return l, s
}

func (s sammler) naechste(t *testing.T) puffer.Beobachtung {
	t.Helper()
	select {
	case b := <-s:
		return b
	case <-time.After(10 * time.Second):
		t.Fatal("keine Beobachtung")
		return puffer.Beobachtung{}
	}
}

// probeJSON prueft die Grundregel fuer jede Stichprobe: Das Klartextpasswort
// steht nie darin.
func probeJSON(t *testing.T, b puffer.Beobachtung) string {
	t.Helper()
	// Ueber den echten Puffer: genau diese Stichprobe ginge an die Plattform.
	pf := puffer.Neu(5*time.Minute, 2048)
	pf.Hinzu(b)
	pf.AllesVersiegeln()
	roh := []byte(pf.Naechster().Datensaetze[0].Stichprobe)
	if bytes.Contains(roh, []byte(geheim)) || bytes.Contains(roh, []byte(url.QueryEscape(geheim))) {
		t.Fatalf("Klartextpasswort in der Stichprobe: %s", roh)
	}
	if b.Quelle.String() != "127.0.0.1" {
		t.Fatalf("Quelle %v", b.Quelle)
	}
	return string(roh)
}

func starte(t *testing.T, simulation string, h lauscher.Behandler) (string, sammler) {
	t.Helper()
	l, s := neuerLauscher(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go l.Annehmen(ln, simulation, 1, h)
	return ln.Addr().String(), s
}

func verbinde(t *testing.T, a string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", a, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

func enthaelt(t *testing.T, s string, teile ...string) {
	t.Helper()
	for _, x := range teile {
		if !strings.Contains(s, x) {
			t.Fatalf("%q fehlt in %s", x, s)
		}
	}
}

func TestSSHLehntJedeAnmeldungAb(t *testing.T) {
	wirt, err := WirtsschluesselLaden(filepath.Join(t.TempDir(), "ssh"))
	if err != nil {
		t.Fatal(err)
	}
	a, s := starte(t, "ssh", SSH(wirt, "SSH-2.0-OpenSSH_7.4"))
	var gesehen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password(geheim)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error { gesehen = k; return nil },
		ClientVersion:   "SSH-2.0-Test_1.0",
		Timeout:         10 * time.Second,
	}
	if c, err := ssh.Dial("tcp", a, cfg); err == nil {
		c.Close()
		t.Fatal("SSH-Anmeldung gelungen")
	} else if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("unerwarteter Fehler: %v", err)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"name":"root"`, "passwort_sha256", `"passwort_laenge":17`, "SSH-2.0-Test_1.0")

	// Der Wirtsschluessel bleibt ueber einen Neustart gleich.
	pfad := filepath.Join(t.TempDir(), "ssh")
	k1, _ := WirtsschluesselLaden(pfad)
	k2, _ := WirtsschluesselLaden(pfad)
	if !bytes.Equal(k1.PublicKey().Marshal(), k2.PublicKey().Marshal()) || gesehen == nil {
		t.Fatal("Wirtsschluessel wechselt")
	}
}

func TestTelnet(t *testing.T) {
	a, s := starte(t, "telnet", Telnet())
	c := verbinde(t, a)
	defer c.Close()
	r := bufio.NewReader(c)
	var alles strings.Builder
	for i := 0; i < 3; i++ {
		c.Write([]byte{255, 251, 1}) // IAC WILL ECHO -- darf nicht im Namen landen
		io.WriteString(c, "admin\r\n"+geheim+"\r\n")
	}
	io.Copy(&alles, r)
	if strings.Count(alles.String(), "Login incorrect") != 3 {
		t.Fatalf("Antwort: %q", alles.String())
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `{"name":"admin","passwort_laenge":17`)
}

func TestHTTPundWordPress(t *testing.T) {
	l, s := neuerLauscher(t)
	zert, err := ZertifikatLaden(filepath.Join(t.TempDir(), "zert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	w := &Web{Server: "nginx/1.18.0", HTTP: true, WordPress: true, Port: 80, Melde: l.Melde}
	srv := w.Bedienen(l.Listener(ln), zert)
	defer srv.Close()
	basis := "http://" + ln.Addr().String()
	hole := func(c *http.Client, methode, u string, body url.Values) (*http.Response, string) {
		t.Helper()
		var r *http.Response
		var err error
		if body != nil {
			r, err = c.PostForm(u, body)
		} else {
			req, _ := http.NewRequest(methode, u, nil)
			r, err = c.Do(req)
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		return r, string(b)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	r, b := hole(c, "GET", basis+"/", nil)
	if r.StatusCode != 200 || r.Header.Get("Server") != "nginx/1.18.0" || !strings.Contains(b, "Welcome to nginx!") {
		t.Fatalf("Startseite: %d %v %s", r.StatusCode, r.Header, b)
	}
	if o := s.naechste(t); o.Simulation != "http" {
		t.Fatalf("Simulation %q", o.Simulation)
	}
	r, b = hole(c, "GET", basis+"/gibtsnicht", nil)
	if r.StatusCode != 404 || !strings.Contains(b, "<center>nginx/1.18.0</center>") {
		t.Fatalf("404: %d %s", r.StatusCode, b)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"pfad":["/gibtsnicht"]`, `"methode":["GET"]`, "user-agent")

	r, b = hole(c, "GET", basis+"/.env", nil)
	if r.StatusCode != 200 || strings.Contains(strings.ToLower(b), "password") || strings.Contains(strings.ToLower(b), "key") {
		t.Fatalf(".env: %d %q", r.StatusCode, b)
	}
	s.naechste(t)

	r, b = hole(c, "POST", basis+"/wp-login.php", url.Values{"log": {"admin"}, "pwd": {geheim}})
	if r.StatusCode != 200 || !strings.Contains(b, "is incorrect") || len(r.Cookies()) > 0 {
		t.Fatalf("wp-login: %d %v %s", r.StatusCode, r.Cookies(), b)
	}
	o := s.naechste(t)
	if o.Simulation != "wordpress" {
		t.Fatalf("Simulation %q", o.Simulation)
	}
	// Der Body-Praefix der Stichprobe enthielte das Passwort -- probeJSON prueft das.
	enthaelt(t, probeJSON(t, o), `"name":"admin"`, "passwort_sha256")

	enthaelt(t, probeJSON(t, o), `"felder":["log,pwd"]`)

	r, _ = hole(c, "GET", basis+"/wp-login.php?log=admin&pwd="+url.QueryEscape(geheim), nil)
	enthaelt(t, probeJSON(t, s.naechste(t)), `pwd=%2A`)

	r, _ = hole(c, "GET", basis+"/wp-admin/", nil)
	if r.StatusCode != 302 {
		t.Fatalf("wp-admin: %d", r.StatusCode)
	}
	s.naechste(t)

	// Gleicher Port, TLS: erkannt am ersten Byte.
	tc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "beispiel.test"}}}
	r, _ = hole(tc, "GET", "https://"+ln.Addr().String()+"/xmlrpc.php", nil)
	if r.StatusCode != 405 || r.TLS == nil || len(r.TLS.PeerCertificates[0].Subject.String()) != 0 {
		t.Fatalf("TLS: %d %+v", r.StatusCode, r.TLS)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"sni":["beispiel.test"]`)
}

func dnsFrage(name string, typ uint16, edns bool) []byte {
	p := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		p = append(p, byte(len(l)))
		p = append(p, l...)
	}
	p = append(p, 0, byte(typ>>8), byte(typ), 0, 1)
	if edns {
		p[11] = 1
		p = append(p, 0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0)
	}
	return p
}

func TestDNSNieVerstaerker(t *testing.T) {
	h := DNS()
	frage := dnsFrage("beispiel.test", 255, true)
	a, probe := h(frage)
	if len(a) > len(frage) || a[3]&0x0f != 5 || a[2]&0x80 == 0 || binary.BigEndian.Uint16(a[6:8]) != 0 || a[0] != 0x12 {
		t.Fatalf("Antwort: % x", a)
	}
	roh := probeJSON(t, puffer.Beobachtung{Quelle: netip.MustParseAddr("127.0.0.1"), Simulation: "dns", Zeit: time.Now(), Probe: probe})
	enthaelt(t, roh, `"name":["beispiel.test"]`, `"typ":["ANY"]`, `"rd":[true]`, `"edns":[4096]`)

	for _, kaputt := range [][]byte{nil, {1, 2, 3}, frage[:14], append([]byte{0x12, 0x34, 0x81}, frage[3:]...), {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}} {
		if a, _ := h(kaputt); a != nil {
			t.Fatalf("Antwort auf unlesbares Paket % x", kaputt)
		}
	}
}

func TestDNSUeberTCP(t *testing.T) {
	a, s := starte(t, "dns", DNSTCP())
	c := verbinde(t, a)
	frage := dnsFrage("beispiel.test", 1, false)
	c.Write(append([]byte{0, byte(len(frage))}, frage...))
	var l [2]byte
	io.ReadFull(c, l[:])
	antwort := make([]byte, binary.BigEndian.Uint16(l[:]))
	io.ReadFull(c, antwort)
	c.Close()
	if antwort[3] != 5 {
		t.Fatalf("% x", antwort)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"typ":["A"]`)
}

func TestMySQL(t *testing.T) {
	a, s := starte(t, "mysql", MySQL("5.7.36"))
	c := verbinde(t, a)
	defer c.Close()
	_, gruss, err := mysqlLesen(c)
	if err != nil || gruss[0] != 10 || !bytes.Contains(gruss, []byte("5.7.36\x00")) || !bytes.Contains(gruss, []byte("mysql_native_password")) {
		t.Fatalf("Begruessung: %v % x", err, gruss)
	}
	var p bytes.Buffer
	binary.Write(&p, binary.LittleEndian, uint32(0x000aa20f|0x8)) // mit Datenbank und Plugin
	p.Write(make([]byte, 28))
	p.WriteString("root\x00")
	p.Write([]byte{20})
	p.Write(make([]byte, 20))
	p.WriteString("wordpress\x00mysql_native_password\x00")
	mysqlSchreiben(c, 1, p.Bytes())
	seq, fehler, _ := mysqlLesen(c)
	if seq != 2 || fehler[0] != 0xff || binary.LittleEndian.Uint16(fehler[1:3]) != 1045 {
		t.Fatalf("Fehlerpaket: %d % x", seq, fehler)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"name":"root"`, `"datenbank":["wordpress"]`, `"plugin":["mysql_native_password"]`)
}

func TestPostgres(t *testing.T) {
	a, s := starte(t, "postgres", Postgres())
	c := verbinde(t, a)
	defer c.Close()
	c.Write([]byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}) // SSLRequest
	var n [1]byte
	io.ReadFull(c, n[:])
	if n[0] != 'N' {
		t.Fatalf("SSL: %q", n)
	}
	start := []byte("\x00\x03\x00\x00user\x00postgres\x00database\x00produktion\x00\x00")
	c.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(start)+4)), start...))
	var auth [9]byte
	io.ReadFull(c, auth[:])
	if auth[0] != 'R' || auth[8] != 3 {
		t.Fatalf("Auth: % x", auth)
	}
	pw := append([]byte(geheim), 0)
	c.Write(append([]byte{'p'}, append(binary.BigEndian.AppendUint32(nil, uint32(len(pw)+4)), pw...)...))
	rest, _ := io.ReadAll(c)
	if len(rest) == 0 || rest[0] != 'E' || !bytes.Contains(rest, []byte("C28P01")) {
		t.Fatalf("Fehler: %q", rest)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"name":"postgres"`, `"datenbank":["produktion"]`, `"passwort_laenge":17`)
}

func TestRedis(t *testing.T) {
	a, s := starte(t, "redis", Redis())
	c := verbinde(t, a)
	io.WriteString(c, "*2\r\n$4\r\nAUTH\r\n$17\r\n"+geheim+"\r\nCONFIG SET dir /var/spool/cron\r\nQUIT\r\n")
	alles, _ := io.ReadAll(c)
	c.Close()
	if string(alles) != "-WRONGPASS invalid username-password pair or user is disabled.\r\n-NOAUTH Authentication required.\r\n+OK\r\n" {
		t.Fatalf("Antworten: %q", alles)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"kommandos":["CONFIG SET"]`, `"name":"default"`)
}

func TestRDP(t *testing.T) {
	a, s := starte(t, "rdp", RDP())
	c := verbinde(t, a)
	x224 := append([]byte{0, 0xe0, 0, 0, 0, 0, 0}, "Cookie: mstshash=administrator\r\n"...)
	x224 = append(x224, 1, 0, 8, 0, 3, 0, 0, 0)
	x224[0] = byte(len(x224) - 1)
	c.Write(append([]byte{3, 0, 0, byte(len(x224) + 4)}, x224...))
	io.ReadAll(c)
	c.Close()
	enthaelt(t, probeJSON(t, s.naechste(t)), `"name":"administrator"`, `"protokolle":[3]`)
}

func TestVNC(t *testing.T) {
	a, s := starte(t, "vnc", VNC())
	c := verbinde(t, a)
	defer c.Close()
	v := make([]byte, 12)
	io.ReadFull(c, v)
	io.WriteString(c, "RFB 003.008\n")
	typen := make([]byte, 2)
	io.ReadFull(c, typen)
	c.Write([]byte{2})
	ch := make([]byte, 16)
	io.ReadFull(c, ch)
	c.Write(make([]byte, 16))
	rest, _ := io.ReadAll(c)
	if string(v) != "RFB 003.008\n" || typen[1] != 2 || !bytes.HasPrefix(rest, []byte{0, 0, 0, 1}) {
		t.Fatalf("RFB: %q % x % x", v, typen, rest)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"client":["RFB 003.008"]`, `"sicherheitstyp":[2]`)
}

func TestSMTPundFTP(t *testing.T) {
	a, s := starte(t, "smtp", SMTP("ESMTP Postfix"))
	c := verbinde(t, a)
	io.WriteString(c, "EHLO scanner.test\r\nAUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=\r\nMAIL FROM:<a@beispiel.test>\r\nRCPT TO:<b@beispiel.test>\r\nDATA\r\nQUIT\r\n")
	alles, _ := io.ReadAll(c)
	c.Close()
	enthaelt(t, string(alles), "535 5.7.8", "554 5.7.1", "221 2.0.0")
	enthaelt(t, probeJSON(t, s.naechste(t)), `"helo":["scanner.test"]`, `"name":"auth:PLAIN"`, `"empfaenger":["TO:`)

	a, s = starte(t, "ftp", FTP("(vsFTPd 3.0.3)"))
	c = verbinde(t, a)
	io.WriteString(c, strings.Repeat("USER anonymous\r\nPASS "+geheim+"\r\n", 4))
	alles, _ = io.ReadAll(c)
	c.Close()
	if strings.Count(string(alles), "530 Login incorrect.") != 3 {
		t.Fatalf("FTP: %q", alles)
	}
	probeJSON(t, s.naechste(t))
}

func TestTCPSinkUndErscheinung(t *testing.T) {
	a, s := starte(t, "tcp-sink", TCPSink())
	c := verbinde(t, a)
	io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
	if n, _ := io.ReadAll(c); len(n) != 0 {
		t.Fatalf("tcp-sink sendet: %q", n)
	}
	c.Close()
	enthaelt(t, probeJSON(t, s.naechste(t)), `"anfang_hex":["474554`)

	pfad := filepath.Join(t.TempDir(), "erscheinung.json")
	e1, _ := ErscheinungLaden(pfad)
	e2, _ := ErscheinungLaden(pfad)
	if e1 != e2 || e1.SSH == "" {
		t.Fatalf("Erscheinung wechselt: %+v %+v", e1, e2)
	}
}

func TestKurzEntferntSteuerzeichen(t *testing.T) {
	if k := kurz("a\x1b[31mb\x00c\xff", 5); k != "a�[31" {
		t.Fatalf("%q", k)
	}
}
