package steuerung

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/plattform"
	"github.com/blocksberghexhex/badbot/intern/puffer"
	"github.com/blocksberghexhex/badbot/intern/sperre"
	"github.com/blocksberghexhex/badbot/protokoll"
	"golang.org/x/crypto/ssh"
)

// attrappe spielt die Plattform nach.
type attrappe struct {
	mu         sync.Mutex
	konfig     protokoll.Konfiguration
	ist        []protokoll.Ist
	stapel     []protokoll.Stapel
	status     int // fuer /ereignisse und /lebenszeichen erzwungen, 0 = normal
	ereignisSt int
	sperrliste protokoll.Sperrliste
	gemeldet   protokoll.Lebenszeichen // zuletzt empfangenes Lebenszeichen
}

func (a *attrappe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer bb1_test_x" {
		w.WriteHeader(401)
		return
	}
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		body, _ = gzip.NewReader(r.Body)
	}
	if a.status != 0 {
		w.WriteHeader(a.status)
		w.Write([]byte(`{"fehler":"x","text":"erzwungen"}`))
		return
	}
	switch r.URL.Path {
	case "/v1/lebenszeichen":
		json.NewDecoder(body).Decode(&a.gemeldet)
		json.NewEncoder(w).Encode(protokoll.LebenszeichenAntwort{KonfigurationStand: a.konfig.Stand, SperrlisteStand: a.sperrliste.Stand, Hinweise: []string{}})
	case "/v1/konfiguration":
		json.NewEncoder(w).Encode(a.konfig)
	case "/v1/konfiguration/ist":
		var i protokoll.Ist
		json.NewDecoder(body).Decode(&i)
		a.ist = append(a.ist, i)
	case "/v1/ereignisse":
		if a.ereignisSt != 0 {
			st := a.ereignisSt
			a.ereignisSt = 0
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(st)
			return
		}
		var s protokoll.Stapel
		json.NewDecoder(body).Decode(&s)
		a.stapel = append(a.stapel, s)
		json.NewEncoder(w).Encode(protokoll.StapelAntwort{Angenommen: len(s.Datensaetze)})
	case "/v1/sperrliste":
		json.NewEncoder(w).Encode(a.sperrliste)
	}
}

func freiePorts(t *testing.T, n int) []int32 {
	var l []int32
	var offen []net.Listener
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		offen = append(offen, ln)
		l = append(l, int32(ln.Addr().(*net.TCPAddr).Port))
	}
	for _, ln := range offen {
		ln.Close()
	}
	return l
}

func TestSteuerung(t *testing.T) {
	att := &attrappe{}
	srv := httptest.NewServer(att)
	defer srv.Close()

	frei := freiePorts(t, 3)
	abb := map[int32]int32{22: frei[0], 80: frei[1], 53: frei[2]}
	att.konfig = protokoll.Konfiguration{Stand: "k-1", TaktSekunden: 30, FensterSekunden: 300, StichprobeBytes: 2048,
		Simulationen: []protokoll.SimulationSoll{
			{Name: "ssh", Ports: []int32{22}, Aktiv: true},
			{Name: "telnet", Ports: []int32{22}, Aktiv: true}, // Konflikt
			{Name: "http", Ports: []int32{80}, Aktiv: true},
			{Name: "wordpress", Ports: []int32{80}, Aktiv: true},
			{Name: "dns", Ports: []int32{53}, Aktiv: true},
			{Name: "redis", Ports: []int32{6379}, Aktiv: false},
		}}
	att.konfig.Sperren.Stufe = "netz"
	jetzt := time.Now()
	att.sperrliste = protokoll.Sperrliste{Stand: "s-1", Art: "voll", GueltigBis: jetzt.Add(time.Hour), Hinzu: []string{"203.0.113.0/24", "2001:db8::/32"}}

	log := slog.New(slog.DiscardHandler)
	p := puffer.Neu(5*time.Minute, 2048)
	s := &Steuerung{
		Z: plattform.Neu(srv.URL, "bb1_test_x", "1.0.0", "linux"), P: p,
		L: lauscher.Neu(lauscher.Vorgabe, p.Hinzu, log), S: sperre.Neu(true, nil, log),
		Log: log, Daten: t.TempDir(), Version: "1.0.0", Bind: "127.0.0.1",
		Abbildung: func(p int32) int32 { return abb[p] },
		Plattform: "macos", Faehigkeiten: []string{"sperren-pf"},
	}
	if err := s.Vorbereiten(jetzt); err != nil {
		t.Fatal(err)
	}
	defer s.Beenden()

	if takt := s.Runde(context.Background(), jetzt); takt != 30*time.Second {
		t.Fatalf("Takt %v", takt)
	}
	att.mu.Lock()
	if g := att.gemeldet; g.Plattform != "macos" || !slices.Contains(g.Faehigkeiten, "sperren-pf") {
		t.Errorf("Lebenszeichen: %+v", g)
	}
	if len(att.ist) != 1 {
		t.Fatalf("Ist: %+v", att.ist)
	}
	ist := map[string]protokoll.SimulationIst{}
	for _, si := range att.ist[0].Simulationen {
		ist[si.Name] = si
	}
	att.mu.Unlock()
	if !ist["ssh"].Aktiv || ist["telnet"].Aktiv || !strings.Contains(ist["telnet"].Fehler, "belegt") ||
		!ist["http"].Aktiv || !ist["wordpress"].Aktiv || !ist["dns"].Aktiv || ist["redis"].Aktiv {
		t.Fatalf("Ist: %+v", ist)
	}
	if s.S.Anzahl() != 2 || s.S.Stand() != "s-1" {
		t.Fatalf("Sperrliste: %d %q", s.S.Anzahl(), s.S.Stand())
	}
	if k := s.koeder(); len(k.TCP) != 3 || len(k.UDP) != 1 {
		t.Fatalf("Koeder: %+v", k)
	}

	// Verkehr auf die Simulationen.
	cfg := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}
	if c, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(abb[22])), cfg); err == nil {
		c.Close()
		t.Fatal("SSH-Anmeldung gelungen")
	}
	r, err := http.PostForm("http://127.0.0.1:"+itoa(abb[80])+"/wp-login.php", url.Values{"log": {"admin"}, "pwd": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	time.Sleep(200 * time.Millisecond)

	// Naechstes Fenster: die Datensaetze gehen hinaus.
	s.Runde(context.Background(), jetzt.Add(6*time.Minute))
	att.mu.Lock()
	sims := map[string]bool{}
	for _, st := range att.stapel {
		for _, d := range st.Datensaetze {
			sims[d.Simulation] = d.Quelle == "127.0.0.1"
		}
	}
	att.mu.Unlock()
	if !sims["ssh"] || !sims["wordpress"] {
		t.Fatalf("gemeldet: %v", sims)
	}

	// Konfiguration aendert sich: wordpress aus, http bleibt -- der Dienst
	// wird neu gestartet und meldet danach als http.
	att.mu.Lock()
	att.konfig.Stand = "k-2"
	att.konfig.Simulationen[3].Aktiv = false
	att.konfig.Sperren.Stufe = "aus"
	att.mu.Unlock()
	s.Runde(context.Background(), jetzt.Add(7*time.Minute))
	if d := s.laufend["web/80"]; d == nil || d.sim != "http" {
		t.Fatalf("Web-Dienst: %+v", d)
	}
	if s.S.Anzahl() != 0 {
		t.Fatal("Sperrstufe aus, Sperren bleiben")
	}

	// 429: Pause, nichts verloren.
	s.L.Melde(puffer.Beobachtung{Quelle: mustAddr("198.51.100.7"), Simulation: "http", Port: 80, Zeit: jetzt.Add(8 * time.Minute)})
	att.mu.Lock()
	att.ereignisSt = 429
	vorher := len(att.stapel)
	att.mu.Unlock()
	s.Runde(context.Background(), jetzt.Add(14*time.Minute))
	s.Runde(context.Background(), jetzt.Add(15*time.Minute)) // noch in der Pause
	if len(att.stapel) != vorher || s.P.Stand().Datensaetze == 0 {
		t.Fatalf("waehrend 429 gemeldet oder verloren: %d %+v", len(att.stapel), s.P.Stand())
	}
	s.Runde(context.Background(), jetzt.Add(17*time.Minute))
	if len(att.stapel) != vorher+1 {
		t.Fatal("nach der Pause nicht nachgeliefert")
	}

	// 401: stumm, langsamer Takt, Sperren bleiben bis zum Ablauf.
	att.mu.Lock()
	att.status = 401
	att.mu.Unlock()
	if takt := s.Runde(context.Background(), jetzt.Add(18*time.Minute)); takt != 10*time.Minute || !s.stumm {
		t.Fatalf("nach 401: Takt %v, stumm %v", takt, s.stumm)
	}
	att.mu.Lock()
	att.status = 0
	att.mu.Unlock()
	s.Runde(context.Background(), jetzt.Add(30*time.Minute))
	if s.stumm {
		t.Fatal("bleibt stumm, obwohl die Plattform wieder annimmt")
	}
}

func itoa(p int32) string { return strconv.Itoa(int(p)) }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestBezugsbetrieb: alle Simulationen aus, nur die Sperrliste wird bezogen
// und angewendet -- der Collector ersetzt so den frueheren Bezugs-Client.
func TestBezugsbetrieb(t *testing.T) {
	att := &attrappe{}
	srv := httptest.NewServer(att)
	defer srv.Close()
	att.konfig = protokoll.Konfiguration{Stand: "k-1", Simulationen: []protokoll.SimulationSoll{{Name: "ssh", Ports: []int32{22}}}}
	att.konfig.Sperren.Stufe = "as"
	jetzt := time.Now()
	att.sperrliste = protokoll.Sperrliste{Stand: "s-1", Art: "voll", GueltigBis: jetzt.Add(time.Hour), Hinzu: []string{"203.0.113.0/24"}}
	log := slog.New(slog.DiscardHandler)
	p := puffer.Neu(5*time.Minute, 2048)
	s := &Steuerung{Z: plattform.Neu(srv.URL, "bb1_test_x", "1.0.0", "linux"), P: p, L: lauscher.Neu(lauscher.Vorgabe, p.Hinzu, log),
		S: sperre.Neu(true, nil, log), Log: log, Daten: t.TempDir(), Version: "1.0.0", Bind: "127.0.0.1"}
	if err := s.Vorbereiten(jetzt); err != nil {
		t.Fatal(err)
	}
	defer s.Beenden()
	s.Runde(context.Background(), jetzt)
	if len(s.laufend) != 0 || s.S.Anzahl() != 1 {
		t.Fatalf("Bezugsbetrieb: %d Dienste, %d Sperren", len(s.laufend), s.S.Anzahl())
	}
	if k := s.koeder(); len(k.TCP)+len(k.UDP) != 0 {
		t.Fatalf("Koeder ohne Simulation: %+v", k)
	}
	if ist := att.ist[0].Simulationen[0]; ist.Aktiv {
		t.Fatalf("Ist: %+v", ist)
	}
}
