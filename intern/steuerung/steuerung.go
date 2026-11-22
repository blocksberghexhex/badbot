// Package steuerung fuehrt den Collector: Lebenszeichen im Takt, Konfiguration
// aus dem Panel anwenden, Stapel melden, Sperrliste holen und anwenden.
package steuerung

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/plattform"
	"github.com/blocksberghexhex/badbot/intern/puffer"
	"github.com/blocksberghexhex/badbot/intern/sim"
	"github.com/blocksberghexhex/badbot/intern/sperre"
	"github.com/blocksberghexhex/badbot/protokoll"
	"golang.org/x/crypto/ssh"
)

// Steuerung haelt alles zusammen.
type Steuerung struct {
	Z       *plattform.Zugang
	P       *puffer.Puffer
	L       *lauscher.Lauscher
	S       *sperre.Sperre
	Log     *slog.Logger
	Daten   string
	Version string
	// Bind ist die Adresse, auf der gelauscht wird ("" = alle).
	Bind string
	// Abbildung verschiebt Ports -- nur fuer Tests, die keine Ports unter
	// 1024 oeffnen duerfen.
	Abbildung func(int32) int32
	// Faehigkeiten meldet das Lebenszeichen (z. B. "sperren-nftables").
	Faehigkeiten []string
	// Plattform meldet das Lebenszeichen: "linux", "windows", "macos".
	Plattform string

	Erscheinung sim.Erscheinung
	Wirt        ssh.Signer
	Zertifikat  *tls.Certificate

	mu       sync.Mutex
	konfig   *protokoll.Konfiguration
	laufend  map[string]*dienst
	ist      protokoll.Ist
	stumm    bool      // endgueltiger Fehler: keine Meldungen mehr
	pauseBis time.Time // 429: bis dahin nichts senden
	gemeldet map[string]time.Time
}

type dienst struct {
	sim  string // Simulation, bei Web "http+wordpress"
	port int32
	udp  bool
	stop func()
}

// Vorbereiten laedt Erscheinung, Wirtsschluessel, Zertifikat und Puffer aus dem
// Datenverzeichnis.
func (s *Steuerung) Vorbereiten(jetzt time.Time) error {
	var err error
	if s.Erscheinung, err = sim.ErscheinungLaden(filepath.Join(s.Daten, "erscheinung.json")); err != nil {
		return fmt.Errorf("Erscheinung: %w", err)
	}
	if s.Wirt, err = sim.WirtsschluesselLaden(filepath.Join(s.Daten, "ssh_wirt")); err != nil {
		return fmt.Errorf("SSH-Wirtsschluessel: %w", err)
	}
	if s.Zertifikat, err = sim.ZertifikatLaden(filepath.Join(s.Daten, "zertifikat.pem")); err != nil {
		return fmt.Errorf("Zertifikat: %w", err)
	}
	if err := s.P.Laden(s.pufferPfad(), jetzt); err != nil {
		s.Log.Warn("Puffer nicht lesbar, beginne leer", "fehler", err)
	}
	return nil
}

func (s *Steuerung) pufferPfad() string { return filepath.Join(s.Daten, "puffer.json") }

// Laufen arbeitet bis ctx endet und raeumt dann auf.
func (s *Steuerung) Laufen(ctx context.Context) {
	takt := time.Minute
	for {
		if t := s.Runde(ctx, time.Now()); t > 0 {
			takt = t
		}
		select {
		case <-ctx.Done():
			s.Beenden()
			return
		case <-time.After(takt):
		}
	}
}

// Runde ist ein Takt. Sie liefert den Takt der Konfiguration.
func (s *Steuerung) Runde(ctx context.Context, jetzt time.Time) time.Duration {
	s.P.Versiegeln(jetzt)

	s.mu.Lock()
	stumm := s.stumm
	s.mu.Unlock()

	lz, err := s.Z.Lebenszeichen(ctx, protokoll.Lebenszeichen{
		Version: s.Version, Plattform: s.plattform(), Faehigkeiten: s.faehigkeiten(),
		Uhrzeit: jetzt.UTC(), Puffer: s.P.Stand(),
	})
	switch {
	case err == nil:
		if stumm {
			s.Log.Info("Plattform nimmt wieder an")
		}
		s.mu.Lock()
		s.stumm = false
		s.mu.Unlock()
		s.hinweise(lz.Hinweise)
		if lz.AktuelleVersion != "" && lz.AktuelleVersion != s.Version {
			s.einmal("version", time.Hour*24, func() {
				s.Log.Warn("Neue Version verfuegbar", "installiert", s.Version, "aktuell", lz.AktuelleVersion)
			})
		}
		s.konfigurationPruefen(ctx, lz.KonfigurationStand)
		s.melden(ctx, jetzt)
		s.sperrlistePruefen(ctx, lz.SperrlisteStand)
	case plattform.IstEndgueltig(err):
		s.mu.Lock()
		s.stumm = true
		s.mu.Unlock()
		s.einmal("endgueltig", time.Hour, func() {
			s.Log.Error("Plattform lehnt den Collector ab; Meldungen eingestellt, Sperren bleiben bis zu ihrem Ablauf", "fehler", err)
		})
	default:
		s.Log.Warn("Plattform nicht erreichbar", "fehler", err)
	}

	if err := s.S.Anwenden(ctx, jetzt, s.koeder()); err != nil {
		s.Log.Error("Sperren nicht angewendet, alter Stand bleibt", "fehler", err)
	}
	if err := s.P.Speichern(s.pufferPfad()); err != nil {
		s.Log.Warn("Puffer nicht gespeichert", "fehler", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stumm {
		return 10 * time.Minute
	}
	if s.konfig != nil && s.konfig.TaktSekunden > 0 {
		return time.Duration(s.konfig.TaktSekunden) * time.Second
	}
	return time.Minute
}

var hinweisTexte = map[string]string{
	"quell-ip-fehlerhaft":  "Die Simulationen sehen nicht die echte Quelladresse. Docker: \"userland-proxy\": false in /etc/docker/daemon.json oder network_mode: host. Bis das behoben ist, verwirft die Plattform alle Meldungen.",
	"uhrzeit-abweichung":   "Die Uhr dieses Rechners weicht ab. Zeitsynchronisation (NTP) einrichten, sonst werden Meldungen verworfen.",
	"puffer-voll":          "Der Puffer ist uebergelaufen; Beobachtungen gingen verloren.",
	"schluessel-laeuft-ab": "Der API-Schluessel laeuft bald ab. Im Panel verlaengern oder neu ausstellen.",
}

func (s *Steuerung) hinweise(h []string) {
	for _, x := range h {
		text, ok := hinweisTexte[x]
		if !ok {
			text = "Hinweis der Plattform"
		}
		s.einmal("hinweis:"+x, time.Hour, func() { s.Log.Warn(text, "hinweis", x) })
	}
}

// einmal gibt eine Meldung hoechstens einmal je Abstand aus.
func (s *Steuerung) einmal(art string, abstand time.Duration, f func()) {
	s.mu.Lock()
	if s.gemeldet == nil {
		s.gemeldet = map[string]time.Time{}
	}
	zuletzt, ok := s.gemeldet[art]
	frei := !ok || time.Since(zuletzt) > abstand
	if frei {
		s.gemeldet[art] = time.Now()
	}
	s.mu.Unlock()
	if frei {
		f()
	}
}

// plattform: "linux", "windows" oder "macos"; ohne Angabe Linux, wie bisher.
func (s *Steuerung) plattform() string {
	if s.Plattform == "" {
		return "linux"
	}
	return s.Plattform
}

func (s *Steuerung) faehigkeiten() []string {
	l := []string{"tcp-sink", "ssh", "telnet", "http", "wordpress", "dns", "smtp", "ftp", "mysql", "postgres", "redis", "rdp", "vnc", "docker", "elasticsearch", "mqtt"}
	return append(l, s.Faehigkeiten...)
}

func (s *Steuerung) konfigurationPruefen(ctx context.Context, stand string) {
	s.mu.Lock()
	alt := ""
	if s.konfig != nil {
		alt = s.konfig.Stand
	}
	s.mu.Unlock()
	if stand != "" && stand == alt {
		return
	}
	k, err := s.Z.Konfiguration(ctx, alt)
	if errors.Is(err, plattform.ErrUnveraendert) {
		return
	}
	if err != nil {
		s.Log.Warn("Konfiguration nicht abrufbar", "fehler", err)
		return
	}
	ist := s.Anwenden(k)
	if err := s.Z.Ist(ctx, ist); err != nil {
		s.Log.Warn("Ist-Stand nicht gemeldet", "fehler", err)
	}
}

// Anwenden startet und stoppt Simulationen nach der Konfiguration und liefert
// den tatsaechlichen Stand.
func (s *Steuerung) Anwenden(k *protokoll.Konfiguration) protokoll.Ist {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.laufend == nil {
		s.laufend = map[string]*dienst{}
	}
	fenster := time.Duration(k.FensterSekunden) * time.Second
	if fenster <= 0 {
		fenster = 5 * time.Minute
	}
	grenze := k.StichprobeBytes
	if grenze <= 0 {
		grenze = 2048
	}
	s.P.Einstellen(fenster, grenze)
	if k.Sperren.Stufe == "aus" {
		s.S.Leeren()
	}

	// Soll: Schluessel -> Dienst. http und wordpress teilen sich je Port einen.
	type soll struct {
		sim      string
		port     int32
		udp      bool
		http, wp bool
		besitzer []string
	}
	gewuenscht := map[string]*soll{}
	fehler := map[string][]string{}
	belegt := map[string]string{} // "tcp/22" -> Simulation
	for _, ss := range k.Simulationen {
		if !ss.Aktiv {
			continue
		}
		for _, port := range ss.Ports {
			if port < 1 || port > 65535 {
				fehler[ss.Name] = append(fehler[ss.Name], fmt.Sprintf("Port %d ungueltig", port))
				continue
			}
			web := ss.Name == "http" || ss.Name == "wordpress"
			tk := fmt.Sprintf("tcp/%d", port)
			if b, ok := belegt[tk]; ok && !(web && (b == "http" || b == "wordpress")) {
				fehler[ss.Name] = append(fehler[ss.Name], fmt.Sprintf("Port %d schon von %s belegt", port, b))
				continue
			}
			belegt[tk] = ss.Name
			if web {
				sch := fmt.Sprintf("web/%d", port)
				g := gewuenscht[sch]
				if g == nil {
					g = &soll{sim: "web", port: port}
					gewuenscht[sch] = g
				}
				g.http = g.http || ss.Name == "http"
				g.wp = g.wp || ss.Name == "wordpress"
				g.besitzer = append(g.besitzer, ss.Name)
				continue
			}
			gewuenscht[fmt.Sprintf("%s/%d", ss.Name, port)] = &soll{sim: ss.Name, port: port, besitzer: []string{ss.Name}}
			if ss.Name == "dns" {
				gewuenscht[fmt.Sprintf("dns-udp/%d", port)] = &soll{sim: "dns", port: port, udp: true, besitzer: []string{"dns"}}
			}
		}
	}
	for _, g := range gewuenscht {
		if g.sim == "web" {
			g.sim = webName(g.http, g.wp)
		}
	}

	// Beenden, was nicht mehr (oder anders) gewuenscht ist.
	for sch, d := range s.laufend {
		if g, ok := gewuenscht[sch]; !ok || g.sim != d.sim {
			d.stop()
			delete(s.laufend, sch)
		}
	}
	// Starten, was fehlt.
	gestartet := map[string][]int32{}
	for sch, g := range gewuenscht {
		if _, ok := s.laufend[sch]; !ok {
			stop, err := s.starten(g.sim, g.port, g.udp)
			if err != nil {
				for _, b := range g.besitzer {
					fehler[b] = append(fehler[b], fmt.Sprintf("Port %d: %v", g.port, kurzFehler(err)))
				}
				continue
			}
			s.laufend[sch] = &dienst{sim: g.sim, port: g.port, udp: g.udp, stop: stop}
		}
		if !g.udp {
			for _, b := range g.besitzer {
				gestartet[b] = append(gestartet[b], g.port)
			}
		}
	}

	ist := protokoll.Ist{Stand: k.Stand, Simulationen: []protokoll.SimulationIst{}}
	for _, ss := range k.Simulationen {
		ports := gestartet[ss.Name]
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		si := protokoll.SimulationIst{Name: ss.Name, Aktiv: len(ports) > 0, Ports: ports, Fehler: strings.Join(fehler[ss.Name], "; ")}
		if si.Ports == nil {
			si.Ports = []int32{}
		}
		ist.Simulationen = append(ist.Simulationen, si)
	}
	s.konfig, s.ist = k, ist
	return ist
}

// webName benennt den gemeinsamen HTTP-Dienst eines Ports.
func webName(http, wp bool) string {
	switch {
	case http && wp:
		return "http+wordpress"
	case wp:
		return "wordpress"
	}
	return "http"
}

// kurzFehler: "listen tcp :22: bind: address already in use" -> "address already in use"
func kurzFehler(err error) string {
	t := err.Error()
	if i := strings.LastIndex(t, ": "); i >= 0 {
		return t[i+2:]
	}
	return t
}

func (s *Steuerung) adresse(port int32) string {
	if s.Abbildung != nil {
		port = s.Abbildung(port)
	}
	return net.JoinHostPort(s.Bind, fmt.Sprint(port))
}

func (s *Steuerung) starten(simulation string, port int32, udp bool) (func(), error) {
	a := s.adresse(port)
	if udp {
		return s.L.UDP(a, simulation, port, sim.DNS())
	}
	if strings.HasPrefix(simulation, "http") || simulation == "wordpress" {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return nil, err
		}
		w := &sim.Web{Server: s.Erscheinung.Nginx, HTTP: strings.HasPrefix(simulation, "http"),
			WordPress: strings.HasSuffix(simulation, "wordpress"), Port: port, Melde: s.L.Melde}
		srv := w.Bedienen(s.L.Listener(ln), s.Zertifikat)
		return func() { srv.Close() }, nil
	}
	if simulation == "docker" || simulation == "elasticsearch" {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return nil, err
		}
		var h http.Handler = &sim.Docker{Version: s.Erscheinung.Docker, Port: port, Melde: s.L.Melde}
		if simulation == "elasticsearch" {
			h = &sim.Elastic{Version: s.Erscheinung.Elastic, Port: port, Melde: s.L.Melde}
		}
		srv := sim.HTTPDienst(s.L.Listener(ln), h)
		return func() { srv.Close() }, nil
	}
	var h lauscher.Behandler
	e := s.Erscheinung
	switch simulation {
	case "tcp-sink":
		h = sim.TCPSink()
	case "ssh":
		h = sim.SSH(s.Wirt, e.SSH)
	case "telnet":
		h = sim.Telnet()
	case "dns":
		h = sim.DNSTCP()
	case "smtp":
		h = sim.SMTP(e.SMTP)
	case "ftp":
		h = sim.FTP(e.FTP)
	case "mysql":
		h = sim.MySQL(e.MySQL)
	case "postgres":
		h = sim.Postgres()
	case "redis":
		h = sim.Redis()
	case "rdp":
		h = sim.RDP()
	case "vnc":
		h = sim.VNC()
	case "mqtt":
		h = sim.MQTT()
	default:
		return nil, fmt.Errorf("Simulation %q gibt es in dieser Version nicht", simulation)
	}
	return s.L.TCP(a, simulation, port, h)
}

// Ist liefert den zuletzt angewendeten Stand.
func (s *Steuerung) Ist() protokoll.Ist {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ist
}

func (s *Steuerung) koeder() sperre.Koeder {
	s.mu.Lock()
	defer s.mu.Unlock()
	var k sperre.Koeder
	for _, d := range s.laufend {
		if d.udp {
			k.UDP = append(k.UDP, d.port)
		} else {
			k.TCP = append(k.TCP, d.port)
		}
	}
	return k
}

// melden schickt alle versiegelten Stapel.
func (s *Steuerung) melden(ctx context.Context, jetzt time.Time) {
	s.mu.Lock()
	pause := jetzt.Before(s.pauseBis)
	s.mu.Unlock()
	if pause {
		return
	}
	for i := 0; i < 50; i++ { // je Takt begrenzt, damit ein grosser Rueckstau nicht blockiert
		st := s.P.Naechster()
		if st == nil {
			return
		}
		a, err := s.Z.Ereignisse(ctx, *st)
		var f *plattform.Fehler
		switch {
		case err == nil:
			s.P.Bestaetigt(st.Stapel)
			if a.Verworfen > 0 {
				s.Log.Info("Plattform hat Datensaetze verworfen", "verworfen", a.Verworfen, "gruende", a.Gruende)
			}
			s.hinweise(a.Hinweise)
		case errors.As(err, &f) && f.Status == http.StatusRequestEntityTooLarge:
			s.P.Teilen(st.Stapel)
		case errors.As(err, &f) && f.Status == http.StatusBadRequest:
			s.Log.Error("Stapel unlesbar fuer die Plattform, verworfen", "fehler", err)
			s.P.Verwerfen(st.Stapel)
		case errors.As(err, &f) && f.Status == http.StatusTooManyRequests:
			warte := f.RetryAfter
			if warte <= 0 {
				warte = time.Minute
			}
			s.mu.Lock()
			s.pauseBis = jetzt.Add(warte)
			s.mu.Unlock()
			return
		case plattform.IstEndgueltig(err):
			s.mu.Lock()
			s.stumm = true
			s.mu.Unlock()
			return
		default:
			s.Log.Warn("Stapel nicht gemeldet, spaeter erneut", "fehler", err)
			return
		}
	}
}

func (s *Steuerung) sperrlistePruefen(ctx context.Context, stand string) {
	s.mu.Lock()
	aus := s.konfig == nil || s.konfig.Sperren.Stufe == "aus"
	s.mu.Unlock()
	if aus || stand == "" || stand == s.S.Stand() {
		return
	}
	l, err := s.Z.Sperrliste(ctx, s.S.Stand())
	if errors.Is(err, plattform.ErrUnveraendert) {
		return
	}
	if err != nil {
		// Der letzte gueltige Stand bleibt bis gueltig_bis.
		s.Log.Warn("Sperrliste nicht abrufbar", "fehler", err)
		return
	}
	if err := s.S.Uebernehmen(l); err != nil {
		s.Log.Error("Sperrliste unbrauchbar, alter Stand bleibt", "fehler", err)
	}
}

// Beenden stoppt alle Simulationen, versucht die letzten Stapel zu melden und
// sichert den Puffer. Die Sperren werden entfernt: Ohne laufenden Collector
// veralten sie, und niemand nimmt sie mehr zurueck.
func (s *Steuerung) Beenden() {
	s.mu.Lock()
	for sch, d := range s.laufend {
		d.stop()
		delete(s.laufend, sch)
	}
	stumm := s.stumm
	s.mu.Unlock()
	s.P.AllesVersiegeln()
	ctx, abbruch := context.WithTimeout(context.Background(), 10*time.Second)
	defer abbruch()
	if !stumm {
		s.melden(ctx, time.Now())
	}
	if err := s.P.Speichern(s.pufferPfad()); err != nil {
		s.Log.Error("Puffer nicht gesichert", "fehler", err)
	}
	if err := s.S.Entfernen(ctx); err != nil {
		s.Log.Error("Sperren nicht entfernt", "fehler", err)
	}
}
