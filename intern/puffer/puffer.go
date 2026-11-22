// Package puffer verdichtet Beobachtungen und haelt sie bis zur Meldung.
//
// Je Quelladresse, Simulation und Zeitfenster entsteht genau ein Datensatz
// mit Anzahl, erstem und letztem Zeitpunkt, beruehrten Ports und einer
// begrenzten Stichprobe. Abgeschlossene Fenster werden zu Stapeln mit fester
// Kennung versiegelt: Ein Stapel, der nach einer Stoerung erneut geschickt
// wird, traegt dieselbe Kennung und wird von der Plattform nur einmal gezaehlt.
package puffer

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/blocksberghexhex/badbot/protokoll"
)

// Merkmal ist eine Einzelheit fuer die Stichprobe, z. B. ein Benutzername.
type Merkmal struct {
	Feld string
	Wert any
}

// Beobachtung ist ein einzelner Zugriff, wie eine Simulation ihn sieht.
type Beobachtung struct {
	Quelle     netip.Addr
	Simulation string
	Port       int32
	Zeit       time.Time
	Probe      []Merkmal
	// Nur PHP-Collector: Quelle stammt aus X-Forwarded-For eines Vorschaltnetzes.
	UeberVorschaltnetz bool
	VerbindungVon      netip.Addr
}

type schluessel struct {
	fenster    time.Time
	quelle     netip.Addr
	simulation string
	von        netip.Addr
	vorschalt  bool
}

type eintrag struct {
	erster, letzter time.Time
	anzahl          int64
	ports           []int32
	gekuerzt        bool
	probe           map[string][]any
	probeGroesse    int
}

// Grenzen gegen Speicherueberlauf bei einem Verbindungssturm.
const (
	hoechstOffen    = 100000 // offene Datensaetze
	hoechstWartend  = 200000 // versiegelte, noch nicht gemeldete Datensaetze
	nachlieferfrist = 72 * time.Hour
)

// Puffer verdichtet und haelt Datensaetze.
type Puffer struct {
	mu          sync.Mutex
	fenster     time.Duration
	probeGrenze int
	offen       map[schluessel]*eintrag
	wartend     []*protokoll.Stapel
	nWartend    int
	verworfen   int64
}

// Neu: fenster = Zeitfenster der Verdichtung, probeGrenze = Bytes je Stichprobe.
func Neu(fenster time.Duration, probeGrenze int) *Puffer {
	return &Puffer{fenster: fenster, probeGrenze: probeGrenze, offen: map[schluessel]*eintrag{}}
}

// Einstellen uebernimmt neue Werte aus der Konfiguration.
func (p *Puffer) Einstellen(fenster time.Duration, probeGrenze int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if fenster > 0 {
		p.fenster = fenster
	}
	if probeGrenze > 0 {
		p.probeGrenze = probeGrenze
	}
}

// Hinzu nimmt eine Beobachtung auf. Laeuft der Puffer ueber, wird gezaehlt
// statt blockiert -- die Simulation bleibt antwortfaehig.
func (p *Puffer) Hinzu(b Beobachtung) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := schluessel{fenster: b.Zeit.UTC().Truncate(p.fenster), quelle: b.Quelle.Unmap(), simulation: b.Simulation,
		vorschalt: b.UeberVorschaltnetz, von: b.VerbindungVon}
	e, ok := p.offen[k]
	if !ok {
		if len(p.offen) >= hoechstOffen {
			p.verworfen++
			return
		}
		e = &eintrag{erster: b.Zeit, letzter: b.Zeit, probe: map[string][]any{}}
		p.offen[k] = e
	}
	e.anzahl++
	if b.Zeit.Before(e.erster) {
		e.erster = b.Zeit
	}
	if b.Zeit.After(e.letzter) {
		e.letzter = b.Zeit
	}
	if b.Port > 0 {
		e.portHinzu(b.Port)
	}
	for _, m := range b.Probe {
		e.probeHinzu(m, p.probeGrenze)
	}
}

func (e *eintrag) portHinzu(port int32) {
	for _, x := range e.ports {
		if x == port {
			return
		}
	}
	if len(e.ports) >= protokoll.HoechstPorts {
		e.gekuerzt = true
		return
	}
	e.ports = append(e.ports, port)
}

// probeHinzu haelt die ersten verschiedenen Werte je Feld, bis die
// Stichprobe ihre Groesse erreicht.
func (e *eintrag) probeHinzu(m Merkmal, grenze int) {
	for _, w := range e.probe[m.Feld] {
		if gleich(w, m.Wert) {
			return
		}
	}
	roh, err := json.Marshal(m.Wert)
	if err != nil {
		return
	}
	zusatz := len(roh) + 1
	if _, ok := e.probe[m.Feld]; !ok {
		zusatz += len(m.Feld) + 5
	}
	if e.probeGroesse+zusatz+2 > grenze {
		return
	}
	e.probe[m.Feld] = append(e.probe[m.Feld], m.Wert)
	e.probeGroesse += zusatz
}

func gleich(a, b any) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return string(ra) == string(rb)
}

// Versiegeln macht aus allen Fenstern, die vor jetzt geendet haben, Stapel.
func (p *Puffer) Versiegeln(jetzt time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.versiegeln(func(k schluessel) bool { return !k.fenster.Add(p.fenster).After(jetzt) })
}

// AllesVersiegeln versiegelt auch das laufende Fenster -- beim Beenden.
func (p *Puffer) AllesVersiegeln() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.versiegeln(func(schluessel) bool { return true })
}

func (p *Puffer) versiegeln(fertig func(schluessel) bool) {
	var saetze []protokoll.Datensatz
	for k, e := range p.offen {
		if !fertig(k) {
			continue
		}
		delete(p.offen, k)
		if p.nWartend+len(saetze) >= hoechstWartend {
			p.verworfen += e.anzahl
			continue
		}
		d := protokoll.Datensatz{
			Fenster: k.fenster, Quelle: k.quelle.String(), Simulation: k.simulation, Anzahl: e.anzahl,
			Erster: e.erster.UTC(), Letzter: e.letzter.UTC(), Ports: e.ports, PortsGekuerzt: e.gekuerzt,
		}
		if d.Ports == nil {
			d.Ports = []int32{}
		}
		sort.Slice(d.Ports, func(i, j int) bool { return d.Ports[i] < d.Ports[j] })
		if len(e.probe) > 0 {
			d.Stichprobe, _ = json.Marshal(e.probe)
		}
		if k.vorschalt {
			d.UeberVorschaltnetz = true
			d.VerbindungVon = k.von.String()
		}
		saetze = append(saetze, d)
	}
	// Feste Reihenfolge, damit Stapel reproduzierbar sind (Tests, Fehlersuche).
	sort.Slice(saetze, func(i, j int) bool {
		if !saetze[i].Fenster.Equal(saetze[j].Fenster) {
			return saetze[i].Fenster.Before(saetze[j].Fenster)
		}
		if saetze[i].Quelle != saetze[j].Quelle {
			return saetze[i].Quelle < saetze[j].Quelle
		}
		return saetze[i].Simulation < saetze[j].Simulation
	})
	for len(saetze) > 0 {
		n := min(len(saetze), protokoll.HoechstSaetze)
		p.wartend = append(p.wartend, &protokoll.Stapel{Stapel: neueUUID(), Datensaetze: saetze[:n]})
		p.nWartend += n
		saetze = saetze[n:]
	}
}

// Naechster liefert den aeltesten wartenden Stapel (oder nil). Er bleibt im
// Puffer, bis Bestaetigt ihn entfernt.
func (p *Puffer) Naechster() *protokoll.Stapel {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.wartend) == 0 {
		return nil
	}
	return p.wartend[0]
}

// Bestaetigt entfernt einen gemeldeten Stapel.
func (p *Puffer) Bestaetigt(kennung string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.wartend {
		if s.Stapel == kennung {
			p.nWartend -= len(s.Datensaetze)
			p.wartend = append(p.wartend[:i], p.wartend[i+1:]...)
			return
		}
	}
}

// Teilen ersetzt einen Stapel, den die Plattform als zu gross abgelehnt hat,
// durch zwei halbe mit neuen Kennungen.
func (p *Puffer) Teilen(kennung string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.wartend {
		if s.Stapel != kennung || len(s.Datensaetze) < 2 {
			continue
		}
		h := len(s.Datensaetze) / 2
		a := &protokoll.Stapel{Stapel: neueUUID(), Datensaetze: s.Datensaetze[:h]}
		b := &protokoll.Stapel{Stapel: neueUUID(), Datensaetze: s.Datensaetze[h:]}
		p.wartend = append(p.wartend[:i], append([]*protokoll.Stapel{a, b}, p.wartend[i+1:]...)...)
		return
	}
}

// Verwerfen entfernt einen Stapel, den die Plattform nie annehmen wird.
func (p *Puffer) Verwerfen(kennung string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.wartend {
		if s.Stapel == kennung {
			p.verworfen += int64(len(s.Datensaetze))
			p.nWartend -= len(s.Datensaetze)
			p.wartend = append(p.wartend[:i], p.wartend[i+1:]...)
			return
		}
	}
}

// Stand fuer das Lebenszeichen.
func (p *Puffer) Stand() protokoll.Puffer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return protokoll.Puffer{Datensaetze: p.nWartend + len(p.offen), VerworfenSeitStart: p.verworfen}
}

// ---------------------------------------------------------------------------
// Sichern und Laden: Was beim Beenden nicht gemeldet ist, wird beim naechsten
// Start nachgeliefert -- innerhalb der Nachlieferfrist der Plattform.

// Speichern schreibt die wartenden Stapel atomar in eine Datei.
func (p *Puffer) Speichern(pfad string) error {
	p.mu.Lock()
	roh, err := json.Marshal(p.wartend)
	p.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := pfad + ".neu"
	if err := os.WriteFile(tmp, roh, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, pfad)
}

// Laden liest gespeicherte Stapel; Datensaetze ausserhalb der Nachlieferfrist
// fallen weg, weil die Plattform sie ohnehin ablehnte.
func (p *Puffer) Laden(pfad string, jetzt time.Time) error {
	roh, err := os.ReadFile(filepath.Clean(pfad))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var stapel []*protokoll.Stapel
	if err := json.Unmarshal(roh, &stapel); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range stapel {
		var behalten []protokoll.Datensatz
		for _, d := range s.Datensaetze {
			if jetzt.Sub(d.Fenster) < nachlieferfrist-time.Hour {
				behalten = append(behalten, d)
			}
		}
		if len(behalten) == 0 {
			continue
		}
		if len(behalten) != len(s.Datensaetze) {
			// Ein veraenderter Stapel bekommt eine neue Kennung -- die alte
			// koennte der Plattform mit anderem Inhalt bekannt sein.
			s = &protokoll.Stapel{Stapel: neueUUID(), Datensaetze: behalten}
		}
		p.wartend = append(p.wartend, s)
		p.nWartend += len(s.Datensaetze)
	}
	return os.Remove(pfad)
}

func neueUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
