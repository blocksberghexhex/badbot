// Package lauscher nimmt Verbindungen fuer die Simulationen an und setzt
// dabei die Grenzen durch: gleichzeitige Verbindungen gesamt und je
// Quelladresse, Dauer, gelesene Bytes, Leerlauf. Wer eine Grenze
// ueberschreitet, wird getrennt -- die Simulation bleibt fuer alle anderen
// antwortfaehig.
//
// Gemeldet wird ausschliesslich die Gegenstelle der Verbindung, nie eine
// Adresse aus dem, was sie schickt.
package lauscher

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// Grenzen je Collector: Sie halten ihn auch unter Last klein und machen
// ihn nie zum Verstaerker.
type Grenzen struct {
	Gesamt      int           // gleichzeitige Verbindungen
	JeQuelle    int           // gleichzeitige Verbindungen je Quelladresse
	Dauer       time.Duration // hoechste Dauer einer Verbindung
	Bytes       int64         // hoechstens gelesene Bytes je Verbindung
	Leerlauf    time.Duration // ohne Eingabe bis zum Trennen
	UDPJeMinute int           // UDP-Antworten je Quelladresse
}

// Vorgabe der Grenzen.
var Vorgabe = Grenzen{Gesamt: 512, JeQuelle: 8, Dauer: 30 * time.Second, Bytes: 16 << 10, Leerlauf: 10 * time.Second, UDPJeMinute: 10}

// Behandler spielt den Ablauf einer Simulation ab und liefert, was in die
// Stichprobe soll. Er darf nie eine Anmeldung gewaehren und nichts von dem
// ausfuehren, was ankommt.
type Behandler func(v *Verbindung) []puffer.Merkmal

// UDPBehandler beantwortet ein Paket. Eine Antwort, die groesser waere als
// die Anfrage, wird verworfen -- ein Collector darf nie Verstaerker sein.
type UDPBehandler func(paket []byte) (antwort []byte, probe []puffer.Merkmal)

// Lauscher verwaltet alle Verbindungen eines Collectors.
type Lauscher struct {
	G     Grenzen
	Melde func(puffer.Beobachtung)
	Log   *slog.Logger
	// DauerJe weicht fuer einzelne Simulationen von G.Dauer ab (SSH braucht
	// fuer den Schluesselaustausch und drei Versuche laenger).
	DauerJe map[string]time.Duration

	mu       sync.Mutex
	aktiv    int
	jeQuelle map[netip.Addr]int
	udp      map[netip.Addr]*udpZaehler
	// Getrennte, weil eine Grenze erreicht war -- fuer Lasttest und Lebenszeichen.
	abgewiesen int64
}

type udpZaehler struct {
	beginn time.Time
	anzahl int
}

// Neu baut einen Lauscher.
func Neu(g Grenzen, melde func(puffer.Beobachtung), log *slog.Logger) *Lauscher {
	return &Lauscher{G: g, Melde: melde, Log: log, DauerJe: map[string]time.Duration{"ssh": 60 * time.Second}, jeQuelle: map[netip.Addr]int{}, udp: map[netip.Addr]*udpZaehler{}}
}

// Abgewiesen zaehlt Verbindungen, die an einer Grenze scheiterten.
func (l *Lauscher) Abgewiesen() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.abgewiesen
}

// Aktiv zaehlt die offenen Verbindungen.
func (l *Lauscher) Aktiv() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.aktiv
}

func (l *Lauscher) belegen(q netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.aktiv >= l.G.Gesamt || l.jeQuelle[q] >= l.G.JeQuelle {
		l.abgewiesen++
		return false
	}
	l.aktiv++
	l.jeQuelle[q]++
	return true
}

func (l *Lauscher) freigeben(q netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.aktiv--
	if l.jeQuelle[q]--; l.jeQuelle[q] <= 0 {
		delete(l.jeQuelle, q)
	}
}

// Gegenstelle liest die Adresse der Gegenstelle.
func Gegenstelle(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// Verbindung ist eine angenommene Verbindung mit ihren Grenzen.
type Verbindung struct {
	net.Conn
	Quelle   netip.Addr
	Port     int32
	gelesen  int64
	grenze   int64
	leerlauf time.Duration
	ende     time.Time
}

// Read setzt Leerlauf- und Bytegrenze durch. Nach der Bytegrenze liefert sie
// io.EOF, als haette die Gegenstelle aufgehoert.
func (v *Verbindung) Read(b []byte) (int, error) {
	if v.gelesen >= v.grenze {
		return 0, io.EOF
	}
	frist := time.Now().Add(v.leerlauf)
	if frist.After(v.ende) {
		frist = v.ende
	}
	v.Conn.SetReadDeadline(frist)
	if rest := v.grenze - v.gelesen; int64(len(b)) > rest {
		b = b[:rest]
	}
	n, err := v.Conn.Read(b)
	v.gelesen += int64(n)
	return n, err
}

// TCP lauscht auf einem Port fuer eine Simulation. stop beendet das Lauschen;
// laufende Verbindungen enden an ihrer Zeitgrenze.
func (l *Lauscher) TCP(adresse, simulation string, port int32, h Behandler) (stop func(), err error) {
	ln, err := net.Listen("tcp", adresse)
	if err != nil {
		return nil, err
	}
	go l.Annehmen(ln, simulation, port, h)
	return func() { ln.Close() }, nil
}

// Annehmen bedient einen schon geoeffneten Listener, bis er geschlossen wird.
func (l *Lauscher) Annehmen(ln net.Listener, simulation string, port int32, h Behandler) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Voruebergehend (z. B. zu viele offene Dateien): kurz warten statt kreiseln.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		q := Gegenstelle(c.RemoteAddr())
		zeit := time.Now()
		if !q.IsValid() || !l.belegen(q) {
			c.Close()
			// Auch eine abgewiesene Verbindung ist eine Beobachtung -- nur ohne Stichprobe.
			if q.IsValid() {
				l.Melde(puffer.Beobachtung{Quelle: q, Simulation: simulation, Port: port, Zeit: zeit})
			}
			continue
		}
		go func() {
			defer l.freigeben(q)
			defer c.Close()
			ende := zeit.Add(l.G.Dauer)
			c.SetDeadline(ende)
			v := &Verbindung{Conn: c, Quelle: q, Port: port, grenze: l.G.Bytes, leerlauf: l.G.Leerlauf, ende: ende}
			probe := sicher(l.Log, simulation, func() []puffer.Merkmal { return h(v) })
			l.Melde(puffer.Beobachtung{Quelle: q, Simulation: simulation, Port: port, Zeit: zeit, Probe: probe})
		}()
	}
}

func (l *Lauscher) dauer(simulation string) time.Duration {
	if d, ok := l.DauerJe[simulation]; ok {
		return d
	}
	return l.G.Dauer
}

// sicher faengt eine Panik in einer Simulation ab -- ein Fehler im Ablauf
// eines Protokolls darf den Collector nicht beenden.
func sicher(log *slog.Logger, simulation string, f func() []puffer.Merkmal) (probe []puffer.Merkmal) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Simulation abgestuerzt", "simulation", simulation, "fehler", r)
			probe = nil
		}
	}()
	return f()
}

// Listener begrenzt einen fremden Listener (fuer net/http): Ueber der Grenze
// wird sofort getrennt, jede Verbindung bekommt die Zeitgrenze.
func (l *Lauscher) Listener(ln net.Listener) net.Listener {
	return &begrenzt{Listener: ln, l: l}
}

type begrenzt struct {
	net.Listener
	l *Lauscher
}

func (b *begrenzt) Accept() (net.Conn, error) {
	for {
		c, err := b.Listener.Accept()
		if err != nil {
			return nil, err
		}
		q := Gegenstelle(c.RemoteAddr())
		if !q.IsValid() || !b.l.belegen(q) {
			c.Close()
			continue
		}
		// Eine Frist per SetDeadline ueberschriebe net/http mit eigenen
		// Fristen; ein Zeitgeber, der die Verbindung schliesst, haelt.
		f := &freigabe{Conn: c}
		zeitgeber := time.AfterFunc(b.l.G.Dauer, func() { f.Close() })
		f.frei = func() { zeitgeber.Stop(); b.l.freigeben(q) }
		return f, nil
	}
}

type freigabe struct {
	net.Conn
	einmal sync.Once
	frei   func()
}

func (f *freigabe) Close() error {
	f.einmal.Do(f.frei)
	return f.Conn.Close()
}

// UDP lauscht auf einem UDP-Port. Die Quelle eines UDP-Pakets ist faelschbar;
// die Plattform weiss das und zaehlt solche Beobachtungen nur als Bestaetigung.
func (l *Lauscher) UDP(adresse, simulation string, port int32, h UDPBehandler) (stop func(), err error) {
	pc, err := net.ListenPacket("udp", adresse)
	if err != nil {
		return nil, err
	}
	return l.UDPAuf(pc, simulation, port, h), nil
}

// UDPAuf bedient eine schon geoeffnete Paketverbindung.
func (l *Lauscher) UDPAuf(pc net.PacketConn, simulation string, port int32, h UDPBehandler) (stop func()) {
	go func() {
		lesepuffer := make([]byte, 1500)
		for {
			n, absender, err := pc.ReadFrom(lesepuffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			q := Gegenstelle(absender)
			if !q.IsValid() {
				continue
			}
			paket := append([]byte(nil), lesepuffer[:n]...)
			antwort, probe := sicherUDP(l.Log, simulation, h, paket)
			l.Melde(puffer.Beobachtung{Quelle: q, Simulation: simulation, Port: port, Zeit: time.Now(), Probe: probe})
			if len(antwort) > 0 && len(antwort) <= len(paket) && l.udpErlaubt(q) {
				pc.WriteTo(antwort, absender)
			}
		}
	}()
	return func() { pc.Close() }
}

func sicherUDP(log *slog.Logger, simulation string, h UDPBehandler, paket []byte) (antwort []byte, probe []puffer.Merkmal) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Simulation abgestuerzt", "simulation", simulation, "fehler", r)
			antwort, probe = nil, nil
		}
	}()
	return h(paket)
}

func (l *Lauscher) udpErlaubt(q netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	jetzt := time.Now()
	if len(l.udp) > 100000 {
		l.udp = map[netip.Addr]*udpZaehler{} // grob, aber begrenzt den Speicher
	}
	z, ok := l.udp[q]
	if !ok || jetzt.Sub(z.beginn) > time.Minute {
		l.udp[q] = &udpZaehler{beginn: jetzt, anzahl: 1}
		return true
	}
	z.anzahl++
	return z.anzahl <= l.G.UDPJeMinute
}
