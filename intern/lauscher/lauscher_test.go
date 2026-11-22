package lauscher

import (
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blocksberghexhex/badbot/intern/puffer"
)

func neu(g Grenzen) (*Lauscher, *atomic.Int64) {
	var n atomic.Int64
	return Neu(g, func(puffer.Beobachtung) { n.Add(1) }, slog.New(slog.DiscardHandler)), &n
}

func lauschen(t *testing.T, l *Lauscher, h Behandler) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go l.Annehmen(ln, "test", 1, h)
	return ln.Addr().String()
}

func warte(t *testing.T, bed func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if bed() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Bedingung nicht erreicht")
}

func TestGrenzeJeQuelle(t *testing.T) {
	l, gemeldet := neu(Vorgabe)
	freigabe := make(chan struct{})
	a := lauschen(t, l, func(v *Verbindung) []puffer.Merkmal { <-freigabe; return nil })
	var offen []net.Conn
	for i := 0; i < Vorgabe.JeQuelle; i++ {
		c, _ := net.Dial("tcp", a)
		offen = append(offen, c)
	}
	warte(t, func() bool { return l.Aktiv() == Vorgabe.JeQuelle })
	c, _ := net.Dial("tcp", a)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("ueber der Grenze nicht getrennt: %v", err)
	}
	// Auch die abgewiesene Verbindung ist eine Beobachtung.
	warte(t, func() bool { return l.Abgewiesen() == 1 && gemeldet.Load() == 1 })
	close(freigabe)
	for _, c := range offen {
		c.Close()
	}
	warte(t, func() bool { return l.Aktiv() == 0 && gemeldet.Load() == int64(Vorgabe.JeQuelle)+1 })
}

func TestBytegrenze(t *testing.T) {
	l, _ := neu(Vorgabe)
	gelesen := make(chan int, 1)
	a := lauschen(t, l, func(v *Verbindung) []puffer.Merkmal {
		n, _ := io.Copy(io.Discard, v)
		gelesen <- int(n)
		return nil
	})
	c, _ := net.Dial("tcp", a)
	c.Write(make([]byte, 64<<10))
	if n := <-gelesen; n != int(Vorgabe.Bytes) {
		t.Fatalf("gelesen %d Bytes", n)
	}
	c.Close()
}

func TestLeerlauf(t *testing.T) {
	g := Vorgabe
	g.Leerlauf = 200 * time.Millisecond
	l, _ := neu(g)
	fertig := make(chan time.Duration, 1)
	a := lauschen(t, l, func(v *Verbindung) []puffer.Merkmal {
		t0 := time.Now()
		v.Read(make([]byte, 10))
		fertig <- time.Since(t0)
		return nil
	})
	c, _ := net.Dial("tcp", a)
	defer c.Close()
	if d := <-fertig; d > 2*time.Second {
		t.Fatalf("Leerlauf nicht durchgesetzt: %v", d)
	}
}

func TestUDPNieVerstaerker(t *testing.T) {
	l, gemeldet := neu(Vorgabe)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := l.UDPAuf(pc, "dns", 53, func(p []byte) ([]byte, []puffer.Merkmal) {
		if p[0] == 'g' {
			return make([]byte, len(p)*10), nil
		}
		return p, nil
	})
	defer stop()
	c, _ := net.Dial("udp", pc.LocalAddr().String())
	defer c.Close()
	c.Write([]byte("gross"))
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(make([]byte, 100)); err == nil {
		t.Fatalf("Verstaerkte Antwort gesendet: %d Bytes", n)
	}
	antworten := 0
	for i := 0; i < 20; i++ {
		c.Write([]byte("klein"))
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := c.Read(make([]byte, 100)); err == nil {
			antworten++
		}
	}
	// Das grosse Paket bekommt keine Antwort, zaehlt aber nicht gegen die Rate.
	if antworten != Vorgabe.UDPJeMinute {
		t.Fatalf("Ratenbegrenzung: %d Antworten", antworten)
	}
	// Jedes Paket ist eine Beobachtung, auch ohne Antwort.
	warte(t, func() bool { return gemeldet.Load() == 21 })
}

// TestLast: viele Quellen, viele Verbindungen, ein langsamer Behandler. Der
// Lauscher muss die Gesamtgrenze halten, jede Verbindung melden und danach
// alle Plaetze und Goroutinen freigeben.
func TestLast(t *testing.T) {
	if testing.Short() {
		t.Skip("Lasttest")
	}
	g := Vorgabe
	g.Gesamt = 64
	l, gemeldet := neu(g)
	var hoechst atomic.Int64
	a := lauschen(t, l, func(v *Verbindung) []puffer.Merkmal {
		if n := int64(l.Aktiv()); n > hoechst.Load() {
			hoechst.Store(n)
		}
		io.Copy(io.Discard, v)
		return []puffer.Merkmal{{Feld: "x", Wert: 1}}
	})
	vorher := runtime.NumGoroutine()
	fdVorher := dateihandles()
	const quellen, jeQuelle = 50, 40
	var wg sync.WaitGroup
	var verbunden atomic.Int64
	start := time.Now()
	for q := 0; q < quellen; q++ {
		lokal := &net.TCPAddr{IP: net.IPv4(127, 0, 1, byte(q+1))}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{LocalAddr: lokal, Timeout: 5 * time.Second}
			for i := 0; i < jeQuelle; i++ {
				c, err := d.Dial("tcp", a)
				if err != nil {
					continue
				}
				verbunden.Add(1)
				c.Write([]byte("hallo"))
				c.Close()
			}
		}()
	}
	wg.Wait()
	warte(t, func() bool { return gemeldet.Load() == verbunden.Load() && l.Aktiv() == 0 })
	if hoechst.Load() > int64(g.Gesamt) {
		t.Fatalf("Gesamtgrenze ueberschritten: %d", hoechst.Load())
	}
	t.Logf("%d Verbindungen in %v, abgewiesen %d, hoechstens %d gleichzeitig", verbunden.Load(), time.Since(start), l.Abgewiesen(), hoechst.Load())
	warte(t, func() bool { return runtime.NumGoroutine() <= vorher+5 })
	// Jede getrennte Verbindung gibt ihr Dateihandle frei.
	warte(t, func() bool { return fdVorher < 0 || dateihandles() <= fdVorher+5 })
	if verbunden.Load() < quellen*jeQuelle*9/10 {
		t.Fatalf("nur %d Verbindungen", verbunden.Load())
	}
}

// dateihandles zaehlt die offenen Dateihandles des Prozesses (-1 ohne /proc).
func dateihandles() int {
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(e)
}
