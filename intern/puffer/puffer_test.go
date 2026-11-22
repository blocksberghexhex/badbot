package puffer

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

// doku liefert die i-te Adresse aus 2001:db8::/32 -- Beispieladressen nur aus
// den Dokumentationsbereichen.
func doku(i int) netip.Addr {
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i), 15: 1})
}

func beob(q string, sim string, port int32, sek int, probe ...Merkmal) Beobachtung {
	return Beobachtung{Quelle: netip.MustParseAddr(q), Simulation: sim, Port: port, Zeit: t0.Add(time.Duration(sek) * time.Second), Probe: probe}
}

func TestVerdichtung(t *testing.T) {
	p := Neu(5*time.Minute, 2048)
	for i := 0; i < 1000; i++ {
		p.Hinzu(beob("203.0.113.9", "tcp-sink", int32(1000+i%80), i%250))
	}
	p.Hinzu(beob("203.0.113.9", "ssh", 22, 5, Merkmal{"anmeldungen", map[string]any{"name": "root"}}))
	p.Hinzu(beob("::ffff:203.0.113.9", "ssh", 22, 6, Merkmal{"anmeldungen", map[string]any{"name": "root"}}))
	p.Hinzu(beob("203.0.113.9", "ssh", 22, 400)) // naechstes Fenster

	// Vor Fensterende wird nichts versiegelt.
	p.Versiegeln(t0.Add(4 * time.Minute))
	if p.Naechster() != nil {
		t.Fatal("laufendes Fenster versiegelt")
	}
	p.Versiegeln(t0.Add(5 * time.Minute))
	s := p.Naechster()
	if s == nil || len(s.Datensaetze) != 2 {
		t.Fatalf("Stapel: %+v", s)
	}
	var scan, ssh = s.Datensaetze[1], s.Datensaetze[0]
	if scan.Simulation != "tcp-sink" || scan.Anzahl != 1000 || len(scan.Ports) != 64 || !scan.PortsGekuerzt {
		t.Fatalf("Portscan: %d Ports, gekuerzt=%v, anzahl=%d", len(scan.Ports), scan.PortsGekuerzt, scan.Anzahl)
	}
	// IPv4-in-IPv6 ist dieselbe Quelle; doppelte Stichprobe nur einmal.
	if ssh.Anzahl != 2 || ssh.Quelle != "203.0.113.9" || string(ssh.Stichprobe) != `{"anmeldungen":[{"name":"root"}]}` {
		t.Fatalf("SSH: %+v %s", ssh, ssh.Stichprobe)
	}
	if !scan.Erster.Equal(t0) || !scan.Letzter.Equal(t0.Add(249*time.Second)) {
		t.Fatalf("Zeiten: %v %v", scan.Erster, scan.Letzter)
	}
	p.Bestaetigt(s.Stapel)
	if p.Naechster() != nil || p.Stand().Datensaetze != 1 {
		t.Fatalf("nach Bestaetigung: %+v", p.Stand())
	}
}

func TestStichprobeIstBegrenzt(t *testing.T) {
	p := Neu(5*time.Minute, 300)
	for i := 0; i < 100; i++ {
		p.Hinzu(beob("203.0.113.9", "ssh", 22, 1, Merkmal{"anmeldungen", map[string]any{"name": "nutzer", "passwort_laenge": i}}))
	}
	p.AllesVersiegeln()
	d := p.Naechster().Datensaetze[0]
	if len(d.Stichprobe) > 300 || !json.Valid(d.Stichprobe) || d.Anzahl != 100 {
		t.Fatalf("Stichprobe %d Bytes: %s", len(d.Stichprobe), d.Stichprobe)
	}
}

func TestStapelGroesseUndTeilen(t *testing.T) {
	p := Neu(5*time.Minute, 2048)
	for i := 0; i < 12000; i++ {
		p.Hinzu(Beobachtung{Quelle: doku(i), Simulation: "ssh", Port: 22, Zeit: t0})
	}
	p.AllesVersiegeln()
	var groessen []int
	for s := p.Naechster(); s != nil; s = p.Naechster() {
		groessen = append(groessen, len(s.Datensaetze))
		if len(groessen) == 1 {
			p.Teilen(s.Stapel)
			continue
		}
		p.Bestaetigt(s.Stapel)
	}
	// 12000 = 5000 + 5000 + 2000; der erste wird in zwei Haelften geteilt.
	if fmt.Sprint(groessen) != "[5000 2500 2500 5000 2000]" {
		t.Fatalf("Stapelgroessen: %v", groessen)
	}
}

func TestSpeichernUndNachliefern(t *testing.T) {
	pfad := filepath.Join(t.TempDir(), "puffer.json")
	p := Neu(5*time.Minute, 2048)
	p.Hinzu(beob("203.0.113.9", "ssh", 22, 0))
	p.AllesVersiegeln()
	kennung := p.Naechster().Stapel
	if err := p.Speichern(pfad); err != nil {
		t.Fatal(err)
	}

	neu := Neu(5*time.Minute, 2048)
	if err := neu.Laden(pfad, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Dieselbe Kennung: Die Plattform zaehlt einen schon angekommenen Stapel nicht doppelt.
	if s := neu.Naechster(); s == nil || s.Stapel != kennung {
		t.Fatalf("nachgeliefert: %+v", s)
	}

	// Zu alt: faellt weg.
	p.Speichern(pfad)
	alt := Neu(5*time.Minute, 2048)
	alt.Laden(pfad, t0.Add(80*time.Hour))
	if alt.Naechster() != nil {
		t.Fatal("Datensatz ausserhalb der Nachlieferfrist behalten")
	}
}

func TestUeberlaufWirdGezaehlt(t *testing.T) {
	p := Neu(5*time.Minute, 2048)
	for i := 0; i < hoechstOffen+10; i++ {
		p.Hinzu(Beobachtung{Quelle: doku(i), Simulation: "ssh", Zeit: t0})
	}
	if st := p.Stand(); st.VerworfenSeitStart != 10 || st.Datensaetze != hoechstOffen {
		t.Fatalf("Stand: %+v", st)
	}
}
