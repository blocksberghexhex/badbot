package sperre

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blocksberghexhex/badbot/protokoll"
)

var jetzt = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func TestStandUndAusnahmen(t *testing.T) {
	s := Neu(true, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/28")}, slog.New(slog.DiscardHandler))
	if err := s.Uebernehmen(&protokoll.Sperrliste{Stand: "s-1", Art: "voll", GueltigBis: jetzt.Add(time.Hour),
		Hinzu: []string{"203.0.113.0/24", "203.0.113.9/32", "192.0.2.44/32", "198.51.100.0/24", "2001:db8::/32", "2001:db8:dead::/48", "127.0.0.1/32"}}); err != nil {
		t.Fatal(err)
	}
	// /32 in /24 faellt weg, die Ausnahme beruehrt 198.51.100.0/24, Loopback nie.
	if n := s.Anzahl(); n != 3 {
		t.Fatalf("wirksam: %v", s.wirksam())
	}
	s.Uebernehmen(&protokoll.Sperrliste{Stand: "s-2", Art: "aenderungen", GueltigBis: jetzt.Add(time.Hour), Entfernt: []string{"192.0.2.44/32"}, Hinzu: []string{"192.0.2.128/25"}})
	r := Regelsatz(s.wirksam(), Koeder{TCP: []int32{22, 80, 22}, UDP: []int32{53}})
	for _, x := range []string{"add element inet badbot sperre4 { 192.0.2.128/25, 203.0.113.0/24 }", "add element inet badbot sperre6 { 2001:db8::/32 }",
		"koeder_tcp { type inet_service; elements = { 22, 80 }; }", "ct state established,related accept"} {
		if !strings.Contains(r, x) {
			t.Fatalf("%q fehlt:\n%s", x, r)
		}
	}
	if s.Stand() != "s-2" {
		t.Fatal(s.Stand())
	}
	if err := s.Uebernehmen(&protokoll.Sperrliste{Art: "voll", Hinzu: []string{"kaputt"}}); err == nil || s.Stand() != "s-2" {
		t.Fatal("kaputte Liste uebernommen")
	}
}

func TestAblaufEntferntSperren(t *testing.T) {
	s := Neu(true, nil, slog.New(slog.DiscardHandler))
	s.Uebernehmen(&protokoll.Sperrliste{Stand: "s-1", Art: "voll", GueltigBis: jetzt, Hinzu: []string{"203.0.113.0/24"}})
	s.Anwenden(context.Background(), jetzt.Add(-time.Minute), Koeder{})
	if !s.aktiv {
		t.Fatal("nicht angewendet")
	}
	s.Anwenden(context.Background(), jetzt.Add(time.Minute), Koeder{})
	if s.aktiv || s.Anzahl() != 0 || s.Stand() != "" {
		t.Fatal("abgelaufene Sperrliste bleibt aktiv")
	}
}

// TestNftables wendet die Regelsaetze mit dem echten nft in einem eigenen
// Netz-Namensraum an -- die Regeln des Rechners bleiben unberuehrt.
func TestNftables(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("braucht root")
	}
	for _, p := range []string{"nft", "unshare"} {
		if _, err := exec.LookPath(p); err != nil {
			t.Skip(p + " fehlt")
		}
	}
	if exec.Command("unshare", "-n", "nft", "list", "ruleset").Run() != nil {
		t.Skip("kein Netz-Namensraum moeglich")
	}
	dir := t.TempDir()
	// Ein Namensraum fuer die ganze Pruefung: nft wird ueber nsenter in den
	// Namensraum eines schlafenden Prozesses geschickt.
	schlaf := exec.Command("unshare", "-n", "sleep", "60")
	if err := schlaf.Start(); err != nil {
		t.Fatal(err)
	}
	defer schlaf.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	nft := filepath.Join(dir, "nft")
	os.WriteFile(nft, []byte("#!/bin/sh\nexec nsenter -t "+itoa(schlaf.Process.Pid)+" -n nft \"$@\"\n"), 0o755)
	liste := func() string {
		out, _ := exec.Command(nft, "list", "table", "inet", "badbot").CombinedOutput()
		return string(out)
	}

	s := Neu(false, nil, slog.New(slog.DiscardHandler))
	s.U = &NFTables{Programm: nft}
	ctx := context.Background()
	s.Uebernehmen(&protokoll.Sperrliste{Stand: "s-1", Art: "voll", GueltigBis: jetzt.Add(time.Hour), Hinzu: []string{"203.0.113.0/24", "2001:db8::/32"}})
	if err := s.Anwenden(ctx, jetzt, Koeder{TCP: []int32{22, 80}, UDP: []int32{53}}); err != nil {
		t.Fatal(err)
	}
	if l := liste(); !strings.Contains(l, "203.0.113.0/24") || !strings.Contains(l, "2001:db8::/32") || !strings.Contains(l, "22, 80") {
		t.Fatalf("Tabelle:\n%s", l)
	}

	// Austausch in einem Zug: Danach steht nur der neue Stand.
	var viele []string
	for i := 0; i < 2500; i++ {
		viele = append(viele, netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 4: byte(i >> 8), 5: byte(i), 15: 1}).String()+"/128")
	}
	s.Uebernehmen(&protokoll.Sperrliste{Stand: "s-2", Art: "voll", GueltigBis: jetzt.Add(time.Hour), Hinzu: viele})
	if err := s.Anwenden(ctx, jetzt, Koeder{TCP: []int32{22}}); err != nil {
		t.Fatal(err)
	}
	if l := liste(); strings.Contains(l, "203.0.113.0/24") || !strings.Contains(l, "2001:db8:9c3::1") {
		t.Fatalf("nach Austausch:\n%.2000s", l)
	}

	// Ein Fehler laesst den alten Stand stehen.
	kaputt := filepath.Join(dir, "kaputt")
	s.U = &NFTables{Programm: kaputt}
	os.WriteFile(kaputt, []byte("#!/bin/sh\nexec "+nft+" -f - <<'X'\ntable inet badbot\ndelete table inet badbot\nunsinn\nX\n"), 0o755)
	s.Uebernehmen(&protokoll.Sperrliste{Stand: "s-3", Art: "voll", GueltigBis: jetzt.Add(time.Hour), Hinzu: []string{"192.0.2.0/24"}})
	if err := s.Anwenden(ctx, jetzt, Koeder{}); err == nil {
		t.Fatal("Fehler nicht gemeldet")
	}
	if l := liste(); !strings.Contains(l, "2001:db8:9c3::1") {
		t.Fatalf("alter Stand verloren:\n%.500s", l)
	}

	s.U = &NFTables{Programm: nft}
	s.Leeren()
	if err := s.Anwenden(ctx, jetzt, Koeder{}); err != nil {
		t.Fatal(err)
	}
	if l := liste(); !strings.Contains(l, "No such file") {
		t.Fatalf("Tabelle nicht entfernt:\n%s", l)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
