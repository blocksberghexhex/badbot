package sperre

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blocksberghexhex/badbot/protokoll"
)

func netze(t ...string) []netip.Prefix {
	var l []netip.Prefix
	for _, x := range t {
		l = append(l, netip.MustParsePrefix(x))
	}
	return l
}

func TestPFRegeln(t *testing.T) {
	r := PFRegeln(netze("192.0.2.0/24", "2001:db8::/32"), Koeder{TCP: []int32{80, 22, 22}, UDP: []int32{53}})
	for _, x := range []string{
		"table <badbot_sperre> const { \\\n\t192.0.2.0/24, 2001:db8::/32 }",
		"pass in quick proto tcp from <badbot_sperre> to any port { 22, 80 }",
		"pass in quick proto udp from <badbot_sperre> to any port { 53 }",
		"block drop in quick from <badbot_sperre> to any",
	} {
		if !strings.Contains(r, x) {
			t.Errorf("%q fehlt:\n%s", x, r)
		}
	}
	// Die Freigaben stehen vor der Sperre: Bei "quick" gilt die erste Regel.
	if strings.Index(r, "pass in quick") > strings.Index(r, "block drop") {
		t.Error("Sperre vor den Koederports")
	}
	if r := PFRegeln(netze("192.0.2.0/24"), Koeder{}); strings.Contains(r, "pass") {
		t.Errorf("Freigabe ohne Koederports:\n%s", r)
	}
	var viele []netip.Prefix
	for i := 0; i < 120; i++ {
		viele = append(viele, netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32))
	}
	if n := strings.Count(PFRegeln(viele, Koeder{}), "\\\n"); n != 3 {
		t.Errorf("%d Fortsetzungszeilen, erwartet 3", n)
	}
}

// falsch legt ein Programm an, das seine Aufrufe und stdin protokolliert.
func falsch(t *testing.T, name, rumpf string) (programm, protokoll string) {
	dir := t.TempDir()
	protokoll = filepath.Join(dir, "aufrufe")
	programm = filepath.Join(dir, name)
	skript := "#!/bin/sh\necho \"$*\" >> " + protokoll + "\n" + rumpf + "\n"
	if err := os.WriteFile(programm, []byte(skript), 0o755); err != nil {
		t.Fatal(err)
	}
	return programm, protokoll
}

func lesen(t *testing.T, p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func TestPF(t *testing.T) {
	dir := t.TempDir()
	regeln := filepath.Join(dir, "regeln")
	prog, prot := falsch(t, "pfctl", `case "$*" in
"-s Anchors") echo "  com.apple" ;;
"-E") echo "pf enabled" >&2; echo "Token : 4711" >&2 ;;
*"-f -") cat > `+regeln+` ;;
esac`)
	p := &PF{Programm: prog}
	ctx := context.Background()
	if err := p.Anwenden(ctx, netze("203.0.113.0/24"), Koeder{TCP: []int32{22}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Anwenden(ctx, netze("192.0.2.0/24"), Koeder{TCP: []int32{22}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lesen(t, regeln), "192.0.2.0/24") {
		t.Fatalf("Regeln: %s", lesen(t, regeln))
	}
	if err := p.Entfernen(ctx); err != nil {
		t.Fatal(err)
	}
	erwartet := "-s Anchors\n-a com.apple/badbot -f -\n-E\n-a com.apple/badbot -f -\n-a com.apple/badbot -F all\n-X 4711\n"
	if got := lesen(t, prot); got != erwartet {
		t.Fatalf("Aufrufe:\n%s\nerwartet:\n%s", got, erwartet)
	}

	// Ohne eingebundenen Anker: Fehler statt scheinbarer Sperre.
	prog2, _ := falsch(t, "pfctl", `[ "$*" = "-s Anchors" ] && echo "  andere"; exit 0`)
	if err := (&PF{Programm: prog2}).Anwenden(ctx, netze("203.0.113.0/24"), Koeder{}); err == nil || !strings.Contains(err.Error(), "nicht eingebunden") {
		t.Fatalf("fehlender Anker: %v", err)
	}
}

func TestWindowsSkript(t *testing.T) {
	var viele []netip.Prefix
	for i := 0; i < 2500; i++ {
		viele = append(viele, netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, byte(100 + i/256), byte(i)}), 32))
	}
	viele = append(viele, netze("2001:db8::/32")...)
	s := WindowsSkript(viele, Koeder{TCP: []int32{80, 22}, UDP: []int32{53}}, "g7")
	for _, x := range []string{
		"$ErrorActionPreference = 'Stop'",
		"$neu = 'badbot-sperre-g7-'",
		"-Protocol TCP -LocalPort '1-21','23-79','81-65535' -RemoteAddress '198.51.100.0/32'",
		"-Protocol UDP -LocalPort '1-52','54-65535'",
		"-Protocol ICMPv6 -RemoteAddress '2001:db8::/32' | Out-Null",
		"Where-Object { $_.Name -like 'badbot-sperre-*' -and $_.Name -notlike ($neu + '*') } | Remove-NetFirewallRule",
		"} catch {",
	} {
		if !strings.Contains(s, x) {
			t.Errorf("%q fehlt", x)
		}
	}
	// 2501 Adressen: je drei Regeln fuer TCP und UDP, drei fuer ICMPv4, eine fuer ICMPv6.
	if n := strings.Count(s, "New-NetFirewallRule"); n != 10 {
		t.Errorf("%d Regeln, erwartet 10", n)
	}
	// IPv6 gehoert nicht in eine ICMPv4-Regel.
	for _, z := range strings.Split(s, "\n") {
		if strings.Contains(z, "ICMPv4") && strings.Contains(z, "2001:db8") {
			t.Error("IPv6 in ICMPv4-Regel")
		}
	}
	// Erst die neue Generation, dann das Aufraeumen der alten.
	if strings.LastIndex(s, "New-NetFirewallRule") > strings.Index(s, "-notlike ($neu") {
		t.Error("alte Regeln werden vor dem Aufbau der neuen entfernt")
	}
}

func TestPortLuecken(t *testing.T) {
	for _, f := range []struct {
		koeder []int32
		aus    string
	}{
		{nil, "1-65535"},
		{[]int32{1, 65535}, "2-65534"},
		{[]int32{22, 23, 24}, "1-21,25-65535"},
		{[]int32{2}, "1,3-65535"},
	} {
		if got := strings.Join(portLuecken(f.koeder), ","); got != f.aus {
			t.Errorf("portLuecken(%v) = %s, erwartet %s", f.koeder, got, f.aus)
		}
	}
	if psText("C:\\Pro'gramme\\x.exe") != "'C:\\Pro''gramme\\x.exe'" {
		t.Error(psText("C:\\Pro'gramme\\x.exe"))
	}
}

func TestWindowsFirewall(t *testing.T) {
	dir := t.TempDir()
	kopie := filepath.Join(dir, "skript")
	// Das letzte Argument ist die Skriptdatei; sie wird zur Pruefung kopiert.
	prog, prot := falsch(t, "powershell.exe", `for a; do letztes="$a"; done; cp "$letztes" `+kopie)
	arbeit := t.TempDir()
	w := &WindowsFirewall{Programm: prog, Verzeichnis: arbeit, Jetzt: func() time.Time { return time.Unix(0, 42) }}
	s := Neu(false, nil, slog.New(slog.DiscardHandler))
	s.U = w
	s.Uebernehmen(&protokoll.Sperrliste{Stand: "s-1", Art: "voll", GueltigBis: jetzt.Add(time.Hour), Hinzu: []string{"203.0.113.0/24"}})
	if err := s.Anwenden(context.Background(), jetzt, Koeder{TCP: []int32{3389}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lesen(t, kopie), "badbot-sperre-16-") || !strings.Contains(lesen(t, kopie), "'1-3388','3390-65535'") {
		t.Fatalf("Skript:\n%s", lesen(t, kopie))
	}
	if a := lesen(t, prot); !strings.HasPrefix(a, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+arbeit) {
		t.Fatalf("Aufruf: %s", a)
	}
	if rest, _ := os.ReadDir(arbeit); len(rest) != 0 {
		t.Fatal("Skriptdatei bleibt liegen")
	}
	// Gleicher Stand: kein zweiter Aufruf.
	s.Anwenden(context.Background(), jetzt, Koeder{TCP: []int32{3389}})
	if n := strings.Count(lesen(t, prot), "\n"); n != 1 {
		t.Fatalf("%d Aufrufe", n)
	}
	if err := w.KoederErlauben(context.Background(), `C:\Program Files\badbot-collector\badbot-collector.exe`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lesen(t, kopie), `-Program 'C:\Program Files\badbot-collector\badbot-collector.exe'`) {
		t.Fatalf("Freigabe:\n%s", lesen(t, kopie))
	}
	// Ein Fehler kommt mit der Ausgabe zurueck.
	kaputt, _ := falsch(t, "powershell.exe", `echo "Zugriff verweigert"; exit 1`)
	w.Programm = kaputt
	if err := w.Entfernen(context.Background()); err == nil || !strings.Contains(err.Error(), "Zugriff verweigert") {
		t.Fatalf("Fehler: %v", err)
	}
}
