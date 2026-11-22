package logdatei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWechselBeiGrenze(t *testing.T) {
	pfad := filepath.Join(t.TempDir(), "collector.log")
	d, err := Oeffnen(pfad, 100)
	if err != nil {
		t.Fatal(err)
	}
	zeile := strings.Repeat("x", 39) + "\n"
	for i := 0; i < 5; i++ {
		d.Write([]byte(zeile))
	}
	d.Close()
	a, _ := os.ReadFile(pfad)
	b, _ := os.ReadFile(pfad + ".1")
	// 5 Zeilen zu 40 Byte, Grenze 100: 2 in der alten, 1 in der aktuellen
	// (die erste Vorgaengerin ist dabei ueberschrieben worden).
	if len(a) != 40 || len(b) != 80 {
		t.Fatalf("aktuell %d, alt %d", len(a), len(b))
	}
	// Wiederoeffnen haengt an.
	d, _ = Oeffnen(pfad, 100)
	d.Write([]byte("y\n"))
	d.Close()
	if a, _ := os.ReadFile(pfad); len(a) != 42 {
		t.Fatalf("nicht angehaengt: %d", len(a))
	}
}
