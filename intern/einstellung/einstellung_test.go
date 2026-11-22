package einstellung

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func umgebung(m map[string]string) func(string) string {
	return func(n string) string { return m[n] }
}

func TestVorgabenJeSystem(t *testing.T) {
	w := VorgabenFuer("windows", umgebung(map[string]string{"ProgramData": `D:\PD`}))
	if w.Daten != `D:\PD\badbot-collector` || w.Schluessel != `D:\PD\badbot-collector\schluessel` || w.Konfig != `D:\PD\badbot-collector\collector.env` {
		t.Errorf("windows: %+v", w)
	}
	if w := VorgabenFuer("windows", umgebung(nil)); !strings.HasPrefix(w.Daten, `C:\ProgramData`) {
		t.Errorf("windows ohne ProgramData: %+v", w)
	}
	if m := VorgabenFuer("darwin", umgebung(nil)); m.Daten != "/Library/Application Support/badbot-collector" || m.Schluessel == "" {
		t.Errorf("darwin: %+v", m)
	}
	// Linux bleibt, wie es war: alles aus der Umgebung.
	if l := VorgabenFuer("linux", umgebung(nil)); l.Daten != "/var/lib/badbot-collector" || l.Konfig != "" || l.Schluessel != "" {
		t.Errorf("linux: %+v", l)
	}
	if PlattformName("darwin") != "macos" || PlattformName("windows") != "windows" || PlattformName("linux") != "linux" {
		t.Error("PlattformName")
	}
}

func TestEinstellungsdateiUndVorrang(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "schluessel"), []byte("bb1_aus_datei\n"), 0o600)
	konfig := filepath.Join(dir, "collector.env")
	os.WriteFile(konfig, []byte("\ufeff# Kommentar\nBADBOT_LOG_LEVEL=debug\nBADBOT_SPERREN_AUSNAHMEN = \"192.0.2.0/24, 198.51.100.7\"\nBADBOT_DATEN="+dir+"\nBADBOT_SCHLUESSEL_DATEI="+filepath.Join(dir, "schluessel")+"\n"), 0o600)

	e, err := Laden("linux", umgebung(map[string]string{"BADBOT_KONFIG": konfig, "BADBOT_LOG_LEVEL": "warn"}))
	if err != nil {
		t.Fatal(err)
	}
	if e.LogLevel != "warn" { // Umgebung vor Datei
		t.Errorf("LogLevel %q", e.LogLevel)
	}
	if e.Schluessel != "bb1_aus_datei" || e.Daten != dir || len(e.Ausnahmen) != 2 || e.Ausnahmen[1].String() != "198.51.100.7/32" || e.Plattform != "linux" {
		t.Errorf("%+v", e)
	}

	os.WriteFile(konfig, []byte("LOG_LEVEL=debug\n"), 0o600)
	if _, err := Laden("linux", umgebung(map[string]string{"BADBOT_KONFIG": konfig})); err == nil || !strings.Contains(err.Error(), "Zeile 1") {
		t.Errorf("Tippfehler nicht gemeldet: %v", err)
	}
	// Ausdruecklich genannte Datei muss da sein; die Vorgabedatei nicht.
	if _, err := Laden("linux", umgebung(map[string]string{"BADBOT_KONFIG": filepath.Join(dir, "fehlt"), "BADBOT_SCHLUESSEL": "bb1_x"})); err == nil {
		t.Error("fehlende Einstellungsdatei nicht gemeldet")
	}
}

func TestSchluesselAusVorgabeort(t *testing.T) {
	// Unter macOS liegt der Schluessel ohne weitere Angabe im Datenverzeichnis;
	// fehlt er, nennt der Fehler die Datei.
	_, err := Laden("darwin", umgebung(nil))
	if err == nil || !strings.Contains(err.Error(), "Schluesseldatei") {
		t.Fatalf("%v", err)
	}
	e, err := Laden("darwin", umgebung(map[string]string{"BADBOT_SCHLUESSEL": "bb1_direkt"}))
	if err != nil || e.Schluessel != "bb1_direkt" || e.Plattform != "macos" {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := Laden("linux", umgebung(map[string]string{"BADBOT_SCHLUESSEL": "bb1_x", "BADBOT_API": "http://api.example.org"})); err == nil {
		t.Error("http ohne lokale Adresse angenommen")
	}
}
