// Package einstellung liest die lokale Einstellung des Collectors aus der
// Umgebung. Was der Collector tut, kommt aus dem Panel; hier steht nur, wie
// er die Plattform erreicht und wo er Daten ablegt.
package einstellung

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// Einstellung des Collectors.
type Einstellung struct {
	API        string         // Adresse der Plattform
	Schluessel string         // API-Schluessel aus dem Panel
	Daten      string         // Verzeichnis fuer Puffer, Wirtsschluessel, Zertifikat
	Trocken    bool           // Sperren nur protokollieren, nicht anwenden
	Ausnahmen  []netip.Prefix // nie sperren, z. B. das eigene Verwaltungsnetz
	LogLevel   string
	LogDatei   string // leer: Standardfehlerausgabe
	Plattform  string // "linux", "windows" oder "macos"
}

// VorgabeAPI ist die Adresse der Plattform.
const VorgabeAPI = "https://api.badbot.icu"

// Vorgaben je Betriebssystem. Unter Linux kommt alles aus der Umgebung
// (systemd, Docker); Windows-Dienste und launchd-Daemons reichen Umgebung
// nur umstaendlich durch, dort liegen Einstellungsdatei und Schluessel an
// festen Orten im Datenverzeichnis.
type Vorgaben struct {
	Daten      string
	Konfig     string // Einstellungsdatei; leer: keine
	Schluessel string // Schluesseldatei, wenn nichts anderes angegeben ist
}

// VorgabenFuer liefert die Vorgaben fuer ein Betriebssystem (GOOS).
func VorgabenFuer(goos string, getenv func(string) string) Vorgaben {
	switch goos {
	case "windows":
		basis := getenv("ProgramData")
		if basis == "" {
			basis = `C:\ProgramData`
		}
		d := basis + `\badbot-collector`
		return Vorgaben{Daten: d, Konfig: d + `\collector.env`, Schluessel: d + `\schluessel`}
	case "darwin":
		d := "/Library/Application Support/badbot-collector"
		return Vorgaben{Daten: d, Konfig: d + "/collector.env", Schluessel: d + "/schluessel"}
	}
	return Vorgaben{Daten: "/var/lib/badbot-collector"}
}

// PlattformName: so heisst das System im Panel.
func PlattformName(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return goos
}

// AusUmgebung liest:
//
//	BADBOT_API              Adresse der Plattform (Vorgabe https://api.badbot.icu)
//	BADBOT_SCHLUESSEL       API-Schluessel, oder
//	BADBOT_SCHLUESSEL_DATEI Datei, in der er steht (empfohlen, Rechte 0600)
//	BADBOT_DATEN            Datenverzeichnis (Vorgabe /var/lib/badbot-collector)
//	BADBOT_SPERREN_TROCKEN  1 = Sperren nur protokollieren
//	BADBOT_SPERREN_AUSNAHMEN Netze, die nie gesperrt werden (kommagetrennt)
//	BADBOT_LOG_LEVEL        debug, info, warn, error
//	BADBOT_LOG_DATEI        Logdatei statt Standardfehlerausgabe
//	BADBOT_KONFIG           Einstellungsdatei mit denselben Namen (NAME=wert)
//
// Die Umgebung hat Vorrang vor der Einstellungsdatei.
func AusUmgebung() (*Einstellung, error) {
	return Laden(runtime.GOOS, os.Getenv)
}

// Laden liest die Einstellung fuer ein Betriebssystem.
func Laden(goos string, getenv func(string) string) (*Einstellung, error) {
	v := VorgabenFuer(goos, getenv)
	datei := getenv("BADBOT_KONFIG")
	pflicht := datei != ""
	if datei == "" {
		datei = v.Konfig
	}
	ausDatei := map[string]string{}
	if datei != "" {
		var err error
		if ausDatei, err = konfigLesen(datei); err != nil && (pflicht || !errors.Is(err, os.ErrNotExist)) {
			return nil, err
		}
	}
	wert := func(name, vorgabe string) string {
		if w := strings.TrimSpace(getenv(name)); w != "" {
			return w
		}
		if w := strings.TrimSpace(ausDatei[name]); w != "" {
			return w
		}
		return vorgabe
	}

	e := &Einstellung{
		API:       wert("BADBOT_API", VorgabeAPI),
		Daten:     wert("BADBOT_DATEN", v.Daten),
		Trocken:   wert("BADBOT_SPERREN_TROCKEN", "") == "1",
		LogLevel:  wert("BADBOT_LOG_LEVEL", "info"),
		LogDatei:  wert("BADBOT_LOG_DATEI", ""),
		Plattform: PlattformName(goos),
	}
	e.API = strings.TrimSuffix(e.API, "/")
	u, err := url.Parse(e.API)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("BADBOT_API unbrauchbar: %q", e.API)
	}
	// Nur https. http allein fuer lokale Tests -- ein Schalter, der die
	// Zertifikatspruefung abschaltet, existiert absichtlich nicht.
	if u.Scheme != "https" && !(u.Scheme == "http" && lokal(u.Hostname())) {
		return nil, errors.New("BADBOT_API muss https verwenden")
	}

	for _, n := range strings.FieldsFunc(wert("BADBOT_SPERREN_AUSNAHMEN", ""), func(r rune) bool { return r == ',' || r == ' ' }) {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			a, err2 := netip.ParseAddr(n)
			if err2 != nil {
				return nil, fmt.Errorf("BADBOT_SPERREN_AUSNAHMEN: %q ist kein Netz", n)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		e.Ausnahmen = append(e.Ausnahmen, p.Masked())
	}

	e.Schluessel = wert("BADBOT_SCHLUESSEL", "")
	schluesselDatei := wert("BADBOT_SCHLUESSEL_DATEI", "")
	if schluesselDatei == "" && e.Schluessel == "" {
		schluesselDatei = v.Schluessel
	}
	if schluesselDatei != "" {
		b, err := os.ReadFile(schluesselDatei)
		if err != nil {
			return nil, fmt.Errorf("Schluesseldatei: %w", err)
		}
		e.Schluessel = strings.TrimSpace(string(b))
	}
	if !strings.HasPrefix(e.Schluessel, "bb1_") {
		return nil, errors.New("kein gueltiger API-Schluessel (BADBOT_SCHLUESSEL oder BADBOT_SCHLUESSEL_DATEI)")
	}
	return e, nil
}

// konfigLesen: Zeilen NAME=wert, Kommentare mit #. Nur BADBOT_-Namen -- ein
// Tippfehler soll auffallen, statt still ignoriert zu werden.
func konfigLesen(datei string) (map[string]string, error) {
	f, err := os.Open(datei)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	z := bufio.NewScanner(f)
	for nr := 1; z.Scan(); nr++ {
		zeile := strings.TrimSpace(strings.TrimPrefix(z.Text(), "\ufeff"))
		if zeile == "" || strings.HasPrefix(zeile, "#") {
			continue
		}
		name, w, ok := strings.Cut(zeile, "=")
		name = strings.TrimSpace(name)
		if !ok || !strings.HasPrefix(name, "BADBOT_") {
			return nil, fmt.Errorf("%s, Zeile %d: erwartet BADBOT_NAME=wert", datei, nr)
		}
		w = strings.TrimSpace(w)
		if len(w) >= 2 && w[0] == '"' && w[len(w)-1] == '"' {
			w = w[1 : len(w)-1]
		}
		m[name] = w
	}
	return m, z.Err()
}

func lokal(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
}
