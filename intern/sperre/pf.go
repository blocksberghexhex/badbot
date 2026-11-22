package sperre

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// VorgabeAnker: Unterhalb von "com.apple" wertet das mitgelieferte
// /etc/pf.conf jeden Anker aus ('anchor "com.apple/*"'). So greifen die
// Sperren, ohne dass die Systemdatei geaendert wird -- die ueberschreibt
// macOS bei Updates ohnehin.
const VorgabeAnker = "com.apple/badbot"

// PF setzt die Sperren unter macOS um: ein eigener Anker mit einer Tabelle.
// pfctl laedt einen Anker in einem Zug; scheitert das Laden, bleibt der alte.
type PF struct {
	Programm string // Vorgabe "pfctl"
	Anker    string // Vorgabe VorgabeAnker

	mu       sync.Mutex
	token    string // Referenz aus "pfctl -E"; gibt beim Entfernen frei
	geprueft bool
}

func (p *PF) programm() string {
	if p.Programm == "" {
		return "pfctl"
	}
	return p.Programm
}

func (p *PF) anker() string {
	if p.Anker == "" {
		return VorgabeAnker
	}
	return p.Anker
}

func (p *PF) Faehigkeit() string { return "sperren-pf" }

func (p *PF) Bereit() error {
	_, err := exec.LookPath(p.programm())
	return err
}

var pfToken = regexp.MustCompile(`Token\s*:\s*(\d+)`)

func (p *PF) Anwenden(ctx context.Context, netze []netip.Prefix, k Koeder) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.geprueft {
		// Ein Anker, den das Regelwerk nicht einbindet, sperrt nichts -- das
		// soll als Fehler auffallen, nicht als scheinbar wirksame Sperre.
		aus, err := ausgabe(ctx, "", p.programm(), "-s", "Anchors")
		if err != nil {
			return err
		}
		oben, _, _ := strings.Cut(p.anker(), "/")
		if !strings.Contains(aus, oben) {
			return fmt.Errorf("pf: Anker %q ist im Regelwerk nicht eingebunden (%s fehlt in /etc/pf.conf)", p.anker(), oben)
		}
		p.geprueft = true
	}
	if err := ausfuehren(ctx, PFRegeln(netze, k), p.programm(), "-a", p.anker(), "-f", "-"); err != nil {
		return err
	}
	if p.token == "" {
		// pf ist unter macOS meist aus. "-E" schaltet es mit Referenzzaehlung
		// ein: Geben wir unsere Referenz zurueck, bleibt pf so, wie es war.
		aus, err := ausgabe(ctx, "", p.programm(), "-E")
		if err != nil {
			return err
		}
		m := pfToken.FindStringSubmatch(aus)
		if m == nil {
			return errors.New("pf: kein Token von pfctl -E")
		}
		p.token = m[1]
	}
	return nil
}

func (p *PF) Entfernen(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ausfuehren(ctx, "", p.programm(), "-a", p.anker(), "-F", "all"); err != nil {
		return err
	}
	if p.token != "" {
		if err := ausfuehren(ctx, "", p.programm(), "-X", p.token); err != nil {
			return err
		}
		p.token = ""
	}
	return nil
}

// PFRegeln erzeugt den Inhalt des Ankers. Bestehende Verbindungen laufen
// ueber die Zustandstabelle von pf und werden von neuen Regeln nicht
// beruehrt.
func PFRegeln(netze []netip.Prefix, k Koeder) string {
	var b strings.Builder
	b.WriteString("table <badbot_sperre> const {")
	for i, n := range netze {
		if i > 0 {
			b.WriteString(",")
		}
		// Fortsetzungszeilen statt einer Zeile mit hunderttausend Eintraegen.
		if i%50 == 0 {
			b.WriteString(" \\\n\t")
		} else {
			b.WriteString(" ")
		}
		b.WriteString(n.String())
	}
	b.WriteString(" }\n")
	if l := portListe(k.TCP); l != "" {
		b.WriteString("pass in quick proto tcp from <badbot_sperre> to any port { " + l + " }\n")
	}
	if l := portListe(k.UDP); l != "" {
		b.WriteString("pass in quick proto udp from <badbot_sperre> to any port { " + l + " }\n")
	}
	b.WriteString("block drop in quick from <badbot_sperre> to any\n")
	return b.String()
}

// portListe: sortiert, ohne Doppelte, kommagetrennt.
func portListe(ports []int32) string {
	var t []string
	for _, p := range sortiert(ports) {
		t = append(t, fmt.Sprint(p))
	}
	return strings.Join(t, ", ")
}
