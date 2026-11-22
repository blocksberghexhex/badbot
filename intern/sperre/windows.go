package sperre

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Gruppe der eigenen Regeln in der Windows-Firewall.
const WindowsGruppe = "badbot"

// WindowsFirewall setzt die Sperren unter Windows um. Die Windows-Firewall
// hat keine Transaktionen: Der neue Stand entsteht als neue Generation von
// Regeln, erst danach verschwindet die alte. Scheitert der Aufbau, werden die
// halb angelegten Regeln entfernt und die alte Generation bleibt.
//
// Sperrregeln haben dort Vorrang vor jeder Freigabe. Die Koederports bleiben
// deshalb nicht durch eine Ausnahme offen, sondern dadurch, dass die
// Sperrregeln nur die uebrigen Ports nennen.
type WindowsFirewall struct {
	Programm    string // Vorgabe "powershell.exe"
	Verzeichnis string // fuer das Skript; Vorgabe das temporaere Verzeichnis
	Jetzt       func() time.Time
}

// Hoechstens so viele Adressen je Regel -- weit unter dem, woran die
// Firewall-Verwaltung zaeh wird.
const windowsJeRegel = 1000

func (w *WindowsFirewall) programm() string {
	if w.Programm == "" {
		return "powershell.exe"
	}
	return w.Programm
}

func (w *WindowsFirewall) Faehigkeit() string { return "sperren-windows-firewall" }

func (w *WindowsFirewall) Bereit() error {
	_, err := exec.LookPath(w.programm())
	return err
}

func (w *WindowsFirewall) Anwenden(ctx context.Context, netze []netip.Prefix, k Koeder) error {
	jetzt := time.Now
	if w.Jetzt != nil {
		jetzt = w.Jetzt
	}
	return w.skript(ctx, WindowsSkript(netze, k, strconv.FormatInt(jetzt().UnixNano(), 36)))
}

func (w *WindowsFirewall) Entfernen(ctx context.Context) error {
	return w.skript(ctx, windowsKopf+
		"Get-NetFirewallRule -Group '"+WindowsGruppe+"' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'badbot-sperre-*' } | Remove-NetFirewallRule\n")
}

// KoederErlauben legt die Freigabe fuer das Programm selbst an. Ohne sie
// laesst die Windows-Firewall eingehende Verbindungen zu den Simulationen
// gar nicht erst durch. Fuer die Einrichtung des Dienstes.
func (w *WindowsFirewall) KoederErlauben(ctx context.Context, programm string) error {
	return w.skript(ctx, windowsKopf+
		"Get-NetFirewallRule -Name 'badbot-koeder' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"+
		"New-NetFirewallRule -Name 'badbot-koeder' -DisplayName 'badbot Koeder' -Group '"+WindowsGruppe+"' -Direction Inbound -Action Allow -Program "+psText(programm)+" | Out-Null\n")
}

// AllesEntfernen raeumt die Gruppe ganz ab, Freigabe eingeschlossen. Fuer
// die Deinstallation.
func (w *WindowsFirewall) AllesEntfernen(ctx context.Context) error {
	return w.skript(ctx, windowsKopf+
		"Get-NetFirewallRule -Group '"+WindowsGruppe+"' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n")
}

// skript laeuft als Datei: Die Adressliste sprengt jede Kommandozeile, und
// ueber stdin liest PowerShell mehrzeilige Bloecke nicht zuverlaessig.
func (w *WindowsFirewall) skript(ctx context.Context, inhalt string) error {
	f, err := os.CreateTemp(w.Verzeichnis, "sperre-*.ps1")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(inhalt); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return ausfuehren(ctx, "", w.programm(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f.Name())
}

const windowsKopf = "$ErrorActionPreference = 'Stop'\n"

// WindowsSkript erzeugt die neue Generation von Sperrregeln und entfernt
// danach die alte.
func WindowsSkript(netze []netip.Prefix, k Koeder, generation string) string {
	var v4, v6, alle []string
	for _, p := range netze {
		alle = append(alle, p.String())
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	praefix := "badbot-sperre-" + generation + "-"
	var b strings.Builder
	b.WriteString(windowsKopf)
	b.WriteString("$neu = '" + praefix + "'\n")
	b.WriteString("try {\n")
	n := 0
	regel := func(protokoll string, ports []string, adressen []string) {
		for i := 0; i < len(adressen); i += windowsJeRegel {
			j := min(i+windowsJeRegel, len(adressen))
			n++
			fmt.Fprintf(&b, "\tNew-NetFirewallRule -Name ($neu + '%d') -DisplayName 'badbot Sperre' -Group '%s' -Direction Inbound -Action Block -Protocol %s",
				n, WindowsGruppe, protokoll)
			if ports != nil {
				b.WriteString(" -LocalPort " + psListe(ports))
			}
			b.WriteString(" -RemoteAddress " + psListe(adressen[i:j]) + " | Out-Null\n")
		}
	}
	if p := portLuecken(k.TCP); len(p) > 0 {
		regel("TCP", p, alle)
	}
	if p := portLuecken(k.UDP); len(p) > 0 {
		regel("UDP", p, alle)
	}
	regel("ICMPv4", nil, v4)
	regel("ICMPv6", nil, v6)
	b.WriteString("} catch {\n")
	b.WriteString("\tGet-NetFirewallRule -Group '" + WindowsGruppe + "' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ($neu + '*') } | Remove-NetFirewallRule\n")
	b.WriteString("\tthrow\n}\n")
	b.WriteString("Get-NetFirewallRule -Group '" + WindowsGruppe + "' | Where-Object { $_.Name -like 'badbot-sperre-*' -and $_.Name -notlike ($neu + '*') } | Remove-NetFirewallRule\n")
	return b.String()
}

// portLuecken: alle Ports ausser den Koederports, als Bereiche.
func portLuecken(koeder []int32) []string {
	var l []string
	von := int32(1)
	for _, p := range sortiert(koeder) {
		if p < 1 || p > 65535 {
			continue
		}
		if p > von {
			l = append(l, bereich(von, p-1))
		}
		von = p + 1
	}
	if von <= 65535 {
		l = append(l, bereich(von, 65535))
	}
	return l
}

func bereich(von, bis int32) string {
	if von == bis {
		return fmt.Sprint(von)
	}
	return fmt.Sprintf("%d-%d", von, bis)
}

func psListe(l []string) string {
	t := make([]string, len(l))
	for i, x := range l {
		t[i] = psText(x)
	}
	return strings.Join(t, ",")
}

// psText: Zeichenkette in einfachen Anfuehrungszeichen; dort ist nur das
// Anfuehrungszeichen selbst besonders und wird verdoppelt.
func psText(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
