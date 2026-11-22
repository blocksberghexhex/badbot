// Befehl badbot-collector ist der Collector von badbot.icu fuer Linux,
// Windows und macOS.
//
// Er betreibt Simulationen verwundbar aussehender Dienste, meldet, wer sie
// kontaktiert, und setzt auf Wunsch die Sperrliste der Plattform in der
// Firewall des Systems um (nftables, Windows-Firewall, pf). Was er tut, wird
// im Panel eingestellt; lokal braucht er nur den API-Schluessel.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/blocksberghexhex/badbot/intern/einstellung"
	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/logdatei"
	"github.com/blocksberghexhex/badbot/intern/plattform"
	"github.com/blocksberghexhex/badbot/intern/puffer"
	"github.com/blocksberghexhex/badbot/intern/sperre"
	"github.com/blocksberghexhex/badbot/intern/steuerung"
)

// Version wird beim Bau gesetzt (-ldflags "-X main.Version=...").
var Version = "entwicklung"

func main() {
	zeigeVersion := flag.Bool("version", false, "Version ausgeben")
	flag.Parse()
	if *zeigeVersion {
		fmt.Println(Version)
		return
	}
	var err error
	switch {
	case flag.Arg(0) == "abfrage":
		os.Exit(abfrageAusfuehren(flag.Args()[1:]))
	case flag.Arg(0) == "dienst":
		err = dienstBefehl(flag.Args()[1:])
	case flag.NArg() > 0:
		err = fmt.Errorf("unbekannter Befehl %q", flag.Arg(0))
	default:
		var dienst bool
		if dienst, err = alsDienst(); err == nil && dienst {
			err = dienstLaufen()
		} else if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			err = laufen(ctx, false)
			stop()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "badbot-collector:", err)
		os.Exit(1)
	}
}

// laufen betreibt den Collector, bis ctx endet. Als Dienst ohne Logdatei
// schreibt er ins Datenverzeichnis -- die Standardfehlerausgabe eines
// Windows-Dienstes liest niemand.
func laufen(ctx context.Context, dienst bool) error {
	e, err := einstellung.AusUmgebung()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.Daten, 0o700); err != nil {
		return fmt.Errorf("Datenverzeichnis: %w", err)
	}
	// Dort entstehen unter Windows die Skripte fuer die Firewall; ein fremder
	// Besitzer koennte sie zwischen Schreiben und Ausfuehren tauschen.
	if dienst {
		if err := einstellung.Vertrauenswuerdig(e.Daten); err != nil {
			return err
		}
	}
	var aus io.Writer = os.Stderr
	if e.LogDatei == "" && dienst {
		e.LogDatei = filepath.Join(e.Daten, "collector.log")
	}
	if e.LogDatei != "" {
		d, err := logdatei.Oeffnen(e.LogDatei, 10<<20)
		if err != nil {
			return fmt.Errorf("Logdatei: %w", err)
		}
		defer d.Close()
		aus = d
	}
	log := slog.New(slog.NewTextHandler(aus, &slog.HandlerOptions{Level: stufe(e.LogLevel)}))

	p := puffer.Neu(5*time.Minute, 2048)
	// Mit BADBOT_LOG_LEVEL=debug steht jeder Zugriff mit Quelladresse im Log --
	// so laesst sich pruefen, ob der Collector die echte Quelle sieht.
	melde := func(b puffer.Beobachtung) {
		p.Hinzu(b)
		log.Debug("Zugriff", "quelle", b.Quelle, "simulation", b.Simulation, "port", b.Port)
	}
	l := lauscher.Neu(lauscher.Vorgabe, melde, log)
	sp := sperre.Neu(e.Trocken, e.Ausnahmen, log)
	sp.U = sperre.Vorgabe(e.Daten)
	var faehig []string
	switch {
	case sp.U == nil:
		log.Warn("Sperren auf diesem System nicht moeglich: Sperren werden nur protokolliert")
		sp.Trocken = true
	case sp.U.Bereit() == nil:
		faehig = append(faehig, sp.U.Faehigkeit())
	case !e.Trocken:
		log.Warn("Firewall-Programm nicht gefunden: Sperren werden nur protokolliert", "fehler", sp.U.Bereit())
		sp.Trocken = true
	}

	s := &steuerung.Steuerung{
		Z:            plattform.Neu(e.API, e.Schluessel, Version, e.Plattform),
		P:            p,
		L:            l,
		S:            sp,
		Log:          log,
		Daten:        e.Daten,
		Version:      Version,
		Faehigkeiten: faehig,
		Plattform:    e.Plattform,
	}
	if err := s.Vorbereiten(time.Now()); err != nil {
		return err
	}
	log.Info("badbot-collector gestartet", "version", Version, "plattform", e.Plattform, "api", e.API, "sperren_trocken", sp.Trocken)
	s.Laufen(ctx)
	log.Info("badbot-collector beendet")
	return nil
}

func stufe(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
