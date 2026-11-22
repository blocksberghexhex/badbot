package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/blocksberghexhex/badbot/intern/einstellung"
	"github.com/blocksberghexhex/badbot/intern/plattform"
	"github.com/blocksberghexhex/badbot/protokoll"
)

// abfrageBefehl: badbot-collector abfrage [-json] ziel...
//
// Fragt Adressen, Netze oder AS in Echtzeit ab. Ohne Ziele auf der
// Befehlszeile liest er sie zeilenweise von der Standardeingabe. Ergebnis
// wie bei grep: 0 = nichts gesperrt, 1 = mindestens ein Ziel gesperrt,
// 2 = Fehler.
func abfrageBefehl(args []string, ein io.Reader, aus io.Writer, getenv func(string) string) (gesperrt bool, err error) {
	fs := flag.NewFlagSet("abfrage", flag.ContinueOnError)
	fs.SetOutput(aus)
	alsJSON := fs.Bool("json", false, "Antwort als JSON")
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	ziele := fs.Args()
	if len(ziele) == 0 {
		roh, err := io.ReadAll(io.LimitReader(ein, 1<<20))
		if err != nil {
			return false, err
		}
		for _, zeile := range strings.Split(string(roh), "\n") {
			zeile, _, _ = strings.Cut(zeile, "#")
			ziele = append(ziele, strings.Fields(zeile)...)
		}
	}
	if len(ziele) == 0 {
		return false, errors.New("kein Ziel: badbot-collector abfrage 192.0.2.7 198.51.100.0/24 AS64500")
	}
	api, schluessel, err := einstellung.AbfrageLaden(runtime.GOOS, getenv)
	if err != nil {
		return false, err
	}
	z := plattform.Neu(api, schluessel, Version, einstellung.PlattformName(runtime.GOOS))
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Minute)
	defer stop()
	erg, err := z.Abfrage(ctx, ziele)
	if err != nil {
		return false, abfrageFehler(err)
	}
	for _, e := range erg {
		gesperrt = gesperrt || e.Gesperrt
	}
	if *alsJSON {
		enc := json.NewEncoder(aus)
		enc.SetIndent("", "  ")
		return gesperrt, enc.Encode(erg)
	}
	for _, e := range erg {
		fmt.Fprintln(aus, abfrageZeile(e))
	}
	return gesperrt, nil
}

// abfrageZeile: "192.0.2.7  gesperrt  adresse bis 2026-11-29 11:00 UTC".
func abfrageZeile(e protokoll.AbfrageErgebnis) string {
	switch {
	case e.Fehler != "":
		return e.Ziel + "\tfehler\t" + e.Fehler
	case !e.Gesperrt:
		return e.Ziel + "\tfrei"
	}
	var teile []string
	for _, t := range e.Treffer {
		bis := "unbefristet"
		if t.Bis != nil {
			bis = "bis " + t.Bis.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		if t.Anzahl > 1 {
			teile = append(teile, fmt.Sprintf("%s (%d) %s", t.Stufe, t.Anzahl, bis))
		} else {
			teile = append(teile, t.Stufe+" "+bis)
		}
	}
	return e.Ziel + "\tgesperrt\t" + strings.Join(teile, ", ")
}

// abfrageFehler: die Kennworte der Plattform in Worten.
func abfrageFehler(err error) error {
	var f *plattform.Fehler
	if !errors.As(err, &f) {
		return err
	}
	switch f.Kennwort {
	case "schluessel-fehlt", "schluessel-ungueltig":
		return errors.New("Abfrage-Schluessel ungueltig oder widerrufen -- im Portal unter Konto anlegen")
	case "nicht-im-paket":
		return errors.New("Echtzeitabfragen gehoeren nicht zum Paket dieses Kontos")
	case "kontingent-erschoepft":
		return errors.New("Abfragekontingent dieses Monats erschoepft")
	case "zu-viele-anfragen":
		return fmt.Errorf("zu viele Anfragen, in %s erneut", max(f.RetryAfter, time.Minute))
	}
	return err
}

// abfrageAusfuehren: Rueckgabewert fuer os.Exit.
func abfrageAusfuehren(args []string) int {
	gesperrt, err := abfrageBefehl(args, os.Stdin, os.Stdout, os.Getenv)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		fmt.Fprintln(os.Stderr, "badbot-collector abfrage:", err)
		return 2
	case gesperrt:
		return 1
	}
	return 0
}
