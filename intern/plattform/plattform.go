// Package plattform spricht mit der Collector-API.
package plattform

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/blocksberghexhex/badbot/protokoll"
)

// Zugang ist die Verbindung zur Plattform.
type Zugang struct {
	Basis      string
	Schluessel string
	Version    string
	Plattform  string
	HTTP       *http.Client
}

// Neu baut einen Zugang mit festen Zeitgrenzen.
func Neu(basis, schluessel, version, plattform string) *Zugang {
	return &Zugang{Basis: basis, Schluessel: schluessel, Version: version, Plattform: plattform,
		HTTP: &http.Client{Timeout: 30 * time.Second,
			// Keine Weiterleitungen: Go nimmt den Authorization-Kopf auf
			// denselben Host mit, auch von https auf http -- eine falsch
			// eingerichtete Weiterleitung schickte den Schluessel im Klartext.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Fehler ist eine Fehlerantwort der Plattform.
type Fehler struct {
	Status     int
	Kennwort   string
	Text       string
	RetryAfter time.Duration
}

func (f *Fehler) Error() string {
	return fmt.Sprintf("Plattform: %d %s %s", f.Status, f.Kennwort, f.Text)
}

// Endgueltig: Weitermachen hilft nicht -- Schluessel ungueltig, Collector
// stumm, Konto gesperrt, Version zu alt.
func (f *Fehler) Endgueltig() bool {
	return f.Status == 401 || f.Status == 403 || f.Status == 426
}

// IstEndgueltig prueft einen beliebigen Fehler.
func IstEndgueltig(err error) bool {
	var f *Fehler
	return errors.As(err, &f) && f.Endgueltig()
}

// ErrUnveraendert: 304, es gibt nichts Neues.
var ErrUnveraendert = errors.New("unveraendert")

func (z *Zugang) anfrage(ctx context.Context, methode, pfad string, ein any, kopf map[string]string) (*http.Response, error) {
	var body io.Reader
	gepackt := false
	if ein != nil {
		roh, err := json.Marshal(ein)
		if err != nil {
			return nil, err
		}
		if len(roh) > 1024 {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			gz.Write(roh)
			gz.Close()
			roh = buf.Bytes()
			gepackt = true
		}
		body = bytes.NewReader(roh)
	}
	req, err := http.NewRequestWithContext(ctx, methode, z.Basis+protokoll.Pfad+pfad, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+z.Schluessel)
	req.Header.Set("User-Agent", "badbot-collector/"+z.Version+" ("+z.Plattform+")")
	if ein != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if gepackt {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range kopf {
		req.Header.Set(k, v)
	}
	return z.HTTP.Do(req)
}

func auswerten(resp *http.Response, aus any) error {
	defer resp.Body.Close()
	roh, err := io.ReadAll(io.LimitReader(resp.Body, protokoll.HoechstBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotModified {
		return ErrUnveraendert
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var f protokoll.Fehler
		json.Unmarshal(roh, &f)
		fe := &Fehler{Status: resp.StatusCode, Kennwort: f.Fehler, Text: f.Text}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			fe.RetryAfter = time.Duration(s) * time.Second
		}
		return fe
	}
	if aus == nil {
		return nil
	}
	return json.Unmarshal(roh, aus)
}

// Lebenszeichen schickt ein Lebenszeichen.
func (z *Zugang) Lebenszeichen(ctx context.Context, lz protokoll.Lebenszeichen) (*protokoll.LebenszeichenAntwort, error) {
	resp, err := z.anfrage(ctx, "POST", "/lebenszeichen", lz, nil)
	if err != nil {
		return nil, err
	}
	var a protokoll.LebenszeichenAntwort
	return &a, auswerten(resp, &a)
}

// Konfiguration holt die Konfiguration; ErrUnveraendert, wenn der Stand gleich ist.
func (z *Zugang) Konfiguration(ctx context.Context, stand string) (*protokoll.Konfiguration, error) {
	kopf := map[string]string{}
	if stand != "" {
		kopf["If-None-Match"] = `"` + stand + `"`
	}
	resp, err := z.anfrage(ctx, "GET", "/konfiguration", nil, kopf)
	if err != nil {
		return nil, err
	}
	var k protokoll.Konfiguration
	return &k, auswerten(resp, &k)
}

// Ist meldet den tatsaechlichen Stand.
func (z *Zugang) Ist(ctx context.Context, ist protokoll.Ist) error {
	resp, err := z.anfrage(ctx, "POST", "/konfiguration/ist", ist, nil)
	if err != nil {
		return err
	}
	return auswerten(resp, nil)
}

// Ereignisse meldet einen Stapel. Ein schon angenommener Stapel (409) gilt
// als Erfolg -- er wurde vorher nur nicht bestaetigt.
func (z *Zugang) Ereignisse(ctx context.Context, s protokoll.Stapel) (*protokoll.StapelAntwort, error) {
	resp, err := z.anfrage(ctx, "POST", "/ereignisse", s, nil)
	if err != nil {
		return nil, err
	}
	var a protokoll.StapelAntwort
	err = auswerten(resp, &a)
	var f *Fehler
	if errors.As(err, &f) && f.Status == http.StatusConflict {
		return &protokoll.StapelAntwort{Angenommen: len(s.Datensaetze)}, nil
	}
	return &a, err
}

// Sperrliste holt die Sperrliste; ErrUnveraendert, wenn der Stand gleich ist.
func (z *Zugang) Sperrliste(ctx context.Context, stand string) (*protokoll.Sperrliste, error) {
	kopf := map[string]string{}
	pfad := "/sperrliste"
	if stand != "" {
		kopf["If-None-Match"] = `"` + stand + `"`
		pfad += "?seit=" + stand
	}
	resp, err := z.anfrage(ctx, "GET", pfad, nil, kopf)
	if err != nil {
		return nil, err
	}
	var s protokoll.Sperrliste
	return &s, auswerten(resp, &s)
}

// Abfrage fragt Ziele in Echtzeit ab, in Paketen zu hoechstens
// protokoll.AbfrageHoechstZiele. Der Zugang braucht dafuer einen
// Abfrage-Schluessel (bbq_...), keinen Collector-Schluessel.
func (z *Zugang) Abfrage(ctx context.Context, ziele []string) ([]protokoll.AbfrageErgebnis, error) {
	var alle []protokoll.AbfrageErgebnis
	for len(ziele) > 0 {
		n := min(len(ziele), protokoll.AbfrageHoechstZiele)
		resp, err := z.anfrage(ctx, "POST", "/abfrage", protokoll.Abfrage{Ziele: ziele[:n]}, nil)
		if err != nil {
			return alle, err
		}
		var a protokoll.AbfrageAntwort
		if err := auswerten(resp, &a); err != nil {
			return alle, err
		}
		if len(a.Ergebnisse) != n {
			return alle, fmt.Errorf("Plattform: %d Ergebnisse fuer %d Ziele", len(a.Ergebnisse), n)
		}
		alle = append(alle, a.Ergebnisse...)
		ziele = ziele[n:]
	}
	return alle, nil
}
