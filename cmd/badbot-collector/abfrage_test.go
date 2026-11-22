package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blocksberghexhex/badbot/protokoll"
)

// Ein Schluessel nur fuer diesen Test; nie ein echter.
const testSchluessel = "bbq_nurfuerdentest"

func abfrageServer(t *testing.T, anfragen *[]int) *httptest.Server {
	bis := time.Date(2026, 11, 29, 11, 0, 0, 0, time.UTC)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/abfrage" || r.Header.Get("Authorization") != "Bearer "+testSchluessel {
			w.WriteHeader(401)
			w.Write([]byte(`{"fehler":"schluessel-ungueltig","text":"x"}`))
			return
		}
		var leser io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			leser = gz
		}
		var a protokoll.Abfrage
		json.NewDecoder(leser).Decode(&a)
		*anfragen = append(*anfragen, len(a.Ziele))
		if len(a.Ziele) > protokoll.AbfrageHoechstZiele {
			w.WriteHeader(413)
			return
		}
		var aus protokoll.AbfrageAntwort
		for _, z := range a.Ziele {
			e := protokoll.AbfrageErgebnis{Ziel: z}
			switch z {
			case "192.0.2.7":
				e.Gesperrt, e.Treffer = true, []protokoll.AbfrageTreffer{{Stufe: "adresse", Bis: &bis, Anzahl: 1}}
			case "AS64500":
				e.Gesperrt, e.Treffer = true, []protokoll.AbfrageTreffer{{Stufe: "as", Anzahl: 1}}
			case "unsinn":
				e.Fehler = "unlesbar"
			}
			aus.Ergebnisse = append(aus.Ergebnisse, e)
		}
		json.NewEncoder(w).Encode(aus)
	}))
}

func umgebung(api, schluessel string) func(string) string {
	return func(n string) string {
		return map[string]string{"BADBOT_API": api, "BADBOT_ABFRAGE_SCHLUESSEL": schluessel, "BADBOT_KONFIG": ""}[n]
	}
}

func TestAbfrageBefehl(t *testing.T) {
	var anfragen []int
	srv := abfrageServer(t, &anfragen)
	defer srv.Close()
	var aus bytes.Buffer
	gesperrt, err := abfrageBefehl([]string{"192.0.2.7", "198.51.100.1", "AS64500", "unsinn"}, nil, &aus, umgebung(srv.URL, testSchluessel))
	if err != nil || !gesperrt {
		t.Fatalf("%v %v", gesperrt, err)
	}
	for _, want := range []string{"192.0.2.7\tgesperrt\tadresse bis 2026-11-29 11:00 UTC", "198.51.100.1\tfrei", "AS64500\tgesperrt\tas unbefristet", "unsinn\tfehler\tunlesbar"} {
		if !strings.Contains(aus.String(), want) {
			t.Fatalf("%q fehlt in:\n%s", want, aus.String())
		}
	}
	// Nichts gesperrt: Rueckgabe "frei".
	if g, err := abfrageBefehl([]string{"198.51.100.1"}, nil, &aus, umgebung(srv.URL, testSchluessel)); err != nil || g {
		t.Fatalf("frei: %v %v", g, err)
	}
	// Ziele von der Standardeingabe, mehr als 100: aufgeteilt.
	anfragen = nil
	var ein strings.Builder
	ein.WriteString("# Kommentar\n")
	for i := 0; i < 150; i++ {
		ein.WriteString("198.51.100.1\n")
	}
	aus.Reset()
	if _, err := abfrageBefehl([]string{"-json"}, strings.NewReader(ein.String()), &aus, umgebung(srv.URL, testSchluessel)); err != nil {
		t.Fatal(err)
	}
	var erg []protokoll.AbfrageErgebnis
	if err := json.Unmarshal(aus.Bytes(), &erg); err != nil || len(erg) != 150 || len(anfragen) != 2 || anfragen[0] != 100 || anfragen[1] != 50 {
		t.Fatalf("Aufteilung: %d Ergebnisse, Anfragen %v, %v", len(erg), anfragen, err)
	}
}

func TestAbfrageSchluesselPflicht(t *testing.T) {
	var anfragen []int
	srv := abfrageServer(t, &anfragen)
	defer srv.Close()
	var aus bytes.Buffer
	// Ein Collector-Schluessel taugt nicht -- und wird gar nicht erst geschickt.
	if _, err := abfrageBefehl([]string{"192.0.2.7"}, nil, &aus, umgebung(srv.URL, "bb1_collector")); err == nil || len(anfragen) != 0 {
		t.Fatalf("Collector-Schluessel: %v, %d Anfragen", err, len(anfragen))
	}
	if _, err := abfrageBefehl([]string{"192.0.2.7"}, nil, &aus, umgebung(srv.URL, "bbq_falsch")); err == nil || !strings.Contains(err.Error(), "im Portal") {
		t.Fatalf("falscher Schluessel: %v", err)
	}
	if _, err := abfrageBefehl([]string{"192.0.2.7"}, nil, &aus, umgebung("http://192.0.2.1", testSchluessel)); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http ohne lokale Adresse: %v", err)
	}
	if _, err := abfrageBefehl(nil, strings.NewReader(""), &aus, umgebung(srv.URL, testSchluessel)); err == nil {
		t.Fatal("ohne Ziel kein Fehler")
	}
}
