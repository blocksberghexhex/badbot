// Package protokoll beschreibt die Collector-API von badbot.icu -- die
// oeffentliche Schnittstelle zwischen Collector und Plattform.
//
// Alle Zeiten in UTC, Adressen in kanonischer Schreibweise. Unbekannte Felder
// werden auf beiden Seiten ignoriert; eine inkompatible Aenderung bekommt
// einen neuen Pfad (/v2/).
package protokoll

import (
	"encoding/json"
	"time"
)

// Version der Schnittstelle im Pfad.
const Pfad = "/v1"

// Lebenszeichen schickt der Collector im Takt der Konfiguration.
type Lebenszeichen struct {
	Version      string    `json:"version"`
	Plattform    string    `json:"plattform"`
	Faehigkeiten []string  `json:"faehigkeiten"`
	Uhrzeit      time.Time `json:"uhrzeit"`
	Puffer       Puffer    `json:"puffer"`
}

// Puffer beschreibt den Stand des lokalen Puffers.
type Puffer struct {
	Datensaetze        int   `json:"datensaetze"`
	VerworfenSeitStart int64 `json:"verworfen_seit_start"`
}

// LebenszeichenAntwort sagt dem Collector, ob es Neues gibt.
type LebenszeichenAntwort struct {
	Uhrzeit            time.Time `json:"uhrzeit"`
	KonfigurationStand string    `json:"konfiguration_stand"`
	SperrlisteStand    string    `json:"sperrliste_stand"`
	AktuelleVersion    string    `json:"aktuelle_version,omitempty"`
	Hinweise           []string  `json:"hinweise"`
}

// Konfiguration kommt aus dem Panel.
type Konfiguration struct {
	Stand           string           `json:"stand"`
	TaktSekunden    int              `json:"takt_sekunden"`
	FensterSekunden int              `json:"fenster_sekunden"`
	StichprobeBytes int              `json:"stichprobe_bytes"`
	Simulationen    []SimulationSoll `json:"simulationen"`
	Sperren         struct {
		Stufe string `json:"stufe"`
	} `json:"sperren"`
	Vorschaltnetze []string `json:"vertrauenswuerdige_vorschaltnetze"`
}

// SimulationSoll ist eine Simulation, wie das Panel sie eingestellt hat.
type SimulationSoll struct {
	Name  string  `json:"name"`
	Ports []int32 `json:"ports"`
	Aktiv bool    `json:"aktiv"`
}

// Ist meldet, was der Collector tatsaechlich anwendet.
type Ist struct {
	Stand        string          `json:"stand"`
	Simulationen []SimulationIst `json:"simulationen"`
}

// SimulationIst ist eine Simulation, wie sie tatsaechlich laeuft.
type SimulationIst struct {
	Name   string  `json:"name"`
	Aktiv  bool    `json:"aktiv"`
	Ports  []int32 `json:"ports"`
	Fehler string  `json:"fehler,omitempty"`
}

// Stapel ist eine Meldung vorverdichteter Datensaetze.
type Stapel struct {
	Stapel      string      `json:"stapel"` // zufaellige UUID; bei Wiederholung dieselbe
	Datensaetze []Datensatz `json:"datensaetze"`
}

// Datensatz: eine Quelladresse an einer Simulation in einem Zeitfenster.
type Datensatz struct {
	Fenster            time.Time       `json:"fenster"`
	Quelle             string          `json:"quelle"`
	Simulation         string          `json:"simulation"`
	Anzahl             int64           `json:"anzahl"`
	Erster             time.Time       `json:"erster"`
	Letzter            time.Time       `json:"letzter"`
	Ports              []int32         `json:"ports"`
	PortsGekuerzt      bool            `json:"ports_gekuerzt,omitempty"`
	Stichprobe         json.RawMessage `json:"stichprobe,omitempty"`
	UeberVorschaltnetz bool            `json:"ueber_vorschaltnetz,omitempty"`
	VerbindungVon      string          `json:"verbindung_von,omitempty"`
}

// StapelAntwort sagt, was angenommen wurde.
type StapelAntwort struct {
	Angenommen int            `json:"angenommen"`
	Verworfen  int            `json:"verworfen"`
	Gruende    map[string]int `json:"gruende"`
	Hinweise   []string       `json:"hinweise,omitempty"`
}

// Sperrliste: vollstaendig oder als Aenderungen seit einem Stand.
type Sperrliste struct {
	Stand      string    `json:"stand"`
	Art        string    `json:"art"` // "voll" oder "aenderungen"
	GueltigBis time.Time `json:"gueltig_bis"`
	Hinzu      []string  `json:"hinzu"`
	Entfernt   []string  `json:"entfernt"`
}

// Fehler ist der Koerper jeder Fehlerantwort.
type Fehler struct {
	Fehler string `json:"fehler"`
	Text   string `json:"text"`
}

// Grenzen des Protokolls.
const (
	HoechstPorts  = 64
	HoechstSaetze = 5000
	HoechstBytes  = 1 << 20
)
