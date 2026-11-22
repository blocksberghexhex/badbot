// Package sperre setzt die Sperrliste der Plattform in der Firewall des
// Systems um: nftables unter Linux, pf unter macOS, die Windows-Firewall
// unter Windows (je ein Umsetzer).
//
// Fuer alle gilt: nur ein eigener, klar benannter Bereich wird angefasst,
// nichts sonst. Eine Aenderung ersetzt den alten Stand erst, wenn der neue
// steht; ein Fehler leert die Sperren nie. Bestehende Verbindungen bleiben.
//
// Gesperrte Quellen erreichen die Koederports weiter -- sonst saehe der
// Collector genau die nicht mehr, die er melden soll.
package sperre

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blocksberghexhex/badbot/protokoll"
)

// Koeder sind die Ports, die offen bleiben.
type Koeder struct {
	TCP, UDP []int32
}

// Umsetzer schreibt einen Sperrstand in die Firewall eines Systems.
type Umsetzer interface {
	// Faehigkeit, wie sie der Plattform gemeldet wird, z. B. "sperren-nftables".
	Faehigkeit() string
	// Bereit: nil, wenn das noetige Programm vorhanden ist.
	Bereit() error
	// Anwenden ersetzt den bisherigen Stand vollstaendig -- oder gar nicht.
	Anwenden(ctx context.Context, netze []netip.Prefix, k Koeder) error
	// Entfernen raeumt den eigenen Bereich ab.
	Entfernen(ctx context.Context) error
}

// Sperre haelt den Stand der Sperrliste und wendet ihn an.
type Sperre struct {
	Trocken   bool           // nur protokollieren
	Ausnahmen []netip.Prefix // lokal nie sperren, z. B. das eigene Verwaltungsnetz
	Log       *slog.Logger
	U         Umsetzer

	mu         sync.Mutex
	netze      map[netip.Prefix]struct{}
	stand      string
	gueltigBis time.Time
	koeder     Koeder
	aktiv      bool   // eigener Bereich steht
	letzter    string // Fingerabdruck des zuletzt angewendeten Stands
}

// Neu baut eine leere Sperre mit dem Umsetzer des Systems.
func Neu(trocken bool, ausnahmen []netip.Prefix, log *slog.Logger) *Sperre {
	return &Sperre{Trocken: trocken, Ausnahmen: ausnahmen, Log: log, U: Vorgabe(""), netze: map[netip.Prefix]struct{}{}}
}

// Stand ist der zuletzt uebernommene Stand der Sperrliste ("" = keiner).
func (s *Sperre) Stand() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stand
}

// Anzahl der gesperrten Netze nach Abzug der Ausnahmen.
func (s *Sperre) Anzahl() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.wirksam())
}

// Uebernehmen fuehrt eine Sperrliste der Plattform in den Stand ein. Angewendet
// wird erst mit Anwenden.
func (s *Sperre) Uebernehmen(l *protokoll.Sperrliste) error {
	neu := map[netip.Prefix]struct{}{}
	if l.Art != "voll" {
		s.mu.Lock()
		for p := range s.netze {
			neu[p] = struct{}{}
		}
		s.mu.Unlock()
	}
	for _, n := range l.Entfernt {
		if p, err := netip.ParsePrefix(n); err == nil {
			delete(neu, p.Masked())
		}
	}
	for _, n := range l.Hinzu {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return fmt.Errorf("Sperrliste: %q ist kein Netz", n)
		}
		neu[p.Masked()] = struct{}{}
	}
	s.mu.Lock()
	s.netze, s.stand, s.gueltigBis = neu, l.Stand, l.GueltigBis
	s.mu.Unlock()
	return nil
}

// Leeren verwirft den Stand, etwa bei Sperrstufe "aus".
func (s *Sperre) Leeren() {
	s.mu.Lock()
	s.netze, s.stand, s.gueltigBis = map[netip.Prefix]struct{}{}, "", time.Time{}
	s.mu.Unlock()
}

// Anwenden schreibt den Stand in die Firewall. Ist gueltig_bis erreicht,
// werden die Sperren entfernt: Ohne Kontakt zur Plattform soll keine alte
// Liste unbegrenzt weiter sperren.
func (s *Sperre) Anwenden(ctx context.Context, jetzt time.Time, k Koeder) error {
	s.mu.Lock()
	if !s.gueltigBis.IsZero() && jetzt.After(s.gueltigBis) {
		s.Log.Warn("Sperrliste abgelaufen, Sperren entfernt", "gueltig_bis", s.gueltigBis)
		s.netze, s.stand, s.gueltigBis = map[netip.Prefix]struct{}{}, "", time.Time{}
	}
	netze := s.wirksam()
	s.koeder = k
	s.mu.Unlock()

	if len(netze) == 0 {
		return s.Entfernen(ctx)
	}
	abdruck := fingerabdruck(netze, k)
	s.mu.Lock()
	gleich := s.aktiv && abdruck == s.letzter
	s.mu.Unlock()
	if gleich {
		return nil
	}
	if s.Trocken || s.U == nil {
		s.Log.Info("Sperren (trocken, nicht angewendet)", "netze", len(netze))
	} else if err := s.U.Anwenden(ctx, netze, k); err != nil {
		return err
	}
	s.mu.Lock()
	s.aktiv, s.letzter = true, abdruck
	s.mu.Unlock()
	return nil
}

func fingerabdruck(netze []netip.Prefix, k Koeder) string {
	var b strings.Builder
	for _, p := range netze {
		b.WriteString(p.String() + ",")
	}
	b.WriteString("|" + elemente(k.TCP) + "|" + elemente(k.UDP))
	return b.String()
}

// Entfernen raeumt den eigenen Bereich in der Firewall ab.
func (s *Sperre) Entfernen(ctx context.Context) error {
	s.mu.Lock()
	aktiv := s.aktiv
	s.mu.Unlock()
	if !aktiv {
		return nil
	}
	if !s.Trocken && s.U != nil {
		if err := s.U.Entfernen(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.aktiv, s.letzter = false, ""
	s.mu.Unlock()
	return nil
}

// wirksam: Stand ohne Ausnahmen und ohne Netze, die in einem groesseren
// enthalten sind (ueberlappende Intervalle lehnt nft ab). Aufruf unter mu.
func (s *Sperre) wirksam() []netip.Prefix {
	var l []netip.Prefix
	for p := range s.netze {
		if !s.ausgenommen(p) {
			l = append(l, p)
		}
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].Addr() != l[j].Addr() {
			return l[i].Addr().Less(l[j].Addr())
		}
		return l[i].Bits() < l[j].Bits()
	})
	var aus []netip.Prefix
	for _, p := range l {
		if n := len(aus); n > 0 && aus[n-1].Addr().Is4() == p.Addr().Is4() && aus[n-1].Contains(p.Addr()) {
			continue
		}
		aus = append(aus, p)
	}
	return aus
}

// ausgenommen: ein Netz, das eine Ausnahme beruehrt, wird ganz ausgelassen.
// Lieber eine Luecke in der Sperre als den eigenen Zugang aussperren.
func (s *Sperre) ausgenommen(p netip.Prefix) bool {
	if p.Addr().IsLoopback() || p.Addr().IsUnspecified() || p.Bits() == 0 {
		return true
	}
	for _, a := range s.Ausnahmen {
		if a.Overlaps(p) {
			return true
		}
	}
	return false
}

func elemente(ports []int32) string {
	l := portListe(ports)
	if l == "" {
		return ""
	}
	return " elements = { " + l + " };"
}

// sortiert: aufsteigend, ohne Doppelte.
func sortiert(ports []int32) []int32 {
	l := append([]int32(nil), ports...)
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	var aus []int32
	for i, p := range l {
		if i > 0 && l[i-1] == p {
			continue
		}
		aus = append(aus, p)
	}
	return aus
}
