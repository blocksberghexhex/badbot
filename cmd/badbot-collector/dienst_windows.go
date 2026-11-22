//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/blocksberghexhex/badbot/intern/einstellung"
	"github.com/blocksberghexhex/badbot/intern/sperre"
)

const dienstName = "badbot-collector"

func alsDienst() (bool, error) { return svc.IsWindowsService() }

func dienstLaufen() error { return svc.Run(dienstName, dienstHandler{}) }

type dienstHandler struct{}

// Execute meldet dem Dienststeuerungs-Manager den Zustand. Endet der
// Collector von selbst, meldet der Dienst einen Fehler -- dann greift die
// bei der Einrichtung gesetzte Wiederholung.
func (dienstHandler) Execute(_ []string, anfragen <-chan svc.ChangeRequest, zustand chan<- svc.Status) (bool, uint32) {
	zustand <- svc.Status{State: svc.StartPending}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	fertig := make(chan error, 1)
	go func() { fertig <- laufen(ctx, true) }()
	zustand <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case a := <-anfragen:
			switch a.Cmd {
			case svc.Interrogate:
				zustand <- a.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Das Abraeumen der Sperren braucht einen Moment.
				zustand <- svc.Status{State: svc.StopPending, WaitHint: 60000}
				stop()
				if err := <-fertig; err != nil {
					festhalten(err)
					return true, 1
				}
				return false, 0
			}
		case err := <-fertig:
			if err != nil {
				festhalten(err)
				return true, 1
			}
			return true, 2
		}
	}
}

// festhalten: Scheitert der Start, etwa ohne Schluessel, gibt es noch keine
// Logdatei -- der Grund muss trotzdem irgendwo stehen.
func festhalten(err error) {
	v := einstellung.VorgabenFuer("windows", os.Getenv)
	f, ferr := os.OpenFile(v.Daten+`\collector.log`, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if ferr != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "time=%s level=ERROR msg=\"Collector beendet\" fehler=%q\n", time.Now().Format(time.RFC3339), err.Error())
}

// dienstBefehl: "installieren" und "entfernen", als Administrator.
func dienstBefehl(args []string) error {
	if len(args) != 1 {
		return errors.New("Aufruf: badbot-collector dienst installieren|entfernen")
	}
	switch args[0] {
	case "installieren":
		return installieren()
	case "entfernen":
		return entfernen()
	}
	return fmt.Errorf("unbekannt: %q", args[0])
}

func installieren() error {
	programm, err := os.Executable()
	if err != nil {
		return err
	}
	v := einstellung.VorgabenFuer("windows", os.Getenv)
	if err := os.MkdirAll(v.Daten, 0o700); err != nil {
		return err
	}
	// Datenverzeichnis nur fuer SYSTEM und Administratoren: Dort liegt der
	// Schluessel, und dort entstehen die Skripte fuer die Firewall.
	if aus, err := exec.Command("icacls", v.Daten, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput(); err != nil {
		return fmt.Errorf("Rechte des Datenverzeichnisses: %v: %s", err, aus)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(dienstName); err == nil {
		s.Close()
		return errors.New("Dienst ist schon eingerichtet")
	}
	s, err := m.CreateService(dienstName, programm, mgr.Config{
		DisplayName:      "badbot-collector",
		Description:      "Collector von badbot.icu: Simulationen, Meldungen, Sperren",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
	})
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
	}, 24*60*60); err != nil {
		return err
	}
	fw := &sperre.WindowsFirewall{Verzeichnis: v.Daten}
	if err := fw.KoederErlauben(context.Background(), programm); err != nil {
		return err
	}
	fmt.Printf("Dienst eingerichtet. API-Schluessel in %s eintragen, dann:\n  Start-Service %s\n", v.Schluessel, dienstName)
	return nil
}

func entfernen() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(dienstName)
	if err != nil {
		return fmt.Errorf("Dienst nicht gefunden: %w", err)
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		for i := 0; i < 90; i++ {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(time.Second)
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	v := einstellung.VorgabenFuer("windows", os.Getenv)
	fw := &sperre.WindowsFirewall{Verzeichnis: v.Daten}
	if err := fw.AllesEntfernen(context.Background()); err != nil {
		return err
	}
	fmt.Println("Dienst und Firewall-Regeln entfernt. Das Datenverzeichnis bleibt:", v.Daten)
	return nil
}
