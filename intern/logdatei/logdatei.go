// Package logdatei schreibt das Log in eine Datei, die nicht unbegrenzt
// waechst. Unter Linux uebernimmt das journald; als Windows-Dienst und als
// launchd-Daemon gibt es niemanden, der das Log abholt.
package logdatei

import (
	"os"
	"sync"
)

// Datei ist eine Logdatei mit einer Vorgaengerin: Erreicht sie die Grenze,
// wird sie zu <name>.1 und eine neue beginnt.
type Datei struct {
	pfad    string
	max     int64
	mu      sync.Mutex
	f       *os.File
	groesse int64
}

// Oeffnen haengt an eine bestehende Datei an.
func Oeffnen(pfad string, max int64) (*Datei, error) {
	d := &Datei{pfad: pfad, max: max}
	if err := d.oeffnen(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Datei) oeffnen() error {
	f, err := os.OpenFile(d.pfad, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	d.f, d.groesse = f, st.Size()
	return nil
}

func (d *Datei) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.groesse > 0 && d.groesse+int64(len(b)) > d.max {
		d.f.Close()
		// Unter Windows ueberschreibt Umbenennen kein bestehendes Ziel.
		os.Remove(d.pfad + ".1")
		os.Rename(d.pfad, d.pfad+".1")
		if err := d.oeffnen(); err != nil {
			return 0, err
		}
	}
	n, err := d.f.Write(b)
	d.groesse += int64(n)
	return n, err
}

// Close schliesst die Datei.
func (d *Datei) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.f.Close()
}
