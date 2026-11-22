//go:build !windows

package main

import "errors"

// Unter Linux und macOS startet systemd bzw. launchd den Collector als
// gewoehnliches Programm und beendet ihn mit SIGTERM.
func alsDienst() (bool, error) { return false, nil }

func dienstLaufen() error { return nil }

func dienstBefehl([]string) error {
	return errors.New("\"dienst\" gibt es nur unter Windows; unter Linux systemd, unter macOS launchd (siehe README)")
}
