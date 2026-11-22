package sperre

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ausfuehren startet ein Firewall-Programm mit eingabe auf stdin. Die
// Ausgabe gehoert zur Fehlermeldung -- ohne sie ist ein abgelehnter
// Regelsatz nicht zu verstehen.
func ausfuehren(ctx context.Context, eingabe, programm string, argumente ...string) error {
	_, err := ausgabe(ctx, eingabe, programm, argumente...)
	return err
}

func ausgabe(ctx context.Context, eingabe, programm string, argumente ...string) (string, error) {
	ctx, abbruch := context.WithTimeout(ctx, 2*time.Minute)
	defer abbruch()
	cmd := exec.CommandContext(ctx, programm, argumente...)
	if eingabe != "" {
		cmd.Stdin = strings.NewReader(eingabe)
	}
	var aus bytes.Buffer
	cmd.Stdout, cmd.Stderr = &aus, &aus
	if err := cmd.Run(); err != nil {
		return aus.String(), fmt.Errorf("%s: %v: %s", programm, err, kuerzen(strings.TrimSpace(aus.String()), 2000))
	}
	return aus.String(), nil
}

func kuerzen(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + " …"
}
