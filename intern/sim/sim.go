// Package sim enthaelt die Simulationen des Collectors.
//
// Jede Simulation spielt einen festen Ablauf ab. Sie gewaehrt nie eine
// Anmeldung, fuehrt nichts aus, laedt nichts nach, setzt nichts in Abfragen
// ein und baut keine Verbindung zur Gegenstelle oder zu Dritten auf.
// Passwoerter werden nur als SHA-256 mit Laenge festgehalten.
package sim

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// Erscheinung: Banner und Versionsangaben, einmal gewaehlt und dann
// beibehalten -- ein Banner, das je Verbindung wechselt, verraet die Falle.
type Erscheinung struct {
	SSH   string `json:"ssh"`
	Nginx string `json:"nginx"`
	SMTP  string `json:"smtp"`
	FTP   string `json:"ftp"`
	MySQL string `json:"mysql"`
	Redis string `json:"redis"`
	// Seit Phase 16; aeltere Dateien bekommen sie beim Laden nachgetragen.
	Docker  string `json:"docker,omitempty"`
	Elastic string `json:"elastic,omitempty"`
}

// Plausible, veraltete Versionen.
var auswahl = struct{ ssh, nginx, smtp, ftp, mysql, redis, docker, elastic []string }{
	ssh:     []string{"SSH-2.0-OpenSSH_7.4", "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"},
	nginx:   []string{"nginx/1.14.0", "nginx/1.16.1", "nginx/1.18.0", "nginx/1.20.1"},
	smtp:    []string{"ESMTP Postfix (Ubuntu)", "ESMTP Postfix (Debian/GNU)", "ESMTP Exim 4.92"},
	ftp:     []string{"(vsFTPd 3.0.3)", "(vsFTPd 3.0.2)", "ProFTPD 1.3.5 Server"},
	mysql:   []string{"5.7.33-0ubuntu0.18.04.1", "5.7.36", "5.6.51", "8.0.23"},
	redis:   []string{"5.0.7", "6.0.9", "4.0.9"},
	docker:  []string{"19.03.13", "20.10.7", "20.10.12"},
	elastic: []string{"6.8.23", "7.10.2", "7.17.9"},
}

func waehle(l []string) string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(l))))
	if err != nil {
		return l[0]
	}
	return l[n.Int64()]
}

// ErscheinungLaden liest die gewaehlte Erscheinung oder waehlt einmal und speichert sie.
func ErscheinungLaden(pfad string) (Erscheinung, error) {
	var e Erscheinung
	if roh, err := os.ReadFile(pfad); err == nil {
		if err := json.Unmarshal(roh, &e); err == nil && e.SSH != "" {
			// Nur Fehlendes ergaenzen; was schon gewaehlt war, bleibt.
			if e.Docker != "" && e.Elastic != "" {
				return e, nil
			}
			if e.Docker == "" {
				e.Docker = waehle(auswahl.docker)
			}
			if e.Elastic == "" {
				e.Elastic = waehle(auswahl.elastic)
			}
			roh, _ := json.Marshal(e)
			return e, os.WriteFile(pfad, roh, 0o600)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return e, err
	}
	e = Erscheinung{SSH: waehle(auswahl.ssh), Nginx: waehle(auswahl.nginx), SMTP: waehle(auswahl.smtp),
		FTP: waehle(auswahl.ftp), MySQL: waehle(auswahl.mysql), Redis: waehle(auswahl.redis),
		Docker: waehle(auswahl.docker), Elastic: waehle(auswahl.elastic)}
	roh, _ := json.Marshal(e)
	return e, os.WriteFile(pfad, roh, 0o600)
}

// Anmeldung ist ein Anmeldeversuch fuer die Stichprobe.
func Anmeldung(name, passwort string) puffer.Merkmal {
	m := map[string]any{"name": kurz(name, 64)}
	if passwort != "" {
		s := sha256.Sum256([]byte(passwort))
		m["passwort_sha256"] = hex.EncodeToString(s[:])
		m["passwort_laenge"] = len(passwort)
	}
	return puffer.Merkmal{Feld: "anmeldungen", Wert: m}
}

// Text ist ein Merkmal mit gekuerztem, bereinigtem Text.
func Text(feld, wert string, n int) puffer.Merkmal {
	return puffer.Merkmal{Feld: feld, Wert: kurz(wert, n)}
}

// kurz kuerzt auf n Zeichen und ersetzt Steuerzeichen -- die Plattform zeigt
// Stichproben an, und erfasste Eingaben sind feindlich.
func kurz(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// zeile liest eine Zeile (bis \n), hoechstens n Bytes. Ohne Zeilenende bis
// zur Grenze gilt das Gelesene als Zeile.
func zeile(r *bufio.Reader, n int) (string, error) {
	var b strings.Builder
	for b.Len() < n {
		c, err := r.ReadByte()
		if err != nil {
			if b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
		if c == '\n' {
			break
		}
		b.WriteByte(c)
	}
	return strings.TrimRight(b.String(), "\r"), nil
}
