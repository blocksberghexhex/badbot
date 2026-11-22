package sim

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// Telnet: Login-Aufforderung, immer "Login incorrect", nach drei Versuchen Schluss.
func Telnet() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		r := bufio.NewReader(&ohneIAC{r: v})
		var probe []puffer.Merkmal
		for i := 0; i < 3; i++ {
			fmt.Fprint(v, "\r\nlogin: ")
			name, err := zeile(r, 128)
			if err != nil {
				break
			}
			fmt.Fprint(v, "Password: ")
			pw, err := zeile(r, 128)
			probe = append(probe, Anmeldung(strings.TrimSpace(name), pw))
			if err != nil {
				break
			}
			fmt.Fprint(v, "\r\nLogin incorrect\r\n")
		}
		return probe
	}
}

// ohneIAC entfernt Telnet-Optionsverhandlung (IAC ...) aus dem Strom. Wir
// verhandeln nichts; die Bytes sollen nur nicht im Benutzernamen landen.
type ohneIAC struct {
	r       interface{ Read([]byte) (int, error) }
	zustand int
}

func (o *ohneIAC) Read(b []byte) (int, error) {
	roh := make([]byte, len(b))
	n, err := o.r.Read(roh)
	k := 0
	for _, c := range roh[:n] {
		switch o.zustand {
		case 0:
			if c == 255 {
				o.zustand = 1
				continue
			}
			b[k] = c
			k++
		case 1: // nach IAC: Befehl
			switch {
			case c >= 251 && c <= 254: // WILL WONT DO DONT + Option
				o.zustand = 2
			case c == 250: // SB ... IAC SE
				o.zustand = 3
			default:
				o.zustand = 0
			}
		case 2:
			o.zustand = 0
		case 3:
			if c == 255 {
				o.zustand = 4
			}
		case 4:
			o.zustand = 3
			if c == 240 {
				o.zustand = 0
			}
		}
	}
	return k, err
}

// SMTP: Banner, EHLO, MAIL FROM/RCPT TO angenommen, DATA abgelehnt, AUTH
// schlaegt fehl. Nie weitergeleitet, kein Mailinhalt gespeichert.
func SMTP(banner string) lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		r := bufio.NewReader(v)
		var probe []puffer.Merkmal
		empfaenger := 0
		fmt.Fprintf(v, "220 mail %s\r\n", banner)
		for i := 0; i < 30; i++ {
			l, err := zeile(r, 512)
			if err != nil {
				break
			}
			befehl, rest, _ := strings.Cut(l, " ")
			switch strings.ToUpper(befehl) {
			case "EHLO", "HELO":
				probe = append(probe, Text("helo", rest, 100))
				fmt.Fprint(v, "250-mail\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
			case "MAIL":
				probe = append(probe, Text("absender", rest, 120))
				fmt.Fprint(v, "250 2.1.0 Ok\r\n")
			case "RCPT":
				if empfaenger < 5 {
					probe = append(probe, Text("empfaenger", rest, 120))
				}
				empfaenger++
				fmt.Fprint(v, "250 2.1.5 Ok\r\n")
			case "DATA":
				// Die Absicht ist erkennbar, der Inhalt wird nicht angenommen.
				fmt.Fprint(v, "554 5.7.1 Relay access denied\r\n")
			case "AUTH":
				name := smtpAuthName(rest)
				probe = append(probe, Anmeldung(name, ""))
				fmt.Fprint(v, "535 5.7.8 Error: authentication failed\r\n")
			case "QUIT":
				fmt.Fprint(v, "221 2.0.0 Bye\r\n")
				return probe
			case "RSET", "NOOP":
				fmt.Fprint(v, "250 2.0.0 Ok\r\n")
			default:
				fmt.Fprint(v, "502 5.5.2 Error: command not recognized\r\n")
			}
		}
		return probe
	}
}

// smtpAuthName: Bei AUTH PLAIN steht der Name im Klartext (base64); er wird
// nicht dekodiert -- wir speichern nur, welches Verfahren versucht wurde.
func smtpAuthName(rest string) string {
	verfahren, _, _ := strings.Cut(rest, " ")
	return "auth:" + strings.ToUpper(verfahren)
}

// FTP: Banner, USER/PASS immer 530, nach drei Versuchen Schluss.
func FTP(banner string) lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		r := bufio.NewReader(v)
		var probe []puffer.Merkmal
		var name string
		fehl := 0
		fmt.Fprintf(v, "220 %s\r\n", banner)
		for i := 0; i < 20 && fehl < 3; i++ {
			l, err := zeile(r, 512)
			if err != nil {
				break
			}
			befehl, rest, _ := strings.Cut(l, " ")
			switch strings.ToUpper(befehl) {
			case "USER":
				name = rest
				fmt.Fprint(v, "331 Please specify the password.\r\n")
			case "PASS":
				probe = append(probe, Anmeldung(name, rest))
				fehl++
				fmt.Fprint(v, "530 Login incorrect.\r\n")
			case "QUIT":
				fmt.Fprint(v, "221 Goodbye.\r\n")
				return probe
			default:
				fmt.Fprint(v, "530 Please login with USER and PASS.\r\n")
			}
		}
		return probe
	}
}
