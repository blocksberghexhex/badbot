package sim

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// MySQL: Begruessung, Anmeldung lesen, Fehler 1045. Das Passwort kommt nur
// als Challenge-Antwort an und laesst sich nicht festhalten -- gewollt.
func MySQL(version string) lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		salz := make([]byte, 20)
		rand.Read(salz)
		for i := range salz { // keine Nullbytes im Salz, wie beim Original
			salz[i] = salz[i]%94 + 33
		}
		var g bytes.Buffer
		g.WriteByte(10)
		g.WriteString(version)
		g.WriteByte(0)
		var id [4]byte
		rand.Read(id[:])
		id[3] &= 0x0f
		g.Write(id[:])
		g.Write(salz[:8])
		g.WriteByte(0)
		// Faehigkeiten ohne SSL: Clients mit "SSL bevorzugt" melden sich dann ohne an.
		g.Write([]byte{0x0f, 0xa2, 0x21, 0x02, 0x00, 0x38, 0x00, 21})
		g.Write(make([]byte, 10))
		g.Write(salz[8:])
		g.WriteByte(0)
		g.WriteString("mysql_native_password\x00")
		if mysqlSchreiben(v, 0, g.Bytes()) != nil {
			return nil
		}
		seq, p, err := mysqlLesen(v)
		if err != nil || len(p) < 32 {
			return nil
		}
		flags := binary.LittleEndian.Uint32(p[0:4])
		probe := []puffer.Merkmal{{Feld: "client_flags", Wert: fmt.Sprintf("%08x", flags)}}
		rest := p[32:]
		name, rest, _ := bytes.Cut(rest, []byte{0})
		probe = append(probe, Anmeldung(string(name), ""))
		// Auth-Antwort ueberspringen, dann Datenbank und Plugin.
		if len(rest) > 0 {
			var n int
			if flags&0x200000 != 0 || flags&0x8000 != 0 {
				n = int(rest[0])
				rest = rest[1:]
			} else if n = bytes.IndexByte(rest, 0); n >= 0 {
				n++ // das Nullbyte gehoert zur Auth-Antwort
			}
			if n >= 0 && n <= len(rest) {
				rest = rest[n:]
				if flags&0x8 != 0 {
					var db []byte
					db, rest, _ = bytes.Cut(rest, []byte{0})
					if len(db) > 0 {
						probe = append(probe, Text("datenbank", string(db), 64))
					}
				}
				if flags&0x80000 != 0 {
					plugin, _, _ := bytes.Cut(rest, []byte{0})
					probe = append(probe, Text("plugin", string(plugin), 64))
				}
			}
		}
		mysqlSchreiben(v, seq+1, append([]byte{0xff, 0x15, 0x04}, "#28000Access denied for user (using password: YES)"...))
		return probe
	}
}

func mysqlSchreiben(w io.Writer, seq byte, p []byte) error {
	k := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}
	_, err := w.Write(append(k, p...))
	return err
}

func mysqlLesen(r io.Reader) (byte, []byte, error) {
	var k [4]byte
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return 0, nil, err
	}
	n := int(k[0]) | int(k[1])<<8 | int(k[2])<<16
	if n > 4096 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return k[3], p, err
}

// Postgres: Startpaket lesen, SSL ablehnen, Klartextpasswort anfordern,
// Fehler 28P01.
func Postgres() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		var start []byte
		for i := 0; i < 3; i++ {
			var k [8]byte
			if _, err := io.ReadFull(v, k[:]); err != nil {
				return nil
			}
			n := int(binary.BigEndian.Uint32(k[0:4]))
			code := binary.BigEndian.Uint32(k[4:8])
			if n < 8 || n > 4096 {
				return nil
			}
			rest := make([]byte, n-8)
			if _, err := io.ReadFull(v, rest); err != nil {
				return nil
			}
			switch code {
			case 80877103, 80877104: // SSL- oder GSS-Verschluesselung angefragt
				v.Write([]byte{'N'})
				continue
			case 196608: // Protokoll 3.0
				start = rest
			}
			break
		}
		if start == nil {
			return nil
		}
		param := map[string]string{}
		teile := bytes.Split(start, []byte{0})
		for i := 0; i+1 < len(teile); i += 2 {
			param[string(teile[i])] = string(teile[i+1])
		}
		probe := []puffer.Merkmal{}
		if db := param["database"]; db != "" {
			probe = append(probe, Text("datenbank", db, 64))
		}
		if app := param["application_name"]; app != "" {
			probe = append(probe, Text("anwendung", app, 64))
		}
		v.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})
		pw := ""
		var k [5]byte
		if _, err := io.ReadFull(v, k[:]); err == nil && k[0] == 'p' {
			n := int(binary.BigEndian.Uint32(k[1:5]))
			if n >= 4 && n <= 1024 {
				b := make([]byte, n-4)
				if _, err := io.ReadFull(v, b); err == nil {
					pw = string(bytes.TrimRight(b, "\x00"))
				}
			}
		}
		probe = append(probe, Anmeldung(param["user"], pw))
		var e bytes.Buffer
		e.WriteString("SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")
		k2 := []byte{'E', 0, 0, 0, 0}
		binary.BigEndian.PutUint32(k2[1:], uint32(e.Len()+4))
		v.Write(append(k2, e.Bytes()...))
		return probe
	}
}

// Redis: jedes Kommando bekommt NOAUTH, AUTH schlaegt fehl. Ausgefuehrt
// wird nichts; die Kommandonamen zeigen, was versucht wurde.
func Redis() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		r := bufio.NewReader(v)
		var probe []puffer.Merkmal
		for i := 0; i < 20; i++ {
			teile, err := respLesen(r)
			if err != nil || len(teile) == 0 {
				break
			}
			befehl := strings.ToUpper(teile[0])
			switch befehl {
			case "AUTH":
				name, pw := "default", ""
				if len(teile) == 2 {
					pw = teile[1]
				} else if len(teile) >= 3 {
					name, pw = teile[1], teile[2]
				}
				probe = append(probe, Anmeldung(name, pw))
				io.WriteString(v, "-WRONGPASS invalid username-password pair or user is disabled.\r\n")
				continue
			case "QUIT":
				io.WriteString(v, "+OK\r\n")
				return probe
			}
			if i < 10 {
				k := befehl
				if len(teile) > 1 {
					k += " " + teile[1]
				}
				probe = append(probe, Text("kommandos", k, 64))
			}
			io.WriteString(v, "-NOAUTH Authentication required.\r\n")
		}
		return probe
	}
}

// respLesen liest ein Kommando im RESP-Format oder als Zeile.
func respLesen(r *bufio.Reader) ([]string, error) {
	l, err := zeile(r, 512)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(l, "*") {
		return strings.Fields(l), nil
	}
	n, err := strconv.Atoi(l[1:])
	if err != nil || n < 0 || n > 64 {
		return nil, io.ErrUnexpectedEOF
	}
	teile := make([]string, 0, n)
	for i := 0; i < n; i++ {
		k, err := zeile(r, 32)
		if err != nil || !strings.HasPrefix(k, "$") {
			return nil, io.ErrUnexpectedEOF
		}
		m, err := strconv.Atoi(k[1:])
		if err != nil || m < 0 || m > 4096 {
			return nil, io.ErrUnexpectedEOF
		}
		b := make([]byte, m+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		teile = append(teile, string(b[:m]))
	}
	return teile, nil
}

// RDP: Verbindungsanfrage lesen, trennen.
func RDP() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		var k [4]byte
		if _, err := io.ReadFull(v, k[:]); err != nil || k[0] != 3 {
			return nil
		}
		n := int(binary.BigEndian.Uint16(k[2:4]))
		if n < 11 || n > 1024 {
			return nil
		}
		p := make([]byte, n-4)
		if _, err := io.ReadFull(v, p); err != nil || p[1]&0xf0 != 0xe0 {
			return nil
		}
		rest := p[7:]
		var probe []puffer.Merkmal
		if c, ok := bytes.CutPrefix(rest, []byte("Cookie: mstshash=")); ok {
			name, danach, _ := bytes.Cut(c, []byte("\r\n"))
			probe = append(probe, Anmeldung(string(name), ""))
			rest = danach
		}
		if len(rest) >= 8 && rest[0] == 1 {
			probe = append(probe, puffer.Merkmal{Feld: "protokolle", Wert: binary.LittleEndian.Uint32(rest[4:8])})
		}
		return probe
	}
}

// VNC: RFB-Version, Sicherheitstyp VNC-Anmeldung, die immer fehlschlaegt.
func VNC() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		io.WriteString(v, "RFB 003.008\n")
		var cv [12]byte
		if _, err := io.ReadFull(v, cv[:]); err != nil {
			return nil
		}
		probe := []puffer.Merkmal{Text("client", strings.TrimSpace(string(cv[:])), 12)}
		alt := string(cv[:11]) == "RFB 003.003"
		if alt {
			v.Write([]byte{0, 0, 0, 2})
		} else {
			v.Write([]byte{1, 2})
			var wahl [1]byte
			if _, err := io.ReadFull(v, wahl[:]); err != nil {
				return probe
			}
			probe = append(probe, puffer.Merkmal{Feld: "sicherheitstyp", Wert: int(wahl[0])})
		}
		herausforderung := make([]byte, 16)
		rand.Read(herausforderung)
		v.Write(herausforderung)
		var antwort [16]byte
		if _, err := io.ReadFull(v, antwort[:]); err != nil {
			return probe
		}
		probe = append(probe, Anmeldung("", ""))
		if alt {
			v.Write([]byte{0, 0, 0, 1})
		} else {
			grund := "Authentication failed"
			v.Write(append([]byte{0, 0, 0, 1, 0, 0, 0, byte(len(grund))}, grund...))
		}
		return probe
	}
}
