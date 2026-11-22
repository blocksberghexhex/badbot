package sim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// MQTT spielt einen Broker, der jede Verbindung als „nicht autorisiert“
// ablehnt (Port 1883). Gelesen wird nur das erste Paket (CONNECT): Kennung
// des Clients und, falls mitgeschickt, die Zugangsdaten. Abonniert oder
// veroeffentlicht wird nie etwas.
func MQTT() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		c, err := mqttConnect(v)
		if err != nil {
			if c == nil {
				return nil
			}
			return []puffer.Merkmal{Text("fehler", err.Error(), 64)}
		}
		probe := []puffer.Merkmal{
			Text("protokoll", fmt.Sprintf("%s %d", c.protokoll, c.stufe), 32),
			Text("client", c.client, 64),
		}
		if c.hatName || c.hatPasswort {
			probe = append(probe, Anmeldung(c.name, c.passwort))
		}
		// CONNACK „nicht autorisiert“ -- in MQTT 5 mit eigenem Code und
		// leerer Eigenschaftsliste.
		if c.stufe == 5 {
			v.Write([]byte{0x20, 0x03, 0x00, 0x87, 0x00})
		} else {
			v.Write([]byte{0x20, 0x02, 0x00, 0x05})
		}
		return probe
	}
}

type mqttVerbindung struct {
	protokoll              string
	stufe                  byte
	client, name, passwort string
	hatName, hatPasswort   bool
}

var errKeinConnect = errors.New("kein CONNECT")

// mqttConnect liest ein CONNECT-Paket. Jede Laenge wird gegen das Paket
// geprueft; was nicht passt, endet als Fehler, nie als Lesen ueber das Ende.
func mqttConnect(r io.Reader) (*mqttVerbindung, error) {
	var kopf [1]byte
	if _, err := io.ReadFull(r, kopf[:]); err != nil {
		return nil, err
	}
	c := &mqttVerbindung{}
	if kopf[0] != 0x10 {
		return c, errKeinConnect
	}
	laenge, err := mqttLaenge(r)
	if err != nil || laenge < 10 || laenge > 4096 {
		return c, errors.New("Laenge unbrauchbar")
	}
	p := make([]byte, laenge)
	if _, err := io.ReadFull(r, p); err != nil {
		return c, errors.New("Paket unvollstaendig")
	}
	l := &leser{b: p}
	c.protokoll = string(l.text())
	c.stufe = l.byte()
	flags := l.byte()
	l.n(2) // Keep-Alive
	if c.stufe == 5 {
		l.eigenschaften()
	}
	c.client = string(l.text())
	if flags&0x04 != 0 { // Will
		if c.stufe == 5 {
			l.eigenschaften()
		}
		l.text()
		l.text()
	}
	if flags&0x80 != 0 {
		c.name, c.hatName = string(l.text()), true
	}
	if flags&0x40 != 0 {
		c.passwort, c.hatPasswort = string(l.text()), true
	}
	if l.kaputt || (c.protokoll != "MQTT" && c.protokoll != "MQIsdp") {
		return c, errors.New("CONNECT unbrauchbar")
	}
	return c, nil
}

// mqttLaenge: variable Laenge, hoechstens vier Bytes.
func mqttLaenge(r io.Reader) (int, error) {
	var wert, faktor int = 0, 1
	var b [1]byte
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		wert += int(b[0]&0x7f) * faktor
		if b[0]&0x80 == 0 {
			return wert, nil
		}
		faktor *= 128
	}
	return 0, errors.New("Laenge zu lang")
}

// leser liest aus einem Paket; ueber das Ende hinaus liefert er leer und
// merkt sich den Fehler.
type leser struct {
	b      []byte
	kaputt bool
}

func (l *leser) n(k int) []byte {
	if l.kaputt || k < 0 || k > len(l.b) {
		l.kaputt = true
		return nil
	}
	x := l.b[:k]
	l.b = l.b[k:]
	return x
}

func (l *leser) byte() byte {
	x := l.n(1)
	if x == nil {
		return 0
	}
	return x[0]
}

func (l *leser) text() []byte {
	x := l.n(2)
	if x == nil {
		return nil
	}
	return l.n(int(binary.BigEndian.Uint16(x)))
}

// eigenschaften ueberspringt die Eigenschaftsliste von MQTT 5.
func (l *leser) eigenschaften() {
	wert, faktor := 0, 1
	for i := 0; ; i++ {
		if i == 4 {
			l.kaputt = true
			return
		}
		b := l.byte()
		wert += int(b&0x7f) * faktor
		if b&0x80 == 0 {
			break
		}
		faktor *= 128
	}
	l.n(wert)
}
