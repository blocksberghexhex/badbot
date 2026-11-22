package sim

import (
	"encoding/binary"
	"io"
	"strconv"
	"strings"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// DNS beantwortet jede Anfrage mit REFUSED und wiederholt nur die Frage.
// Nie rekursiv, nie ein Antwortteil -- die Antwort ist hoechstens so lang wie
// die Anfrage, also kein Verstaerker.
func DNS() lauscher.UDPBehandler {
	return func(paket []byte) ([]byte, []puffer.Merkmal) {
		return dnsAntwort(paket)
	}
}

// DNSTCP: dieselbe Antwort ueber TCP (Laengenpraefix). Hier ist die Quelle belegt.
func DNSTCP() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		var probe []puffer.Merkmal
		for i := 0; i < 3; i++ {
			var l [2]byte
			if _, err := io.ReadFull(v, l[:]); err != nil {
				break
			}
			n := int(binary.BigEndian.Uint16(l[:]))
			if n < 12 || n > 4096 {
				break
			}
			paket := make([]byte, n)
			if _, err := io.ReadFull(v, paket); err != nil {
				break
			}
			antwort, p := dnsAntwort(paket)
			probe = append(probe, p...)
			if antwort == nil {
				break
			}
			binary.BigEndian.PutUint16(l[:], uint16(len(antwort)))
			v.Write(append(l[:], antwort...))
		}
		return probe
	}
}

var dnsTypen = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 48: "DNSKEY", 65: "HTTPS", 252: "AXFR", 255: "ANY"}

// dnsAntwort liest Kopf und erste Frage. Was sich nicht lesen laesst, bekommt
// keine Antwort.
func dnsAntwort(p []byte) ([]byte, []puffer.Merkmal) {
	if len(p) < 12 || p[2]&0x80 != 0 { // zu kurz oder selbst eine Antwort
		return nil, nil
	}
	if binary.BigEndian.Uint16(p[4:6]) < 1 {
		return nil, nil
	}
	i := 12
	var name []string
	for {
		if i >= len(p) {
			return nil, nil
		}
		l := int(p[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(p) || len(name) > 127 { // auch: keine Zeiger in der Frage
			return nil, nil
		}
		name = append(name, string(p[i:i+l]))
		i += l
	}
	if i+4 > len(p) {
		return nil, nil
	}
	typ := binary.BigEndian.Uint16(p[i : i+2])
	frageEnde := i + 4

	t, ok := dnsTypen[typ]
	if !ok {
		t = strconv.Itoa(int(typ))
	}
	probe := []puffer.Merkmal{
		Text("name", strings.ToLower(strings.Join(name, ".")), 253),
		{Feld: "typ", Wert: t},
		{Feld: "rd", Wert: p[2]&0x01 != 0},
	}
	if edns := ednsGroesse(p, frageEnde); edns > 0 {
		probe = append(probe, puffer.Merkmal{Feld: "edns", Wert: edns})
	}

	a := make([]byte, frageEnde)
	copy(a, p[:frageEnde])
	a[2] = 0x80 | p[2]&0x79 // QR, Opcode und RD uebernommen, AA/TC aus
	a[3] = 5                // RA aus, REFUSED
	binary.BigEndian.PutUint16(a[4:6], 1)
	clear(a[6:12])
	return a, probe
}

// ednsGroesse sucht im Zusatzteil einen OPT-Eintrag direkt nach der Frage.
func ednsGroesse(p []byte, i int) int {
	if binary.BigEndian.Uint16(p[4:6]) != 1 || binary.BigEndian.Uint16(p[10:12]) < 1 {
		return 0
	}
	// OPT: Name ist die Wurzel (0), Typ 41, Klasse = Puffergroesse.
	if i+5 > len(p) || p[i] != 0 || binary.BigEndian.Uint16(p[i+1:i+3]) != 41 {
		return 0
	}
	return int(binary.BigEndian.Uint16(p[i+3 : i+5]))
}
