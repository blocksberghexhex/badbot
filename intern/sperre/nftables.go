package sperre

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// Tabelle ist der Name der eigenen nftables-Tabelle.
const Tabelle = "badbot"

// NFTables setzt die Sperren unter Linux um: eigene Tabelle "inet badbot",
// jede Aenderung eine einzige nft-Transaktion.
type NFTables struct {
	Programm string // Vorgabe "nft"
}

func (n *NFTables) programm() string {
	if n.Programm == "" {
		return "nft"
	}
	return n.Programm
}

func (n *NFTables) Faehigkeit() string { return "sperren-nftables" }

func (n *NFTables) Bereit() error {
	_, err := exec.LookPath(n.programm())
	return err
}

func (n *NFTables) Anwenden(ctx context.Context, netze []netip.Prefix, k Koeder) error {
	return ausfuehren(ctx, Regelsatz(netze, k), n.programm(), "-f", "-")
}

func (n *NFTables) Entfernen(ctx context.Context) error {
	// "table" vorweg legt sie an, falls jemand sie schon entfernt hat --
	// dann scheitert das Loeschen nicht.
	return ausfuehren(ctx, "table inet "+Tabelle+"\ndelete table inet "+Tabelle+"\n", n.programm(), "-f", "-")
}

// Regelsatz erzeugt die nft-Transaktion. Alte Tabelle weg, neue her -- in
// einem Zug, ohne Moment ohne Sperren.
func Regelsatz(netze []netip.Prefix, k Koeder) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", Tabelle, Tabelle)
	fmt.Fprintf(&b, "table inet %s {\n", Tabelle)
	b.WriteString("\tset sperre4 { type ipv4_addr; flags interval; }\n")
	b.WriteString("\tset sperre6 { type ipv6_addr; flags interval; }\n")
	fmt.Fprintf(&b, "\tset koeder_tcp { type inet_service;%s }\n", elemente(k.TCP))
	fmt.Fprintf(&b, "\tset koeder_udp { type inet_service;%s }\n", elemente(k.UDP))
	b.WriteString("\tchain eingang {\n")
	b.WriteString("\t\ttype filter hook input priority filter - 10; policy accept;\n")
	// Bestehende Verbindungen und lokaler Verkehr bleiben unberuehrt: Wer per
	// SSH angemeldet ist, verliert seine Sitzung nicht durch eine neue Liste.
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tiif lo accept\n")
	b.WriteString("\t\ttcp dport @koeder_tcp accept\n")
	b.WriteString("\t\tudp dport @koeder_udp accept\n")
	b.WriteString("\t\tip saddr @sperre4 drop\n")
	b.WriteString("\t\tip6 saddr @sperre6 drop\n")
	b.WriteString("\t}\n}\n")
	var v4, v6 []string
	for _, p := range netze {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	stueckeln(&b, "sperre4", v4)
	stueckeln(&b, "sperre6", v6)
	return b.String()
}

// stueckeln: grosse Listen in Bloecken, damit keine Zeile ausufert.
func stueckeln(b *strings.Builder, set string, l []string) {
	for i := 0; i < len(l); i += 1000 {
		j := min(i+1000, len(l))
		fmt.Fprintf(b, "add element inet %s %s { %s }\n", Tabelle, set, strings.Join(l[i:j], ", "))
	}
}
