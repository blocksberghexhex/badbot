package sim

import (
	"encoding/hex"
	"time"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// TCPSink meldet Portscans: annehmen, nichts senden, nach den ersten Bytes
// oder fuenf Sekunden trennen. Die ersten 64 Bytes helfen, Protokolle zu
// erkennen -- ausgewertet werden sie nie.
func TCPSink() lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		// Read setzt je Aufruf die Leerlauffrist des Lauschers; die kuerzere
		// Frist des Sinks haelt deshalb ein Zeitgeber durch.
		zeitgeber := time.AfterFunc(5*time.Second, func() { v.Close() })
		defer zeitgeber.Stop()
		b := make([]byte, 64)
		n, _ := v.Read(b)
		if n == 0 {
			return nil
		}
		return []puffer.Merkmal{{Feld: "anfang_hex", Wert: hex.EncodeToString(b[:n])}}
	}
}
