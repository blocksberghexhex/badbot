package sim

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
	"golang.org/x/crypto/ssh"
)

var errAbgelehnt = errors.New("Permission denied")

// SSH: Banner, Schluesselaustausch, jede Anmeldung schlaegt nach kurzer
// Verzoegerung fehl; nach drei Versuchen trennt die Gegenseite oder wir.
func SSH(wirt ssh.Signer, banner string) lauscher.Behandler {
	return func(v *lauscher.Verbindung) []puffer.Merkmal {
		var mu sync.Mutex
		var probe []puffer.Merkmal
		merken := func(m ...puffer.Merkmal) {
			mu.Lock()
			probe = append(probe, m...)
			mu.Unlock()
		}
		cfg := &ssh.ServerConfig{
			ServerVersion: banner,
			MaxAuthTries:  3,
			PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
				merken(Text("client", string(m.ClientVersion()), 100), Anmeldung(m.User(), string(pw)))
				time.Sleep(400 * time.Millisecond)
				return nil, errAbgelehnt
			},
			PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
				merken(Text("client", string(m.ClientVersion()), 100), Anmeldung(m.User(), ""),
					puffer.Merkmal{Feld: "schluessel", Wert: ssh.FingerprintSHA256(k)})
				return nil, errAbgelehnt
			},
		}
		cfg.AddHostKey(wirt)
		// Kein Rueckgabewert wird benutzt: Es gibt keinen Weg, auf dem die
		// Anmeldung gelingt -- alle Rueckrufe lehnen ab, NoClientAuth ist aus.
		if c, _, _, err := ssh.NewServerConn(v, cfg); err == nil {
			c.Close()
		}
		mu.Lock()
		defer mu.Unlock()
		return probe
	}
}

// WirtsschluesselLaden liest den SSH-Wirtsschluessel oder erzeugt ihn einmal.
// Ein bei jedem Start neuer Schluessel waere fuer Angreifer ein Erkennungsmerkmal.
func WirtsschluesselLaden(pfad string) (ssh.Signer, error) {
	if roh, err := os.ReadFile(pfad); err == nil {
		return ssh.ParsePrivateKey(roh)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	roh := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(pfad, roh, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(roh)
}
