//go:build !windows

package einstellung

import (
	"fmt"
	"os"
)

// Vertrauenswuerdig: Unter Linux und macOS darf eine Einstellungs- oder
// Schluesseldatei nicht fuer alle beschreibbar sein. Den Besitzer prueft
// sie nicht -- in Containern gehoert die eingebundene Datei oft einem
// anderen Benutzer als dem, unter dem der Collector laeuft.
func Vertrauenswuerdig(pfad string) error {
	st, err := os.Stat(pfad)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%s ist für alle beschreibbar -- aus Sicherheitsgründen nicht verwendet", pfad)
	}
	return nil
}
