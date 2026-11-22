package sperre

// Vorgabe liefert den Umsetzer dieses Systems. verzeichnis nimmt Hilfsdateien
// auf, wo der Umsetzer welche braucht.
func Vorgabe(verzeichnis string) Umsetzer {
	_ = verzeichnis
	return &PF{}
}
