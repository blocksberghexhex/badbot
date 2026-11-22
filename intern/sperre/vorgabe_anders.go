//go:build !linux && !darwin && !windows

package sperre

// Vorgabe: Auf anderen Systemen gibt es keinen Umsetzer; gesperrt wird dann
// nur im Protokoll.
func Vorgabe(verzeichnis string) Umsetzer { return nil }
