//go:build windows

package einstellung

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Vertrauenswuerdig prueft, dass eine Datei oder ein Verzeichnis SYSTEM oder
// den Administratoren gehoert. In C:\ProgramData darf jeder Benutzer Ordner
// anlegen; wer den Ordner vor der Installation anlegt, bleibt sein Besitzer
// und koennte Einstellungen unterschieben, die der Dienst als SYSTEM ausfuehrt.
func Vertrauenswuerdig(pfad string) error {
	sd, err := windows.GetNamedSecurityInfo(pfad, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	besitzer, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if besitzer.IsWellKnown(windows.WinLocalSystemSid) || besitzer.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return fmt.Errorf("%s gehört weder SYSTEM noch den Administratoren (%s) -- aus Sicherheitsgründen nicht verwendet; Besitz prüfen oder Verzeichnis neu anlegen", pfad, besitzer.String())
}
