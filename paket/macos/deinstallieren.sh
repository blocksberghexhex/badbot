#!/bin/sh
# Entfernt badbot-collector von macOS. Aufruf: sudo deinstallieren.sh
# Beim Beenden raeumt der Collector seine Sperren selbst ab; der pf-Befehl
# danach erwischt Reste, falls er vorher abgestuerzt war.
set -u
if [ "$(id -u)" != 0 ]; then
	echo "Bitte mit sudo aufrufen." >&2
	exit 1
fi
launchctl bootout system/icu.badbot.collector 2>/dev/null || true
pfctl -a com.apple/badbot -F all 2>/dev/null || true
fw=/usr/libexec/ApplicationFirewall/socketfilterfw
[ -x "$fw" ] && "$fw" --remove /usr/local/bin/badbot-collector >/dev/null 2>&1 || true
rm -f /usr/local/bin/badbot-collector /Library/LaunchDaemons/icu.badbot.collector.plist
rm -rf /usr/local/share/badbot-collector
pkgutil --forget icu.badbot.collector >/dev/null 2>&1 || true
echo "Entfernt. Schluessel und Puffer liegen weiter in /Library/Application Support/badbot-collector,"
echo "das Log in /Library/Logs/badbot-collector*.log -- bei Bedarf von Hand loeschen."
