#!/bin/sh
# Baut das macOS-Paket: ein Programm fuer Intel und Apple Silicon, ein .pkg.
# Laeuft nur unter macOS (lipo, pkgbuild, productbuild).
#
# Aufruf: paket/macos/bauen.sh 1.2.3
#
# Signiert und beglaubigt wird nur, wenn die Umgebung es vorgibt:
#   MAC_APP_IDENTITAET  "Developer ID Application: …" (Programm)
#   MAC_PKG_IDENTITAET  "Developer ID Installer: …"   (Paket)
#   MAC_NOTAR_PROFIL    Profil aus "xcrun notarytool store-credentials"
set -eu
version=${1:?Version fehlt}
cd "$(dirname "$0")/../.."
aus=$(pwd)/dist
arbeit=$(mktemp -d)
trap 'rm -rf "$arbeit"' EXIT
mkdir -p "$aus"

for arch in amd64 arm64; do
	GOOS=darwin GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.Version=$version" \
		-o "$arbeit/badbot-collector-$arch" ./cmd/badbot-collector
done
lipo -create -output "$arbeit/badbot-collector" "$arbeit/badbot-collector-amd64" "$arbeit/badbot-collector-arm64"

wurzel=$arbeit/wurzel
mkdir -p "$wurzel/usr/local/bin" "$wurzel/Library/LaunchDaemons" "$wurzel/usr/local/share/badbot-collector" "$arbeit/skripte"
install -m 755 "$arbeit/badbot-collector" "$wurzel/usr/local/bin/"
install -m 644 paket/macos/icu.badbot.collector.plist "$wurzel/Library/LaunchDaemons/"
install -m 755 paket/macos/deinstallieren.sh "$wurzel/usr/local/share/badbot-collector/"
install -m 755 paket/macos/postinstall "$arbeit/skripte/"

if [ -n "${MAC_APP_IDENTITAET:-}" ]; then
	# Gehaertete Laufzeit ist Voraussetzung fuer die Beglaubigung.
	codesign --force --options runtime --timestamp --sign "$MAC_APP_IDENTITAET" "$wurzel/usr/local/bin/badbot-collector"
fi

pkgbuild --root "$wurzel" --scripts "$arbeit/skripte" --identifier icu.badbot.collector \
	--version "$version" --install-location / "$arbeit/komponente.pkg"
paket="$aus/badbot-collector-$version-macos.pkg"
if [ -n "${MAC_PKG_IDENTITAET:-}" ]; then
	productbuild --package "$arbeit/komponente.pkg" --sign "$MAC_PKG_IDENTITAET" --timestamp "$paket"
else
	productbuild --package "$arbeit/komponente.pkg" "$paket"
	echo "WARNUNG: Paket nicht signiert" >&2
fi

if [ -n "${MAC_NOTAR_PROFIL:-}" ]; then
	xcrun notarytool submit "$paket" --keychain-profile "$MAC_NOTAR_PROFIL" --wait
	xcrun stapler staple "$paket"
fi
echo "$paket"
