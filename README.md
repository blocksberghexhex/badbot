# badbot-collector

> Für gewöhnlichen PHP-Webspace ohne eigenen Server gibt es den
> PHP-Collector: [`php/README.md`](php/README.md).

Der Collector von [badbot.icu](https://badbot.icu), für Linux, Windows und
macOS. Er betreibt auf deinem Server Dienste, die verwundbar aussehen — SSH, Telnet, ein veralteter nginx,
WordPress, Datenbanken, DNS, eine offene Docker-API, MQTT und andere — und meldet, wer sie anspricht. Aus den
Meldungen vieler Collectoren entstehen die Sperrlisten von badbot.icu. Auf
Wunsch übernimmt der Collector diese Listen und sperrt die gemeldeten Netze
in der Firewall deines Servers: nftables unter Linux, die Windows-Firewall
unter Windows, pf unter macOS.

## Was der Collector tut — und was nie

- **Er gewährt nie eine Anmeldung.** Jede Simulation spielt einen festen
  Ablauf ab und lehnt jeden Anmeldeversuch ab. Es gibt keine vorgetäuschte
  Shell, keine Datenbank, keinen Mailversand.
- **Er führt nichts aus und lädt nichts nach.** Was ankommt, wird höchstens
  gekürzt mitgeschrieben, nie interpretiert.
- **Er baut keine Verbindungen auf** — weder zur Gegenstelle noch zu Dritten.
  Seine einzige ausgehende Verbindung geht zur API von badbot.icu.
- **Er ist kein Verstärker.** UDP-Antworten (DNS) sind nie größer als die
  Anfrage und je Quelle begrenzt. DNS-Anfragen werden nie aufgelöst.
- **Passwörter verlassen den Server nie im Klartext**, nur als SHA-256 mit
  Länge.

Gemeldet werden je Quelladresse, Simulation und Fünf-Minuten-Fenster: die
Adresse, die Anzahl der Zugriffe, die berührten Ports, der Zeitraum und eine
kleine Stichprobe (etwa Benutzernamen, aufgerufene Pfade, Client-Kennungen).

## Voraussetzungen

- Ein Rechner mit **eigener öffentlicher IP-Adresse**, auf dem sonst wenig
  läuft: Linux-Server (eine kleine VM genügt, 1 CPU, 512 MB RAM), Windows 10
  oder Windows Server 2016 und neuer, macOS 13 und neuer. Hinter einem
  Router sieht der Collector nur, was der Router zu ihm weiterleitet.
- Ein Konto bei badbot.icu und ein dort angelegter Collector. Beim Anlegen
  zeigt das Panel den **API-Schlüssel einmal** an.
- **Port 22 frei machen**, wenn die SSH-Simulation auf 22 laufen soll: den
  eigenen SSH-Zugang vorher auf einen anderen Port legen und prüfen, dass die
  Anmeldung dort funktioniert. Belegte Ports meldet der Collector im Panel;
  er startet die übrigen trotzdem.
- Eine Firewall davor (beim Anbieter oder auf dem Server) muss die Ports der
  eingeschalteten Simulationen durchlassen.

## Installation mit Docker

```sh
git clone https://github.com/blocksberghexhex/badbot.git
cd badbot
install -m 600 /dev/null schluessel.txt
nano schluessel.txt        # API-Schlüssel einfügen, eine Zeile
docker compose up -d --build
docker compose logs -f
```

Die Datei `docker-compose.yml` startet den Collector **im Host-Netz**. Das ist
Pflicht: Über das übliche Bridge-Netz ersetzt Docker die Quelladresse durch die
eigene Gateway-Adresse, und der Collector sähe jede Verbindung von
`172.17.0.1` kommen. Solche Meldungen verwirft die Plattform; im Panel und im
Log erscheint der Hinweis `quell-ip-fehlerhaft`. Wer nicht im Host-Netz laufen
will, braucht `"userland-proxy": false` in `/etc/docker/daemon.json`.

Der Container läuft schreibgeschützt, ohne Rechte außer zwei Fähigkeiten:
`NET_BIND_SERVICE` (Ports unter 1024) und `NET_ADMIN` (Sperren).

## Installation ohne Docker

```sh
go build -o badbot-collector ./cmd/badbot-collector     # Go 1.27
sudo install -m 755 badbot-collector /usr/local/bin/
sudo install -d -m 700 /etc/badbot-collector
sudo install -m 600 /dev/null /etc/badbot-collector/schluessel
sudoedit /etc/badbot-collector/schluessel                 # API-Schlüssel
sudo install -m 644 badbot-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now badbot-collector
journalctl -u badbot-collector -f
```

Für Sperren muss `nft` installiert sein (Paket `nftables`). Fehlt es, meldet
der Collector das und protokolliert die Sperren nur.

## Installation unter Windows

1. Im Panel einen Collector mit der Plattform **Windows** anlegen und den
   Schlüssel notieren.
2. Das Installationspaket `badbot-collector-<version>-windows-x64.msi` von
   der Release-Seite als Administrator ausführen. Es richtet ein:
   - das Programm unter `C:\Program Files\badbot-collector`,
   - den Dienst `badbot-collector` (startet automatisch, läuft als
     LocalSystem, startet nach einem Fehler neu),
   - eine Freigabe für das Programm in der Windows-Firewall,
   - das Datenverzeichnis `C:\ProgramData\badbot-collector`, das nur SYSTEM
     und Administratoren lesen dürfen.
3. Den Schlüssel als einzige Zeile in
   `C:\ProgramData\badbot-collector\schluessel` speichern.
4. In PowerShell als Administrator:

   ```powershell
   Start-Service badbot-collector
   Get-Content C:\ProgramData\badbot-collector\collector.log -Wait
   ```

Ohne Installationspaket — mit der `.exe` von der Release-Seite oder selbst
gebaut (`GOOS=windows go build ./cmd/badbot-collector`) — richtet der
Collector den Dienst selbst ein. Die `.exe` vorher an ihren festen Ort legen,
etwa `C:\Program Files\badbot-collector\`:

```powershell
& 'C:\Program Files\badbot-collector\badbot-collector.exe' dienst installieren
```

Entfernen: über „Apps“ in den Einstellungen, beziehungsweise mit
`badbot-collector.exe dienst entfernen`. Das Datenverzeichnis bleibt in
beiden Fällen.

Belegte Ports: Windows hält 135, 139 und 445 selbst, und RDP liegt auf 3389.
Beim Anlegen lässt das Panel die ersten drei weg; was trotzdem belegt ist,
meldet der Collector im Panel und startet die übrigen Simulationen.

## Installation unter macOS

1. Im Panel einen Collector mit der Plattform **macOS** anlegen und den
   Schlüssel notieren.
2. Das Paket `badbot-collector-<version>-macos.pkg` von der Release-Seite
   öffnen. Es legt das Programm nach `/usr/local/bin`, den Dienst nach
   `/Library/LaunchDaemons/icu.badbot.collector.plist` und gibt das
   Programm in der Programm-Firewall von macOS frei, falls die an ist.
3. Schlüssel eintragen und Dienst starten:

   ```sh
   sudo nano "/Library/Application Support/badbot-collector/schluessel"
   sudo launchctl bootstrap system /Library/LaunchDaemons/icu.badbot.collector.plist
   tail -f /Library/Logs/badbot-collector.log
   ```

Neustart nach Änderungen: `sudo launchctl kickstart -k system/icu.badbot.collector`.
Entfernen: `sudo /usr/local/share/badbot-collector/deinstallieren.sh`.

Der Collector läuft als root: Er braucht Ports unter 1024 und pf. Port 22
ist belegt, wenn „Entfernte Anmeldung“ an ist, 445 bei der Dateifreigabe,
5900 bei der Bildschirmfreigabe.

## Einstellungen

Was der Collector tut — welche Simulationen auf welchen Ports, ob er sperrt —
stellst du **im Panel** ein. Er übernimmt Änderungen innerhalb einer Minute
und meldet zurück, was tatsächlich läuft. Lokal gibt es nur:

| Variable | Bedeutung |
|---|---|
| `BADBOT_SCHLUESSEL_DATEI` | Datei mit dem API-Schlüssel (empfohlen) |
| `BADBOT_SCHLUESSEL` | der API-Schlüssel direkt — landet leicht in Prozesslisten und Logs |
| `BADBOT_DATEN` | Datenverzeichnis (Vorgaben siehe unten) |
| `BADBOT_SPERREN_AUSNAHMEN` | Netze, die nie gesperrt werden, kommagetrennt — dein eigenes Verwaltungsnetz |
| `BADBOT_SPERREN_TROCKEN` | `1`: Sperren nur protokollieren, nicht anwenden |
| `BADBOT_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |
| `BADBOT_API` | Adresse der API, Vorgabe `https://api.badbot.icu` |
| `BADBOT_LOG_DATEI` | Logdatei statt Standardfehlerausgabe; sie wird bei 10 MB gewechselt |
| `BADBOT_KONFIG` | Datei mit diesen Einstellungen, je Zeile `NAME=wert` |

Unter Windows und macOS gibt es feste Orte, weil Dienste dort Umgebungsvariablen
nur umständlich bekommen. Die Umgebung hat Vorrang vor der Datei.

| | Linux | Windows | macOS |
|---|---|---|---|
| Datenverzeichnis | `/var/lib/badbot-collector` | `C:\ProgramData\badbot-collector` | `/Library/Application Support/badbot-collector` |
| Schlüssel ohne weitere Angabe | — | `…\schluessel` im Datenverzeichnis | `…/schluessel` im Datenverzeichnis |
| Einstellungsdatei | — | `…\collector.env` im Datenverzeichnis | `…/collector.env` im Datenverzeichnis |
| Log | journald bzw. `docker compose logs` | `…\collector.log` im Datenverzeichnis | `/Library/Logs/badbot-collector.log` |

## Sperren

Ist im Panel eine Sperrstufe gewählt, holt der Collector die Sperrliste und
schreibt sie in einen **eigenen Bereich der Firewall**. Andere Regeln fasst er
nicht an.

- Bestehende Verbindungen bleiben bestehen — eine neue Liste beendet keine
  laufende SSH- oder RDP-Sitzung.
- Die Ports der Simulationen bleiben für alle erreichbar; sonst sähe der
  Collector genau die nicht mehr, die er melden soll.
- Ein neuer Stand ersetzt den alten erst, wenn er vollständig steht. Scheitert
  er, gilt der alte weiter.
- Die Liste hat ein Ablaufdatum. Erreicht der Collector die Plattform bis
  dahin nicht, entfernt er die Sperren. Beim Beenden entfernt er sie ebenfalls.
- `BADBOT_SPERREN_AUSNAHMEN` schützt deinen eigenen Zugang zusätzlich zur
  Ausnahmeliste der Plattform.

| System | Bereich | Ansehen | Notfalls entfernen |
|---|---|---|---|
| Linux | nftables-Tabelle `inet badbot` | `nft list table inet badbot` | `nft delete table inet badbot` |
| Windows | Regeln der Gruppe `badbot` in der Windows-Firewall | `Get-NetFirewallRule -Group badbot` | `Get-NetFirewallRule -Group badbot \| Remove-NetFirewallRule` |
| macOS | pf-Anker `com.apple/badbot` | `sudo pfctl -a com.apple/badbot -sr` | `sudo pfctl -a com.apple/badbot -F all` |

Linux braucht `nft` (Paket `nftables`). Fehlt das Firewall-Programm, meldet
der Collector das und protokolliert die Sperren nur.

Unter **Windows** haben Sperrregeln Vorrang vor jeder Freigabe. Die Ports der
Simulationen bleiben deshalb offen, weil die Sperrregeln nur die übrigen Ports
nennen. Der Austausch läuft so: erst die neuen Regeln anlegen, dann die alten
löschen.

Unter **macOS** ist pf meist ausgeschaltet. Der Collector schaltet es mit
einer eigenen Referenz ein und gibt sie beim Beenden zurück; danach ist pf so,
wie es vorher war. Der Anker liegt unter `com.apple`, weil das mitgelieferte
`/etc/pf.conf` alles darunter auswertet — so bleibt die Systemdatei
unverändert. Wer eine eigene `pf.conf` ohne `anchor "com.apple/*"` betreibt,
bekommt eine Fehlermeldung statt wirkungsloser Sperren.

## Daten auf dem Server

Im Datenverzeichnis liegen:

| Datei | Inhalt |
|---|---|
| `puffer.json` | noch nicht gemeldete Datensätze; nach einem Neustart werden sie nachgeliefert |
| `ssh_wirt` | SSH-Wirtsschlüssel der Simulation, beim ersten Start erzeugt |
| `zertifikat.pem` | selbst signiertes Zertifikat für HTTPS, ohne Namen |
| `erscheinung.json` | die einmal gewählten Banner und Versionen |

Ein Banner, das sich ständig ändert, verrät die Falle; deshalb bleiben
Wirtsschlüssel, Zertifikat und Erscheinung über Neustarts gleich.

## Prüfen, ob die Quelladresse stimmt

Mit `BADBOT_LOG_LEVEL=debug` schreibt der Collector jeden Zugriff mit
Quelladresse ins Log. Dann von einem **anderen** Rechner aus:

```sh
ssh -p 22 test@<adresse-deines-servers>
```

Die Anmeldung schlägt fehl, und im Log steht eine Zeile `Zugriff` mit der
Adresse des anderen Rechners. Steht dort eine Adresse aus `172.16.0.0/12` oder
`10.0.0.0/8`, sieht der Collector die echte Quelle nicht (siehe Installation
mit Docker). Im Panel zählt der Zugriff nach spätestens sechs Minuten unter
„heute“ mit. Danach `BADBOT_LOG_LEVEL` wieder entfernen — das Log wächst
sonst schnell.

## Entwicklung

```sh
go test ./...
go vet ./...
```

Der Test der Sperren mit nftables läuft nur als root und in einem eigenen
Netz-Namensraum; die Regeln des Rechners bleiben unberührt. pf und die
Windows-Firewall werden mit nachgebildeten Programmen geprüft; die Regeln,
die sie bekommen, stehen im Test.

Pakete bauen (je auf dem eigenen System):

```sh
paket/macos/bauen.sh 1.2.3            # macOS: .pkg für Intel und Apple Silicon
```

```powershell
paket\windows\bauen.ps1 -Version 1.2.3   # Windows: .msi, braucht WiX 5
```

Zu jedem Tag `v*` baut `.github/workflows/release.yml` alle Programme und
Pakete und legt sie mit `SHA256SUMS` als Release ab. Signiert wird, wenn die
im Workflow genannten Secrets gesetzt sind.

## Lizenz

[badbot Client License 1.0.0](LICENSE.md). Kurz und unverbindlich — maßgeblich
ist der Lizenztext:

- **Nutzen darfst du den Collector für jeden Zweck**, auch gewerblich, auch
  für Kunden und auf beliebig vielen Servern.
- **Den Quelltext darfst du lesen und prüfen** — dafür ist er offen. Bauen
  aus dem Quelltext und Ausfüllen der Konfiguration sind erlaubt.
- **Nicht erlaubt:** den Collector verändern, Teile davon in anderen
  Projekten verwenden, ihn weitergeben oder unter anderem Namen anbieten.
- Der Name „badbot“ und die Hinweise auf Urheber und Lizenz bleiben, wie sie
  sind.
