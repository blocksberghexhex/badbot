# badbot-collector für PHP-Webspace

Der Collector von [badbot.icu](https://badbot.icu) für gewöhnlichen Webspace:
eine Datei `badbot.php` plus Konfiguration, keine Abhängigkeiten.

**PHP 8.5 oder neuer.** Unterstützt werden nur die beiden neuesten
PHP-Versionen (derzeit 8.5 und 8.6). Ältere bekommen bald keine
Sicherheitsupdates mehr; auf ihnen verweigert der Collector den Dienst und
lässt die Webseite unverändert weiterlaufen. Im Kundenmenü des Hosters lässt
sich die PHP-Version meist je Seite umstellen.

Er öffnet keine Ports. Er bedient auf deiner Webseite nur **Köderpfade** —
Adressen, die auf deiner Seite niemand Legitimes aufruft — und meldet, wer sie
abfragt:

| Köder | Pfade | erfasst |
|---|---|---|
| WordPress | `/wp-login.php`, `/xmlrpc.php`, `/wp-admin/`, `/wp-content/plugins/…/` | Benutzernamen, Passwörter als SHA-256 mit Länge, XML-RPC-Methoden, Plugin-Namen |
| Konfiguration | `/.env`, `/.git/config`, `/.git/HEAD`, `/config.php.bak`, `/wp-config.php.old` | Pfad, User-Agent |
| Datenbank-Oberflächen | `/phpmyadmin/`, `/pma/`, `/adminer.php` | Benutzernamen, Passwörter als SHA-256 mit Länge |

Auf Wunsch sperrt er außerdem die Netze der badbot-Sperrliste für deine ganze
Webseite.

## Was er tut — und was nie

- **Keine Anmeldung gelingt.** Jede Antwort ist fest vorgegeben und enthält
  nichts von dem, was ankam.
- **Gewöhnliche Besucher werden nie gemeldet**, nur Aufrufe von Köderpfaden.
- **Vorhandene Dateien werden nie überdeckt.** Gibt es auf deiner Seite eine
  echte `.env` oder ein echtes `phpmyadmin/`, bedient der Webserver diese wie
  bisher. Läuft WordPress, bleiben die WordPress-Köder aus — sonst würden
  deine Redakteure gemeldet.
- **Nichts wird ausgeführt.** Kein `eval`, keine Shell, kein Einbinden von
  Eingaben, Datenbankzugriffe nur mit Platzhaltern. Ein Test prüft das bei
  jeder Änderung am Quelltext.
- **Passwörter verlassen den Server nur als SHA-256 mit Länge.**
- **Die Sperrprüfung stört deine Seite nie.** Jeder Fehler darin wird
  geschluckt; im schlimmsten Fall sperrt sie nicht.

## Installation

1. Im Panel von badbot.icu einen Collector vom Typ **PHP** anlegen. Der
   API-Schlüssel wird **einmal** angezeigt.
2. Ein Verzeichnis im Web-Wurzelverzeichnis anlegen, z. B. `badbot/`, und
   `badbot.php` hineinkopieren.
3. `badbot-konfig.beispiel.php` als `badbot-konfig.php` daneben ablegen und
   ausfüllen. Schlüssel und Datenverzeichnis gehören **außerhalb** des
   Web-Wurzelverzeichnisses, wo der Webspace das erlaubt:

   ```
   /home/kunde/
   ├── badbot-daten/          ← Datenverzeichnis, Schlüsseldatei (0600)
   └── public_html/           ← Web-Wurzelverzeichnis
       ├── .htaccess
       └── badbot/
           ├── badbot.php
           └── badbot-konfig.php
   ```

   Liegt das Datenverzeichnis doch im Web-Wurzelverzeichnis, legt der
   Collector dort eine `.htaccess` an, die jeden Abruf verbietet.
4. Prüfen — per SSH, oder einmalig über die Cron-Oberfläche des Hosters:

   ```sh
   php badbot/badbot.php --pruefen
   ```

   Erwartet: `Lebenszeichen angenommen` und `Konfiguration … übernommen`.
5. Die Umleitung der Köderpfade erzeugen und **ganz oben** in die `.htaccess`
   des Web-Wurzelverzeichnisses einfügen (vor allen anderen Regeln, auch vor
   denen von WordPress):

   ```sh
   php badbot/badbot.php --htaccess /badbot/badbot.php
   ```

   Die Regeln greifen nur, wenn es die Datei oder das Verzeichnis nicht gibt.
   Für nginx gibt `--nginx /badbot/badbot.php` einen Vorschlag aus, der an
   den eigenen `fastcgi_pass` angepasst werden muss.
6. **Sperren (optional):** `badbot.php` vor jede Anfrage schalten. Wo der
   Webspace es erlaubt, in der `.htaccess` oder `.user.ini`:

   ```
   # .htaccess (mod_php)
   php_value auto_prepend_file /home/kunde/public_html/badbot/badbot.php
   ```

   ```
   ; .user.ini (PHP-FPM / CGI)
   auto_prepend_file = /home/kunde/public_html/badbot/badbot.php
   ```

   Sonst eine Zeile ganz oben in den Einstieg der Seite (z. B. `index.php`):

   ```php
   require __DIR__ . '/badbot/badbot.php';
   ```

   Die Sperrstufe stellst du im Panel ein; `aus` schaltet das Sperren ab.
7. **Cron (empfohlen):** `php /home/kunde/public_html/badbot/badbot.php --runde`
   alle fünf Minuten. Ohne Cron meldet der Collector am Ende von
   Köderaufrufen und — bei PHP-FPM — am Ende gewöhnlicher Seitenaufrufe; bei
   wenig Verkehr kann das Panel ihn dann zeitweise als abwesend zeigen.

## Testen

Von einem anderen Rechner aus:

```sh
curl -i https://deine-seite.example/.env
```

Die Antwort ist eine harmlose Beispieldatei. Nach spätestens sechs Minuten
zählt das Panel den Zugriff unter „heute“. Mit `php badbot/badbot.php --runde --alles`
wird sofort gemeldet, auch das laufende Fünf-Minuten-Fenster.

## Hinter einem CDN

Steht die Seite hinter einem CDN, sieht PHP nur die Adresse des CDN. Der
Collector übernimmt die Adresse aus `X-Forwarded-For` **nur**, wenn die
Verbindung aus einem Netz kommt, das badbot.icu als CDN freigegeben hat; die
Plattform prüft das nach. Bei jedem anderen Absender ist der Header
Angreifereingabe und wird ignoriert.

Steht die Seite hinter einem Proxy des Hosters, der die Besucheradresse
verbirgt, meldet die Plattform `quell-ip-fehlerhaft` (siehe `--pruefen`) und
verwirft die Meldungen. Dann hilft nur der Hoster.

## Speicher

Vorgabe ist das Datenverzeichnis. Wer dort nicht schreiben darf, nutzt die
MySQL-Datenbank des Webspace (`'speicher' => 'pdo'`); der Collector legt
die Tabelle `badbot_daten` selbst an. Das Datenverzeichnis ist trotzdem der
bessere Weg: Mit OPcache kostet die Sperrprüfung dann je Anfrage fast nichts.

## Befehle

| Befehl | |
|---|---|
| `--pruefen` | Runde ausführen und Zustand zeigen |
| `--runde [--alles]` | Runde ausführen (für Cron); `--alles` meldet auch das laufende Fenster |
| `--htaccess /pfad/zu/badbot.php` | Umleitung für Apache ausgeben |
| `--nginx /pfad/zu/badbot.php` | Vorschlag für nginx ausgeben |
| `--htaccess-sperren` | aktuelle Sperrliste als `Require not ip`-Block ausgeben, für Webspace ohne PHP-Vorschaltung; bei großen Listen langsam |
| `--version` | Version |

## Entwicklung

```sh
php tests/lauf.php    # Einzeltests und Sicherheitsprüfung
php tests/e2e.php     # mit echtem PHP-Webserver und nachgebildeter Plattform
```

## Lizenz

[badbot Client License 1.0.0](../LICENSE.md). Kurz und unverbindlich — maßgeblich
ist der Lizenztext:

- **Nutzen darfst du den Collector für jeden Zweck**, auch gewerblich, auch
  für Kunden und auf beliebig vielen Servern.
- **Den Quelltext darfst du lesen und prüfen** — dafür ist er offen. Bauen
  aus dem Quelltext und Ausfüllen der Konfiguration sind erlaubt.
- **Nicht erlaubt:** den Collector verändern, Teile davon in anderen
  Projekten verwenden, ihn weitergeben oder unter anderem Namen anbieten.
- Der Name „badbot“ und die Hinweise auf Urheber und Lizenz bleiben, wie sie
  sind.
