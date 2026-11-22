<?php
// Konfiguration des badbot-collectors. Als badbot-konfig.php neben
// badbot.php ablegen. Anleitung: README.md
return [
    // API-Schlüssel aus dem Panel. Am besten in einer Datei außerhalb des
    // Web-Verzeichnisses (eine Zeile, Rechte 0600) ...
    // dirname(__DIR__, 2): zwei Ebenen über badbot.php -- liegt badbot.php in
    // public_html/badbot/, also neben public_html, nicht darin.
    'schluessel_datei' => \dirname(__DIR__, 2) . '/badbot-daten/schluessel',
    // ... oder direkt hier eintragen und schluessel_datei leeren:
    'schluessel' => '',

    // Verzeichnis für Puffer und Sperrliste, möglichst außerhalb des
    // Web-Verzeichnisses. Wird angelegt, falls es fehlt.
    'daten' => \dirname(__DIR__, 2) . '/badbot-daten',

    // Web-Wurzelverzeichnis der Seite. Leer: wird beim ersten Aufruf eines
    // Köderpfads übernommen. Dient der Erkennung von WordPress.
    'webroot' => '',

    // 'datei' (Vorgabe) oder 'pdo' für die MySQL-Datenbank des Webspace.
    'speicher' => 'datei',
    'pdo' => [
        'dsn' => '',       // z. B. 'mysql:host=localhost;dbname=...;charset=utf8mb4'
        'benutzer' => '',
        'passwort' => '',
    ],

    // Netze, die nie gesperrt werden -- etwa das eigene Büro.
    'sperren_ausnahmen' => [],
    // true: Sperrliste nicht anwenden (nur melden).
    'sperren_trocken' => false,
];
