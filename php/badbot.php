<?php
/**
 * badbot-collector für PHP-Webspace — https://badbot.icu
 *
 * Bedient Köderpfade (WordPress-Anmeldung, Konfigurationsdateien,
 * Datenbank-Oberflächen), meldet, wer sie aufruft, und sperrt auf Wunsch die
 * Netze der Sperrliste für die ganze Webseite. Anleitung: README.md.
 *
 * Grundregeln, die diese Datei nie bricht:
 * - Keine Anmeldung gelingt. Jede Antwort ist fest vorgegeben und enthält
 *   nichts von dem, was ankam.
 * - Nichts wird ausgeführt oder eingebunden, was von außen kommt; Datenbank-
 *   zugriffe nur mit Platzhaltern.
 * - Gemeldet werden nur Aufrufe von Köderpfaden, nie gewöhnliche Besucher.
 * - Passwörter verlassen den Server nur als SHA-256 mit Länge.
 * - Als vorgeschaltete Datei (Sperrprüfung) darf sie die Webseite nie
 *   stören: Jeder Fehler wird geschluckt.
 *
 * PHP >= 8.5, keine Abhängigkeiten. Unterstützt werden nur die beiden
 * neuesten PHP-Versionen: Ältere bekommen bald keine Sicherheitsupdates mehr,
 * und ein Collector auf einem ungepflegten PHP ist selbst ein Angriffsziel.
 */

declare(strict_types=1);

namespace BadbotCollector;

// Bedingt deklariert: Die Datei kann je Anfrage zweimal geladen werden
// (auto_prepend_file und Umleitung eines Köderpfads). Unbedingte
// Deklarationen bindet PHP vorab und bricht dann mit "already declared" ab.
if (!\defined('BADBOT_COLLECTOR_VERSION')) {
    \define('BADBOT_COLLECTOR_VERSION', '0.2.0');
    \define('BADBOT_PHP_MINDESTENS', 80500);

    /** Grenzen und Vorgaben. */
    final class K
    {
        public const HOECHST_PORTS = 64;
        public const HOECHST_SAETZE = 5000;
        public const HOECHST_BYTES = 900000;      // unter 1 MiB, mit Abstand
        // Jeder Köderaufruf liest und schreibt den offenen Puffer ganz; bei
        // zu vielen Einträgen kostet ein Aufruf mehr Speicher, als der
        // Webspace erlaubt, und der Collector hängt.
        public const HOECHST_OFFEN = 2000;
        public const HOECHST_WARTEND = 10000;
        public const HOECHST_STICHPROBE = 1024;
        public const NACHLIEFERFRIST = 71 * 3600; // die Plattform nimmt 72 h an
        public const KOERPER = 16384;             // gelesene Bytes je Anfrage
        public const API = 'https://api.badbot.icu';
        public const SIMULATIONEN = ['wp-koeder', 'konfig-koeder', 'db-koeder'];
    }

    // -----------------------------------------------------------------------
    // Einstellung (badbot-konfig.php)

    final class Einstellung
    {
        public string $schluessel = '';
        public string $daten = '';
        public string $webroot = '';
        public string $api = K::API;
        public string $speicher = 'datei';
        /** @var array{dsn:string,benutzer:string,passwort:string} */
        public array $pdo = ['dsn' => '', 'benutzer' => '', 'passwort' => ''];
        /** @var string[] */
        public array $ausnahmen = [];
        public bool $trocken = false;

        public static function pfad(string $neben): string
        {
            if (\defined('BADBOT_KONFIG')) {
                return (string) \constant('BADBOT_KONFIG');
            }
            $env = \getenv('BADBOT_KONFIG');
            if (\is_string($env) && $env !== '') {
                return $env;
            }
            return \dirname($neben) . '/badbot-konfig.php';
        }

        public static function laden(string $pfad): self
        {
            if (!\is_file($pfad)) {
                throw new \RuntimeException('Konfiguration fehlt: ' . $pfad);
            }
            // Fester Pfad aus dem Dateisystem, nie aus der Anfrage.
            $w = require $pfad;
            if (!\is_array($w)) {
                throw new \RuntimeException('Konfiguration liefert kein Array');
            }
            $e = new self();
            $e->schluessel = \trim((string) ($w['schluessel'] ?? ''));
            if (($w['schluessel_datei'] ?? '') !== '') {
                $roh = @\file_get_contents((string) $w['schluessel_datei']);
                if ($roh === false) {
                    throw new \RuntimeException('Schlüsseldatei nicht lesbar');
                }
                $e->schluessel = \trim($roh);
            }
            if (!\str_starts_with($e->schluessel, 'bb1_')) {
                throw new \RuntimeException('kein gültiger API-Schlüssel');
            }
            $e->daten = \rtrim((string) ($w['daten'] ?? ''), '/');
            if ($e->daten === '') {
                throw new \RuntimeException('Datenverzeichnis fehlt (daten)');
            }
            $e->webroot = \rtrim((string) ($w['webroot'] ?? ''), '/');
            $e->api = \rtrim((string) ($w['api'] ?? K::API), '/');
            $u = \parse_url($e->api);
            $host = \is_array($u) ? (string) ($u['host'] ?? '') : '';
            $schema = \is_array($u) ? (string) ($u['scheme'] ?? '') : '';
            // Nur https; http allein für lokale Tests. Einen Schalter gegen die
            // Zertifikatsprüfung gibt es absichtlich nicht.
            if ($host === '' || !($schema === 'https' || ($schema === 'http' && Netz::lokal($host)))) {
                throw new \RuntimeException('api muss https verwenden');
            }
            $e->speicher = (string) ($w['speicher'] ?? 'datei');
            if (!\in_array($e->speicher, ['datei', 'pdo'], true)) {
                throw new \RuntimeException('speicher: datei oder pdo');
            }
            $pdo = $w['pdo'] ?? [];
            $e->pdo = [
                'dsn' => (string) ($pdo['dsn'] ?? ''),
                'benutzer' => (string) ($pdo['benutzer'] ?? ''),
                'passwort' => (string) ($pdo['passwort'] ?? ''),
            ];
            foreach ((array) ($w['sperren_ausnahmen'] ?? []) as $n) {
                if (Netz::bereich((string) $n) === null) {
                    throw new \RuntimeException('sperren_ausnahmen: kein Netz');
                }
                $e->ausnahmen[] = (string) $n;
            }
            $e->trocken = (bool) ($w['sperren_trocken'] ?? false);
            return $e;
        }
    }

    // -----------------------------------------------------------------------
    // Adressen und Netze

    final class Netz
    {
        public static function lokal(string $host): bool
        {
            return \in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true) || \str_ends_with($host, '.localhost');
        }

        /** Kanonische Schreibweise; IPv4 in IPv6 wird IPv4. */
        public static function normal(string $ip): ?string
        {
            $b = self::bin($ip);
            return $b === null ? null : (string) \inet_ntop($b);
        }

        private static function bin(string $ip): ?string
        {
            if ($ip === '' || \strlen($ip) > 45) {
                return null;
            }
            $b = @\inet_pton($ip);
            if (!\is_string($b)) {
                return null;
            }
            if (\strlen($b) === 16 && \strncmp($b, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) === 0) {
                $b = \substr($b, 12);
            }
            return $b;
        }

        /** Hex-Darstellung, gleich lang je Familie und damit vergleichbar. */
        public static function hex(string $ip): ?string
        {
            $b = self::bin($ip);
            return $b === null ? null : \bin2hex($b);
        }

        /**
         * Erster und letzter Wert eines Netzes als Hex.
         * @return array{0:string,1:string}|null
         */
        public static function bereich(string $netz): ?array
        {
            $teile = \explode('/', $netz, 2);
            $b = self::bin($teile[0]);
            if ($b === null) {
                return null;
            }
            $laenge = \strlen($b) * 8;
            $bits = $laenge;
            if (isset($teile[1])) {
                if (!\ctype_digit($teile[1])) {
                    return null;
                }
                $bits = (int) $teile[1];
                // ::ffff:a.b.c.d/n meint das IPv4-Netz mit n-96 Bits.
                if (\strlen($b) === 4 && \str_contains($teile[0], ':')) {
                    $bits -= 96;
                }
                if ($bits < 0 || $bits > $laenge) {
                    return null;
                }
            }
            $anfang = '';
            $ende = '';
            for ($i = 0; $i < \strlen($b); $i++) {
                $rest = \max(0, \min(8, $bits - $i * 8));
                $maske = $rest === 0 ? 0 : (0xff << (8 - $rest)) & 0xff;
                $o = \ord($b[$i]);
                $anfang .= \chr($o & $maske);
                $ende .= \chr(($o & $maske) | (~$maske & 0xff));
            }
            return [\bin2hex($anfang), \bin2hex($ende)];
        }

        /** @param string[] $netze */
        public static function enthalten(string $ip, array $netze): bool
        {
            $x = self::hex($ip);
            if ($x === null) {
                return false;
            }
            foreach ($netze as $n) {
                $r = self::bereich((string) $n);
                if ($r !== null && \strlen($r[0]) === \strlen($x) && $r[0] <= $x && $x <= $r[1]) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Sortierte, verschmolzene Bereiche je Familie, flach [anfang, ende, ...].
         * @param string[] $netze
         * @return array{v4:string[],v6:string[]}
         */
        public static function bereiche(array $netze): array
        {
            $l = ['v4' => [], 'v6' => []];
            foreach ($netze as $n) {
                $r = self::bereich($n);
                if ($r !== null) {
                    $l[\strlen($r[0]) === 8 ? 'v4' : 'v6'][] = $r;
                }
            }
            $aus = ['v4' => [], 'v6' => []];
            foreach ($l as $fam => $r) {
                \usort($r, static fn (array $a, array $b): int => \strcmp($a[0], $b[0]));
                $flach = [];
                foreach ($r as [$a, $e]) {
                    $n = \count($flach);
                    if ($n > 0 && $a <= $flach[$n - 1]) {
                        if ($e > $flach[$n - 1]) {
                            $flach[$n - 1] = $e;
                        }
                        continue;
                    }
                    $flach[] = $a;
                    $flach[] = $e;
                }
                $aus[$fam] = $flach;
            }
            return $aus;
        }

        /** @param string[] $flach */
        public static function suchen(array $flach, string $hex): bool
        {
            $lo = 0;
            $hi = \intdiv(\count($flach), 2) - 1;
            while ($lo <= $hi) {
                $m = \intdiv($lo + $hi, 2);
                if ($hex < $flach[2 * $m]) {
                    $hi = $m - 1;
                } elseif ($hex > $flach[2 * $m + 1]) {
                    $lo = $m + 1;
                } else {
                    return true;
                }
            }
            return false;
        }

        private const NIE_GESPERRT = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/3',
            '::/8', 'fc00::/7', 'fe80::/10', 'ff00::/8'];

        /** Zu große Netze (größer als /8 bzw. /19) und reservierte Bereiche sperrt keine Liste. */
        public static function nieSperrbar(string $netz): bool
        {
            $nn = self::netzNormal($netz);
            if ($nn === null) {
                return true;
            }
            [$adresse, $bits] = \explode('/', $nn, 2);
            $v6 = \str_contains($adresse, ':');
            if ((int) $bits < ($v6 ? 19 : 8)) {
                return true;
            }
            if (self::enthalten($adresse, self::NIE_GESPERRT)) {
                return true;
            }
            foreach (self::NIE_GESPERRT as $r) {
                if (self::enthalten(\explode('/', $r, 2)[0], [$nn])) {
                    return true;
                }
            }
            return false;
        }

        /** Kanonisches Netz "adresse/bits" mit genullten Hostbits. */
        public static function netzNormal(string $netz): ?string
        {
            $r = self::bereich($netz);
            if ($r === null) {
                return null;
            }
            $teile = \explode('/', $netz, 2);
            $laenge = \strlen($r[0]) * 4;
            $bits = isset($teile[1]) ? (int) $teile[1] : $laenge;
            if ($laenge === 32 && \str_contains($teile[0], ':') && isset($teile[1])) {
                $bits -= 96;
            }
            return \inet_ntop((string) \hex2bin($r[0])) . '/' . $bits;
        }

        /**
         * Quelle einer Anfrage. X-Forwarded-For ist Angreifereingabe und gilt
         * nur, wenn die Verbindung selbst aus einem freigegebenen Vorschaltnetz
         * kommt -- dann der letzte Eintrag, den das Vorschaltnetz angefügt hat.
         * @param array<string,mixed> $server
         * @param string[] $vorschalt
         * @return array{quelle:string,vorschalt:bool,von:string}|null
         */
        public static function quelle(array $server, array $vorschalt): ?array
        {
            $ra = self::normal((string) ($server['REMOTE_ADDR'] ?? ''));
            if ($ra === null) {
                return null;
            }
            if ($vorschalt !== [] && self::enthalten($ra, $vorschalt)) {
                $teile = \explode(',', (string) ($server['HTTP_X_FORWARDED_FOR'] ?? ''));
                $q = self::normal(\trim((string) \end($teile)));
                if ($q !== null) {
                    return ['quelle' => $q, 'vorschalt' => true, 'von' => $ra];
                }
            }
            return ['quelle' => $ra, 'vorschalt' => false, 'von' => ''];
        }
    }

    // -----------------------------------------------------------------------
    // Text für die Stichprobe

    final class Text
    {
        /** Kürzt auf n Zeichen, ersetzt Steuerzeichen; erfasste Eingaben sind feindlich. */
        public static function kurz(string $s, int $n): string
        {
            if (\preg_match('//u', $s) !== 1) {
                $s = (string) \preg_replace('/[\x80-\xff]/', '?', $s);
            }
            $s = (string) \preg_replace('/[\x00-\x1f\x7f]/u', "\u{FFFD}", $s);
            if (\preg_match('/^.{0,' . $n . '}/su', $s, $m) === 1) {
                return $m[0];
            }
            return '';
        }

        /** @return array<string,mixed> */
        public static function anmeldung(string $name, string $passwort): array
        {
            $m = ['name' => self::kurz($name, 64)];
            if ($passwort !== '') {
                $m['passwort_sha256'] = \hash('sha256', $passwort);
                $m['passwort_laenge'] = \strlen($passwort);
            }
            return $m;
        }

        /** Pfad mit Abfrage; Werte von Parametern, die nach Zugangsdaten heißen, ersetzt. */
        public static function pfad(string $uri): string
        {
            $teile = \explode('?', $uri, 2);
            if (!isset($teile[1]) || $teile[1] === '') {
                return self::kurz($teile[0], 200);
            }
            $paare = [];
            foreach (\explode('&', $teile[1]) as $p) {
                $kv = \explode('=', $p, 2);
                if (isset($kv[1]) && \preg_match('/pass|pwd|secret|token/i', \urldecode($kv[0])) === 1) {
                    $p = $kv[0] . '=%2A';
                }
                $paare[] = $p;
            }
            return self::kurz($teile[0] . '?' . \implode('&', $paare), 200);
        }
    }

    // -----------------------------------------------------------------------
    // Köder: feste Antworten, Stichprobe

    final class Koeder
    {
        private const KONFIG = [
            '/.env' => ["APP_ENV=production\nAPP_DEBUG=false\nLOG_CHANNEL=stack\n", 'text/plain'],
            '/.git/config' => ["[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n", 'text/plain'],
            '/.git/HEAD' => ["ref: refs/heads/master\n", 'text/plain'],
            '/config.php.bak' => ['', 'text/plain'],
            '/wp-config.php.old' => ['', 'text/plain'],
        ];
        private const PMA = ['/phpmyadmin/', '/phpmyadmin/index.php', '/pma/', '/pma/index.php'];

        private const NICHT_GEFUNDEN = "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n";

        /** Muster für die Umleitung (.htaccess) -- muss alle Köderpfade abdecken. */
        public const MUSTER_KONFIG = '\.env|\.git/(config|HEAD)|config\.php\.bak|wp-config\.php\.old';
        public const MUSTER_DB = 'adminer\.php|phpmyadmin/(index\.php)?|pma/(index\.php)?';
        public const MUSTER_WP = 'wp-login\.php|xmlrpc\.php|wp-admin(/.*)?|wp-content/plugins/[^/]+/.*';

        /**
         * Beantwortet eine Anfrage an einen Köderpfad.
         * @param array<string,mixed> $server
         * @param array<string,bool> $aktiv Simulation => eingeschaltet
         * @return array{status:int,typ:string,inhalt:string,kopf:array<string,string>,sim:?string,probe:array<string,mixed>}
         */
        public static function antwort(array $server, string $koerper, array $aktiv, bool $wordpressVorhanden): array
        {
            $uri = (string) ($server['REQUEST_URI'] ?? '/');
            $pfad = (string) (\parse_url('http://x' . $uri, \PHP_URL_PATH) ?? '/');
            $methode = \strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));
            $post = $methode === 'POST';
            $leer = ['status' => 404, 'typ' => 'text/html; charset=UTF-8', 'inhalt' => self::NICHT_GEFUNDEN, 'kopf' => [], 'sim' => null, 'probe' => []];

            $sim = null;
            if (isset(self::KONFIG[$pfad])) {
                $sim = 'konfig-koeder';
            } elseif (\in_array($pfad, self::PMA, true) || $pfad === '/adminer.php') {
                $sim = 'db-koeder';
            } elseif (self::istWp($pfad)) {
                $sim = 'wp-koeder';
            }
            // Läuft echtes WordPress, gehören diese Pfade den Redakteuren.
            if ($sim === null || empty($aktiv[$sim]) || ($sim === 'wp-koeder' && $wordpressVorhanden)) {
                return $leer;
            }

            $probe = [
                'methode' => [Text::kurz($methode, 16)],
                'pfad' => [Text::pfad($uri)],
                'ua' => [Text::kurz((string) ($server['HTTP_USER_AGENT'] ?? ''), 200)],
            ];
            $felder = [];
            $istFormular = \str_starts_with(\strtolower((string) ($server['CONTENT_TYPE'] ?? '')), 'application/x-www-form-urlencoded');
            if ($post && $istFormular) {
                // parse_str mit Ziel-Array: legt keine Variablen an.
                \parse_str($koerper, $felder);
                if ($felder !== []) {
                    $namen = \array_map('strval', \array_keys($felder));
                    \sort($namen);
                    $probe['felder'] = [Text::kurz(\implode(',', $namen), 200)];
                }
            }
            $wert = static function (array $f, string ...$pfad): string {
                foreach ($pfad as $k) {
                    if (!\is_array($f) || !isset($f[$k])) {
                        return '';
                    }
                    $f = $f[$k];
                }
                return \is_string($f) ? $f : '';
            };

            $a = ['status' => 200, 'typ' => 'text/html; charset=UTF-8', 'inhalt' => '', 'kopf' => [], 'sim' => $sim, 'probe' => []];
            if ($sim === 'konfig-koeder') {
                [$a['inhalt'], $a['typ']] = self::KONFIG[$pfad];
            } elseif ($sim === 'db-koeder') {
                if ($pfad === '/adminer.php') {
                    if ($post) {
                        $probe['anmeldungen'] = [Text::anmeldung($wert($felder, 'auth', 'username'), $wert($felder, 'auth', 'password'))];
                    }
                    $a['inhalt'] = self::adminer($post);
                } else {
                    if ($post) {
                        $probe['anmeldungen'] = [Text::anmeldung($wert($felder, 'pma_username'), $wert($felder, 'pma_password'))];
                    }
                    $a['inhalt'] = self::pma($post);
                }
            } elseif ($pfad === '/wp-login.php') {
                if ($post) {
                    $probe['anmeldungen'] = [Text::anmeldung($wert($felder, 'log'), $wert($felder, 'pwd'))];
                }
                $a['inhalt'] = self::wpLogin($post);
            } elseif ($pfad === '/xmlrpc.php') {
                if (!$post) {
                    $a['status'] = 405;
                    $a['typ'] = 'text/plain';
                    $a['inhalt'] = 'XML-RPC server accepts POST requests only.';
                } else {
                    \preg_match_all('#<methodName>\s*([A-Za-z0-9._]{1,64})\s*</methodName>#', $koerper, $m);
                    $methoden = \array_slice(\array_values(\array_unique($m[1])), 0, 5);
                    if ($methoden !== []) {
                        $probe['xmlrpc'] = $methoden;
                    }
                    $a['typ'] = 'text/xml; charset=UTF-8';
                    $a['inhalt'] = self::XMLRPC_FEHLER;
                }
            } elseif ($pfad === '/wp-admin' || \str_starts_with($pfad, '/wp-admin/')) {
                $a['status'] = 302;
                $a['kopf']['Location'] = '/wp-login.php?reauth=1';
            } elseif (\preg_match('#^/wp-content/plugins/([A-Za-z0-9._-]{1,64})/#', $pfad, $m) === 1) {
                $probe['plugin'] = [$m[1]];
            }
            $a['probe'] = $probe;
            return $a;
        }

        private static function istWp(string $pfad): bool
        {
            return \in_array($pfad, ['/wp-login.php', '/xmlrpc.php', '/wp-admin'], true)
                || \str_starts_with($pfad, '/wp-admin/')
                || \preg_match('#^/wp-content/plugins/[^/]+/#', $pfad) === 1;
        }

        private static function pma(bool $fehler): string
        {
            $meldung = $fehler ? '<div class="error">mysqli::real_connect(): (HY000/1045): Access denied</div>' : '';
            return "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>phpMyAdmin</title></head>\n<body>" . $meldung
                . "<form method=\"post\" action=\"index.php\"><input type=\"text\" name=\"pma_username\"><input type=\"password\" name=\"pma_password\"><input type=\"submit\" value=\"Go\"></form></body></html>\n";
        }

        private static function adminer(bool $fehler): string
        {
            $meldung = $fehler ? '<div class="error">Invalid credentials.</div>' : '';
            return "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Login - Adminer</title></head>\n<body>" . $meldung
                . "<form action=\"\" method=\"post\"><input name=\"auth[driver]\" type=\"hidden\" value=\"server\"><input name=\"auth[server]\"><input name=\"auth[username]\"><input type=\"password\" name=\"auth[password]\"><input name=\"auth[db]\"><input type=\"submit\" value=\"Login\"></form></body></html>\n";
        }

        private static function wpLogin(bool $fehler): string
        {
            $meldung = $fehler ? '<div id="login_error"><strong>Error:</strong> The username or password you entered is incorrect.</div>' : '';
            return "<!DOCTYPE html>\n<html lang=\"en-US\"><head><meta charset=\"UTF-8\"><title>Log In &lsaquo; WordPress</title></head>\n<body class=\"login\"><div id=\"login\">" . $meldung
                . "<form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\"><p><label for=\"user_login\">Username or Email Address</label><input type=\"text\" name=\"log\" id=\"user_login\"></p><p><label for=\"user_pass\">Password</label><input type=\"password\" name=\"pwd\" id=\"user_pass\"></p><p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" id=\"wp-submit\" value=\"Log In\"></p></form></div></body></html>\n";
        }

        private const XMLRPC_FEHLER = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member><member><name>faultString</name><value><string>Incorrect username or password.</string></value></member></struct></value></fault></methodResponse>\n";
    }

    // -----------------------------------------------------------------------
    // Speicher: Dokumente, atomar geändert

    interface Speicher
    {
        /** @return array<string,mixed>|null */
        public function lesen(string $name): ?array;

        /** Ändert ein Dokument unter Sperre; $f bekommt es per Referenz. */
        public function aendern(string $name, callable $f): mixed;

        /** @param array<string,mixed>|null $liste null löscht */
        public function sperrlisteSchreiben(?array $liste): void;

        /** @return array<string,mixed>|null */
        public function sperrlisteLesen(): ?array;
    }

    final class DateiSpeicher implements Speicher
    {
        public function __construct(private string $dir)
        {
            if (!\is_dir($dir) && !@\mkdir($dir, 0700, true) && !\is_dir($dir)) {
                throw new \RuntimeException('Datenverzeichnis nicht anlegbar');
            }
            // Liegt das Verzeichnis doch im Web-Wurzelverzeichnis: nichts herausgeben.
            $schutz = $dir . '/.htaccess';
            if (!\is_file($schutz)) {
                @\file_put_contents($schutz, "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
            }
        }

        public function lesen(string $name): ?array
        {
            $roh = @\file_get_contents($this->dir . '/' . $name . '.json');
            if (!\is_string($roh) || $roh === '') {
                return null;
            }
            $d = \json_decode($roh, true);
            return \is_array($d) ? $d : null;
        }

        public function aendern(string $name, callable $f): mixed
        {
            $sperre = \fopen($this->dir . '/' . $name . '.lock', 'c');
            if ($sperre === false || !\flock($sperre, \LOCK_EX)) {
                throw new \RuntimeException('Sperre nicht erhalten: ' . $name);
            }
            try {
                $d = $this->lesen($name) ?? [];
                $erg = $f($d);
                $this->schreiben($this->dir . '/' . $name . '.json', (string) \json_encode($d, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE));
                return $erg;
            } finally {
                \flock($sperre, \LOCK_UN);
                \fclose($sperre);
            }
        }

        /** Erst in eine Nachbardatei, dann umbenennen: nie eine halb geschriebene Datei. */
        private function schreiben(string $pfad, string $inhalt): void
        {
            $tmp = $pfad . '.' . \bin2hex(\random_bytes(4)) . '.tmp';
            if (\file_put_contents($tmp, $inhalt) === false || !\rename($tmp, $pfad)) {
                @\unlink($tmp);
                throw new \RuntimeException('nicht schreibbar: ' . \basename($pfad));
            }
        }

        public function sperrlisteSchreiben(?array $liste): void
        {
            $pfad = $this->dir . '/sperrliste.php';
            if ($liste === null) {
                @\unlink($pfad);
            } else {
                // Als PHP-Datei: Mit OPcache liegt die Liste im geteilten Speicher
                // und kostet je Anfrage fast nichts.
                $this->schreiben($pfad, "<?php\nreturn " . \var_export($liste, true) . ";\n");
            }
            if (\function_exists('opcache_invalidate')) {
                @\opcache_invalidate($pfad, true);
            }
        }

        public function sperrlisteLesen(): ?array
        {
            $pfad = $this->dir . '/sperrliste.php';
            if (!\is_file($pfad)) {
                return null;
            }
            // Pfad aus der eigenen Einstellung, Inhalt von var_export geschrieben.
            $l = include $pfad;
            return \is_array($l) ? $l : null;
        }
    }

    /** Puffer in der Datenbank des Webspace (MySQL/MariaDB). */
    final class PdoSpeicher implements Speicher
    {
        private \PDO $db;
        private string $treiber;
        private int $tiefe = 0;

        /** @param array{dsn:string,benutzer:string,passwort:string} $z */
        public function __construct(array $z)
        {
            $this->db = new \PDO($z['dsn'], $z['benutzer'] !== '' ? $z['benutzer'] : null, $z['passwort'] !== '' ? $z['passwort'] : null, [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_EMULATE_PREPARES => false,
            ]);
            $this->treiber = (string) $this->db->getAttribute(\PDO::ATTR_DRIVER_NAME);
            if ($this->treiber === 'mysql') {
                $this->db->exec('CREATE TABLE IF NOT EXISTS badbot_daten (name VARCHAR(64) NOT NULL PRIMARY KEY, wert MEDIUMTEXT NOT NULL) DEFAULT CHARSET=utf8mb4');
            } else {
                $this->db->exec('CREATE TABLE IF NOT EXISTS badbot_daten (name VARCHAR(64) NOT NULL PRIMARY KEY, wert TEXT NOT NULL)');
            }
        }

        public function lesen(string $name): ?array
        {
            $q = $this->db->prepare('SELECT wert FROM badbot_daten WHERE name = ?');
            $q->execute([$name]);
            $roh = $q->fetchColumn();
            if (!\is_string($roh)) {
                return null;
            }
            $d = \json_decode($roh, true);
            return \is_array($d) ? $d : null;
        }

        public function aendern(string $name, callable $f): mixed
        {
            // Verschachtelt (offen -> wartend) läuft alles in einer Transaktion.
            $aussen = $this->tiefe === 0;
            if ($aussen) {
                $this->db->beginTransaction();
            }
            $this->tiefe++;
            try {
                $neu = $this->treiber === 'mysql'
                    ? 'INSERT IGNORE INTO badbot_daten (name, wert) VALUES (?, ?)'
                    : 'INSERT OR IGNORE INTO badbot_daten (name, wert) VALUES (?, ?)';
                $this->db->prepare($neu)->execute([$name, '{}']);
                $q = $this->db->prepare($this->treiber === 'mysql'
                    ? 'SELECT wert FROM badbot_daten WHERE name = ? FOR UPDATE'
                    : 'SELECT wert FROM badbot_daten WHERE name = ?');
                $q->execute([$name]);
                $d = \json_decode((string) $q->fetchColumn(), true);
                if (!\is_array($d)) {
                    $d = [];
                }
                $erg = $f($d);
                $this->db->prepare('UPDATE badbot_daten SET wert = ? WHERE name = ?')
                    ->execute([(string) \json_encode($d, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE), $name]);
                $this->tiefe--;
                if ($aussen) {
                    $this->db->commit();
                }
                return $erg;
            } catch (\Throwable $t) {
                $this->tiefe--;
                if ($aussen && $this->db->inTransaction()) {
                    $this->db->rollBack();
                }
                throw $t;
            }
        }

        public function sperrlisteSchreiben(?array $liste): void
        {
            if ($liste === null) {
                $this->db->prepare('DELETE FROM badbot_daten WHERE name = ?')->execute(['sperrliste']);
                return;
            }
            $this->aendern('sperrliste', static function (array &$d) use ($liste): void {
                $d = $liste;
            });
        }

        public function sperrlisteLesen(): ?array
        {
            return $this->lesen('sperrliste');
        }
    }

    // -----------------------------------------------------------------------
    // Puffer: verdichtet je Fenster, Quelle und Simulation

    final class Puffer
    {
        /**
         * @param array<string,mixed> $offen
         * @param array{quelle:string,vorschalt:bool,von:string} $q
         * @param array<string,mixed> $probe
         */
        public static function hinzu(array &$offen, array $q, string $sim, int $port, int $zeit, array $probe, int $fenster, int $grenze): void
        {
            $f = \intdiv($zeit, $fenster) * $fenster;
            $schl = $f . '|' . $q['quelle'] . '|' . $sim . '|' . $q['von'];
            $saetze = &$offen['saetze'];
            if (!\is_array($saetze)) {
                $saetze = [];
            }
            if (!isset($saetze[$schl])) {
                if (\count($saetze) >= K::HOECHST_OFFEN) {
                    $offen['verworfen'] = (int) ($offen['verworfen'] ?? 0) + 1;
                    return;
                }
                $saetze[$schl] = ['fenster' => $f, 'quelle' => $q['quelle'], 'simulation' => $sim, 'anzahl' => 0,
                    'erster' => $zeit, 'letzter' => $zeit, 'ports' => [], 'gekuerzt' => false, 'probe' => [],
                    'vorschalt' => $q['vorschalt'], 'von' => $q['von']];
            }
            $e = &$saetze[$schl];
            $e['anzahl']++;
            $e['erster'] = \min($e['erster'], $zeit);
            $e['letzter'] = \max($e['letzter'], $zeit);
            if ($port > 0 && $port < 65536 && !\in_array($port, $e['ports'], true)) {
                if (\count($e['ports']) < K::HOECHST_PORTS) {
                    $e['ports'][] = $port;
                } else {
                    $e['gekuerzt'] = true;
                }
            }
            // Erste und verschiedenartige Beobachtungen, bis die Größe erreicht ist.
            foreach ($probe as $feld => $werte) {
                foreach ((array) $werte as $w) {
                    $liste = $e['probe'][$feld] ?? [];
                    if (\in_array($w, $liste, true)) {
                        continue;
                    }
                    $versuch = $e['probe'];
                    $versuch[$feld] = \array_merge($liste, [$w]);
                    if (\strlen((string) \json_encode($versuch, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE)) <= $grenze) {
                        $e['probe'] = $versuch;
                    }
                }
            }
        }

        /**
         * Nimmt abgeschlossene Fenster aus $offen und liefert sie als Datensätze.
         * @param array<string,mixed> $offen
         * @return array<int,array<string,mixed>>
         */
        public static function versiegeln(array &$offen, int $jetzt, int $fenster, bool $alles): array
        {
            $fertig = [];
            foreach ((array) ($offen['saetze'] ?? []) as $schl => $e) {
                if ($alles || $e['fenster'] + $fenster <= $jetzt) {
                    $fertig[] = self::datensatz($e);
                    unset($offen['saetze'][$schl]);
                }
            }
            return $fertig;
        }

        /** @param array<string,mixed> $e @return array<string,mixed> */
        private static function datensatz(array $e): array
        {
            $d = ['fenster' => self::zeit($e['fenster']), 'quelle' => $e['quelle'], 'simulation' => $e['simulation'],
                'anzahl' => $e['anzahl'], 'erster' => self::zeit($e['erster']), 'letzter' => self::zeit($e['letzter']),
                'ports' => $e['ports']];
            if ($e['gekuerzt']) {
                $d['ports_gekuerzt'] = true;
            }
            if ($e['probe'] !== []) {
                $d['stichprobe'] = $e['probe'];
            }
            if ($e['vorschalt']) {
                $d['ueber_vorschaltnetz'] = true;
                $d['verbindung_von'] = $e['von'];
            }
            return $d;
        }

        public static function zeit(int $t): string
        {
            return \gmdate('Y-m-d\TH:i:s\Z', $t);
        }

        /**
         * Hängt Datensätze als Stapel an die Warteliste. Zu alte fallen weg,
         * über der Grenze die ältesten.
         * @param array<string,mixed> $wartend
         * @param array<int,array<string,mixed>> $saetze
         */
        public static function einreihen(array &$wartend, array $saetze, int $jetzt): void
        {
            $stapel = (array) ($wartend['stapel'] ?? []);
            foreach (\array_chunk($saetze, K::HOECHST_SAETZE) as $teil) {
                foreach (self::teilenNachGroesse($teil) as $t) {
                    $stapel[] = ['stapel' => self::uuid(), 'datensaetze' => $t];
                }
            }
            $grenze = $jetzt - K::NACHLIEFERFRIST;
            $gesamt = 0;
            foreach ($stapel as $i => $s) {
                $alt = \strtotime((string) $s['datensaetze'][0]['fenster']);
                if ($alt !== false && $alt < $grenze) {
                    $wartend['verworfen'] = (int) ($wartend['verworfen'] ?? 0) + \count($s['datensaetze']);
                    unset($stapel[$i]);
                    continue;
                }
                $gesamt += \count($s['datensaetze']);
            }
            $stapel = \array_values($stapel);
            while ($gesamt > K::HOECHST_WARTEND && $stapel !== []) {
                $weg = \array_shift($stapel);
                $gesamt -= \count($weg['datensaetze']);
                $wartend['verworfen'] = (int) ($wartend['verworfen'] ?? 0) + \count($weg['datensaetze']);
            }
            $wartend['stapel'] = $stapel;
        }

        /**
         * @param array<int,array<string,mixed>> $saetze
         * @return array<int,array<int,array<string,mixed>>>
         */
        private static function teilenNachGroesse(array $saetze): array
        {
            if (\count($saetze) <= 1 || \strlen((string) \json_encode($saetze)) <= K::HOECHST_BYTES) {
                return [$saetze];
            }
            $h = \intdiv(\count($saetze), 2);
            return \array_merge(self::teilenNachGroesse(\array_slice($saetze, 0, $h)), self::teilenNachGroesse(\array_slice($saetze, $h)));
        }

        /** Teilt einen Stapel in zwei mit neuen Kennungen (413). @param array<string,mixed> $wartend */
        public static function teilen(array &$wartend, string $kennung): void
        {
            foreach ((array) ($wartend['stapel'] ?? []) as $i => $s) {
                if ($s['stapel'] !== $kennung) {
                    continue;
                }
                $n = \count($s['datensaetze']);
                if ($n < 2) {
                    \array_splice($wartend['stapel'], $i, 1);
                    $wartend['verworfen'] = (int) ($wartend['verworfen'] ?? 0) + $n;
                    return;
                }
                $h = \intdiv($n, 2);
                \array_splice($wartend['stapel'], $i, 1, [
                    ['stapel' => self::uuid(), 'datensaetze' => \array_slice($s['datensaetze'], 0, $h)],
                    ['stapel' => self::uuid(), 'datensaetze' => \array_slice($s['datensaetze'], $h)],
                ]);
                return;
            }
        }

        /** @param array<string,mixed> $wartend */
        public static function entfernen(array &$wartend, string $kennung): void
        {
            $wartend['stapel'] = \array_values(\array_filter((array) ($wartend['stapel'] ?? []),
                static fn (array $s): bool => $s['stapel'] !== $kennung));
        }

        public static function uuid(): string
        {
            $b = \random_bytes(16);
            $b[6] = \chr((\ord($b[6]) & 0x0f) | 0x40);
            $b[8] = \chr((\ord($b[8]) & 0x3f) | 0x80);
            $h = \bin2hex($b);
            return \substr($h, 0, 8) . '-' . \substr($h, 8, 4) . '-' . \substr($h, 12, 4) . '-' . \substr($h, 16, 4) . '-' . \substr($h, 20);
        }
    }

    // -----------------------------------------------------------------------
    // Plattform

    final class Antwort
    {
        /** @param array<string,mixed>|null $daten */
        public function __construct(public int $status, public ?array $daten, public int $retryAfter = 0, public string $fehler = '')
        {
        }

        public function endgueltig(): bool
        {
            return \in_array($this->status, [401, 403, 426], true);
        }
    }

    final class Plattform
    {
        public function __construct(private string $basis, private string $schluessel)
        {
        }

        /** @param array<string,mixed>|null $ein @param array<string,string> $kopf */
        public function anfrage(string $methode, string $pfad, ?array $ein = null, array $kopf = []): Antwort
        {
            $koerper = null;
            $kopf['Authorization'] = 'Bearer ' . $this->schluessel;
            $kopf['User-Agent'] = 'badbot-collector/' . BADBOT_COLLECTOR_VERSION . ' (php)';
            if ($ein !== null) {
                $koerper = (string) \json_encode($ein, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE);
                $kopf['Content-Type'] = 'application/json';
                if (\strlen($koerper) > 1024 && \function_exists('gzencode')) {
                    $koerper = (string) \gzencode($koerper);
                    $kopf['Content-Encoding'] = 'gzip';
                }
            }
            $url = $this->basis . '/v1' . $pfad;
            $zeilen = [];
            foreach ($kopf as $k => $v) {
                $zeilen[] = $k . ': ' . $v;
            }
            if (\function_exists('curl_init')) {
                return $this->curl($methode, $url, $zeilen, $koerper);
            }
            return $this->strom($methode, $url, $zeilen, $koerper);
        }

        /** @param string[] $zeilen */
        private function curl(string $methode, string $url, array $zeilen, ?string $koerper): Antwort
        {
            $c = \curl_init($url);
            $retry = 0;
            \curl_setopt_array($c, [
                \CURLOPT_CUSTOMREQUEST => $methode,
                \CURLOPT_HTTPHEADER => $zeilen,
                \CURLOPT_RETURNTRANSFER => true,
                \CURLOPT_TIMEOUT => 20,
                \CURLOPT_CONNECTTIMEOUT => 8,
                \CURLOPT_FOLLOWLOCATION => false,
                \CURLOPT_SSL_VERIFYPEER => true,
                \CURLOPT_SSL_VERIFYHOST => 2,
                \CURLOPT_HEADERFUNCTION => static function ($c, string $z) use (&$retry): int {
                    if (\stripos($z, 'retry-after:') === 0) {
                        $retry = (int) \trim(\substr($z, 12));
                    }
                    return \strlen($z);
                },
            ]);
            if ($koerper !== null) {
                \curl_setopt($c, \CURLOPT_POSTFIELDS, $koerper);
            }
            $roh = \curl_exec($c);
            $status = (int) \curl_getinfo($c, \CURLINFO_RESPONSE_CODE);
            $fehler = \curl_error($c);
            if (!\is_string($roh)) {
                return new Antwort(0, null, 0, $fehler !== '' ? $fehler : 'keine Antwort');
            }
            return $this->auswerten($status, $roh, $retry);
        }

        /** @param string[] $zeilen */
        private function strom(string $methode, string $url, array $zeilen, ?string $koerper): Antwort
        {
            $ctx = \stream_context_create([
                'http' => ['method' => $methode, 'header' => \implode("\r\n", $zeilen), 'content' => $koerper ?? '',
                    'timeout' => 20, 'ignore_errors' => true, 'follow_location' => 0],
                'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
            ]);
            $roh = @\file_get_contents($url, false, $ctx);
            $kopf = \http_get_last_response_headers() ?? [];
            if (!\is_string($roh) || $kopf === []) {
                return new Antwort(0, null, 0, 'keine Antwort');
            }
            $status = \preg_match('#^HTTP/\S+\s+(\d{3})#', (string) $kopf[0], $m) === 1 ? (int) $m[1] : 0;
            $retry = 0;
            foreach ($kopf as $z) {
                if (\stripos((string) $z, 'retry-after:') === 0) {
                    $retry = (int) \trim(\substr((string) $z, 12));
                }
            }
            return $this->auswerten($status, $roh, $retry);
        }

        private function auswerten(int $status, string $roh, int $retry): Antwort
        {
            $d = $roh === '' ? null : \json_decode(\substr($roh, 0, 1 << 20), true);
            $d = \is_array($d) ? $d : null;
            $fehler = $status >= 400 ? (string) ($d['fehler'] ?? ('HTTP ' . $status)) : '';
            return new Antwort($status, $d, $retry, $fehler);
        }
    }

    // -----------------------------------------------------------------------
    // Collector: Anfragen, Runde, Kommandozeile

    final class Collector
    {
        public Plattform $plattform;

        public function __construct(public Einstellung $e, public Speicher $sp, ?Plattform $p = null)
        {
            $this->plattform = $p ?? new Plattform($e->api, $e->schluessel);
        }

        public static function laden(string $neben): self
        {
            $e = Einstellung::laden(Einstellung::pfad($neben));
            $sp = $e->speicher === 'pdo' ? new PdoSpeicher($e->pdo) : new DateiSpeicher($e->daten);
            return new self($e, $sp);
        }

        /** @return array<string,mixed> */
        private function konfig(): array
        {
            $z = $this->sp->lesen('zustand') ?? [];
            return \is_array($z['konfig'] ?? null) ? $z['konfig'] : [];
        }

        /** @param array<string,mixed> $k @return array<string,bool> */
        public static function aktiv(array $k): array
        {
            $a = [];
            foreach ((array) ($k['simulationen'] ?? []) as $s) {
                if (\in_array($s['name'] ?? '', K::SIMULATIONEN, true)) {
                    $a[(string) $s['name']] = (bool) ($s['aktiv'] ?? false);
                }
            }
            return $a;
        }

        public function webroot(): string
        {
            if ($this->e->webroot !== '') {
                return $this->e->webroot;
            }
            $z = $this->sp->lesen('zustand') ?? [];
            return (string) ($z['webroot'] ?? '');
        }

        public function wordpressVorhanden(): bool
        {
            $w = $this->webroot();
            return $w !== '' && (\is_file($w . '/wp-login.php') || \is_file($w . '/wp-includes/version.php'));
        }

        /**
         * Eine Anfrage an einen Köderpfad: antworten, festhalten.
         * @param array<string,mixed> $server
         * @return array{status:int,typ:string,inhalt:string,kopf:array<string,string>,sim:?string,probe:array<string,mixed>}
         */
        public function koeder(array $server, string $koerper, int $jetzt): array
        {
            $k = $this->konfig();
            $doc = \rtrim((string) ($server['DOCUMENT_ROOT'] ?? ''), '/');
            if ($this->e->webroot === '' && $doc !== '') {
                $z = $this->sp->lesen('zustand') ?? [];
                if (($z['webroot'] ?? '') !== $doc) {
                    $this->sp->aendern('zustand', static function (array &$z) use ($doc): void {
                        $z['webroot'] = $doc;
                    });
                }
            }
            $a = Koeder::antwort($server, $koerper, self::aktiv($k), $this->wordpressVorhanden());
            if ($a['sim'] !== null) {
                $q = Netz::quelle($server, (array) ($k['vertrauenswuerdige_vorschaltnetze'] ?? []));
                if ($q !== null) {
                    $fenster = (int) ($k['fenster_sekunden'] ?? 300);
                    $grenze = \min((int) ($k['stichprobe_bytes'] ?? 1024), K::HOECHST_STICHPROBE);
                    $port = (int) ($server['SERVER_PORT'] ?? 0);
                    $sim = $a['sim'];
                    $probe = $a['probe'];
                    $this->sp->aendern('offen', static function (array &$o) use ($q, $sim, $port, $jetzt, $probe, $fenster, $grenze): void {
                        Puffer::hinzu($o, $q, $sim, $port, $jetzt, $probe, $fenster > 0 ? $fenster : 300, $grenze > 0 ? $grenze : 2048);
                    });
                }
            }
            return $a;
        }

        /**
         * Sperrprüfung für gewöhnliche Anfragen.
         * @param array<string,mixed> $server
         */
        public function gesperrt(array $server, int $jetzt): bool
        {
            $l = $this->sp->sperrlisteLesen();
            if ($l === null || (int) ($l['gueltig_bis'] ?? 0) < $jetzt) {
                return false;
            }
            $q = Netz::quelle($server, (array) ($l['vorschaltnetze'] ?? []));
            if ($q === null || Netz::enthalten($q['quelle'], $this->e->ausnahmen) || self::nieSperren($q['quelle'])) {
                return false;
            }
            $hex = (string) Netz::hex($q['quelle']);
            return Netz::suchen((array) ($l[\strlen($hex) === 8 ? 'v4' : 'v6'] ?? []), $hex);
        }

        private static function nieSperren(string $ip): bool
        {
            return Netz::enthalten($ip, ['127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10', '169.254.0.0/16', '100.64.0.0/10']);
        }

        /** Ist die nächste Runde fällig? Liest nur den kleinen Zustand. */
        public function faellig(int $jetzt): bool
        {
            $z = $this->sp->lesen('zustand') ?? [];
            return (int) ($z['naechste_runde'] ?? 0) <= $jetzt && (int) ($z['laeuft_bis'] ?? 0) <= $jetzt;
        }

        /**
         * Lebenszeichen, Konfiguration, Meldung, Sperrliste.
         * @return string[] Bericht, eine Zeile je Schritt
         */
        public function runde(int $jetzt, bool $erzwingen = false, bool $alles = false): array
        {
            $bericht = [];
            $los = $this->sp->aendern('zustand', static function (array &$z) use ($jetzt, $erzwingen): bool {
                if ((int) ($z['laeuft_bis'] ?? 0) > $jetzt || (!$erzwingen && (int) ($z['naechste_runde'] ?? 0) > $jetzt)) {
                    return false;
                }
                $takt = (int) ($z['konfig']['takt_sekunden'] ?? 60);
                if (!empty($z['stumm'])) {
                    $takt = 600;
                }
                $z['laeuft_bis'] = $jetzt + 120;
                $z['naechste_runde'] = $jetzt + \max(30, $takt);
                return true;
            });
            if (!$los) {
                return ['Runde läuft bereits oder ist nicht fällig'];
            }
            if (\function_exists('set_time_limit')) {
                @\set_time_limit(90);
            }
            $neu = [];
            try {
                $z = $this->sp->lesen('zustand') ?? [];
                $k = \is_array($z['konfig'] ?? null) ? $z['konfig'] : [];
                $fenster = (int) ($k['fenster_sekunden'] ?? 300);

                // Abgeschlossene Fenster einreihen -- in einem Zug, damit nichts
                // verloren geht oder doppelt ankommt.
                $sp = $this->sp;
                $sp->aendern('offen', static function (array &$o) use ($sp, $jetzt, $fenster, $alles): void {
                    $fertig = Puffer::versiegeln($o, $jetzt, $fenster > 0 ? $fenster : 300, $alles);
                    $sp->aendern('wartend', static function (array &$w) use ($fertig, $jetzt): void {
                        Puffer::einreihen($w, $fertig, $jetzt);
                    });
                });

                $a = $this->plattform->anfrage('POST', '/lebenszeichen', [
                    'version' => BADBOT_COLLECTOR_VERSION,
                    'plattform' => 'php',
                    'faehigkeiten' => \array_merge(K::SIMULATIONEN, ['sperren-php']),
                    'uhrzeit' => Puffer::zeit($jetzt),
                    'puffer' => $this->pufferStand(),
                ]);
                if ($a->endgueltig()) {
                    $neu['stumm'] = true;
                    $neu['fehler'] = $a->fehler;
                    $bericht[] = 'Plattform lehnt den Collector ab (' . $a->status . ' ' . $a->fehler . '); Meldungen eingestellt';
                    return $bericht;
                }
                if ($a->status !== 200 || $a->daten === null) {
                    $neu['fehler'] = 'Plattform nicht erreichbar: ' . ($a->fehler !== '' ? $a->fehler : (string) $a->status);
                    $bericht[] = $neu['fehler'];
                    return $bericht;
                }
                $lz = $a->daten;
                $neu['stumm'] = false;
                $neu['fehler'] = '';
                $neu['hinweise'] = \array_values(\array_map('strval', (array) ($lz['hinweise'] ?? [])));
                $neu['aktuelle_version'] = (string) ($lz['aktuelle_version'] ?? '');
                $neu['letzter_kontakt'] = $jetzt;
                $bericht[] = 'Lebenszeichen angenommen';

                if ((string) ($lz['konfiguration_stand'] ?? '') !== (string) ($k['stand'] ?? '')) {
                    $kopf = isset($k['stand']) ? ['If-None-Match' => '"' . $k['stand'] . '"'] : [];
                    $ka = $this->plattform->anfrage('GET', '/konfiguration', null, $kopf);
                    if ($ka->status === 200 && $ka->daten !== null) {
                        $k = $ka->daten;
                        $neu['konfig'] = $k;
                        $bericht[] = 'Konfiguration ' . (string) ($k['stand'] ?? '') . ' übernommen';
                        // Vorschaltnetze stehen auch in der Sperrliste.
                        $this->sperrlisteNeuSchreiben($k);
                    }
                }

                // Ist melden, sobald es sich ändert -- auch wenn WordPress erst
                // nachträglich auf die Seite kommt.
                if ($k !== []) {
                    $ist = $this->ist($k);
                    $zeichen = \md5((string) \json_encode($ist));
                    if ($zeichen !== ($z['ist_gemeldet'] ?? '')) {
                        if ($this->plattform->anfrage('POST', '/konfiguration/ist', $ist)->status === 200) {
                            $neu['ist_gemeldet'] = $zeichen;
                        }
                    }
                }

                if ((int) ($z['pause_bis'] ?? 0) <= $jetzt) {
                    $bericht = \array_merge($bericht, $this->melden($jetzt, $neu));
                }

                $stufe = (string) ($k['sperren']['stufe'] ?? 'aus');
                if ($stufe === 'aus' || $this->e->trocken) {
                    $this->sp->sperrlisteSchreiben(null);
                } else {
                    $bericht = \array_merge($bericht, $this->sperrliste((string) ($lz['sperrliste_stand'] ?? ''), $k));
                }
                return $bericht;
            } finally {
                $this->sp->aendern('zustand', static function (array &$z) use ($neu): void {
                    foreach ($neu as $schl => $w) {
                        $z[$schl] = $w;
                    }
                    $z['laeuft_bis'] = 0;
                    $z['letzte_runde'] = \time();
                });
            }
        }

        /** @return array{datensaetze:int,verworfen_seit_start:int} */
        private function pufferStand(): array
        {
            $o = $this->sp->lesen('offen') ?? [];
            $w = $this->sp->lesen('wartend') ?? [];
            $n = \count((array) ($o['saetze'] ?? []));
            foreach ((array) ($w['stapel'] ?? []) as $s) {
                $n += \count($s['datensaetze']);
            }
            return ['datensaetze' => $n, 'verworfen_seit_start' => (int) ($o['verworfen'] ?? 0) + (int) ($w['verworfen'] ?? 0)];
        }

        /** @param array<string,mixed> $k @return array<string,mixed> */
        public function ist(array $k): array
        {
            $wp = $this->wordpressVorhanden();
            $l = [];
            foreach ((array) ($k['simulationen'] ?? []) as $s) {
                $name = (string) ($s['name'] ?? '');
                $aktiv = (bool) ($s['aktiv'] ?? false);
                $e = ['name' => $name, 'aktiv' => $aktiv, 'ports' => []];
                if (!\in_array($name, K::SIMULATIONEN, true)) {
                    $e['aktiv'] = false;
                    $e['fehler'] = $aktiv ? 'gibt es im PHP-Collector nicht' : '';
                } elseif ($name === 'wp-koeder' && $aktiv && $wp) {
                    $e['aktiv'] = false;
                    $e['fehler'] = 'WordPress auf dieser Seite gefunden; Köder bleiben aus';
                }
                $l[] = $e;
            }
            return ['stand' => (string) ($k['stand'] ?? ''), 'simulationen' => $l];
        }

        /** @param array<string,mixed> $neu @return string[] */
        private function melden(int $jetzt, array &$neu): array
        {
            $bericht = [];
            for ($i = 0; $i < 20; $i++) {
                $w = $this->sp->lesen('wartend') ?? [];
                $s = ((array) ($w['stapel'] ?? []))[0] ?? null;
                if ($s === null) {
                    break;
                }
                $a = $this->plattform->anfrage('POST', '/ereignisse', $s);
                $kennung = (string) $s['stapel'];
                if ($a->status === 200 || $a->status === 409) {
                    $this->sp->aendern('wartend', static function (array &$w) use ($kennung): void {
                        Puffer::entfernen($w, $kennung);
                    });
                    $angenommen = $a->status === 409 ? \count($s['datensaetze']) : (int) ($a->daten['angenommen'] ?? 0);
                    $bericht[] = 'Stapel gemeldet: ' . $angenommen . ' angenommen, ' . (int) ($a->daten['verworfen'] ?? 0) . ' verworfen';
                    foreach ((array) ($a->daten['hinweise'] ?? []) as $h) {
                        $neu['hinweise'][] = (string) $h;
                    }
                } elseif ($a->status === 413) {
                    $this->sp->aendern('wartend', static function (array &$w) use ($kennung): void {
                        Puffer::teilen($w, $kennung);
                    });
                } elseif ($a->status === 400) {
                    $this->sp->aendern('wartend', static function (array &$w) use ($kennung, $s): void {
                        Puffer::entfernen($w, $kennung);
                        $w['verworfen'] = (int) ($w['verworfen'] ?? 0) + \count($s['datensaetze']);
                    });
                    $bericht[] = 'Stapel unlesbar für die Plattform, verworfen';
                } elseif ($a->status === 429) {
                    $neu['pause_bis'] = $jetzt + \max(60, $a->retryAfter);
                    $bericht[] = 'Plattform bittet um Pause';
                    break;
                } else {
                    if ($a->endgueltig()) {
                        $neu['stumm'] = true;
                    }
                    $bericht[] = 'Stapel nicht gemeldet, später erneut (' . $a->status . ')';
                    break;
                }
            }
            return $bericht;
        }

        /** @param array<string,mixed> $k @return string[] */
        private function sperrliste(string $stand, array $k): array
        {
            $alt = $this->sp->sperrlisteLesen();
            $altStand = (string) ($alt['stand'] ?? '');
            if ($stand === '' || $stand === $altStand) {
                return [];
            }
            $kopf = $altStand !== '' ? ['If-None-Match' => '"' . $altStand . '"'] : [];
            $a = $this->plattform->anfrage('GET', '/sperrliste' . ($altStand !== '' ? '?seit=' . \rawurlencode($altStand) : ''), null, $kopf);
            if ($a->status === 304) {
                return [];
            }
            if ($a->status !== 200 || $a->daten === null) {
                // Der letzte gültige Stand bleibt bis gueltig_bis.
                return ['Sperrliste nicht abrufbar (' . $a->status . ')'];
            }
            $l = $a->daten;
            $netze = [];
            if (($l['art'] ?? '') !== 'voll') {
                foreach ((array) ($alt['netze'] ?? []) as $n) {
                    $netze[(string) $n] = true;
                }
            }
            foreach ((array) ($l['entfernt'] ?? []) as $n) {
                $nn = Netz::netzNormal((string) $n);
                if ($nn !== null) {
                    unset($netze[$nn]);
                }
            }
            foreach ((array) ($l['hinzu'] ?? []) as $n) {
                $nn = Netz::netzNormal((string) $n);
                if ($nn === null) {
                    return ['Sperrliste unbrauchbar, alter Stand bleibt'];
                }
                $netze[$nn] = true;
            }
            $bis = \strtotime((string) ($l['gueltig_bis'] ?? ''));
            $this->sp->sperrlisteSchreiben(self::kompilieren((string) ($l['stand'] ?? ''), $bis === false ? 0 : $bis, \array_keys($netze), $k));
            return ['Sperrliste ' . (string) ($l['stand'] ?? '') . ': ' . \count($netze) . ' Netze'];
        }

        /** @param array<string,mixed> $k */
        private function sperrlisteNeuSchreiben(array $k): void
        {
            $alt = $this->sp->sperrlisteLesen();
            if ($alt !== null) {
                $this->sp->sperrlisteSchreiben(self::kompilieren((string) $alt['stand'], (int) $alt['gueltig_bis'], (array) $alt['netze'], $k));
            }
        }

        /**
         * @param string[] $netze
         * @param array<string,mixed> $k
         * @return array<string,mixed>
         */
        public static function kompilieren(string $stand, int $gueltigBis, array $netze, array $k): array
        {
            // Was eine Liste nie sperren darf, fällt heraus -- ob Fehler oder
            // manipulierte Liste: sonst bekäme jeder Besucher der Seite 403.
            $netze = \array_values(\array_filter($netze, static fn ($n): bool => !Netz::nieSperrbar((string) $n)));
            $b = Netz::bereiche($netze);
            return ['stand' => $stand, 'gueltig_bis' => $gueltigBis, 'netze' => \array_values($netze),
                'v4' => $b['v4'], 'v6' => $b['v6'],
                'vorschaltnetze' => \array_values(\array_map('strval', (array) ($k['vertrauenswuerdige_vorschaltnetze'] ?? [])))];
        }

        // -------------------------------------------------------------------
        // Kommandozeile

        /** @param string[] $argv */
        public static function kommandozeile(string $datei, array $argv): int
        {
            $befehl = $argv[1] ?? '--hilfe';
            if ($befehl === '--version') {
                echo BADBOT_COLLECTOR_VERSION, "\n";
                return 0;
            }
            if ($befehl === '--htaccess' || $befehl === '--nginx') {
                $url = $argv[2] ?? '';
                if (!\str_starts_with($url, '/')) {
                    \fwrite(\STDERR, "Aufruf: php badbot.php $befehl /pfad/zu/badbot.php\n");
                    return 2;
                }
                $wp = true;
                try {
                    $wp = !self::laden($datei)->wordpressVorhanden();
                } catch (\Throwable $t) {
                    // ohne Konfiguration: alle Köder
                }
                echo $befehl === '--htaccess' ? self::htaccess($url, $wp) : self::nginx($url, $wp);
                return 0;
            }
            try {
                $c = self::laden($datei);
            } catch (\Throwable $t) {
                \fwrite(\STDERR, 'badbot-collector: ' . $t->getMessage() . "\n");
                return 1;
            }
            if ($befehl === '--runde' || $befehl === '--pruefen') {
                if (isset($argv[2]) && $argv[2] !== '--alles') {
                    \fwrite(\STDERR, "unbekannte Option\n");
                    return 2;
                }
                foreach ($c->runde(\time(), true, ($argv[2] ?? '') === '--alles') as $z) {
                    echo $z, "\n";
                }
                $z = $c->sp->lesen('zustand') ?? [];
                if ($befehl === '--pruefen') {
                    echo 'Webroot: ', $c->webroot() !== '' ? $c->webroot() : '(noch unbekannt -- webroot in der Konfiguration setzen oder einen Köderpfad aufrufen)', "\n";
                    echo 'WordPress gefunden: ', $c->wordpressVorhanden() ? 'ja (WordPress-Köder bleiben aus)' : 'nein', "\n";
                    $l = $c->sp->sperrlisteLesen();
                    echo 'Sperrliste: ', $l === null ? 'keine' : ((string) $l['stand'] . ', ' . \count((array) $l['netze']) . ' Netze, gültig bis ' . \gmdate('Y-m-d H:i', (int) $l['gueltig_bis']) . ' UTC'), "\n";
                    foreach ((array) ($z['hinweise'] ?? []) as $h) {
                        echo 'Hinweis der Plattform: ', self::hinweisText((string) $h), "\n";
                    }
                    if (($z['aktuelle_version'] ?? '') !== '' && $z['aktuelle_version'] !== BADBOT_COLLECTOR_VERSION) {
                        echo 'Neue Version verfügbar: ', (string) $z['aktuelle_version'], "\n";
                    }
                }
                return ($z['fehler'] ?? '') === '' ? 0 : 1;
            }
            if ($befehl === '--htaccess-sperren') {
                $l = $c->sp->sperrlisteLesen();
                echo self::htaccessSperren($l === null ? [] : (array) $l['netze']);
                return 0;
            }
            \fwrite(\STDERR, "Befehle: --pruefen, --runde [--alles], --htaccess /pfad/zu/badbot.php, --nginx /pfad/zu/badbot.php, --htaccess-sperren, --version\n");
            return $befehl === '--hilfe' ? 0 : 2;
        }

        public static function hinweisText(string $h): string
        {
            return match ($h) {
                'quell-ip-fehlerhaft' => 'Die Seite sieht nicht die echte Quelladresse (Proxy des Hosters?). Die Plattform verwirft die Meldungen.',
                'uhrzeit-abweichung' => 'Die Uhr des Servers weicht ab.',
                'puffer-voll' => 'Der Puffer ist übergelaufen; Beobachtungen gingen verloren.',
                'schluessel-laeuft-ab' => 'Der API-Schlüssel läuft bald ab.',
                default => $h,
            };
        }

        public static function htaccess(string $url, bool $wp): string
        {
            $muster = Koeder::MUSTER_KONFIG . '|' . Koeder::MUSTER_DB . ($wp ? '|' . Koeder::MUSTER_WP : '');
            return "# BEGIN badbot-collector -- vor allen anderen Regeln einfügen\n"
                . "<IfModule mod_rewrite.c>\nRewriteEngine On\n"
                . "# Vorhandene Dateien und Verzeichnisse werden nie überdeckt.\n"
                . "RewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\n"
                . 'RewriteRule ^(' . $muster . ')$ ' . $url . " [L]\n</IfModule>\n# END badbot-collector\n"
                . ($wp ? '' : "# WordPress gefunden: WordPress-Köder ausgelassen.\n");
        }

        public static function nginx(string $url, bool $wp): string
        {
            $muster = Koeder::MUSTER_KONFIG . '|' . Koeder::MUSTER_DB . ($wp ? '|' . Koeder::MUSTER_WP : '');
            return "# badbot-collector: in den server-Block, vor andere location-Blöcke.\n"
                . 'location ~ ^/(' . $muster . ")\$ {\n    try_files \$uri \$uri/ @badbot;\n}\n"
                . "location @badbot {\n    include fastcgi_params;\n    fastcgi_param SCRIPT_FILENAME \$document_root" . $url . ";\n"
                . "    fastcgi_pass unix:/run/php/php-fpm.sock;  # anpassen\n}\n";
        }

        /** @param string[] $netze */
        public static function htaccessSperren(array $netze): string
        {
            $t = "# BEGIN badbot-sperren -- erzeugt, nicht von Hand ändern\n<RequireAll>\nRequire all granted\n";
            foreach (\array_chunk($netze, 50) as $teil) {
                $t .= 'Require not ip ' . \implode(' ', $teil) . "\n";
            }
            return $t . "</RequireAll>\n# END badbot-sperren\n";
        }
    }

    /** Ausgabe einer Köderantwort. @param array{status:int,typ:string,inhalt:string,kopf:array<string,string>} $a */
    function senden(array $a): void
    {
        \http_response_code($a['status']);
        \header('Content-Type: ' . $a['typ']);
        \header('Cache-Control: no-store');
        \header('X-Robots-Tag: noindex, nofollow');
        foreach ($a['kopf'] as $k => $v) {
            \header($k . ': ' . $v);
        }
        \header('Content-Length: ' . \strlen($a['inhalt']));
        echo $a['inhalt'];
    }

    /** Antwort abschließen, damit die Runde den Aufrufer nicht aufhält. */
    function abschliessen(): bool
    {
        if (\function_exists('fastcgi_finish_request')) {
            \fastcgi_finish_request();
            return true;
        }
        if (\function_exists('litespeed_finish_request')) {
            \litespeed_finish_request();
            return true;
        }
        \ignore_user_abort(true);
        while (\ob_get_level() > 0) {
            @\ob_end_flush();
        }
        \flush();
        return false;
    }

    /** Läuft dieses PHP? Ältere Versionen lehnt der Collector ab. */
    function phpPassend(int $version = \PHP_VERSION_ID): bool
    {
        // Nur die Testumgebung darf das abschalten (tests/cli.php, tests/router.php).
        return $version >= BADBOT_PHP_MINDESTENS || \defined('BADBOT_ALTES_PHP_ERLAUBEN');
    }

    function einstieg(string $datei): void
    {
        static $erledigt = false;
        if ($erledigt) {
            return;
        }
        $erledigt = true;
        if (!phpPassend()) {
            $text = 'badbot-collector: braucht PHP 8.5 oder neuer, läuft unter ' . \PHP_VERSION;
            if (\PHP_SAPI === 'cli') {
                \fwrite(\STDERR, $text . "\n");
                exit(1);
            }
            // Weder Köder noch Sperre -- die Webseite läuft unverändert weiter.
            \error_log($text);
            return;
        }

        $skript = (string) ($_SERVER['SCRIPT_FILENAME'] ?? '');
        $direkt = $skript !== '' && \realpath($skript) === \realpath($datei);
        if (\PHP_SAPI === 'cli') {
            if ($direkt) {
                exit(Collector::kommandozeile($datei, (array) ($_SERVER['argv'] ?? [])));
            }
            return; // von einem fremden Kommandozeilenskript eingebunden: nichts tun
        }

        $jetzt = \time();
        if ($direkt) {
            // Köderpfad, über die Umleitung hierher geleitet.
            try {
                $c = Collector::laden($datei);
                $koerper = (string) @\file_get_contents('php://input', false, null, 0, K::KOERPER);
                senden($c->koeder($_SERVER, $koerper, $jetzt));
            } catch (\Throwable $t) {
                \error_log('badbot-collector: ' . $t->getMessage());
                senden(['status' => 404, 'typ' => 'text/plain', 'inhalt' => "Not Found\n", 'kopf' => []]);
                return;
            }
            abschliessen();
            try {
                if ($c->faellig($jetzt)) {
                    $c->runde($jetzt);
                }
            } catch (\Throwable $t) {
                \error_log('badbot-collector: ' . $t->getMessage());
            }
            return;
        }

        // Vorgeschaltet vor die Webseite: Sperrprüfung. Darf die Seite nie stören.
        try {
            $c = Collector::laden($datei);
            if ($c->gesperrt($_SERVER, $jetzt)) {
                \http_response_code(403);
                \header('Content-Type: text/plain');
                \header('Cache-Control: no-store');
                echo "403 Forbidden\n";
                exit;
            }
            if ($c->faellig($jetzt) && \function_exists('fastcgi_finish_request')) {
                // Nur wo sich die Antwort vorher abschließen lässt: Besucher der
                // Seite warten nie auf die Plattform.
                \register_shutdown_function(static function () use ($c, $jetzt): void {
                    try {
                        \fastcgi_finish_request();
                        $c->runde($jetzt);
                    } catch (\Throwable $t) {
                        \error_log('badbot-collector: ' . $t->getMessage());
                    }
                });
            }
        } catch (\Throwable $t) {
            \error_log('badbot-collector: ' . $t->getMessage());
        }
    }
}

if (!\defined('BADBOT_TEST')) {
    einstieg(__FILE__);
}
