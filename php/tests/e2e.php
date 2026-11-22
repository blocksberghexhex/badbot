<?php
// Ende-zu-Ende mit echtem PHP-Webserver: Webseite mit Umleitung und
// Sperrprüfung, Kommandozeile, nachgebildete Plattform. php tests/e2e.php
declare(strict_types=1);

const BADBOT_TEST = true;
require __DIR__ . '/../badbot.php';
require_once __DIR__ . '/lauf_hilfen.php';

use BadbotCollector\Koeder;

$tmp = tmpdir();
mkdir("$tmp/web");
$badbot = realpath(__DIR__ . '/../badbot.php');
$portA = freierPort();
$portS = freierPort();
$attrappe = "$tmp/attrappe.json";
file_put_contents($attrappe, json_encode([
    'konfig' => ['stand' => 'k-1', 'takt_sekunden' => 60, 'fenster_sekunden' => 300, 'stichprobe_bytes' => 2048,
        'simulationen' => [['name' => 'wp-koeder', 'ports' => [], 'aktiv' => true], ['name' => 'konfig-koeder', 'ports' => [], 'aktiv' => true],
            ['name' => 'db-koeder', 'ports' => [], 'aktiv' => true]],
        'sperren' => ['stufe' => 'netz'], 'vertrauenswuerdige_vorschaltnetze' => ['127.0.0.0/8']],
    'sperrliste' => ['stand' => 's-1', 'art' => 'voll', 'gueltig_bis' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600),
        'hinzu' => ['198.51.100.0/24', '2001:db8::/32'], 'entfernt' => []],
]));
file_put_contents("$tmp/konfig.php", '<?php return ' . var_export([
    'schluessel' => 'bb1_test_geheim', 'daten' => "$tmp/daten", 'webroot' => "$tmp/web", 'api' => "http://127.0.0.1:$portA",
], true) . ';');

$env = ['ATTRAPPE_DATEI' => $attrappe, 'BADBOT_KONFIG' => "$tmp/konfig.php", 'BADBOT_DATEI' => $badbot,
    'BADBOT_MUSTER' => Koeder::MUSTER_KONFIG . '|' . Koeder::MUSTER_DB . '|' . Koeder::MUSTER_WP, 'PATH' => getenv('PATH')];
$server = [
    proc_open([PHP_BINARY, '-S', "127.0.0.1:$portA", __DIR__ . '/attrappe.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $r, null, $env),
    proc_open([PHP_BINARY, '-S', "127.0.0.1:$portS", '-t', "$tmp/web", __DIR__ . '/router.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', "$tmp/web.log", 'w']], $r, null, $env),
];
register_shutdown_function(function () use ($server): void {
    foreach ($server as $p) {
        proc_terminate($p);
    }
});
warteAufPort($portA);
warteAufPort($portS);

$cli = function (string ...$args) use ($env, $badbot): array {
    $p = proc_open(array_merge([PHP_BINARY, __DIR__ . '/cli.php'], $args), [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $rohre, null, $env);
    $aus = stream_get_contents($rohre[1]) . stream_get_contents($rohre[2]);
    return [proc_close($p), $aus];
};
$web = function (string $methode, string $pfad, array $kopf = [], string $koerper = '') use ($portS): array {
    $ctx = stream_context_create(['http' => ['method' => $methode, 'header' => implode("\r\n", $kopf), 'content' => $koerper, 'ignore_errors' => true, 'follow_location' => 0]]);
    $inhalt = (string) file_get_contents("http://127.0.0.1:$portS$pfad", false, $ctx);
    $kopf = function_exists('http_get_last_response_headers') ? http_get_last_response_headers() : $http_response_header;
    preg_match('#^HTTP/\S+ (\d+)#', $kopf[0], $m);
    return [(int) $m[1], $inhalt];
};
$platt = fn (): array => json_decode((string) file_get_contents($attrappe), true);
$platzAendern = function (callable $f) use ($attrappe): void {
    $z = json_decode((string) file_get_contents($attrappe), true);
    $f($z);
    file_put_contents($attrappe, json_encode($z));
};
$xff = fn (string $ip): string => 'X-Forwarded-For: ' . $ip;

/** Wartet, bis eine im Hintergrund angestoßene Runde fertig ist. */
function rundeAbwarten(string $tmp): void
{
    for ($i = 0; $i < 100; $i++) {
        $z = json_decode((string) @file_get_contents("$tmp/daten/zustand.json"), true);
        if (is_array($z) && (int) ($z['laeuft_bis'] ?? 0) === 0 && isset($z['letzte_runde'])) {
            return;
        }
        usleep(50000);
    }
    throw new RuntimeException('Runde endet nicht');
}

test('e2e: vor der ersten Runde ist kein Köder aktiv; der Aufruf stößt sie an', function () use ($web, $platt, $tmp): void {
    gleich($web('GET', '/.env')[0], 404, '.env ohne Konfiguration');
    for ($i = 0; $i < 50 && empty($platt()['ist']); $i++) {
        usleep(100000);
    }
    pruefe(!empty($platt()['ist']), 'erste Runde ohne Cron nicht gelaufen');
    rundeAbwarten($tmp);
});

test('e2e: Prüfung zeigt Konfiguration und Sperrliste', function () use ($cli, $platt): void {
    [$rc, $aus] = $cli('--pruefen');
    pruefe($rc === 0, "Rückgabe $rc: $aus");
    foreach (['Lebenszeichen angenommen', 'Sperrliste: s-1, 2 Netze', 'WordPress gefunden: nein'] as $z) {
        pruefe(str_contains($aus, $z), "fehlt: $z\n$aus");
    }
    $p = $platt();
    gleich($p['lebenszeichen'][0]['plattform'], 'php', 'Plattform im Lebenszeichen');
    gleich(array_column($p['ist'][0]['simulationen'], 'aktiv'), [true, true, true], 'Ist');
});

test('e2e: Köder antworten, Besucher und Sperren', function () use ($web, $xff): void {
    [$s, $i] = $web('POST', '/wp-login.php', ['Content-Type: application/x-www-form-urlencoded', $xff('203.0.113.50')], 'log=admin&pwd=Sommer2026');
    pruefe($s === 200 && str_contains($i, 'is incorrect'), "wp-login: $s");
    gleich($web('GET', '/.env', [$xff('203.0.113.50')])[0], 200, '.env');
    gleich($web('GET', '/phpmyadmin/', [$xff('192.0.2.7')])[0], 200, 'phpMyAdmin');
    gleich($web('GET', '/kontakt', [$xff('192.0.2.7')]), [200, "SEITE OK\n"], 'gewöhnlicher Besucher');
    // Gesperrt: die Seite nicht, die Köder schon -- sonst versiegt die Erfassung.
    gleich($web('GET', '/kontakt', [$xff('198.51.100.9')]), [403, "403 Forbidden\n"], 'gesperrt');
    gleich($web('GET', '/.git/config', [$xff('198.51.100.9')])[0], 200, 'Köder bleibt für Gesperrte offen');
    gleich($web('GET', '/kontakt', ['X-Forwarded-For: 2001:db8::1'])[0], 403, 'IPv6 gesperrt');
});

test('e2e: echte Dateien werden nie überdeckt', function () use ($web, $tmp): void {
    file_put_contents("$tmp/web/.env", "ECHT\n");
    gleich($web('GET', '/.env'), [200, "ECHT\n"], 'vorhandene Datei');
    unlink("$tmp/web/.env");
});

test('e2e: Meldung erreicht die Plattform', function () use ($cli, $platt): void {
    [$rc, $aus] = $cli('--runde', '--alles');
    pruefe($rc === 0 && str_contains($aus, 'Stapel gemeldet'), $aus);
    $saetze = [];
    foreach ($platt()['stapel'] as $st) {
        foreach ($st['datensaetze'] as $d) {
            $saetze[$d['quelle'] . ' ' . $d['simulation']] = $d;
        }
    }
    ksort($saetze);
    gleich(array_keys($saetze), ['192.0.2.7 db-koeder', '198.51.100.9 konfig-koeder', '203.0.113.50 konfig-koeder', '203.0.113.50 wp-koeder'], 'gemeldete Quellen (kein Besucher)');
    $wp = $saetze['203.0.113.50 wp-koeder'];
    gleich([$wp['ueber_vorschaltnetz'], $wp['verbindung_von']], [true, '127.0.0.1'], 'Vorschaltnetz');
    gleich($wp['stichprobe']['anmeldungen'][0]['passwort_sha256'], hash('sha256', 'Sommer2026'), 'Passwort gehasht');
    pruefe(!str_contains(json_encode($platt()['stapel']), 'Sommer2026'), 'Klartextpasswort gemeldet');
});

test('e2e: ohne Cron -- ein Köderaufruf stößt die fällige Runde an', function () use ($web, $platt, $tmp, $xff): void {
    $vorher = count($platt()['lebenszeichen']);
    $z = json_decode((string) file_get_contents("$tmp/daten/zustand.json"), true);
    $z['naechste_runde'] = 0;
    file_put_contents("$tmp/daten/zustand.json", json_encode($z));
    gleich($web('GET', '/.env', [$xff('203.0.113.51')])[0], 200, 'Köder');
    for ($i = 0; $i < 50 && count($platt()['lebenszeichen']) === $vorher; $i++) {
        usleep(100000);
    }
    gleich(count($platt()['lebenszeichen']), $vorher + 1, 'Lebenszeichen nach dem Köderaufruf');
    rundeAbwarten($tmp);
});

test('e2e: WordPress kommt dazu -- Köder aus, Ist gemeldet', function () use ($cli, $web, $platt, $tmp): void {
    file_put_contents("$tmp/web/wp-login.php", "<?php echo 'ECHTES WP';");
    gleich($web('GET', '/wp-login.php'), [200, 'ECHTES WP'], 'echtes WordPress bedient');
    gleich($web('GET', '/xmlrpc.php')[0], 404, 'übrige WordPress-Köder aus');
    $cli('--runde');
    $ist = end($platt()['ist'])['simulationen'][0];
    pruefe($ist['name'] === 'wp-koeder' && !$ist['aktiv'] && str_contains($ist['fehler'], 'WordPress'), json_encode($ist));
    [, $aus] = $cli('--htaccess', '/badbot/badbot.php');
    pruefe(!str_contains($aus, 'wp-login') && str_contains($aus, 'WordPress-Köder ausgelassen'), $aus);
    unlink("$tmp/web/wp-login.php");
});

test('e2e: Schlüssel widerrufen -- stumm, Sperren bleiben', function () use ($cli, $web, $platzAendern, $xff): void {
    $platzAendern(function (array &$z): void {
        $z['erzwingen'] = 401;
    });
    [$rc, $aus] = $cli('--runde');
    pruefe($rc === 1 && str_contains($aus, 'lehnt den Collector ab'), $aus);
    gleich($web('GET', '/kontakt', [$xff('198.51.100.9')])[0], 403, 'Sperre bleibt bis zum Ablauf');
});

test('e2e: Sperrstufe aus entfernt die Sperren', function () use ($cli, $web, $platzAendern, $xff): void {
    $platzAendern(function (array &$z): void {
        unset($z['erzwingen']);
        $z['konfig']['stand'] = 'k-2';
        $z['konfig']['sperren']['stufe'] = 'aus';
    });
    $cli('--runde');
    gleich($web('GET', '/kontakt', [$xff('198.51.100.9')])[0], 200, 'nicht mehr gesperrt');
});

echo $GLOBALS['fehler'] === 0 ? "\nalle e2e-Tests bestanden\n" : "\n{$GLOBALS['fehler']} e2e-Tests fehlgeschlagen\n";
exit($GLOBALS['fehler'] === 0 ? 0 : 1);
