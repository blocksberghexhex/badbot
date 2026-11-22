<?php
declare(strict_types=1);

use BadbotCollector\Koeder;

const MARKE = 'MARKE<script>9f3e';
const AKTIV = ['wp-koeder' => true, 'konfig-koeder' => true, 'db-koeder' => true];

function anfrage(string $methode, string $uri, string $koerper = '', bool $wp = false, array $aktiv = AKTIV): array
{
    $s = ['REQUEST_METHOD' => $methode, 'REQUEST_URI' => $uri, 'HTTP_USER_AGENT' => 'Scanner ' . MARKE, 'REMOTE_ADDR' => '203.0.113.9'];
    if ($methode === 'POST') {
        $s['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
    }
    $a = Koeder::antwort($s, $koerper, $aktiv, $wp);
    // Grundregel: Nichts von dem, was ankam, steht in der Antwort.
    pruefe(!str_contains($a['inhalt'], 'MARKE') && !str_contains($a['inhalt'], '9f3e'), "Eingabe in der Antwort auf $uri");
    pruefe(!str_contains(json_encode($a['probe']), 'Sommer2026'), "Klartextpasswort in der Stichprobe zu $uri");
    return $a;
}

test('Köder: Konfigurationsdateien', function (): void {
    $a = anfrage('GET', '/.env?x=' . urlencode(MARKE));
    gleich([$a['status'], $a['sim']], [200, 'konfig-koeder'], '.env');
    pruefe(!preg_match('/pass|key|secret|token/i', $a['inhalt']), 'nichts, das wie ein Zugangsdatum aussieht');
    gleich(anfrage('GET', '/.git/config')['sim'], 'konfig-koeder', '.git/config');
    gleich(anfrage('GET', '/config.php.bak')['status'], 200, 'config.php.bak');
});

test('Köder: WordPress-Anmeldung schlägt immer fehl', function (): void {
    $a = anfrage('GET', '/wp-login.php');
    pruefe($a['status'] === 200 && str_contains($a['inhalt'], 'name="pwd"'), 'Formular');
    $a = anfrage('POST', '/wp-login.php', 'log=admin&pwd=Sommer2026&wp-submit=' . urlencode(MARKE));
    pruefe(str_contains($a['inhalt'], 'is incorrect'), 'Fehlermeldung');
    gleich($a['probe']['anmeldungen'][0]['name'], 'admin', 'Benutzer');
    gleich($a['probe']['anmeldungen'][0]['passwort_laenge'], 10, 'Passwortlänge');
    gleich($a['probe']['felder'], ['log,pwd,wp-submit'], 'nur Feldnamen');
    pruefe(!isset($a['probe']['body']), 'kein Body in der Stichprobe');
    $a = anfrage('GET', '/wp-admin/options.php');
    gleich([$a['status'], $a['kopf']['Location'] ?? ''], [302, '/wp-login.php?reauth=1'], 'wp-admin leitet um');
    $a = anfrage('GET', '/wp-content/plugins/revslider/temp/update_extract/x.php');
    gleich($a['probe']['plugin'], ['revslider'], 'Plugin-Pfad');
    $a = anfrage('POST', '/xmlrpc.php', '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><methodName>wp.getUsersBlogs</methodName></value></param></params></methodCall>');
    gleich($a['probe']['xmlrpc'], ['system.multicall', 'wp.getUsersBlogs'], 'XML-RPC-Methoden');
    pruefe(str_contains($a['inhalt'], '<int>403</int>'), 'XML-RPC-Fehler');
    gleich(anfrage('GET', '/xmlrpc.php')['status'], 405, 'XML-RPC per GET');
});

test('Köder: Datenbank-Oberflächen', function (): void {
    $a = anfrage('POST', '/phpmyadmin/index.php', 'pma_username=root&pma_password=Sommer2026');
    gleich([$a['sim'], $a['probe']['anmeldungen'][0]['name']], ['db-koeder', 'root'], 'phpMyAdmin');
    pruefe(str_contains($a['inhalt'], 'Access denied'), 'phpMyAdmin lehnt ab');
    $a = anfrage('POST', '/adminer.php', 'auth%5Bdriver%5D=server&auth%5Busername%5D=admin&auth%5Bpassword%5D=Sommer2026');
    gleich($a['probe']['anmeldungen'][0]['passwort_laenge'], 10, 'Adminer');
    pruefe(str_contains($a['inhalt'], 'Invalid credentials'), 'Adminer lehnt ab');
});

test('Köder: nur Köderpfade, nur eingeschaltete, kein WordPress-Köder bei echtem WordPress', function (): void {
    foreach (['/', '/kontakt', '/badbot/badbot.php', '/wp-content/themes/x/style.css', '/.envx', '/phpmyadmin/sql.php'] as $p) {
        $a = anfrage('GET', $p);
        gleich([$a['status'], $a['sim']], [404, null], "kein Köder: $p");
    }
    gleich(anfrage('GET', '/wp-login.php', '', true)['sim'], null, 'echtes WordPress');
    gleich(anfrage('GET', '/.env', '', true)['sim'], 'konfig-koeder', 'andere Köder bleiben');
    gleich(anfrage('GET', '/.env', '', false, ['konfig-koeder' => false])['sim'], null, 'ausgeschaltet');
    gleich(anfrage('GET', '/.env', '', false, [])['sim'], null, 'ohne Konfiguration');
});

test('Köder: Umleitungsmuster decken genau die Köder ab', function (): void {
    $muster = '#^/(' . Koeder::MUSTER_KONFIG . '|' . Koeder::MUSTER_DB . '|' . Koeder::MUSTER_WP . ')$#';
    foreach (['/.env', '/.git/config', '/.git/HEAD', '/config.php.bak', '/wp-config.php.old', '/adminer.php', '/phpmyadmin/', '/phpmyadmin/index.php', '/pma/', '/pma/index.php', '/wp-login.php', '/xmlrpc.php', '/wp-admin', '/wp-admin/x.php', '/wp-content/plugins/a/b.php'] as $p) {
        pruefe(preg_match($muster, $p) === 1, "Muster fehlt: $p");
        pruefe(anfrage('GET', $p)['sim'] !== null, "umgeleitet, aber kein Köder: $p");
    }
    foreach (['/', '/index.php', '/wp-content/uploads/a.jpg', '/kontakt'] as $p) {
        pruefe(preg_match($muster, $p) !== 1, "Muster zu weit: $p");
    }
});
