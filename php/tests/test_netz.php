<?php
declare(strict_types=1);

use BadbotCollector\Netz;
use BadbotCollector\Text;

test('Netz: Schreibweise und Bereiche', function (): void {
    gleich(Netz::normal('::ffff:203.0.113.9'), '203.0.113.9', 'IPv4 in IPv6');
    gleich(Netz::normal('2001:DB8:0::1'), '2001:db8::1', 'IPv6 kanonisch');
    gleich(Netz::normal('203.0.113.300'), null, 'ungültig');
    gleich(Netz::normal(''), null, 'leer');
    gleich(Netz::bereich('203.0.113.9/24'), ['cb007100', 'cb0071ff'], 'IPv4-Netz');
    gleich(Netz::bereich('2001:db8::/32'), ['20010db8000000000000000000000000', '20010db8ffffffffffffffffffffffff'], 'IPv6-Netz');
    gleich(Netz::bereich('203.0.113.0/33'), null, 'zu viele Bits');
    gleich(Netz::bereich('203.0.113.0/x'), null, 'keine Zahl');
    gleich(Netz::netzNormal('203.0.113.9/24'), '203.0.113.0/24', 'Hostbits genullt');
    gleich(Netz::netzNormal('2001:db8::1'), '2001:db8::1/128', 'Einzeladresse');
    pruefe(Netz::enthalten('203.0.113.77', ['192.0.2.0/24', '203.0.113.0/25']), 'enthalten');
    pruefe(!Netz::enthalten('203.0.113.200', ['203.0.113.0/25']), 'nicht enthalten');
    pruefe(!Netz::enthalten('2001:db8::1', ['203.0.113.0/24']), 'Familie getrennt');
});

test('Netz: verschmolzene Liste und Suche', function (): void {
    $b = Netz::bereiche(['203.0.113.0/24', '203.0.113.128/25', '192.0.2.10/32', '198.51.100.0/24', '2001:db8::/48', '2001:db8:0:1::/64']);
    gleich(count($b['v4']), 6, 'enthaltenes Netz verschmolzen');
    gleich(count($b['v6']), 2, 'IPv6 verschmolzen');
    foreach (['203.0.113.200' => true, '192.0.2.10' => true, '192.0.2.11' => false, '198.51.100.255' => true, '192.0.2.12' => false, '2001:db8:0:1::5' => true, '2001:db8:1::' => false] as $ip => $soll) {
        $hex = Netz::hex($ip);
        gleich(Netz::suchen($b[strlen($hex) === 8 ? 'v4' : 'v6'], $hex), $soll, "Suche $ip");
    }
    gleich(Netz::suchen([], 'cb007101'), false, 'leere Liste');
});

test('Quelle: X-Forwarded-For nur aus Vorschaltnetzen', function (): void {
    $vor = ['198.51.100.0/24'];
    gleich(Netz::quelle(['REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '192.0.2.1'], $vor),
        ['quelle' => '203.0.113.9', 'vorschalt' => false, 'von' => ''], 'Kopfzeile von außen ignoriert');
    gleich(Netz::quelle(['REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_FORWARDED_FOR' => '192.0.2.99, 203.0.113.50'], $vor),
        ['quelle' => '203.0.113.50', 'vorschalt' => true, 'von' => '198.51.100.7'], 'letzter Eintrag des Vorschaltnetzes');
    gleich(Netz::quelle(['REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_FORWARDED_FOR' => 'unsinn'], $vor),
        ['quelle' => '198.51.100.7', 'vorschalt' => false, 'von' => ''], 'unlesbar: Verbindung zählt');
    gleich(Netz::quelle(['REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_FORWARDED_FOR' => '192.0.2.1'], []),
        ['quelle' => '198.51.100.7', 'vorschalt' => false, 'von' => ''], 'ohne Vorschaltnetze nie');
    gleich(Netz::quelle([], $vor), null, 'ohne Adresse');
});

test('Text: kürzen, Steuerzeichen, Zugangsdaten im Pfad', function (): void {
    gleich(Text::kurz("a\x1b[31mb\x00c", 5), "a\u{FFFD}[31", 'Steuerzeichen');
    gleich(Text::kurz("\xff\xfeab", 10), '??ab', 'kein UTF-8');
    gleich(Text::kurz('äöü', 2), 'äö', 'Zeichen, nicht Bytes');
    gleich(Text::pfad('/wp-login.php?log=admin&pwd=geheim&redirect_to=x'), '/wp-login.php?log=admin&pwd=%2A&redirect_to=x', 'pwd ersetzt');
    gleich(Text::pfad('/x?access_token=abc&user_pass=1'), '/x?access_token=%2A&user_pass=%2A', 'token, pass ersetzt');
    $a = Text::anmeldung('root', 'Sommer2026');
    gleich($a['passwort_laenge'], 10, 'Länge');
    gleich($a['passwort_sha256'], hash('sha256', 'Sommer2026'), 'Hash');
    gleich(Text::anmeldung('root', ''), ['name' => 'root'], 'ohne Passwort');
});
