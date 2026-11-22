<?php
declare(strict_types=1);

use BadbotCollector\Collector;
use BadbotCollector\DateiSpeicher;
use BadbotCollector\Einstellung;
use BadbotCollector\PdoSpeicher;
use BadbotCollector\Speicher;

function speicherPruefen(Speicher $sp): void
{
    gleich($sp->lesen('x'), null, 'leer');
    $sp->aendern('x', function (array &$d): void {
        $d['n'] = 1;
    });
    // Verschachtelt: Beide Änderungen kommen an, oder keine.
    $sp->aendern('x', function (array &$d) use ($sp): void {
        $d['n']++;
        $sp->aendern('y', function (array &$e): void {
            $e['m'] = 'ä';
        });
    });
    gleich([$sp->lesen('x')['n'], $sp->lesen('y')['m']], [2, 'ä'], 'Änderungen');
    try {
        $sp->aendern('x', function (array &$d) use ($sp): void {
            $d['n'] = 99;
            throw new RuntimeException('Abbruch');
        });
    } catch (RuntimeException $t) {
    }
    gleich($sp->lesen('x')['n'], 2, 'abgebrochene Änderung nicht geschrieben');

    $l = Collector::kompilieren('s-1', 2000000000, ['203.0.113.0/24', '2001:db8::/32'], ['vertrauenswuerdige_vorschaltnetze' => ['198.51.100.0/24']]);
    $sp->sperrlisteSchreiben($l);
    gleich($sp->sperrlisteLesen(), $l, 'Sperrliste');
    $sp->sperrlisteSchreiben(null);
    gleich($sp->sperrlisteLesen(), null, 'Sperrliste gelöscht');
}

test('Speicher: Datei', function (): void {
    $d = tmpdir();
    speicherPruefen(new DateiSpeicher($d . '/daten'));
    pruefe(str_contains((string) file_get_contents($d . '/daten/.htaccess'), 'Require all denied'), 'Datenverzeichnis gegen Abruf geschützt');
});

test('Speicher: PDO (SQLite statt MySQL)', function (): void {
    speicherPruefen(new PdoSpeicher(['dsn' => 'sqlite:' . tmpdir() . '/p.db', 'benutzer' => '', 'passwort' => '']));
});

test('Sperrprüfung: Liste, Ablauf, Ausnahmen, Vorschaltnetz', function (): void {
    $d = tmpdir();
    file_put_contents($d . '/k.php', "<?php return ['schluessel' => 'bb1_test_x', 'daten' => " . var_export($d . '/daten', true) . ", 'sperren_ausnahmen' => ['203.0.113.128/25']];");
    $c = new Collector(Einstellung::laden($d . '/k.php'), new DateiSpeicher($d . '/daten'));
    $jetzt = 1800000000;
    $c->sp->sperrlisteSchreiben(Collector::kompilieren('s-1', $jetzt + 60, ['203.0.113.0/24', '2001:db8::/32', '10.0.0.0/8'], ['vertrauenswuerdige_vorschaltnetze' => ['198.51.100.0/24']]));
    $fall = fn (string $ra, string $xff = '') => $c->gesperrt(['REMOTE_ADDR' => $ra, 'HTTP_X_FORWARDED_FOR' => $xff], $jetzt);
    pruefe($fall('203.0.113.9'), 'gesperrt');
    pruefe($fall('2001:db8:1::5'), 'IPv6 gesperrt');
    pruefe(!$fall('192.0.2.1'), 'nicht gelistet');
    pruefe(!$fall('203.0.113.200'), 'lokale Ausnahme');
    pruefe(!$fall('10.1.2.3'), 'private Adressen nie');
    pruefe($fall('198.51.100.7', '203.0.113.9'), 'hinter dem Vorschaltnetz gesperrt');
    pruefe(!$fall('192.0.2.1', '198.51.100.7, 203.0.113.9'), 'X-Forwarded-For von außen zählt nicht');
    pruefe(!$c->gesperrt(['REMOTE_ADDR' => '203.0.113.9'], $jetzt + 61), 'abgelaufen');
});

test('Einstellung: Pflichtangaben', function (): void {
    $d = tmpdir();
    $fall = function (string $inhalt) use ($d): string {
        file_put_contents($d . '/k.php', '<?php return ' . $inhalt . ';');
        try {
            Einstellung::laden($d . '/k.php');
            return 'ok';
        } catch (RuntimeException $t) {
            return $t->getMessage();
        }
    };
    gleich($fall("['schluessel' => 'x', 'daten' => '/t']"), 'kein gültiger API-Schlüssel', 'Schlüssel');
    gleich($fall("['schluessel' => 'bb1_a_b', 'daten' => '/t', 'api' => 'http://example.org']"), 'api muss https verwenden', 'https');
    gleich($fall("['schluessel' => 'bb1_a_b', 'daten' => '/t', 'api' => 'http://127.0.0.1:9']"), 'ok', 'lokal http');
    gleich($fall("['schluessel' => 'bb1_a_b', 'daten' => '/t', 'sperren_ausnahmen' => ['unsinn']]"), 'sperren_ausnahmen: kein Netz', 'Ausnahmen');
});

test('PHP-Version: nur die beiden neuesten', function (): void {
    pruefe(BadbotCollector\phpPassend(80500) && BadbotCollector\phpPassend(80600), '8.5 und 8.6');
    // In der Testumgebung ist die Prüfung abschaltbar -- hier nicht abgeschaltet.
    pruefe(!defined('BADBOT_ALTES_PHP_ERLAUBEN'), 'Testlauf schaltet die Prüfung nicht ab');
    pruefe(!BadbotCollector\phpPassend(80499) && !BadbotCollector\phpPassend(80300), '8.4 und älter abgelehnt');
});
