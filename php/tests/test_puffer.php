<?php
declare(strict_types=1);

use BadbotCollector\K;
use BadbotCollector\Puffer;

const T0 = 1795255200; // 2026-11-21 10:00:00 UTC, auf 300 s ausgerichtet

function q(string $ip): array
{
    return ['quelle' => $ip, 'vorschalt' => false, 'von' => ''];
}

test('Puffer: Verdichtung, Ports, Stichprobe', function (): void {
    $o = [];
    for ($i = 0; $i < 100; $i++) {
        Puffer::hinzu($o, q('203.0.113.9'), 'wp-koeder', 1000 + $i, T0 + $i, ['anmeldungen' => [['name' => 'admin', 'n' => $i]]], 300, 400);
    }
    Puffer::hinzu($o, q('203.0.113.9'), 'wp-koeder', 443, T0 + 301, [], 300, 400);
    gleich(Puffer::versiegeln($o, T0 + 299, 300, false), [], 'laufendes Fenster bleibt');
    $s = Puffer::versiegeln($o, T0 + 300, 300, false);
    gleich(count($s), 1, 'ein Datensatz');
    $d = $s[0];
    gleich([$d['anzahl'], count($d['ports']), $d['ports_gekuerzt'] ?? false], [100, K::HOECHST_PORTS, true], 'Anzahl, Ports');
    gleich([$d['fenster'], $d['erster'], $d['letzter']], ['2026-11-21T10:00:00Z', '2026-11-21T10:00:00Z', '2026-11-21T10:01:39Z'], 'Zeiten');
    pruefe(strlen(json_encode($d['stichprobe'])) <= 400, 'Stichprobe begrenzt');
    pruefe(count($d['stichprobe']['anmeldungen']) > 1, 'verschiedene Beobachtungen');
    gleich(count($o['saetze']), 1, 'zweites Fenster offen');
    gleich(count(Puffer::versiegeln($o, T0, 300, true)), 1, 'alles versiegeln');
});

test('Puffer: Stapel, Teilen, Nachlieferfrist, Überlauf', function (): void {
    $saetze = [];
    for ($i = 0; $i < 12000; $i++) {
        $saetze[] = ['fenster' => Puffer::zeit(T0), 'quelle' => '2001:db8::' . dechex($i), 'simulation' => 'konfig-koeder', 'anzahl' => 1];
    }
    $w = [];
    Puffer::einreihen($w, $saetze, T0 + 600);
    gleich(array_map(fn ($s) => count($s['datensaetze']), $w['stapel']), [5000, 5000, 2000], 'Stapelgrößen');
    pruefe(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $w['stapel'][0]['stapel']) === 1, 'UUID v4');
    $erster = $w['stapel'][0]['stapel'];
    Puffer::teilen($w, $erster);
    gleich(array_map(fn ($s) => count($s['datensaetze']), $w['stapel']), [2500, 2500, 5000, 2000], 'geteilt');
    pruefe($w['stapel'][0]['stapel'] !== $erster, 'neue Kennung nach dem Teilen');
    Puffer::entfernen($w, $w['stapel'][0]['stapel']);
    gleich(count($w['stapel']), 3, 'entfernt');

    // Zu alt für die Plattform: fällt weg und wird gezählt.
    $w2 = [];
    Puffer::einreihen($w2, array_slice($saetze, 0, 3), T0 + K::NACHLIEFERFRIST + 3600);
    gleich([count($w2['stapel']), $w2['verworfen']], [0, 3], 'Nachlieferfrist');

    $o = [];
    for ($i = 0; $i < K::HOECHST_OFFEN + 5; $i++) {
        Puffer::hinzu($o, q('2001:db8::' . dechex($i)), 'db-koeder', 443, T0, [], 300, 2048);
    }
    gleich([count($o['saetze']), $o['verworfen']], [K::HOECHST_OFFEN, 5], 'Überlauf gezählt');
});

test('Puffer: Vorschaltnetz bleibt erhalten', function (): void {
    $o = [];
    Puffer::hinzu($o, ['quelle' => '203.0.113.50', 'vorschalt' => true, 'von' => '198.51.100.7'], 'wp-koeder', 443, T0, [], 300, 2048);
    $d = Puffer::versiegeln($o, T0, 300, true)[0];
    gleich([$d['ueber_vorschaltnetz'], $d['verbindung_von']], [true, '198.51.100.7'], 'Vorschaltnetz');
    pruefe(!isset($d['stichprobe']), 'leere Stichprobe weggelassen');
});
