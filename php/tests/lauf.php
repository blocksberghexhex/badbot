<?php
// Tests des PHP-Collectors, ohne Abhängigkeiten: php tests/lauf.php
declare(strict_types=1);

const BADBOT_TEST = true;
require __DIR__ . '/../badbot.php';

require_once __DIR__ . '/lauf_hilfen.php';

foreach (glob(__DIR__ . '/test_*.php') as $datei) {
    require $datei;
}

echo $GLOBALS['fehler'] === 0 ? "\nalle Tests bestanden\n" : "\n{$GLOBALS['fehler']} Tests fehlgeschlagen\n";
exit($GLOBALS['fehler'] === 0 ? 0 : 1);
