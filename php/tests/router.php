<?php
const BADBOT_ALTES_PHP_ERLAUBEN = true; // nur Test, siehe tests/cli.php
// Webseite für e2e.php (php -S): ahmt die erzeugte Umleitung und die
// vorgeschaltete Sperrprüfung nach.
$badbot = (string) getenv('BADBOT_DATEI');
$pfad = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$datei = $_SERVER['DOCUMENT_ROOT'] . $pfad;
if (is_file($datei) || (is_dir($datei) && $pfad !== '/')) {
    // Vorhandene Dateien werden nie überdeckt (RewriteCond !-f, !-d).
    return false;
}
if (preg_match('#^/(' . getenv('BADBOT_MUSTER') . ')$#', $pfad) === 1) {
    $_SERVER['SCRIPT_FILENAME'] = $badbot;
    require $badbot;
    return true;
}
require $badbot; // wie auto_prepend_file
echo "SEITE OK\n";
return true;
