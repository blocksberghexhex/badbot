<?php
// Startet badbot.php von der Kommandozeile auch unter einem älteren PHP --
// nur für die Tests in dieser Umgebung, nie für den Betrieb.
const BADBOT_ALTES_PHP_ERLAUBEN = true;
$_SERVER['SCRIPT_FILENAME'] = __DIR__ . '/../badbot.php';
$_SERVER['argv'] = array_merge([$_SERVER['SCRIPT_FILENAME']], array_slice($_SERVER['argv'], 1));
require __DIR__ . '/../badbot.php';
