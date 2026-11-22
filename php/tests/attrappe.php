<?php
// Nachgebildete Plattform für e2e.php (php -S). Zustand in ATTRAPPE_DATEI.
declare(strict_types=1);

$datei = (string) getenv('ATTRAPPE_DATEI');
$h = fopen($datei, 'c+');
flock($h, LOCK_EX);
$z = json_decode((string) stream_get_contents($h), true) ?: [];

$antwort = function (int $status, ?array $d = null, array $kopf = []) use ($h, &$z): void {
    rewind($h);
    ftruncate($h, 0);
    fwrite($h, (string) json_encode($z));
    flock($h, LOCK_UN);
    http_response_code($status);
    foreach ($kopf as $k => $v) {
        header("$k: $v");
    }
    if ($d !== null) {
        header('Content-Type: application/json');
        echo json_encode($d);
    }
    exit;
};

$pfad = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$z['aufrufe'][] = $_SERVER['REQUEST_METHOD'] . ' ' . $pfad;
if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer bb1_test_geheim') {
    $antwort(401, ['fehler' => 'schluessel-ungueltig', 'text' => '']);
}
if (!empty($z['erzwingen'])) {
    $antwort((int) $z['erzwingen'], ['fehler' => 'erzwungen', 'text' => '']);
}
$roh = (string) file_get_contents('php://input');
if (($_SERVER['HTTP_CONTENT_ENCODING'] ?? '') === 'gzip') {
    $roh = (string) gzdecode($roh);
    $z['gzip'] = ($z['gzip'] ?? 0) + 1;
}
$ein = json_decode($roh, true);

switch ($pfad) {
    case '/v1/lebenszeichen':
        $z['lebenszeichen'][] = $ein;
        $antwort(200, ['uhrzeit' => gmdate('c'), 'konfiguration_stand' => $z['konfig']['stand'], 'sperrliste_stand' => $z['sperrliste']['stand'], 'hinweise' => $z['hinweise'] ?? []]);
    case '/v1/konfiguration':
        if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === '"' . $z['konfig']['stand'] . '"') {
            $antwort(304);
        }
        $antwort(200, $z['konfig']);
    case '/v1/konfiguration/ist':
        $z['ist'][] = $ein;
        $antwort(200, ['angenommen' => true]);
    case '/v1/ereignisse':
        $z['stapel'][] = $ein;
        $antwort(200, ['angenommen' => count($ein['datensaetze']), 'verworfen' => 0, 'gruende' => (object) []]);
    case '/v1/sperrliste':
        $antwort(200, $z['sperrliste']);
}
$antwort(404, ['fehler' => 'unbekannt', 'text' => '']);
