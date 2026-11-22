<?php
declare(strict_types=1);

// Sicherheitsprüfung des Quelltexts: Sie läuft mit jedem
// Testlauf und vor jeder Veröffentlichung. Sie prüft Tokens, nicht Text --
// Kommentare und Zeichenketten lösen nichts aus.

/** @return array<int,array{0:int|string,1:string,2:int}> ohne Leerraum und Kommentare */
function tokens(string $datei): array
{
    $l = [];
    foreach (token_get_all((string) file_get_contents($datei)) as $t) {
        if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $l[] = is_array($t) ? $t : [$t, $t, 0];
    }
    return $l;
}

const VERBOTEN = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec', 'assert',
    'create_function', 'unserialize', 'extract', 'call_user_func', 'call_user_func_array', 'mail', 'fsockopen',
    'pfsockopen', 'socket_create', 'stream_socket_client', 'mysqli_query', 'mysql_query', 'putenv', 'ini_set',
    'dl', 'move_uploaded_file', 'header_register_callback', 'preg_replace_callback', 'eval'];

/**
 * Prüft eine Quelldatei und liefert die Verstöße.
 * @return string[]
 */
function sicherheitspruefung(string $datei): array
{
    $v = [];
    $pruefe = function (bool $ok, string $was) use (&$v): void {
        if (!$ok) {
            $v[] = $was;
        }
    };
    $t = tokens($datei);
    $funktion = [];   // Stapel [Name, Klammertiefe]
    $tiefe = 0;
    $naechsteFunktion = null;
    $einbinden = 0;
    for ($i = 0; $i < count($t); $i++) {
        [$art, $text, $zeile] = $t[$i];
        $ort = "Zeile $zeile";
        if ($art === T_FUNCTION && ($t[$i + 1][0] ?? null) === T_STRING) {
            $naechsteFunktion = $t[$i + 1][1];
        }
        if ($art === '{' || $art === T_CURLY_OPEN || $art === T_DOLLAR_OPEN_CURLY_BRACES) {
            $tiefe++;
            if ($naechsteFunktion !== null) {
                $funktion[] = [$naechsteFunktion, $tiefe];
                $naechsteFunktion = null;
            }
        }
        if ($art === '}') {
            if ($funktion !== [] && end($funktion)[1] === $tiefe) {
                array_pop($funktion);
            }
            $tiefe--;
        }
        if ($art === ';') {
            $naechsteFunktion = null; // Deklaration ohne Rumpf
        }
        $in = $funktion === [] ? '' : end($funktion)[0];

        $pruefe($art !== T_EVAL, "eval in $ort");
        $pruefe($art !== '`', "Backtick (Shell) in $ort");
        $pruefe(!in_array($art, [T_INCLUDE_ONCE, T_REQUIRE_ONCE], true), "include_once/require_once in $ort");
        $pruefe($art !== '$', "variable Variable in $ort");
        if ($art === T_VARIABLE) {
            $pruefe(!in_array($text, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$GLOBALS'], true), "$text in $ort");
        }
        if ($art === T_INCLUDE || $art === T_REQUIRE) {
            // Nur die eigene Konfiguration und die eigene Sperrliste, beide über
            // einen Pfad aus dem Dateisystem.
            $einbinden++;
            $pruefe(($t[$i + 1][1] ?? '') === '$pfad' && ($t[$i + 2][0] ?? '') === ';', "Einbinden mit unerwartetem Ziel in $ort");
            $pruefe(in_array($in, ['laden', 'sperrlisteLesen'], true), "Einbinden außerhalb von laden/sperrlisteLesen in $ort");
        }
        // Seit PHP 8 ist \name ein eigenes Token -- ohne das liefe jeder
        // vollqualifizierte Aufruf an der Prüfung vorbei.
        $name = in_array($art, [T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED], true) ? strtolower(ltrim($text, '\\')) : null;
        if ($name !== null && ($t[$i + 1][0] ?? '') === '(') {
            $vorher = $t[$i - 1][0] ?? null;
            $methode = in_array($vorher, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true);
            if (!$methode) {
                $pruefe(!in_array($name, VERBOTEN, true), "verbotene Funktion $name in $ort");
            }
            if ($name === 'parse_str') {
                // Nur mit Ziel-Array: sonst legt parse_str Variablen an.
                $pruefe(($t[$i + 2][0] ?? null) === T_VARIABLE && ($t[$i + 3][0] ?? null) === ',', "parse_str ohne Ziel in $ort");
            }
            if ($vorher === T_OBJECT_OPERATOR && $name === 'query') {
                $pruefe(false, "PDO::query in $ort -- nur prepare/execute");
            }
            if ($vorher === T_OBJECT_OPERATOR && in_array($name, ['prepare', 'exec'], true)) {
                // SQL nie zusammengesetzt: keine Verkettung, keine Interpolation.
                $k = 0;
                for ($j = $i + 1; $j < count($t); $j++) {
                    $k += $t[$j][0] === '(' ? 1 : ($t[$j][0] === ')' ? -1 : 0);
                    $pruefe(!in_array($t[$j][0], ['.', '"', T_ENCAPSED_AND_WHITESPACE, T_START_HEREDOC], true), "zusammengesetztes SQL in $ort");
                    if ($k === 0) {
                        break;
                    }
                }
            }
        }
        if ($art === T_ECHO || $art === T_PRINT) {
            // Ausgaben nur an drei Stellen: Köderantwort, Sperrantwort, Kommandozeile.
            $pruefe(in_array($in, ['senden', 'einstieg', 'kommandozeile'], true), "Ausgabe außerhalb der vorgesehenen Stellen in $ort ($in)");
        }
    }
    $pruefe($einbinden === 2, "$einbinden Stellen mit include/require statt 2");
    return $v;
}

test('Sicherheit: keine Ausführung, kein Einbinden von Eingaben, SQL nur mit Platzhaltern', function (): void {
    gleich(sicherheitspruefung(__DIR__ . '/../badbot.php'), [], 'Verstöße');
});

test('Sicherheit: Mutationsprobe -- die Prüfung schlägt an', function (): void {
    $d = tmpdir();
    $quelle = (string) file_get_contents(__DIR__ . '/../badbot.php');
    $faelle = [
        'eval' => ["echo \$a['inhalt'];", "eval(\$a['inhalt']);"],
        'Shell' => ['\\flush();', '\\shell_exec(\'x\'); \\flush();'],
        'Backtick' => ['\\flush();', '`id`; \\flush();'],
        'SQL' => ["prepare('SELECT wert FROM badbot_daten WHERE name = ?')", "prepare('SELECT wert FROM badbot_daten WHERE name = ' . \$name)"],
        'GET' => ["\$uri = (string) (\$server['REQUEST_URI'] ?? '/');", "\$uri = (string) (\$_GET['u'] ?? '/');"],
        'Einbinden' => ['$l = include $pfad;', '$l = include $server[\'x\'];'],
        'Ausgabe' => ["\$probe = [\n", "echo \$uri;\n            \$probe = [\n"],
    ];
    foreach ($faelle as $was => [$alt, $neu]) {
        pruefe(str_contains($quelle, $alt), "Mutationsstelle fehlt: $was");
        file_put_contents($d . '/badbot.php', str_replace($alt, $neu, $quelle));
        pruefe(sicherheitspruefung($d . '/badbot.php') !== [], "Mutation nicht erkannt: $was");
    }
});
