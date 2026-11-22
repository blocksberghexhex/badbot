<?php
declare(strict_types=1);

$GLOBALS['fehler'] = 0;

function pruefe(bool $bedingung, string $was): void
{
    if (!$bedingung) {
        throw new RuntimeException($was);
    }
}

function gleich(mixed $ist, mixed $soll, string $was): void
{
    pruefe($ist === $soll, $was . ': ' . var_export($ist, true) . ' statt ' . var_export($soll, true));
}

function test(string $name, callable $f): void
{
    try {
        $f();
        echo "ok   $name\n";
    } catch (Throwable $t) {
        $GLOBALS['fehler']++;
        echo "FEHL $name: " . $t->getMessage() . ' (' . basename($t->getFile()) . ':' . $t->getLine() . ")\n";
    }
}

function tmpdir(): string
{
    $d = sys_get_temp_dir() . '/badbot-test-' . bin2hex(random_bytes(4));
    mkdir($d, 0700, true);
    return $d;
}

function freierPort(): int
{
    $s = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr((string) strrchr((string) stream_socket_get_name($s, false), ':'), 1);
    fclose($s);
    return $port;
}

function warteAufPort(int $port): void
{
    for ($i = 0; $i < 100; $i++) {
        $s = @fsockopen('127.0.0.1', $port, $e, $t, 0.1);
        if ($s !== false) {
            fclose($s);
            return;
        }
        usleep(50000);
    }
    throw new RuntimeException("Port $port antwortet nicht");
}
