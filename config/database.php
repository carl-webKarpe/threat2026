<?php

declare(strict_types=1);

function database_connection(): PDO
{
    // Optional local settings in config/database.local.php (ignored by git), e.g. the MySQL root password.
    $localConfigFile = __DIR__ . '/database.local.php';
    $local = is_file($localConfigFile) ? require $localConfigFile : [];
    $local = is_array($local) ? $local : [];

    $host = getenv('MALDETECT_DB_HOST') ?: ($local['host'] ?? '127.0.0.1');
    $port = getenv('MALDETECT_DB_PORT') ?: (string) ($local['port'] ?? '3306');
    $database = getenv('MALDETECT_DB_NAME') ?: ($local['database'] ?? 'maldetect_db');
    $username = getenv('MALDETECT_DB_USER') ?: ($local['username'] ?? 'root');
    $password = getenv('MALDETECT_DB_PASSWORD') ?: (string) ($local['password'] ?? '');

    return new PDO(
        "mysql:host={$host};port={$port};dbname={$database};charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ],
    );
}