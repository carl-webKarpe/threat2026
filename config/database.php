<?php

declare(strict_types=1);

function database_connection(): PDO
{
    $host = getenv('MALDETECT_DB_HOST') ?: '127.0.0.1';
    $port = getenv('MALDETECT_DB_PORT') ?: '3306';
    $database = getenv('MALDETECT_DB_NAME') ?: 'maldetect_db';
    $username = getenv('MALDETECT_DB_USER') ?: 'root';
    $password = getenv('MALDETECT_DB_PASSWORD') ?: '';

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