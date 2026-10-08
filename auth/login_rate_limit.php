<?php

declare(strict_types=1);

function login_attempt_username_hash(string $username): string
{
    return hash('sha256', strtolower(trim($username)));
}

function login_attempt_is_limited(PDO $pdo, string $ipAddress, string $username): bool
{
    $usernameHash = login_attempt_username_hash($username);
    $statement = $pdo->prepare(
        'SELECT
                SUM(username_hash = :username_hash) AS account_attempts,
                SUM(ip_address = :ip_ip) AS ip_attempts
         FROM login_attempts
         WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
    );
    $statement->execute([
        'ip_ip' => $ipAddress,
        'username_hash' => $usernameHash,
    ]);
    $attempts = $statement->fetch(PDO::FETCH_ASSOC) ?: [];

    return (int) ($attempts['account_attempts'] ?? 0) >= 10
        || (int) ($attempts['ip_attempts'] ?? 0) >= 40;
}

function record_failed_login_attempt(PDO $pdo, string $ipAddress, string $username): void
{
    $pdo->exec('DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 1 DAY)');
    $statement = $pdo->prepare(
        'INSERT INTO login_attempts (ip_address, username_hash) VALUES (:ip_address, :username_hash)'
    );
    $statement->execute([
        'ip_address' => $ipAddress,
        'username_hash' => login_attempt_username_hash($username),
    ]);
}

function clear_login_attempts(PDO $pdo, string $ipAddress, string $username): void
{
    $statement = $pdo->prepare(
        'DELETE FROM login_attempts WHERE ip_address = :ip_address AND username_hash = :username_hash'
    );
    $statement->execute([
        'ip_address' => $ipAddress,
        'username_hash' => login_attempt_username_hash($username),
    ]);
}
