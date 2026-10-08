<?php

declare(strict_types=1);

function reserve_superadmin_otp_request(PDO $pdo, int $userId, string $ipAddress): bool
{
    $pdo->exec('DELETE FROM superadmin_otp_requests WHERE requested_at < DATE_SUB(NOW(), INTERVAL 1 DAY)');

    $statement = $pdo->prepare(
        'SELECT
            SUM(user_id = :user_id) AS account_requests,
            SUM(ip_address = :ip_address) AS ip_requests
         FROM superadmin_otp_requests
         WHERE requested_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
    );
    $statement->execute([
        'user_id' => $userId,
        'ip_address' => $ipAddress,
    ]);
    $counts = $statement->fetch(PDO::FETCH_ASSOC) ?: [];

    if ((int) ($counts['account_requests'] ?? 0) >= 3 || (int) ($counts['ip_requests'] ?? 0) >= 6) {
        return false;
    }

    $insert = $pdo->prepare(
        'INSERT INTO superadmin_otp_requests (user_id, ip_address) VALUES (:user_id, :ip_address)'
    );
    $insert->execute([
        'user_id' => $userId,
        'ip_address' => $ipAddress,
    ]);

    return true;
}
