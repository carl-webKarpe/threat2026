<?php

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start([
            'cookie_httponly' => true,
            'cookie_samesite' => 'Lax',
            'cookie_secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
            'use_strict_mode' => true,
        ]);
    }
}

function require_login(): void
{
    start_secure_session();

    $userId = filter_var($_SESSION['user_id'] ?? null, FILTER_VALIDATE_INT);
    $sessionRole = (string) ($_SESSION['role'] ?? '');
    if (empty($_SESSION['authenticated']) || !is_int($userId) || $userId < 1) {
        header('Location: ../loginform.php');
        exit;
    }

    try {
        $statement = database_connection()->prepare(
            'SELECT role, is_active FROM users WHERE id = :id LIMIT 1'
        );
        $statement->execute(['id' => $userId]);
        $account = $statement->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable $exception) {
        error_log('Authentication state check failed: ' . $exception->getMessage());
        $account = false;
    }

    if (
        !$account ||
        (int) $account['is_active'] !== 1 ||
        !hash_equals((string) $account['role'], $sessionRole)
    ) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $parameters = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $parameters['path'], $parameters['domain'], $parameters['secure'], $parameters['httponly']);
        }
        session_destroy();
        header('Location: ../loginform.php');
        exit;
    }
}

function require_superadmin_verification(): void
{
    require_login();

    if ($_SESSION['role'] !== 'superadmin' || empty($_SESSION['superadmin_verified'])) {
        header('Location: ../unauthorized.php');
        exit;
    }
}

function current_user(): array
{
    start_secure_session();

    return [
        'id' => (int) ($_SESSION['user_id'] ?? 0),
        'full_name' => (string) ($_SESSION['full_name'] ?? ''),
        'username' => (string) ($_SESSION['username'] ?? ''),
        'role' => (string) ($_SESSION['role'] ?? ''),
    ];
}
