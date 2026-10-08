<?php

declare(strict_types=1);

require_once __DIR__ . '/auth_check.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/../config/database.php';

function require_superadmin_page(): void
{
    require_superadmin_verification();
}

function superadmin_h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function superadmin_redirect(string $page, string $message = '', string $error = ''): never
{
    $query = [];
    if ($message !== '') {
        $query['message'] = $message;
    }
    if ($error !== '') {
        $query['error'] = $error;
    }
    header('Location: ' . $page . ($query ? '?' . http_build_query($query) : ''));
    exit;
}

function superadmin_require_post_csrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !verify_csrf_token($_POST['csrf_token'] ?? null)) {
        superadmin_redirect('dashboard.php', '', 'The request could not be verified. Please try again.');
    }
}

function superadmin_validate_account(array $input, bool $passwordRequired = false): array
{
    $username = trim((string) ($input['username'] ?? ''));
    $name = trim((string) ($input['name'] ?? ''));
    $email = trim((string) ($input['email'] ?? ''));
    $role = strtolower(trim((string) ($input['role'] ?? '')));
    $password = (string) ($input['password'] ?? '');
    $confirmation = (string) ($input['password_confirmation'] ?? '');

    if ($username === '' || strlen($username) > 100 || !preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
        throw new InvalidArgumentException('Username must contain only letters, numbers, dots, underscores, or hyphens.');
    }
    if ($name === '' || strlen($name) > 255) {
        throw new InvalidArgumentException('Full name is required and must be 255 characters or fewer.');
    }
    if ($email !== '' && (strlen($email) > 255 || !filter_var($email, FILTER_VALIDATE_EMAIL))) {
        throw new InvalidArgumentException('Enter a valid email address.');
    }
    if (!in_array($role, ['admin', 'user'], true)) {
        throw new InvalidArgumentException('Only Admin and User accounts can be managed here.');
    }
    if ($passwordRequired || $password !== '' || $confirmation !== '') {
        if (strlen($password) < 12 || $password !== $confirmation) {
            throw new InvalidArgumentException('Passwords must match and contain at least 12 characters.');
        }
    }

    return [
        'username' => $username,
        'name' => $name,
        'email' => $email === '' ? null : $email,
        'role' => $role,
        'password' => $password,
    ];
}

function superadmin_audit(string $action, ?int $targetUserId = null, string $details = ''): void
{
    try {
        $statement = database_connection()->prepare(
            'INSERT INTO audit_logs (actor_user_id, action, target_user_id, details, ip_address)
             VALUES (:actor_user_id, :action, :target_user_id, :details, :ip_address)'
        );
        $statement->execute([
            'actor_user_id' => current_user()['id'],
            'action' => $action,
            'target_user_id' => $targetUserId,
            'details' => $details,
            'ip_address' => substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45),
        ]);
    } catch (Throwable $exception) {
        error_log('Audit log failure: ' . $exception->getMessage());
    }
}

function superadmin_find_managed_account(PDO $pdo, int $id): array
{
    $statement = $pdo->prepare(
        'SELECT id, name, username, email, role, is_active, created_at, last_login
         FROM users WHERE id = :id AND role IN (\'admin\', \'user\') LIMIT 1'
    );
    $statement->execute(['id' => $id]);
    $account = $statement->fetch();
    if (!is_array($account)) {
        throw new RuntimeException('Account not found.');
    }
    return $account;
}
