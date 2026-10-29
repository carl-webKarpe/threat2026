<?php

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/otp_functions.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/login_rate_limit.php';
require_once __DIR__ . '/otp_rate_limit.php';

start_secure_session();

/** Keeps the username (never the password) for 30 days when "Remember my username" is ticked; otherwise forgets it. */
function remember_login_username(?string $username): void
{
    $path = rtrim(str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/'), 2)), '/') . '/';
    setcookie('maldetect_username', $username ?? '', [
        'expires' => $username === null ? time() - 3600 : time() + 30 * 24 * 3600,
        'path' => $path,
        'secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../login.php');
    exit;
}

if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
    $_SESSION['login_error'] = 'Invalid login request. Please refresh and try again.';
    header('Location: ../login.php');
    exit;
}

unset(
    $_SESSION['user_id'],
    $_SESSION['username'],
    $_SESSION['full_name'],
    $_SESSION['authenticated'],
    $_SESSION['role'],
    $_SESSION['superadmin_verified']
);

$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';

// Shown again in the form if this login fails.
$_SESSION['login_username'] = mb_substr($username, 0, 100);

if ($username === '' || $password === '') {
    $_SESSION['login_error'] = 'Please enter your username and password.';
    header('Location: ../login.php');
    exit;
}

$isSuperadminOtpAttempt = false;
unset(
    $_SESSION['pending_superadmin_id'],
    $_SESSION['pending_superadmin_name'],
    $_SESSION['pending_superadmin_email'],
    $_SESSION['pending_superadmin_role'],
    $_SESSION['otp_sent_at'],
    $_SESSION['otp_error'],
    $_SESSION['otp_message']
);

try {
    $pdo = database_connection();
    $ipAddress = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: 'unknown';

    if (login_attempt_is_limited($pdo, $ipAddress, $username)) {
        $_SESSION['login_error'] = 'Invalid username or password. Please wait before trying again.';
        header('Location: ../login.php');
        exit;
    }

    /*
     * Find the account.
     */
    $stmt = $pdo->prepare("
        SELECT
            id,
            username,
            password,
            name,
            email,
            role,
            is_active
        FROM users
        WHERE username = :username
        LIMIT 1
    ");

    $stmt->execute(['username' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password'])) {
        record_failed_login_attempt($pdo, $ipAddress, $username);
        $_SESSION['login_error'] = 'Invalid username or password.';
        header('Location: ../login.php');
        exit;
    }

    clear_login_attempts($pdo, $ipAddress, $username);
    remember_login_username(($_POST['remember'] ?? '') === '1' ? (string) $user['username'] : null);

    /*
     * Check account status.
     */
    if ((int) ($user['is_active'] ?? 0) !== 1) {

        $_SESSION['login_error'] = 'Invalid username or password.';

        header('Location: ../login.php');
        exit;
    }

    /*
     * ==========================================
     * SUPERADMIN
     * ==========================================
     */

    if ($user['role'] === 'superadmin') {

        if (
            empty($user['email']) ||
            !filter_var($user['email'], FILTER_VALIDATE_EMAIL)
        ) {

            $_SESSION['login_error'] =
                'Your Superadmin account does not have a valid email address.';

            header('Location: ../login.php');
            exit;
        }

        if (!reserve_superadmin_otp_request($pdo, (int) $user['id'], $ipAddress)) {
            $_SESSION['login_error'] = 'Too many verification code requests. Please wait before trying again.';
            header('Location: ../login.php');
            exit;
        }

        /*
         * Do NOT authenticate the Superadmin yet.
         */
        $isSuperadminOtpAttempt = true;

        session_regenerate_id(true);

        $_SESSION['pending_superadmin_id'] =
            (int) $user['id'];

        $_SESSION['pending_superadmin_name'] =
            $user['name'];

        $_SESSION['pending_superadmin_email'] =
            $user['email'];
        $_SESSION['pending_superadmin_role'] =
            'superadmin';

        /*
         * Send real Gmail OTP.
         */
        sendSuperadminOtp(
            $pdo,
            (int) $user['id'],
            (string) $user['name'],
            (string) $user['email']
        );

        /*
         * Record OTP request time.
         */
        $_SESSION['otp_sent_at'] = time();

        header('Location: ../superadmin/otp.php');
        exit;
    }

    /*
     * ==========================================
     * ADMIN
     * ==========================================
     */

    if ($user['role'] === 'admin') {

        session_regenerate_id(true);

        $_SESSION['user_id'] =
            (int) $user['id'];

        $_SESSION['authenticated'] = true;

        $_SESSION['username'] =
            $user['username'];

        $_SESSION['full_name'] =
            $user['name'];

        $_SESSION['role'] =
            'admin';

        $_SESSION['superadmin_verified'] =
            false;

        record_last_login($pdo, (int) $user['id']);

        header('Location: ../admin/dashboard.php');
        exit;
    }

    /*
     * ==========================================
     * USER
     * ==========================================
     */

    if ($user['role'] === 'user') {

        session_regenerate_id(true);

        $_SESSION['user_id'] =
            (int) $user['id'];

        $_SESSION['authenticated'] = true;

        $_SESSION['username'] =
            $user['username'];

        $_SESSION['full_name'] =
            $user['name'];

        $_SESSION['role'] =
            'user';

        $_SESSION['superadmin_verified'] =
            false;

        record_last_login($pdo, (int) $user['id']);

        header('Location: ../user/dashboard.php');
        exit;
    }

    /*
     * Unknown role.
     */
    $_SESSION['login_error'] =
        'Your account has an invalid role.';

    header('Location: ../login.php');
    exit;

} catch (Throwable $e) {

    error_log(
        'MalDetect login error: ' . $e->getMessage()
    );

    $_SESSION['login_error'] = $isSuperadminOtpAttempt
        ? 'Could not send the Superadmin verification code. Check the registered email address and mail configuration.'
        : 'Unable to complete login. Please try again.';

    unset(
        $_SESSION['pending_superadmin_id'],
        $_SESSION['pending_superadmin_name'],
        $_SESSION['pending_superadmin_email'],
        $_SESSION['pending_superadmin_role'],
        $_SESSION['otp_sent_at']
    );

    header('Location: ../login.php');
    exit;
}