<?php

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/otp_functions.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/otp_rate_limit.php';

start_secure_session();


/*
 * Must be POST.
 */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {

    header('Location: ../login.php');
    exit;
}


/*
 * Must have pending Superadmin.
 */
if (empty($_SESSION['pending_superadmin_id'])) {

    header('Location: ../login.php');
    exit;
}


/*
 * CSRF validation.
 */
if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {

    $_SESSION['otp_error'] =
        'Invalid security request.';

    header('Location: ../superadmin/otp.php');
    exit;
}


/*
 * 60-second resend cooldown.
 */
$lastSent =
    (int) ($_SESSION['otp_sent_at'] ?? 0);

if (
    $lastSent > 0 &&
    (time() - $lastSent) < 60
) {

    $remaining =
        60 - (time() - $lastSent);

    $_SESSION['otp_error'] =
        "Please wait {$remaining} seconds before requesting another code.";

    header('Location: ../superadmin/otp.php');
    exit;
}


$userId =
    (int) $_SESSION['pending_superadmin_id'];


try {
    $pdo = database_connection();
    $ipAddress = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: 'unknown';

    /*
     * Get current Superadmin.
     */
    $stmt = $pdo->prepare("
        SELECT
            id,
            name,
            email,
            role,
            is_active
        FROM users
        WHERE id = ?
        LIMIT 1
    ");

    $stmt->execute([$userId]);

    $user =
        $stmt->fetch(PDO::FETCH_ASSOC);


    /*
     * Validate account.
     */
    if (
        !$user ||
        $user['role'] !== 'superadmin' ||
        (int) $user['is_active'] !== 1
    ) {

        session_unset();
        session_destroy();

        header('Location: ../login.php');
        exit;
    }


    if (
        empty($user['email']) ||
        !filter_var(
            $user['email'],
            FILTER_VALIDATE_EMAIL
        )
    ) {

        $_SESSION['otp_error'] =
            'Your Superadmin account does not have a valid email address.';

        header('Location: ../superadmin/otp.php');
        exit;
    }


    if (!reserve_superadmin_otp_request($pdo, $userId, $ipAddress)) {
        $_SESSION['otp_error'] = 'Too many verification code requests. Please wait before trying again.';
        header('Location: ../superadmin/otp.php');
        exit;
    }


    /*
     * Send new OTP.
     */
    sendSuperadminOtp(
        $pdo,
        (int) $user['id'],
        (string) $user['name'],
        (string) $user['email']
    );


    /*
     * Update cooldown.
     */
    $_SESSION['otp_sent_at'] =
        time();


    $_SESSION['otp_message'] =
        'A new verification code has been sent to your email.';


    header('Location: ../superadmin/otp.php');
    exit;


} catch (Throwable $e) {

    error_log(
        'MalDetect resend OTP error: ' .
        $e->getMessage()
    );

    $_SESSION['otp_error'] =
        'Unable to send the verification code. Please try again later.';

    header('Location: ../superadmin/otp.php');
    exit;
}