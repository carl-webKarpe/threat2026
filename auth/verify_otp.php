<?php

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/csrf.php';

start_secure_session();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../superadmin/otp.php');
    exit;
}


/*
 * Check pending Superadmin.
 */
if (empty($_SESSION['pending_superadmin_id'])) {

    header('Location: ../login.php');
    exit;
}


/*
 * CSRF protection.
 */
if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {

    $_SESSION['otp_error'] =
        'Invalid security request. Please try again.';

    header('Location: ../superadmin/otp.php');
    exit;
}


/*
 * Get OTP.
 */
$enteredOtp = trim(
    $_POST['otp'] ?? ''
);


/*
 * OTP must contain exactly six digits.
 */
if (
    !preg_match('/^[0-9]{6}$/', $enteredOtp)
) {

    $_SESSION['otp_error'] =
        'Please enter the 6-digit verification code.';

    header('Location: ../superadmin/otp.php');
    exit;
}


$userId =
    (int) $_SESSION['pending_superadmin_id'];


try {
    $pdo = database_connection();

    $recentFailures = $pdo->prepare(
        'SELECT COALESCE(SUM(attempts), 0)
         FROM superadmin_otps
         WHERE user_id = :user_id
           AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
    );
    $recentFailures->execute(['user_id' => $userId]);
    if ((int) $recentFailures->fetchColumn() >= 10) {
        $_SESSION['otp_error'] = 'Too many attempts. Please wait 15 minutes before trying again.';
        header('Location: ../superadmin/otp.php');
        exit;
    }

    /*
     * Get latest unused OTP.
     */
    $stmt = $pdo->prepare("
        SELECT
            id,
            otp_hash,
            expires_at,
            attempts,
            used
        FROM superadmin_otps
        WHERE user_id = ?
          AND used = 0
        ORDER BY id DESC
        LIMIT 1
    ");

    $stmt->execute([$userId]);

    $otpRecord =
        $stmt->fetch(PDO::FETCH_ASSOC);


    /*
     * No active OTP.
     */
    if (!$otpRecord) {

        $_SESSION['otp_error'] =
            'Invalid or expired verification code.';

        header('Location: ../superadmin/otp.php');
        exit;
    }


    /*
     * Maximum attempts.
     */
    if ((int) $otpRecord['attempts'] >= 5) {

        $invalidate = $pdo->prepare("
            UPDATE superadmin_otps
            SET used = 1
            WHERE id = ?
        ");

        $invalidate->execute([
            $otpRecord['id']
        ]);

        $_SESSION['otp_error'] =
            'Too many failed attempts. Please request a new code.';

        header('Location: ../superadmin/otp.php');
        exit;
    }


    /*
     * Check expiration.
     */
    if (
        strtotime($otpRecord['expires_at']) < time()
    ) {

        $invalidate = $pdo->prepare("
            UPDATE superadmin_otps
            SET used = 1
            WHERE id = ?
        ");

        $invalidate->execute([
            $otpRecord['id']
        ]);

        $_SESSION['otp_error'] =
            'Invalid or expired verification code.';

        header('Location: ../superadmin/otp.php');
        exit;
    }


    /*
     * Verify hashed OTP.
     */
    $valid =
        password_verify(
            $enteredOtp,
            $otpRecord['otp_hash']
        );


    /*
     * Wrong OTP.
     */
    if (!$valid) {

        $increment = $pdo->prepare("
            UPDATE superadmin_otps
            SET attempts = attempts + 1
            WHERE id = ?
              AND used = 0
        ");

        $increment->execute([
            $otpRecord['id']
        ]);

        $newAttempts =
            ((int) $otpRecord['attempts']) + 1;


        if ($newAttempts >= 5) {

            $invalidate = $pdo->prepare("
                UPDATE superadmin_otps
                SET used = 1
                WHERE id = ?
            ");

            $invalidate->execute([
                $otpRecord['id']
            ]);

            $_SESSION['otp_error'] =
                'Too many failed attempts. Please request a new code.';

        } else {

            $_SESSION['otp_error'] =
                'Invalid or expired verification code.';
        }

        header('Location: ../superadmin/otp.php');
        exit;
    }


    /*
     * OTP is correct.
     *
     * Mark as used BEFORE creating the
     * authenticated session.
     */
    $markUsed = $pdo->prepare("
        UPDATE superadmin_otps
        SET used = 1
        WHERE id = ?
          AND used = 0
    ");

    $markUsed->execute([
        $otpRecord['id']
    ]);


    /*
     * Retrieve Superadmin information.
     */
    $userStmt = $pdo->prepare("
        SELECT
            id,
            username,
            name,
            role,
            is_active
        FROM users
        WHERE id = ?
          AND role = 'superadmin'
        LIMIT 1
    ");

    $userStmt->execute([$userId]);

    $user =
        $userStmt->fetch(PDO::FETCH_ASSOC);


    if (
        !$user ||
        (int) $user['is_active'] !== 1
    ) {

        session_unset();
        session_destroy();

        header('Location: ../login.php');
        exit;
    }


    /*
     * New authenticated session.
     */
    session_regenerate_id(true);


    /*
     * Full authentication.
     */
    $_SESSION['user_id'] =
        (int) $user['id'];

    $_SESSION['authenticated'] = true;

    $_SESSION['username'] =
        $user['username'];

    $_SESSION['full_name'] =
        $user['name'];

    $_SESSION['role'] =
        'superadmin';

    $_SESSION['superadmin_verified'] =
        true;

    /*
     * Remove temporary OTP session data.
     */
    unset(
        $_SESSION['pending_superadmin_id'],
        $_SESSION['pending_superadmin_name'],
        $_SESSION['pending_superadmin_email'],
        $_SESSION['pending_superadmin_role'],
        $_SESSION['otp_sent_at'],
        $_SESSION['csrf_token'],
        $_SESSION['otp_error']
    );


    record_last_login($pdo, (int) $user['id']);

    /*
     * Redirect to Superadmin dashboard.
     */
    header('Location: ../superadmin/dashboard.php');
    exit;


} catch (Throwable $e) {

    error_log(
        'MalDetect OTP verification error: ' .
        $e->getMessage()
    );

    $_SESSION['otp_error'] =
        'Unable to verify the code. Please try again.';

    header('Location: ../superadmin/otp.php');
    exit;
}