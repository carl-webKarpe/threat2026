<?php

declare(strict_types=1);

use PHPMailer\PHPMailer\PHPMailer;

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/database.php';

/**
 * Load Gmail SMTP configuration.
 */
function getMailConfig(): array
{
    $configFile = __DIR__ . '/../config/mail.local.php';

    if (!file_exists($configFile)) {
        throw new RuntimeException('Mail configuration file is missing.');
    }

    $config = require $configFile;

    $required = [
        'host',
        'port',
        'username',
        'password',
        'encryption',
        'from_email',
        'from_name'
    ];

    foreach ($required as $key) {
        if (empty($config[$key])) {
            throw new RuntimeException("Mail configuration is incomplete.");
        }
    }

    return $config;
}

/**
 * Mask an email address for display.
 *
 * Example:
 * amprelblancada@gmail.com
 * becomes:
 * a***********@gmail.com
 */
function maskEmail(string $email): string
{
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return 'your registered email';
    }

    [$local, $domain] = explode('@', $email, 2);

    if (strlen($local) <= 2) {
        $maskedLocal = substr($local, 0, 1) . '*';
    } else {
        $maskedLocal =
            substr($local, 0, 1) .
            str_repeat('*', max(3, strlen($local) - 1));
    }

    return $maskedLocal . '@' . $domain;
}

/**
 * Invalidate all previous unused OTPs for a Superadmin.
 */
function invalidateOldOtps(PDO $pdo, int $userId): void
{
    $stmt = $pdo->prepare("
        UPDATE superadmin_otps
        SET used = 1
        WHERE user_id = ?
          AND used = 0
    ");

    $stmt->execute([$userId]);
}

/**
 * Send a new Superadmin OTP.
 *
 * Returns the OTP record ID.
 */
function sendSuperadminOtp(
    PDO $pdo,
    int $userId,
    string $name,
    string $email
): int {

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException(
            'The Superadmin account does not have a valid email address.'
        );
    }

    $mailConfig = getMailConfig();

    // Invalidate previous codes.
    invalidateOldOtps($pdo, $userId);

    // Generate cryptographically secure 6-digit OTP.
    $otp = (string) random_int(100000, 999999);

    // Hash OTP before database storage.
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);

    // Expire after 5 minutes.
    $expiresAt = date(
        'Y-m-d H:i:s',
        time() + (5 * 60)
    );

    // Store hashed OTP.
    $stmt = $pdo->prepare("
        INSERT INTO superadmin_otps
        (
            user_id,
            otp_hash,
            expires_at,
            attempts
        )
        VALUES
        (
            ?,
            ?,
            ?,
            0
        )
    ");

    $stmt->execute([
        $userId,
        $otpHash,
        $expiresAt
    ]);

    $otpId = (int) $pdo->lastInsertId();

    $mail = new PHPMailer(true);

    try {

        // SMTP configuration.
        $mail->isSMTP();
        $mail->Host = $mailConfig['host'];
        $mail->SMTPAuth = true;
        $mail->Username = $mailConfig['username'];
        $mail->Password = $mailConfig['password'];

        if ($mailConfig['encryption'] === 'tls') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        } else {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        }

        $mail->Port = (int) $mailConfig['port'];

        // Sender.
        $mail->setFrom(
            $mailConfig['from_email'],
            $mailConfig['from_name']
        );

        // Recipient.
        $mail->addAddress($email, $name);

        // Email format.
        $mail->isHTML(true);

        $mail->Subject =
            'MalDetect Superadmin Verification Code';

        $safeName = htmlspecialchars(
            $name ?: 'Superadmin',
            ENT_QUOTES,
            'UTF-8'
        );

        $safeOtp = htmlspecialchars(
            $otp,
            ENT_QUOTES,
            'UTF-8'
        );

        $mail->Body = "
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset='UTF-8'>
                <title>MalDetect Verification Code</title>
            </head>

            <body style='
                margin:0;
                padding:0;
                background:#0b1220;
                font-family:Arial,sans-serif;
            '>

                <div style='
                    max-width:560px;
                    margin:40px auto;
                    background:#111827;
                    border-radius:18px;
                    padding:35px;
                    color:#ffffff;
                '>

                    <h1 style='
                        margin-top:0;
                        color:#ffffff;
                    '>
                        MalDetect
                    </h1>

                    <p style='color:#cbd5e1;'>
                        Hello {$safeName},
                    </p>

                    <p style='color:#cbd5e1;'>
                        Your Superadmin verification code is:
                    </p>

                    <div style='
                        background:#1f2937;
                        border-radius:14px;
                        padding:22px;
                        text-align:center;
                        margin:25px 0;
                    '>

                        <div style='
                            font-size:36px;
                            font-weight:bold;
                            letter-spacing:10px;
                            color:#facc15;
                        '>
                            {$safeOtp}
                        </div>

                    </div>

                    <p style='color:#cbd5e1;'>
                        This verification code will expire in
                        <strong>5 minutes</strong>.
                    </p>

                    <p style='color:#94a3b8;font-size:14px;'>
                        If you did not attempt to sign in to MalDetect,
                        please ignore this email and review your account
                        security.
                    </p>

                    <hr style='
                        border:0;
                        border-top:1px solid #374151;
                        margin:25px 0;
                    '>

                    <p style='
                        color:#64748b;
                        font-size:12px;
                    '>
                        MalDetect Security System
                    </p>

                </div>

            </body>
            </html>
        ";

        // Plain-text fallback.
        $mail->AltBody =
            "MalDetect Superadmin Verification Code\n\n" .
            "Hello {$name},\n\n" .
            "Your verification code is: {$otp}\n\n" .
            "This code expires in 5 minutes.\n\n" .
            "MalDetect Security System";

        $mail->send();

    } catch (Throwable $e) {

        // Remove OTP if email sending fails.
        try {
            $delete = $pdo->prepare("
                DELETE FROM superadmin_otps
                WHERE id = ?
            ");
            $delete->execute([$otpId]);
        } catch (Throwable $cleanupError) {
            error_log(
                'MalDetect OTP cleanup error: ' . $cleanupError->getMessage()
            );
        }

        // Log technical error on server only.
        error_log(
            'MalDetect OTP email error: ' . $e->getMessage()
        );

        throw new RuntimeException(
            'Unable to send the verification code.'
        );
    }

    return $otpId;
}