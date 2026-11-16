<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/auth_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../auth/otp_functions.php';

start_secure_session();
if (empty($_SESSION['pending_superadmin_id']) || ($_SESSION['pending_superadmin_role'] ?? '') !== 'superadmin') {
    header('Location: ../loginform.php');
    exit;
}

$error = (string) ($_SESSION['otp_error'] ?? '');
$message = (string) ($_SESSION['otp_message'] ?? '');
unset($_SESSION['otp_error'], $_SESSION['otp_message']);
$latest = database_connection()->prepare(
    'SELECT created_at, expires_at FROM superadmin_otps WHERE user_id = :user_id AND used = 0 ORDER BY id DESC LIMIT 1'
);
$latest->execute(['user_id' => (int) $_SESSION['pending_superadmin_id']]);
$otpRecord = $latest->fetch() ?: [];
$createdAt = strtotime((string) ($otpRecord['created_at'] ?? 'now')) ?: time();
$expiresAt = strtotime((string) ($otpRecord['expires_at'] ?? '+5 minutes')) ?: time() + 300;
$maskedEmail = maskEmail((string) ($_SESSION['pending_superadmin_email'] ?? ''));
$cooldownUntil = $createdAt + 60;
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Superadmin Verification | MalDetect</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="grid min-h-screen place-items-center bg-slate-950 px-6 text-white"><main class="w-full max-w-md rounded-3xl border border-violet-300/20 bg-slate-900 p-8 shadow-2xl"><p class="font-mono text-xs tracking-[.22em] text-violet-300">SUPERADMIN SECURITY CHECK</p><h1 class="mt-4 text-3xl font-bold">Check Your Email</h1><p class="mt-3 text-sm leading-6 text-slate-300">A 6-digit verification code was sent to <strong class="text-violet-200"><?= htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8') ?></strong>.</p><?php if ($error !== ''): ?><div class="mt-6 rounded-xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?><?php if ($message !== ''): ?><div class="mt-6 rounded-xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100" role="status"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?><form class="mt-7" method="post" action="../auth/verify_otp.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>"><label class="block text-sm font-semibold text-slate-200" for="otp">Verification code</label><input class="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-center font-mono text-2xl tracking-[.5em] text-white outline-none focus:border-violet-300" id="otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required autofocus><button class="mt-6 w-full rounded-xl bg-violet-300 px-4 py-3 font-bold text-slate-950 hover:bg-white" type="submit">Verify and Continue</button></form><div class="mt-6 text-center text-sm text-slate-400"><p id="expiry">Code expires soon</p><form class="mt-3" method="post" action="../auth/resend_otp.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>"><button id="resend" class="text-violet-300 hover:text-white disabled:cursor-not-allowed disabled:opacity-50" type="submit">Resend Code</button></form></div><form class="mt-6 text-center" method="post" action="../logout.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>"><button class="text-sm text-slate-500 hover:text-white" type="submit">Cancel and return to login</button></form></main><script>
const expiry = document.querySelector('#expiry');
const resend = document.querySelector('#resend');
const expiresAt = <?= $expiresAt * 1000 ?>;
const cooldownUntil = <?= $cooldownUntil * 1000 ?>;
const updateCountdown = () => {
    const now = Date.now();
    const expirySeconds = Math.max(0, Math.ceil((expiresAt - now) / 1000));
    const cooldownSeconds = Math.max(0, Math.ceil((cooldownUntil - now) / 1000));
    expiry.textContent = expirySeconds > 0 ? `Code expires in ${Math.floor(expirySeconds / 60)}:${String(expirySeconds % 60).padStart(2, '0')}` : 'Code expired. Request a new code.';
    resend.disabled = cooldownSeconds > 0;
    resend.textContent = cooldownSeconds > 0 ? `Resend available in ${cooldownSeconds} seconds` : 'Resend Code';
};
updateCountdown();
window.setInterval(updateCountdown, 1000);
</script></body></html>
