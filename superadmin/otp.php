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
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Superadmin Verification | JunMalware</title><?php require __DIR__ . '/../includes/theme_head.php'; ?></head>
<body class="shell grid min-h-screen place-items-center px-6 text-neutral-100 antialiased"><main class="w-full max-w-md rounded-2xl border border-white/10 bg-panel p-8 shadow-lg">
<span class="grid h-11 w-11 place-items-center rounded-xl bg-accent/15 text-accent-light"><svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg></span>
<p class="mt-5 text-[11px] font-medium uppercase tracking-[.3em] text-accent-light">Superadmin security check</p><h1 class="mt-2 font-display text-xl uppercase tracking-[.08em] text-white">Check your email</h1><p class="mt-2 text-sm leading-6 text-neutral-400">A 6-digit verification code was sent to <strong class="text-white"><?= htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8') ?></strong>.</p>
<?php if ($error !== ''): ?><div class="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
<?php if ($message !== ''): ?><div class="mt-6 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-400" role="status"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
<form class="mt-7" method="post" action="../auth/verify_otp.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>"><label class="block text-sm font-medium text-neutral-300" for="otp">Verification code</label><input class="mono mt-1.5 w-full rounded-lg border border-white/15 bg-panel px-4 py-3 text-center text-2xl tracking-[.5em] text-white shadow-sm outline-none focus:border-accent focus:ring-4 focus:ring-accent/30" id="otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required autofocus><button class="mt-5 w-full rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-accent-dark" type="submit">Verify and continue</button></form>
<div class="mt-6 text-center text-sm text-neutral-400"><p id="expiry">Code expires soon</p><form class="mt-2" method="post" action="../auth/resend_otp.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>"><button id="resend" class="font-medium text-accent-light hover:text-white disabled:cursor-not-allowed disabled:text-neutral-600" type="submit">Resend Code</button></form></div>
<form class="mt-6 border-t border-white/5 pt-5 text-center" method="post" action="../logout.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>"><button class="text-sm text-neutral-400 hover:text-white" type="submit">Cancel and return to login</button></form></main>
<script>
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
