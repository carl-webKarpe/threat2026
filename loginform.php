<?php

declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
    'use_strict_mode' => true,
]);

$error = $_SESSION['login_error'] ?? '';
// After a failed login the username stays filled in; with "Remember my username" it is also kept in a cookie.
$rememberedUsername = (string) ($_COOKIE['maldetect_username'] ?? '');
if (!preg_match('/^[A-Za-z0-9._-]{1,100}$/', $rememberedUsername)) {
    $rememberedUsername = '';
}
$username = (string) ($_SESSION['login_username'] ?? $rememberedUsername);
unset($_SESSION['login_error'], $_SESSION['login_username']);
require_once __DIR__ . '/auth/csrf.php';
$loginCsrfToken = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Secure login for JunMalware intelligent malicious software detection.">
    <meta name="theme-color" content="#07070b">
    <title>Sign in | JunMalware</title>
    <?php require __DIR__ . '/includes/theme_head.php'; ?>
</head>
<body class="shell min-h-screen text-neutral-200 antialiased">
    <main class="relative mx-auto grid min-h-screen max-w-7xl items-center gap-12 px-6 py-10 lg:grid-cols-[1.15fr_.85fr] lg:px-12">
        <header class="absolute inset-x-6 top-6 flex items-center justify-between lg:inset-x-12">
            <a href="index.php" class="font-display text-sm uppercase tracking-[.3em] text-white">Jun<span class="text-accent-light">M</span>alware</a>
            <span class="hidden items-center gap-2 text-[11px] uppercase tracking-[.25em] text-neutral-500 sm:flex"><span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>System online</span>
        </header>
        <section class="hidden lg:block" aria-label="About JunMalware">
            <p class="text-xs uppercase tracking-[.4em] text-neutral-400">Malware detection system</p>
            <h1 class="relative isolate mt-5 font-display text-6xl uppercase leading-none tracking-[.12em] text-white xl:text-7xl"><span class="relative inline-block"><span class="absolute -inset-y-3 -left-4 right-[-.15em] -z-10 bg-accent" aria-hidden="true"></span>J</span>un<br>Malware</h1>
            <div class="mt-10 flex max-w-md gap-5">
                <span class="mt-1 h-16 w-px shrink-0 bg-white/20" aria-hidden="true"></span>
                <p class="text-sm leading-7 text-neutral-400">Every download on your monitored PCs is checked with VirusTotal, and file activity is recorded in real time. Results appear on this server only.</p>
            </div>
            <dl class="mt-14 grid max-w-lg grid-cols-3 gap-6 border-t border-white/10 pt-6">
                <div><dt class="text-[10px] uppercase tracking-[.25em] text-neutral-500">01 / Scan</dt><dd class="mt-2 text-sm text-neutral-200">VirusTotal checks</dd></div>
                <div><dt class="text-[10px] uppercase tracking-[.25em] text-neutral-500">02 / Watch</dt><dd class="mt-2 text-sm text-neutral-200">Live file activity</dd></div>
                <div><dt class="text-[10px] uppercase tracking-[.25em] text-neutral-500">03 / Alert</dt><dd class="mt-2 text-sm text-neutral-200">Email and reports</dd></div>
            </dl>
        </section>
        <section class="w-full pt-16 lg:pt-0">
            <div class="mx-auto w-full max-w-sm rounded-2xl border border-white/10 bg-panel/80 p-8 shadow-2xl shadow-black/50 backdrop-blur">
                <p class="text-[11px] uppercase tracking-[.3em] text-accent-light">Secure access</p>
                <h2 class="mt-3 font-display text-xl uppercase tracking-[.1em] text-white">Sign in</h2>
                <p class="mt-2 text-sm text-neutral-400">Enter your account details to continue.</p>
                <?php if ($error !== ''): ?><div class="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
                <form class="mt-7 space-y-5" method="post" action="auth/login_process.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($loginCsrfToken, ENT_QUOTES, 'UTF-8') ?>">
                    <div>
                        <label class="block text-xs uppercase tracking-[.2em] text-neutral-400" for="username">Username</label>
                        <input class="mt-2 w-full rounded-lg border border-white/15 bg-ink/60 px-3.5 py-2.5 text-sm text-white outline-none transition placeholder:text-neutral-600 focus:border-accent focus:ring-4 focus:ring-accent/30" id="username" name="username" type="text" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>" autocomplete="username" required autofocus placeholder="Enter your username">
                    </div>
                    <div>
                        <label class="block text-xs uppercase tracking-[.2em] text-neutral-400" for="password">Password</label>
                        <div class="relative mt-2">
                            <input class="w-full rounded-lg border border-white/15 bg-ink/60 px-3.5 py-2.5 pr-16 text-sm text-white outline-none transition placeholder:text-neutral-600 focus:border-accent focus:ring-4 focus:ring-accent/30" id="password" name="password" type="password" autocomplete="current-password" required placeholder="Enter your password">
                            <button class="absolute right-2 top-1/2 -translate-y-1/2 rounded-md px-2 py-1 text-[11px] uppercase tracking-[.15em] text-neutral-400 hover:bg-white/10 hover:text-white" type="button" data-toggle-password aria-label="Show password">Show</button>
                        </div>
                    </div>
                    <label class="flex items-center gap-2.5 text-sm text-neutral-400">
                        <input class="h-4 w-4 rounded border-white/20 bg-ink text-accent focus:ring-accent" type="checkbox" name="remember" value="1"<?= $rememberedUsername !== '' ? ' checked' : '' ?>> Remember my username
                    </label>
                    <button class="flex w-full items-center justify-center gap-3 rounded-lg bg-accent px-4 py-3 text-xs font-semibold uppercase tracking-[.25em] text-white shadow-lg shadow-accent/30 transition hover:bg-accent-dark focus:outline-none focus:ring-4 focus:ring-accent/40" type="submit">Sign in <span aria-hidden="true">→</span></button>
                </form>
                <p class="mt-7 text-center text-xs leading-5 text-neutral-500">Accounts are created by the system administrator.<br>There is no public registration.</p>
            </div>
        </section>
    </main>
    <script>const toggle = document.querySelector('[data-toggle-password]'); const password = document.querySelector('#password'); toggle?.addEventListener('click', () => { const visible = password.type === 'password'; password.type = visible ? 'text' : 'password'; toggle.textContent = visible ? 'Hide' : 'Show'; toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password'); });</script>
</body>
</html>
