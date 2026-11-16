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
    <meta name="description" content="Secure login for MalDetect intelligent malicious software detection.">
    <meta name="theme-color" content="#2563eb">
    <title>Sign in | MalDetect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = { theme: { extend: { fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] } } } };</script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <?php require __DIR__ . '/includes/theme_styles.php'; ?>
    <style>.brand-panel { background: linear-gradient(150deg, #1d4ed8 0%, #2563eb 45%, #0ea5e9 100%); } .brand-grid { background-image: linear-gradient(rgba(255,255,255,.08) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.08) 1px, transparent 1px); background-size: 40px 40px; }</style>
</head>
<body class="shell min-h-screen text-slate-800 antialiased">
    <main class="grid min-h-screen lg:grid-cols-2">
        <section class="brand-panel relative hidden overflow-hidden p-12 text-white lg:flex lg:flex-col lg:justify-between xl:p-16" aria-label="About MalDetect">
            <div class="brand-grid pointer-events-none absolute inset-0"></div>
            <a href="index.php" class="relative flex items-center gap-3" aria-label="Back to MalDetect homepage">
                <span class="grid h-10 w-10 place-items-center rounded-xl bg-white/15 ring-1 ring-white/30"><svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></span>
                <span class="text-lg font-bold tracking-tight">MalDetect</span>
            </a>
            <div class="relative max-w-lg">
                <h1 class="text-4xl font-extrabold leading-tight tracking-tight xl:text-5xl">Malicious software detection for your computer lab.</h1>
                <p class="mt-5 text-base leading-7 text-blue-50">Every download on your monitored PCs is checked with VirusTotal, and file activity is recorded in real time. Results appear here, on the server only.</p>
                <ul class="mt-8 space-y-3 text-sm text-blue-50">
                    <li class="flex items-center gap-3"><span class="grid h-6 w-6 place-items-center rounded-full bg-white/15">✓</span>Downloads checked by dozens of antivirus engines (VirusTotal)</li>
                    <li class="flex items-center gap-3"><span class="grid h-6 w-6 place-items-center rounded-full bg-white/15">✓</span>Live file activity: created, renamed, moved, deleted</li>
                    <li class="flex items-center gap-3"><span class="grid h-6 w-6 place-items-center rounded-full bg-white/15">✓</span>Email alerts and reports for administrators</li>
                </ul>
            </div>
            <p class="relative text-xs text-blue-100">Intelligent Malicious Software Detection System</p>
        </section>
        <section class="flex items-center justify-center px-6 py-12 sm:px-12">
            <div class="w-full max-w-sm">
                <a href="index.php" class="mb-10 flex items-center gap-3 lg:hidden"><span class="grid h-9 w-9 place-items-center rounded-lg bg-blue-600 text-white"><svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></span><span class="text-lg font-bold text-slate-900">MalDetect</span></a>
                <h2 class="text-2xl font-bold tracking-tight text-slate-900">Sign in</h2>
                <p class="mt-2 text-sm text-slate-500">Welcome back. Enter your account details to continue.</p>
                <?php if ($error !== ''): ?><div class="mt-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
                <form class="mt-8 space-y-5" method="post" action="auth/login_process.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($loginCsrfToken, ENT_QUOTES, 'UTF-8') ?>">
                    <div>
                        <label class="block text-sm font-medium text-slate-700" for="username">Username</label>
                        <input class="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 shadow-sm outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/15" id="username" name="username" type="text" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>" autocomplete="username" required autofocus placeholder="Enter your username">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-slate-700" for="password">Password</label>
                        <div class="relative mt-1.5">
                            <input class="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 pr-16 text-sm text-slate-900 shadow-sm outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/15" id="password" name="password" type="password" autocomplete="current-password" required placeholder="Enter your password">
                            <button class="absolute right-2 top-1/2 -translate-y-1/2 rounded-md px-2 py-1 text-xs font-semibold text-slate-500 hover:bg-slate-100 hover:text-slate-800" type="button" data-toggle-password aria-label="Show password">Show</button>
                        </div>
                    </div>
                    <label class="flex items-center gap-2.5 text-sm text-slate-600">
                        <input class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500" type="checkbox" name="remember" value="1"<?= $rememberedUsername !== '' ? ' checked' : '' ?>> Remember my username
                    </label>
                    <button class="flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-500/30" type="submit">Sign in <span aria-hidden="true">→</span></button>
                </form>
                <p class="mt-8 text-center text-xs leading-5 text-slate-400">Accounts are created by the system administrator.<br>There is no public registration.</p>
            </div>
        </section>
    </main>
    <script>const toggle = document.querySelector('[data-toggle-password]'); const password = document.querySelector('#password'); toggle?.addEventListener('click', () => { const visible = password.type === 'password'; password.type = visible ? 'text' : 'password'; toggle.textContent = visible ? 'Hide' : 'Show'; toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password'); });</script>
</body>
</html>
