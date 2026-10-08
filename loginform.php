<?php

declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
    'use_strict_mode' => true,
]);

$error = $_SESSION['login_error'] ?? '';
$username = $_SESSION['login_username'] ?? '';
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
    <title>Sign in | MalDetect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { theme: { extend: { fontFamily: { sans: ['Manrope', 'sans-serif'], mono: ['DM Mono', 'monospace'] }, colors: { night: '#0d0b1d', electric: '#b9a3ff', cloud: '#c9c4d9' } } } };
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root { color-scheme: dark; }
        * { box-sizing: border-box; }
        body { margin: 0; background: #0d0b1d; font-family: Manrope, sans-serif; }
        .aurora { background: radial-gradient(circle at 20% 20%, rgba(139,92,246,.3), transparent 30%), radial-gradient(circle at 78% 72%, rgba(52,211,153,.15), transparent 26%), linear-gradient(145deg, #16102d 0%, #0d0b1d 62%); }
        .grid-lines { background-image: linear-gradient(rgba(185,163,255,.07) 1px, transparent 1px), linear-gradient(90deg, rgba(185,163,255,.07) 1px, transparent 1px); background-size: 42px 42px; mask-image: linear-gradient(to bottom, black, transparent 92%); }
        .glass { background: rgba(18, 14, 38, .68); border: 1px solid rgba(219, 210, 255, .13); box-shadow: 0 28px 80px rgba(0,0,0,.28); backdrop-filter: blur(24px); }
        .node { animation: pulse 3.8s ease-in-out infinite; }
        .node:nth-child(2) { animation-delay: .7s; } .node:nth-child(3) { animation-delay: 1.4s; } .node:nth-child(4) { animation-delay: 2.1s; }
        @keyframes pulse { 0%, 100% { opacity: .45; transform: scale(1); } 50% { opacity: 1; transform: scale(1.16); } }
        @keyframes rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
        .enter { animation: rise .7s ease both; } .enter-delay { animation-delay: .12s; }
        @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; } }
    </style>
</head>
<body class="min-h-screen text-white antialiased">
    <main class="mx-auto flex min-h-screen w-full max-w-[1500px] p-3 sm:p-5 lg:p-8">
        <div class="grid min-h-[calc(100vh-1.5rem)] w-full overflow-hidden rounded-[2rem] border border-white/10 bg-[#111027] shadow-2xl lg:grid-cols-[1.08fr_.92fr] lg:min-h-[calc(100vh-4rem)]">
            <section class="aurora relative hidden overflow-hidden p-10 lg:flex lg:flex-col lg:justify-between xl:p-16" aria-label="MalDetect overview">
                <div class="grid-lines pointer-events-none absolute inset-0"></div>
                <a href="index.php" class="relative z-10 flex items-center gap-3 font-mono text-sm tracking-[.2em] transition hover:text-electric" aria-label="Back to MalDetect homepage" title="Back to homepage"><span class="grid h-10 w-10 place-items-center rounded-xl border border-electric/40 bg-electric/10 text-electric">⌁</span>MAL<span class="text-electric">DETECT</span></a>
                <div class="relative z-10 max-w-xl enter"><p class="mb-5 font-mono text-xs tracking-[.24em] text-emerald-300">INTELLIGENT THREAT ANALYSIS</p><h1 class="text-5xl font-extrabold leading-[1.06] tracking-tight xl:text-6xl">Protect.<br><span class="text-electric">Detect.</span><br>Secure.</h1><p class="mt-7 max-w-md text-base leading-8 text-cloud">Detect threats before they become a problem with a clear, intelligent security layer for your digital environment.</p><div class="relative mt-14 h-36 max-w-md" aria-hidden="true"><div class="absolute left-0 right-5 top-1/2 border-t border-dashed border-electric/30"></div><div class="absolute left-[16%] top-[22%] h-20 w-20 rounded-full border border-electric/20"></div><div class="absolute left-[43%] top-[8%] h-28 w-28 rounded-full border border-emerald-300/20"></div><div class="absolute right-[8%] top-[28%] h-14 w-14 rounded-full border border-electric/20"></div><div class="node absolute left-[16%] top-[48%] h-3 w-3 rounded-full bg-electric shadow-[0_0_18px_#b9a3ff]"></div><div class="node absolute left-[48%] top-[15%] h-3 w-3 rounded-full bg-emerald-300 shadow-[0_0_18px_#6ee7b7]"></div><div class="node absolute right-[10%] top-[48%] h-3 w-3 rounded-full bg-electric shadow-[0_0_18px_#b9a3ff]"></div><div class="absolute left-[44%] top-[35%] grid h-16 w-16 place-items-center rounded-2xl border border-electric/40 bg-electric/10 text-electric shadow-[0_0_40px_rgba(139,92,246,.3)]">◈</div></div></div>
                <div class="relative z-10 flex items-center justify-between font-mono text-[10px] tracking-[.15em] text-white/45"><span>SECURITY LAYER / 01</span><span class="flex items-center gap-2"><span class="h-2 w-2 rounded-full bg-emerald-300 shadow-[0_0_10px_#6ee7b7]"></span> SYSTEM ONLINE</span></div>
            </section>
            <section class="relative flex items-center justify-center overflow-hidden px-6 py-12 sm:px-12 lg:px-14 xl:px-20"><div class="absolute -right-24 -top-24 h-72 w-72 rounded-full bg-violet-500/10 blur-3xl"></div><div class="relative z-10 w-full max-w-md enter enter-delay"><div class="mb-10 lg:hidden"><a href="/" class="inline-flex items-center gap-3 font-mono text-sm tracking-[.2em]">MAL<span class="text-electric">DETECT</span></a></div><p class="font-mono text-[10px] tracking-[.24em] text-electric">SECURE AUTHENTICATION</p><h2 class="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">Welcome Back</h2><p class="mt-3 text-sm text-cloud">Sign in to MalDetect to continue your security work.</p><?php if ($error !== ''): ?><div class="mt-7 rounded-xl border border-red-300/25 bg-red-400/10 px-4 py-3 text-sm text-red-100" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?><form class="mt-8" method="post" action="auth/login_process.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($loginCsrfToken, ENT_QUOTES, 'UTF-8') ?>">
<label class="block text-xs font-semibold text-cloud" for="username">Username</label>
<div class="relative mt-2">
    <span class="absolute left-4 top-1/2 -translate-y-1/2 text-electric/60">@</span>
    <input class="w-full rounded-xl border border-white/10 bg-white/[.04] px-11 py-3.5 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-electric/70 focus:bg-white/[.07] focus:ring-4 focus:ring-violet-500/10" id="username" name="username" type="text" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>" autocomplete="username" required autofocus placeholder="Enter your username">
</div>
<div class="mt-6 flex items-center justify-between">
    <label class="text-xs font-semibold text-cloud" for="password">Password</label>
    <span class="font-mono text-[10px] text-white/35">PROTECTED ACCESS</span>
</div>
<div class="relative mt-2">
    <span class="absolute left-4 top-1/2 -translate-y-1/2 text-electric/60">◆</span>
    <input class="w-full rounded-xl border border-white/10 bg-white/[.04] px-11 py-3.5 pr-12 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-electric/70 focus:bg-white/[.07] focus:ring-4 focus:ring-violet-500/10" id="password" name="password" type="password" autocomplete="current-password" required placeholder="Enter your password">
    <button class="absolute right-3 top-1/2 grid h-8 w-8 -translate-y-1/2 place-items-center rounded-lg text-cloud transition hover:bg-white/10 hover:text-white" type="button" data-toggle-password aria-label="Show password">◉</button>
</div>
<label class="mt-5 flex items-center gap-3 text-xs text-cloud">
    <input class="h-4 w-4 rounded border-white/20 bg-night text-violet-500 focus:ring-violet-500" type="checkbox" name="remember" value="1"> Remember this device
</label>
<button class="mt-7 flex w-full items-center justify-center gap-3 rounded-xl bg-electric px-5 py-3.5 text-sm font-bold text-night transition hover:-translate-y-0.5 hover:bg-white hover:shadow-[0_0_30px_rgba(185,163,255,.25)] focus:outline-none focus:ring-4 focus:ring-violet-500/30" type="submit">Sign in securely <span aria-hidden="true">→</span></button>
</form>
<p class="mt-7 text-center text-xs leading-6 text-white/35">Account access is managed by the system administrator.<br>There is no public registration.</p>
</div></section>
        </div>
    </main>
    <script>document.querySelectorAll('a[href="/"]').forEach((link) => { link.href = 'index.php'; link.setAttribute('aria-label', 'Back to MalDetect homepage'); }); const toggle = document.querySelector('[data-toggle-password]'); const password = document.querySelector('#password'); toggle?.addEventListener('click', () => { const visible = password.type === 'password'; password.type = visible ? 'text' : 'password'; toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password'); });</script>
</body>
</html>