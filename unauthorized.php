<?php

declare(strict_types=1);

require_once __DIR__ . '/auth/auth_check.php';
start_secure_session();
$dashboard = match ($_SESSION['role'] ?? '') {
    'superadmin' => 'superadmin/dashboard.php',
    'admin' => 'admin/dashboard.php',
    'user' => 'user/dashboard.php',
    default => 'loginform.php',
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied | JunMalware</title>
    <?php require __DIR__ . '/includes/theme_head.php'; ?>
</head>
<body class="shell min-h-screen text-neutral-100 antialiased">
    <main class="grid min-h-screen place-items-center px-6">
        <section class="w-full max-w-md rounded-2xl border border-white/10 bg-panel p-10 text-center shadow-lg">
            <span class="mx-auto grid h-14 w-14 place-items-center rounded-full bg-red-500/10 text-red-400"><svg class="h-7 w-7" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg></span>
            <h1 class="mt-5 font-display text-xl uppercase tracking-[.08em] text-white">Access denied</h1>
            <p class="mt-2 text-sm text-neutral-400">You do not have permission to access this page.</p>
            <a href="<?= htmlspecialchars($dashboard, ENT_QUOTES, 'UTF-8') ?>" class="mt-8 inline-flex rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-dark">Return to dashboard</a>
        </section>
    </main>
</body>
</html>
