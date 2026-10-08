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
    <title>Access Denied | MalDetect</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-white antialiased">
    <main class="grid min-h-screen place-items-center px-6">
        <section class="w-full max-w-lg rounded-3xl border border-red-300/20 bg-slate-900/80 p-10 text-center shadow-2xl">
            <p class="font-mono text-xs tracking-[.25em] text-red-300">SECURITY GATE</p>
            <h1 class="mt-5 text-4xl font-bold">ACCESS DENIED</h1>
            <p class="mt-4 text-slate-300">You do not have permission to access this page.</p>
            <a href="<?= htmlspecialchars($dashboard, ENT_QUOTES, 'UTF-8') ?>" class="mt-8 inline-flex rounded-xl bg-violet-400 px-5 py-3 font-semibold text-slate-950 transition hover:bg-white">Return to Dashboard</a>
        </section>
    </main>
</body>
</html>
