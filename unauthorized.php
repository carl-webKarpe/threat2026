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
    <script>tailwind.config = { theme: { extend: { fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] } } } };</script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <?php require __DIR__ . '/includes/theme_styles.php'; ?>
</head>
<body class="shell min-h-screen text-slate-800 antialiased">
    <main class="grid min-h-screen place-items-center px-6">
        <section class="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-10 text-center shadow-lg">
            <span class="mx-auto grid h-14 w-14 place-items-center rounded-full bg-red-50 text-red-600"><svg class="h-7 w-7" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg></span>
            <h1 class="mt-5 text-2xl font-bold tracking-tight text-slate-900">Access denied</h1>
            <p class="mt-2 text-sm text-slate-500">You do not have permission to access this page.</p>
            <a href="<?= htmlspecialchars($dashboard, ENT_QUOTES, 'UTF-8') ?>" class="mt-8 inline-flex rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700">Return to dashboard</a>
        </section>
    </main>
</body>
</html>
