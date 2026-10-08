<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();
$pdo = database_connection();
$accountStats = $pdo->query("SELECT COUNT(*) AS total_accounts, SUM(role = 'admin') AS total_admins, SUM(role = 'user') AS total_users, SUM(is_active = 1) AS active_accounts, SUM(is_active = 0) AS inactive_accounts FROM users")->fetch();
$scanStats = $pdo->query("SELECT COUNT(*) AS total_scans, SUM(scan_status = 'completed') AS completed_scans, SUM(scan_status = 'failed') AS failed_scans FROM scans")->fetch();
$cards = [
    ['Total Admins', (int) ($accountStats['total_admins'] ?? 0)],
    ['Total Users', (int) ($accountStats['total_users'] ?? 0)],
    ['Active Accounts', (int) ($accountStats['active_accounts'] ?? 0)],
    ['Inactive Accounts', (int) ($accountStats['inactive_accounts'] ?? 0)],
    ['Total Scans', (int) ($scanStats['total_scans'] ?? 0)],
    ['Completed Scans', (int) ($scanStats['completed_scans'] ?? 0)],
    ['Failed Scans', (int) ($scanStats['failed_scans'] ?? 0)],
];
$pageTitle = 'Superadmin Dashboard';
$currentPage = 'dashboard';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div><main class="min-w-0 flex-1 p-6 sm:p-10"><header class="border-b border-white/10 pb-8"><p class="mono text-xs tracking-[.2em] text-violet-300">SYSTEM CONTROL</p><h1 class="mt-3 text-3xl font-bold">Superadmin Dashboard</h1><p class="mt-2 text-slate-400">Live account and scan activity across MalDetect.</p></header><section class="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="System statistics"><?php foreach ($cards as [$label, $value]): ?><article class="rounded-2xl border border-white/10 bg-white/[.04] p-5"><p class="text-sm text-slate-400"><?= superadmin_h($label) ?></p><p class="mt-3 text-3xl font-bold text-violet-200"><?= $value ?></p></article><?php endforeach; ?></section><section class="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4" aria-label="Management links"><a href="admins.php" class="rounded-2xl border border-white/10 bg-white/[.04] p-6 transition hover:border-violet-300/40"><p class="font-semibold">Admin Management</p><p class="mt-3 text-sm text-slate-500">Manage operational access</p></a><a href="users.php" class="rounded-2xl border border-white/10 bg-white/[.04] p-6 transition hover:border-violet-300/40"><p class="font-semibold">User Management</p><p class="mt-3 text-sm text-slate-500">Manage user access</p></a><a href="history.php" class="rounded-2xl border border-white/10 bg-white/[.04] p-6 transition hover:border-violet-300/40"><p class="font-semibold">Scan History</p><p class="mt-3 text-sm text-slate-500">Review system scans</p></a><a href="audit-logs.php" class="rounded-2xl border border-white/10 bg-white/[.04] p-6 transition hover:border-violet-300/40"><p class="font-semibold">Audit Logs</p><p class="mt-3 text-sm text-slate-500">Review administrative actions</p></a></section></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
