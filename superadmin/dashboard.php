<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();
$pdo = database_connection();
$accountStats = $pdo->query("SELECT COUNT(*) AS total_accounts, SUM(role = 'admin') AS total_admins, SUM(role = 'user') AS total_users, SUM(is_active = 1) AS active_accounts, SUM(is_active = 0) AS inactive_accounts FROM users")->fetch();
$scanStats = $pdo->query("SELECT COUNT(*) AS total_scans, SUM(scan_status = 'completed') AS completed_scans, SUM(scan_status = 'failed') AS failed_scans FROM scans")->fetch();
$accountCards = [
    ['Total Admins', (int) ($accountStats['total_admins'] ?? 0), 'text-slate-900'],
    ['Total Users', (int) ($accountStats['total_users'] ?? 0), 'text-slate-900'],
    ['Active Accounts', (int) ($accountStats['active_accounts'] ?? 0), 'text-emerald-600'],
    ['Inactive Accounts', (int) ($accountStats['inactive_accounts'] ?? 0), 'text-slate-500'],
];
$scanCards = [
    ['Total Scans', (int) ($scanStats['total_scans'] ?? 0), 'text-slate-900'],
    ['Completed Scans', (int) ($scanStats['completed_scans'] ?? 0), 'text-emerald-600'],
    ['Failed Scans', (int) ($scanStats['failed_scans'] ?? 0), (int) ($scanStats['failed_scans'] ?? 0) > 0 ? 'text-red-600' : 'text-slate-900'],
];
$links = [
    ['admins.php', 'Admin Management', 'Add, edit or deactivate admin accounts', 'admins'],
    ['users.php', 'User Management', 'Manage user accounts and access', 'users'],
    ['history.php', 'Scan History', 'Review every file scan in the system', 'history'],
    ['activity.php', 'File Activity', 'Review file activity on monitored PCs (read-only)', 'activity'],
    ['audit-logs.php', 'Audit Logs', 'Review administrative actions', 'audit-logs'],
];
$pageTitle = 'Superadmin Dashboard';
$currentPage = 'dashboard';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
    <div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div>
    <main class="min-w-0 flex-1 p-6 sm:p-8 lg:p-10">
        <header>
            <p class="text-sm text-slate-500"><?= superadmin_h(date('l, F j, Y')) ?></p>
            <h1 class="mt-1 text-3xl font-bold tracking-tight text-slate-900">Superadmin Dashboard</h1>
            <p class="mt-1 text-sm text-slate-500">Accounts and scan activity across MalDetect.</p>
        </header>

        <section class="mt-8" aria-label="Account statistics">
            <h2 class="text-sm font-semibold text-slate-900">Accounts</h2>
            <div class="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <?php foreach ($accountCards as [$label, $value, $color]): ?>
                    <article class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><p class="text-sm font-medium text-slate-500"><?= superadmin_h($label) ?></p><p class="mt-2 text-3xl font-bold tracking-tight <?= $color ?>"><?= $value ?></p></article>
                <?php endforeach; ?>
            </div>
        </section>

        <section class="mt-8" aria-label="Scan statistics">
            <h2 class="text-sm font-semibold text-slate-900">File scans</h2>
            <div class="mt-3 grid gap-4 sm:grid-cols-3">
                <?php foreach ($scanCards as [$label, $value, $color]): ?>
                    <article class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><p class="text-sm font-medium text-slate-500"><?= superadmin_h($label) ?></p><p class="mt-2 text-3xl font-bold tracking-tight <?= $color ?>"><?= $value ?></p></article>
                <?php endforeach; ?>
            </div>
        </section>

        <section class="mt-8" aria-label="Management links">
            <h2 class="text-sm font-semibold text-slate-900">Management</h2>
            <div class="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                <?php foreach ($links as [$href, $title, $text, $iconKey]): ?>
                    <a href="<?= superadmin_h($href) ?>" class="group flex items-start gap-4 rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-blue-300 hover:shadow">
                        <span class="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-blue-50 text-blue-600"><?= sidebar_icon($iconKey) ?></span>
                        <span><span class="block font-semibold text-slate-900 group-hover:text-blue-700"><?= superadmin_h($title) ?></span><span class="mt-1 block text-sm text-slate-500"><?= superadmin_h($text) ?></span></span>
                    </a>
                <?php endforeach; ?>
            </div>
        </section>
    </main>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
