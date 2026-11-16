<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();
$pdo = database_connection();
$accountStats = $pdo->query("SELECT COUNT(*) AS total_accounts, SUM(role = 'admin') AS total_admins, SUM(role = 'user') AS total_users, SUM(is_active = 1) AS active_accounts, SUM(is_active = 0) AS inactive_accounts FROM users")->fetch();
$scanStats = $pdo->query("SELECT COUNT(*) AS total_scans, SUM(scan_status = 'completed') AS completed_scans, SUM(scan_status = 'failed') AS failed_scans FROM scans")->fetch();
$accountCards = [
    ['Total Admins', (int) ($accountStats['total_admins'] ?? 0), 'text-white'],
    ['Total Users', (int) ($accountStats['total_users'] ?? 0), 'text-white'],
    ['Active Accounts', (int) ($accountStats['active_accounts'] ?? 0), 'text-emerald-400'],
    ['Inactive Accounts', (int) ($accountStats['inactive_accounts'] ?? 0), 'text-neutral-400'],
];
$scanCards = [
    ['Total Scans', (int) ($scanStats['total_scans'] ?? 0), 'text-white'],
    ['Completed Scans', (int) ($scanStats['completed_scans'] ?? 0), 'text-emerald-400'],
    ['Failed Scans', (int) ($scanStats['failed_scans'] ?? 0), (int) ($scanStats['failed_scans'] ?? 0) > 0 ? 'text-red-400' : 'text-white'],
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
            <p class="text-sm text-neutral-400"><?= superadmin_h(date('l, F j, Y')) ?></p>
            <h1 class="mt-1 font-display text-2xl uppercase tracking-[.08em] text-white sm:text-3xl">Superadmin Dashboard</h1>
            <p class="mt-1 text-sm text-neutral-400">Accounts and scan activity across JunMalware.</p>
        </header>

        <section class="mt-8" aria-label="Account statistics">
            <h2 class="text-sm font-semibold text-white">Accounts</h2>
            <div class="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <?php foreach ($accountCards as [$label, $value, $color]): ?>
                    <article class="rounded-xl border border-white/10 bg-panel p-5 shadow-sm"><p class="text-sm font-medium text-neutral-400"><?= superadmin_h($label) ?></p><p class="mt-2 text-3xl font-bold tracking-tight <?= $color ?>"><?= $value ?></p></article>
                <?php endforeach; ?>
            </div>
        </section>

        <section class="mt-8" aria-label="Scan statistics">
            <h2 class="text-sm font-semibold text-white">File scans</h2>
            <div class="mt-3 grid gap-4 sm:grid-cols-3">
                <?php foreach ($scanCards as [$label, $value, $color]): ?>
                    <article class="rounded-xl border border-white/10 bg-panel p-5 shadow-sm"><p class="text-sm font-medium text-neutral-400"><?= superadmin_h($label) ?></p><p class="mt-2 text-3xl font-bold tracking-tight <?= $color ?>"><?= $value ?></p></article>
                <?php endforeach; ?>
            </div>
        </section>

        <section class="mt-8" aria-label="Management links">
            <h2 class="text-sm font-semibold text-white">Management</h2>
            <div class="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                <?php foreach ($links as [$href, $title, $text, $iconKey]): ?>
                    <a href="<?= superadmin_h($href) ?>" class="group flex items-start gap-4 rounded-xl border border-white/10 bg-panel p-5 shadow-sm transition hover:border-accent/70 hover:shadow-lg">
                        <span class="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-accent/15 text-accent-light"><?= sidebar_icon($iconKey) ?></span>
                        <span><span class="block font-semibold text-white group-hover:text-accent-light"><?= superadmin_h($title) ?></span><span class="mt-1 block text-sm text-neutral-400"><?= superadmin_h($text) ?></span></span>
                    </a>
                <?php endforeach; ?>
            </div>
        </section>
    </main>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
