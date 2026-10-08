<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();
$pdo = database_connection();
$scans = $pdo->query(
    'SELECT scans.id, scans.original_filename, scans.scan_status, scans.risk_level, scans.created_at,
            users.username, users.name
     FROM scans INNER JOIN users ON users.id = scans.user_id
     ORDER BY scans.created_at DESC LIMIT 100'
)->fetchAll();
$pageTitle = 'System Scan History';
$currentPage = 'history';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div><main class="min-w-0 flex-1 p-6 sm:p-10"><header class="border-b border-white/10 pb-8"><p class="mono text-xs tracking-[.2em] text-violet-300">SYSTEM ACTIVITY</p><h1 class="mt-3 text-3xl font-bold">Scan History</h1><p class="mt-2 text-slate-400">Historical scan ownership is preserved when accounts are deactivated.</p></header><div class="mt-8 overflow-x-auto rounded-2xl border border-white/10 bg-white/[.03]"><table class="w-full min-w-[820px] text-left text-sm"><thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-5 py-4">File</th><th class="px-5 py-4">Owner</th><th class="px-5 py-4">Status</th><th class="px-5 py-4">Risk</th><th class="px-5 py-4">Created</th></tr></thead><tbody class="divide-y divide-white/5"><?php foreach ($scans as $scan): ?><tr><td class="px-5 py-4"><p class="font-semibold"><?= superadmin_h($scan['original_filename']) ?></p><p class="mt-1 text-xs text-slate-500">Scan #<?= (int) $scan['id'] ?></p></td><td class="px-5 py-4"><?= superadmin_h($scan['name']) ?><p class="text-xs text-slate-500"><?= superadmin_h($scan['username']) ?></p></td><td class="px-5 py-4 text-amber-200"><?= superadmin_h(ucfirst($scan['scan_status'])) ?></td><td class="px-5 py-4 text-slate-300"><?= superadmin_h((string) ($scan['risk_level'] ?: 'Pending')) ?></td><td class="px-5 py-4 text-slate-400"><?= superadmin_h($scan['created_at']) ?></td></tr><?php endforeach; ?><?php if (!$scans): ?><tr><td colspan="5" class="px-5 py-12 text-center text-slate-500">No scan records are available.</td></tr><?php endif; ?></tbody></table></div></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
