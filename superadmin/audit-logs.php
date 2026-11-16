<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();
$pdo = database_connection();
$logs = $pdo->query(
    'SELECT audit_logs.created_at, audit_logs.action, audit_logs.details, audit_logs.ip_address,
            actor.username AS actor_username, actor.name AS actor_name,
            target.username AS target_username, target.name AS target_name
     FROM audit_logs
     INNER JOIN users AS actor ON actor.id = audit_logs.actor_user_id
     LEFT JOIN users AS target ON target.id = audit_logs.target_user_id
     ORDER BY audit_logs.created_at DESC LIMIT 100'
)->fetchAll();
$pageTitle = 'Audit Logs';
$currentPage = 'audit-logs';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div><main class="min-w-0 flex-1 p-6 sm:p-10"><header class="border-b border-white/10 pb-8"><p class="text-[11px] font-medium uppercase tracking-[.3em] text-accent-light">SECURITY RECORD</p><h1 class="mt-3 font-display text-2xl uppercase tracking-[.08em] text-white sm:text-3xl">Audit Logs</h1><p class="mt-2 text-neutral-400">Administrative actions are recorded without passwords or API keys.</p></header><div class="mt-8 overflow-x-auto rounded-xl border border-white/10 bg-panel shadow-sm"><table class="w-full min-w-[980px] text-left text-sm"><thead class="border-b border-white/10 text-xs uppercase tracking-wider text-neutral-400"><tr><th class="px-5 py-4">Date</th><th class="px-5 py-4">Actor</th><th class="px-5 py-4">Action</th><th class="px-5 py-4">Target</th><th class="px-5 py-4">IP Address</th><th class="px-5 py-4">Details</th></tr></thead><tbody class="divide-y divide-white/5"><?php foreach ($logs as $log): ?><tr><td class="whitespace-nowrap px-5 py-4 text-neutral-400"><?= superadmin_h($log['created_at']) ?></td><td class="px-5 py-4"><?= superadmin_h($log['actor_name']) ?><p class="text-xs text-neutral-400"><?= superadmin_h($log['actor_username']) ?></p></td><td class="px-5 py-4 font-semibold text-accent-light"><?= superadmin_h($log['action']) ?></td><td class="px-5 py-4"><?= superadmin_h((string) ($log['target_name'] ?: 'System')) ?><p class="text-xs text-neutral-400"><?= superadmin_h((string) ($log['target_username'] ?: '')) ?></p></td><td class="px-5 py-4 font-mono text-xs text-neutral-400"><?= superadmin_h((string) ($log['ip_address'] ?: 'Unknown')) ?></td><td class="max-w-sm px-5 py-4 text-neutral-300"><?= superadmin_h((string) ($log['details'] ?: '')) ?></td></tr><?php endforeach; ?><?php if (!$logs): ?><tr><td colspan="6" class="px-5 py-12 text-center text-neutral-400">No audit events are available.</td></tr><?php endif; ?></tbody></table></div></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
