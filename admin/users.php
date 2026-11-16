<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_role('admin');
require_once __DIR__ . '/../config/database.php';
$pageTitle = 'Users'; $currentPage = 'users';
try { $statement = database_connection()->query('SELECT name, username, role, is_active, created_at FROM users ORDER BY created_at DESC'); $users = $statement->fetchAll(); } catch (Throwable $exception) { error_log($exception->getMessage()); $users = []; }
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div><main class="min-w-0 flex-1 p-6 sm:p-10"><p class="mono text-xs tracking-[.2em] text-violet-300">DIRECTORY</p><h1 class="mt-3 text-3xl font-bold">Users</h1><p class="mt-2 text-sm text-slate-400">View account information. Account management is restricted to the Superadmin.</p><div class="mt-8 overflow-x-auto rounded-2xl border border-white/10 bg-white/[.03]"><table class="w-full min-w-[680px] text-left text-sm"><thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-6 py-4">Full Name</th><th class="px-6 py-4">Username</th><th class="px-6 py-4">Role</th><th class="px-6 py-4">Status</th><th class="px-6 py-4">Created</th></tr></thead><tbody class="divide-y divide-white/5"><?php foreach ($users as $account): ?><tr><td class="px-6 py-4"><?= htmlspecialchars($account['name'], ENT_QUOTES, 'UTF-8') ?></td><td class="px-6 py-4 text-slate-400"><?= htmlspecialchars($account['username'], ENT_QUOTES, 'UTF-8') ?></td><td class="px-6 py-4 uppercase text-violet-200"><?= htmlspecialchars($account['role'], ENT_QUOTES, 'UTF-8') ?></td><td class="px-6 py-4"><?= (bool) $account['is_active'] ? 'Active' : 'Inactive' ?></td><td class="px-6 py-4 text-slate-500"><?= htmlspecialchars((string) $account['created_at'], ENT_QUOTES, 'UTF-8') ?></td></tr><?php endforeach; ?><?php if (!$users): ?><tr><td colspan="5" class="px-6 py-12 text-center text-slate-500">No user records are available.</td></tr><?php endif; ?></tbody></table></div></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
