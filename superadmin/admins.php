<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();
$pdo = database_connection();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    superadmin_require_post_csrf();
    $id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    try {
        if (!is_int($id) || ($_POST['action'] ?? '') !== 'toggle') {
            throw new InvalidArgumentException('Invalid account action.');
        }
        $account = superadmin_find_managed_account($pdo, $id);
        if ($account['role'] !== 'admin') {
            throw new RuntimeException('This account is not an Admin account.');
        }
        $newStatus = (int) $account['is_active'] === 1 ? 0 : 1;
        $statement = $pdo->prepare('UPDATE users SET is_active = :is_active WHERE id = :id AND role = \'admin\'');
        $statement->execute(['is_active' => $newStatus, 'id' => $id]);
        superadmin_audit($newStatus ? 'Account Activated' : 'Account Deactivated', $id, 'Admin account status changed.');
        superadmin_redirect('admins.php', $newStatus ? 'Account activated.' : 'Account deactivated.');
    } catch (Throwable $exception) {
        superadmin_audit('Failed Administrative Action', $id ?: null, 'Admin account action failed.');
        error_log('Admin account action failed: ' . $exception->getMessage());
        superadmin_redirect('admins.php', '', 'The account action could not be completed.');
    }
}

$accounts = $pdo->query("SELECT id, name, username, email, role, is_active, created_at, last_login FROM users WHERE role = 'admin' ORDER BY created_at DESC")->fetchAll();
$message = (string) ($_GET['message'] ?? '');
$error = (string) ($_GET['error'] ?? '');
$pageTitle = 'Admin Management';
$currentPage = 'admins';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div><main class="min-w-0 flex-1 p-6 sm:p-10"><header class="flex flex-col justify-between gap-4 border-b border-white/10 pb-8 sm:flex-row sm:items-end"><div><p class="text-[11px] font-medium uppercase tracking-[.3em] text-accent-light">ACCOUNT CONTROL</p><h1 class="mt-3 font-display text-2xl uppercase tracking-[.08em] text-white sm:text-3xl">Admins</h1><p class="mt-2 text-neutral-400">Manage operational administrator access.</p></div><a href="add-user.php" class="rounded-lg bg-accent px-5 py-3 text-sm font-bold text-white">Add Account</a></header>
<?php if ($message !== ''): ?><p class="mt-6 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400"><?= superadmin_h($message) ?></p><?php endif; ?><?php if ($error !== ''): ?><p class="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400"><?= superadmin_h($error) ?></p><?php endif; ?>
<div class="mt-8 overflow-x-auto rounded-xl border border-white/10 bg-panel shadow-sm"><table class="w-full min-w-[900px] text-left text-sm"><thead class="border-b border-white/10 text-xs uppercase tracking-wider text-neutral-400"><tr><th class="px-5 py-4">Account</th><th class="px-5 py-4">Email</th><th class="px-5 py-4">Status</th><th class="px-5 py-4">Created</th><th class="px-5 py-4">Last Login</th><th class="px-5 py-4">Actions</th></tr></thead><tbody class="divide-y divide-white/5"><?php foreach ($accounts as $account): ?><tr><td class="px-5 py-4"><p class="font-semibold"><?= superadmin_h($account['name']) ?></p><p class="mt-1 text-xs text-neutral-400">#<?= (int) $account['id'] ?> · <?= superadmin_h($account['username']) ?> · Admin</p></td><td class="px-5 py-4 text-neutral-300"><?= superadmin_h((string) ($account['email'] ?: 'Not provided')) ?></td><td class="px-5 py-4"><span class="rounded-full border px-3 py-1 text-xs <?= $account['is_active'] ? 'border-emerald-500/30 text-emerald-400' : 'border-red-500/30 text-red-400' ?>"><?= $account['is_active'] ? 'Active' : 'Inactive' ?></span></td><td class="px-5 py-4 text-neutral-400"><?= superadmin_h($account['created_at']) ?></td><td class="px-5 py-4 text-neutral-400"><?= superadmin_h((string) ($account['last_login'] ?: 'Never')) ?></td><td class="px-5 py-4"><div class="flex items-center gap-3"><a href="edit-user.php?id=<?= (int) $account['id'] ?>" class="text-accent-light hover:text-white">Edit</a><form method="post" onsubmit="return confirm('<?= $account['is_active'] ? 'Deactivate' : 'Activate' ?> this account?')"><input type="hidden" name="csrf_token" value="<?= superadmin_h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $account['id'] ?>"><input type="hidden" name="action" value="toggle"><button class="text-<?= $account['is_active'] ? 'red' : 'emerald' ?>-200"><?= $account['is_active'] ? 'Deactivate' : 'Activate' ?></button></form></div></td></tr><?php endforeach; ?><?php if (!$accounts): ?><tr><td colspan="6" class="px-5 py-12 text-center text-neutral-400">No admin accounts found.</td></tr><?php endif; ?></tbody></table></div></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
