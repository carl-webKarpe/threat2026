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
        if ($account['role'] !== 'user') {
            throw new RuntimeException('This account is not a User account.');
        }
        $newStatus = (int) $account['is_active'] === 1 ? 0 : 1;
        $statement = $pdo->prepare('UPDATE users SET is_active = :is_active WHERE id = :id AND role = \'user\'');
        $statement->execute(['is_active' => $newStatus, 'id' => $id]);
        superadmin_audit($newStatus ? 'Account Activated' : 'Account Deactivated', $id, 'User account status changed.');
        superadmin_redirect('users.php', $newStatus ? 'Account activated.' : 'Account deactivated.');
    } catch (Throwable $exception) {
        superadmin_audit('Failed Administrative Action', $id ?: null, 'User account action failed.');
        error_log('User account action failed: ' . $exception->getMessage());
        superadmin_redirect('users.php', '', 'The account action could not be completed.');
    }
}

$accounts = $pdo->query("SELECT id, name, username, email, role, is_active, created_at, last_login FROM users WHERE role = 'user' ORDER BY created_at DESC")->fetchAll();
$message = (string) ($_GET['message'] ?? '');
$error = (string) ($_GET['error'] ?? '');
$pageTitle = 'User Management';
$currentPage = 'users';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div><main class="min-w-0 flex-1 p-6 sm:p-10"><header class="flex flex-col justify-between gap-4 border-b border-slate-200 pb-8 sm:flex-row sm:items-end"><div><p class="text-xs font-semibold uppercase tracking-wider text-blue-700">ACCOUNT CONTROL</p><h1 class="mt-3 text-3xl font-bold tracking-tight text-slate-900">Users</h1><p class="mt-2 text-slate-500">Manage standard user access without deleting scan ownership.</p></div><a href="add-user.php" class="rounded-lg bg-blue-600 px-5 py-3 text-sm font-bold text-white">Add Account</a></header>
<?php if ($message !== ''): ?><p class="mt-6 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"><?= superadmin_h($message) ?></p><?php endif; ?><?php if ($error !== ''): ?><p class="mt-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"><?= superadmin_h($error) ?></p><?php endif; ?>
<div class="mt-8 overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm"><table class="w-full min-w-[900px] text-left text-sm"><thead class="border-b border-slate-200 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-5 py-4">Account</th><th class="px-5 py-4">Email</th><th class="px-5 py-4">Status</th><th class="px-5 py-4">Created</th><th class="px-5 py-4">Last Login</th><th class="px-5 py-4">Actions</th></tr></thead><tbody class="divide-y divide-slate-100"><?php foreach ($accounts as $account): ?><tr><td class="px-5 py-4"><p class="font-semibold"><?= superadmin_h($account['name']) ?></p><p class="mt-1 text-xs text-slate-500">#<?= (int) $account['id'] ?> · <?= superadmin_h($account['username']) ?> · User</p></td><td class="px-5 py-4 text-slate-700"><?= superadmin_h((string) ($account['email'] ?: 'Not provided')) ?></td><td class="px-5 py-4"><span class="rounded-full border px-3 py-1 text-xs <?= $account['is_active'] ? 'border-emerald-200 text-emerald-700' : 'border-red-200 text-red-700' ?>"><?= $account['is_active'] ? 'Active' : 'Inactive' ?></span></td><td class="px-5 py-4 text-slate-500"><?= superadmin_h($account['created_at']) ?></td><td class="px-5 py-4 text-slate-500"><?= superadmin_h((string) ($account['last_login'] ?: 'Never')) ?></td><td class="px-5 py-4"><div class="flex items-center gap-3"><a href="edit-user.php?id=<?= (int) $account['id'] ?>" class="text-blue-700 hover:text-blue-700">Edit</a><form method="post" onsubmit="return confirm('<?= $account['is_active'] ? 'Deactivate' : 'Activate' ?> this account?')"><input type="hidden" name="csrf_token" value="<?= superadmin_h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $account['id'] ?>"><input type="hidden" name="action" value="toggle"><button class="text-<?= $account['is_active'] ? 'red' : 'emerald' ?>-200"><?= $account['is_active'] ? 'Deactivate' : 'Activate' ?></button></form></div></td></tr><?php endforeach; ?><?php if (!$accounts): ?><tr><td colspan="6" class="px-5 py-12 text-center text-slate-500">No user accounts found.</td></tr><?php endif; ?></tbody></table></div></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
