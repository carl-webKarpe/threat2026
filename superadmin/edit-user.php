<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();
$pdo = database_connection();
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
if (!is_int($id)) {
    superadmin_redirect('dashboard.php', '', 'Invalid account identifier.');
}
try {
    $account = superadmin_find_managed_account($pdo, $id);
} catch (Throwable $exception) {
    superadmin_redirect('dashboard.php', '', 'Account not found.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    superadmin_require_post_csrf();
    try {
        $submitted = superadmin_validate_account($_POST);
        $isActive = isset($_POST['is_active']) ? 1 : 0;
        $oldRole = (string) $account['role'];
        $update = $pdo->prepare(
            'UPDATE users SET name = :name, username = :username, email = :email, role = :role, is_active = :is_active
             WHERE id = :id AND role IN (\'admin\', \'user\')'
        );
        $update->execute([
            'name' => $submitted['name'],
            'username' => $submitted['username'],
            'email' => $submitted['email'],
            'role' => $submitted['role'],
            'is_active' => $isActive,
            'id' => $id,
        ]);
        if ($submitted['password'] !== '') {
            $passwordUpdate = $pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
            $passwordUpdate->execute(['password' => password_hash($submitted['password'], PASSWORD_DEFAULT), 'id' => $id]);
            superadmin_audit('Password Reset', $id, 'Account password reset.');
        }
        if ($oldRole !== $submitted['role']) {
            superadmin_audit('Role Changed', $id, 'Role changed from ' . $oldRole . ' to ' . $submitted['role'] . '.');
        }
        if ((int) $account['is_active'] !== $isActive) {
            superadmin_audit($isActive ? 'Account Activated' : 'Account Deactivated', $id, 'Account status changed.');
        }
        superadmin_audit('Account Updated', $id, 'Account details updated.');
        superadmin_redirect($submitted['role'] === 'admin' ? 'admins.php' : 'users.php', 'Account updated successfully.');
    } catch (PDOException $exception) {
        $error = (int) $exception->errorInfo[1] === 1062 ? 'Username already exists.' : 'The account could not be updated.';
        if ($error !== 'Username already exists.') {
            error_log($exception->getMessage());
        }
    } catch (InvalidArgumentException $exception) {
        $error = $exception->getMessage();
    } catch (Throwable $exception) {
        error_log('Superadmin account update failed: ' . $exception->getMessage());
        $error = 'The account could not be updated.';
    }
}

$pageTitle = 'Edit Account';
$currentPage = $account['role'] === 'admin' ? 'admins' : 'users';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div><main class="min-w-0 flex-1 p-6 sm:p-10"><header class="border-b border-white/10 pb-8"><p class="mono text-xs tracking-[.2em] text-violet-300">ACCOUNT CONTROL</p><h1 class="mt-3 text-3xl font-bold">Edit Account</h1><p class="mt-2 text-slate-400">Update account details or reset its password. Existing passwords are never displayed.</p></header>
<?php if (!empty($error)): ?><p class="mt-6 max-w-2xl rounded-xl border border-red-300/20 bg-red-400/10 px-4 py-3 text-sm text-red-200" role="alert"><?= superadmin_h($error) ?></p><?php endif; ?>
<form method="post" class="mt-8 max-w-2xl space-y-5 rounded-2xl border border-white/10 bg-white/[.03] p-6"><input type="hidden" name="csrf_token" value="<?= superadmin_h(csrf_token()) ?>"><label class="block text-sm text-slate-300">Account Type<select name="role" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100"><option value="admin" <?= $account['role'] === 'admin' ? 'selected' : '' ?>>Admin</option><option value="user" <?= $account['role'] === 'user' ? 'selected' : '' ?>>User</option></select></label>
<label class="block text-sm text-slate-300">Username<input name="username" required maxlength="100" value="<?= superadmin_h($account['username']) ?>" class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100"></label><label class="block text-sm text-slate-300">Full Name<input name="name" required maxlength="255" value="<?= superadmin_h($account['name']) ?>" class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100"></label><label class="block text-sm text-slate-300">Email<input name="email" type="email" maxlength="255" value="<?= superadmin_h((string) $account['email']) ?>" class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100"></label>
<label class="flex items-center gap-3 text-sm text-slate-300"><input name="is_active" type="checkbox" value="1" <?= $account['is_active'] ? 'checked' : '' ?>> Account active</label><div class="border-t border-white/10 pt-5"><p class="text-sm font-semibold">Reset Password</p><p class="mt-1 text-xs text-slate-500">Leave both fields blank to keep the current password.</p><div class="mt-4 grid gap-5 sm:grid-cols-2"><label class="block text-sm text-slate-300">New Password<input name="password" type="password" minlength="12" autocomplete="new-password" class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100"></label><label class="block text-sm text-slate-300">Confirm Password<input name="password_confirmation" type="password" minlength="12" autocomplete="new-password" class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100"></label></div></div><div class="flex gap-3"><a href="<?= $account['role'] === 'admin' ? 'admins.php' : 'users.php' ?>" class="rounded-xl border border-white/10 px-5 py-3 text-sm text-slate-300">Cancel</a><button class="rounded-xl bg-violet-300 px-5 py-3 text-sm font-bold text-slate-950">Save Changes</button></div></form></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
