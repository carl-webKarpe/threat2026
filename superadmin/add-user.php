<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();

$pdo = database_connection();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    superadmin_require_post_csrf();
    try {
        $account = superadmin_validate_account($_POST, true);
        $statement = $pdo->prepare(
            'INSERT INTO users (name, username, email, password, role, is_active)
             VALUES (:name, :username, :email, :password, :role, 1)'
        );
        $statement->execute([
            'name' => $account['name'],
            'username' => $account['username'],
            'email' => $account['email'],
            'password' => password_hash($account['password'], PASSWORD_DEFAULT),
            'role' => $account['role'],
        ]);
        $targetId = (int) $pdo->lastInsertId();
        superadmin_audit('Account Created', $targetId, 'Created ' . $account['role'] . ' account.');
        superadmin_redirect($account['role'] === 'admin' ? 'admins.php' : 'users.php', 'Account created successfully.');
    } catch (PDOException $exception) {
        $error = superadmin_duplicate_message($exception);
        if ($error === null) {
            error_log($exception->getMessage());
            $error = 'The account could not be created.';
        }
    } catch (InvalidArgumentException $exception) {
        $error = $exception->getMessage();
    } catch (Throwable $exception) {
        error_log('Superadmin account creation failed: ' . $exception->getMessage());
        $error = 'The account could not be created.';
    }
}

$pageTitle = 'Add Account';
$currentPage = 'users';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row"><div><?php require __DIR__ . '/../includes/superadmin_sidebar.php'; ?></div>
<main class="min-w-0 flex-1 p-6 sm:p-10"><header class="border-b border-white/10 pb-8"><p class="text-[11px] font-medium uppercase tracking-[.3em] text-accent-light">ACCOUNT CONTROL</p><h1 class="mt-3 font-display text-2xl uppercase tracking-[.08em] text-white sm:text-3xl">Add Account</h1><p class="mt-2 text-neutral-400">Create an Admin or User account. Superadmin accounts are managed separately.</p></header>
<?php if (!empty($error)): ?><p class="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400" role="alert"><?= superadmin_h($error) ?></p><?php endif; ?>
<form method="post" class="mt-8 max-w-2xl space-y-5 rounded-xl border border-white/10 bg-panel shadow-sm p-6"><input type="hidden" name="csrf_token" value="<?= superadmin_h(csrf_token()) ?>">
<label class="block text-sm text-neutral-300">Account Type<select name="role" required class="mt-2 w-full rounded-lg border border-white/10 bg-panel px-4 py-3 text-white"><option value="admin">Admin</option><option value="user">User</option></select></label>
<label class="block text-sm text-neutral-300">Username<input name="username" required maxlength="100" autocomplete="username" value="<?= superadmin_h((string) ($_POST['username'] ?? '')) ?>" class="mt-2 w-full rounded-lg border border-white/10 bg-panel px-4 py-3 text-white"></label>
<label class="block text-sm text-neutral-300">Full Name<input name="name" required maxlength="255" value="<?= superadmin_h((string) ($_POST['name'] ?? '')) ?>" class="mt-2 w-full rounded-lg border border-white/10 bg-panel px-4 py-3 text-white"></label>
<label class="block text-sm text-neutral-300">Email<input name="email" type="email" maxlength="255" value="<?= superadmin_h((string) ($_POST['email'] ?? '')) ?>" class="mt-2 w-full rounded-lg border border-white/10 bg-panel px-4 py-3 text-white"></label>
<div class="grid gap-5 sm:grid-cols-2"><label class="block text-sm text-neutral-300">Password<input name="password" type="password" required minlength="12" autocomplete="new-password" class="mt-2 w-full rounded-lg border border-white/10 bg-panel px-4 py-3 text-white"></label><label class="block text-sm text-neutral-300">Confirm Password<input name="password_confirmation" type="password" required minlength="12" autocomplete="new-password" class="mt-2 w-full rounded-lg border border-white/10 bg-panel px-4 py-3 text-white"></label></div>
<div class="flex gap-3"><a href="dashboard.php" class="rounded-lg border border-white/10 px-5 py-3 text-sm text-neutral-300">Cancel</a><button class="rounded-lg bg-accent px-5 py-3 text-sm font-bold text-white">Create Account</button></div></form></main></div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
