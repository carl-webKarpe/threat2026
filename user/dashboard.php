<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_role('user');
$logoutToken = csrf_token();
$pageTitle = 'User Dashboard';
require_once __DIR__ . '/../includes/header.php';
$h = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
?>
<header class="border-b border-slate-200 bg-white">
    <div class="mx-auto flex max-w-6xl items-center justify-between px-6 py-4 sm:px-10">
        <a href="../index.php" class="flex items-center gap-3">
            <span class="grid h-9 w-9 place-items-center rounded-lg bg-blue-600 text-white"><svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></span>
            <span class="text-base font-bold tracking-tight text-slate-900">MalDetect</span>
        </a>
        <div class="flex items-center gap-3">
            <span class="hidden text-sm text-slate-600 sm:inline"><?= $h($user['full_name']) ?></span>
            <span class="rounded-full bg-blue-50 px-2.5 py-1 text-xs font-semibold text-blue-700 ring-1 ring-blue-200">User</span>
            <form method="post" action="../logout.php"><input type="hidden" name="csrf_token" value="<?= $h($logoutToken) ?>"><button class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50" type="submit">Logout</button></form>
        </div>
    </div>
</header>
<main class="mx-auto max-w-6xl px-6 py-10 sm:px-10">
    <h1 class="text-3xl font-bold tracking-tight text-slate-900">Welcome, <?= $h($user['full_name']) ?></h1>
    <p class="mt-1 text-sm text-slate-500">Your authorized MalDetect workspace.</p>
    <section class="mt-8 flex items-start gap-4 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <span class="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-emerald-50 text-emerald-600"><svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6L9 17l-5-5"/></svg></span>
        <div>
            <h2 class="text-base font-semibold text-slate-900">Access is active</h2>
            <p class="mt-1 max-w-xl text-sm leading-6 text-slate-500">Features assigned to your account will appear here as the system grows. You do not have access to Superadmin or Admin-only pages.</p>
        </div>
    </section>
</main>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
