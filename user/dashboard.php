<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_role('user');
$logoutToken = csrf_token();
$pageTitle = 'User Dashboard';
require_once __DIR__ . '/../includes/header.php';
?><main class="mx-auto min-h-screen max-w-6xl px-6 py-8 sm:px-10"><header class="flex flex-col justify-between gap-5 border-b border-white/10 pb-8 sm:flex-row sm:items-center"><div><a href="../index.php" class="font-mono text-sm tracking-[.18em]">MAL<span class="text-violet-300">DETECT</span></a><h1 class="mt-8 text-3xl font-bold">Welcome, <?= htmlspecialchars($user['full_name'], ENT_QUOTES, 'UTF-8') ?></h1><p class="mt-2 text-sm text-slate-400">Your authorized MalDetect workspace.</p></div><div class="flex items-center gap-4"><span class="rounded-full bg-violet-300/10 px-3 py-2 text-xs uppercase text-violet-200">User</span><form method="post" action="../logout.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($logoutToken, ENT_QUOTES, 'UTF-8') ?>"><button class="rounded-xl border border-white/10 px-4 py-2 text-sm text-slate-300 hover:bg-white/10" type="submit">Logout</button></form></div></header><section class="mt-10 rounded-2xl border border-white/10 bg-white/[.04] p-8"><p class="mono text-xs tracking-[.18em] text-violet-300">ACCOUNT STATUS</p><h2 class="mt-3 text-xl font-bold">Access is active</h2><p class="mt-3 max-w-xl text-sm leading-7 text-slate-400">Features assigned to your account will appear here as the system grows. You do not have access to Superadmin or Admin-only pages.</p></section></main><?php require_once __DIR__ . '/../includes/footer.php'; ?>
