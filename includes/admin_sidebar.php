<?php
require_once __DIR__ . '/../auth/csrf.php';
$currentPage = $currentPage ?? '';
$logoutToken = csrf_token();
$links = [
    'dashboard' => ['Dashboard', 'dashboard.php'],
    'scan' => ['Scan File', 'scan.php'],
    'history' => ['Scan History', 'history.php'],
    'users' => ['Users', 'users.php'],
];
?>
<aside class="w-full shrink-0 border-b border-white/10 bg-slate-950/70 p-5 lg:min-h-screen lg:w-64 lg:border-b-0 lg:border-r">
    <a href="dashboard.php" class="flex items-center gap-3 font-mono text-sm tracking-[.18em]"><span class="grid h-10 w-10 place-items-center rounded-xl border border-violet-300/30 bg-violet-300/10 text-violet-200">MD</span>MAL<span class="text-violet-300">DETECT</span></a>
    <p class="mt-10 font-mono text-[10px] tracking-[.2em] text-slate-500">ADMIN WORKSPACE</p>
    <nav class="mt-4 grid gap-2 sm:grid-cols-4 lg:block" aria-label="Admin navigation">
        <?php foreach ($links as $key => [$label, $href]): ?><a class="block rounded-xl px-4 py-3 text-sm <?= $currentPage === $key ? 'bg-violet-400/15 font-semibold text-violet-200' : 'text-slate-400 hover:bg-white/5 hover:text-white' ?>" href="<?= htmlspecialchars($href, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($label, ENT_QUOTES, 'UTF-8') ?></a><?php endforeach; ?>
        <form class="mt-2" method="post" action="../logout.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($logoutToken, ENT_QUOTES, 'UTF-8') ?>"><button class="block w-full rounded-xl px-4 py-3 text-left text-sm text-slate-400 hover:bg-red-400/10 hover:text-red-200" type="submit">Logout</button></form>
    </nav>
</aside>
