<?php

declare(strict_types=1);

// Sidebar shared by the Admin and Superadmin workspaces. Before including, set $sidebarWorkspace (label),
// $sidebarLinks (key => [label, href]) and $currentPage; $user comes from includes/header.php.

require_once __DIR__ . '/../auth/csrf.php';

/** Outline icons (24x24, stroke) for the sidebar links, by link key. */
function sidebar_icon(string $key): string
{
    $paths = [
        'dashboard' => '<path d="M4 13h6V4H4zM14 20h6v-9h-6zM4 20h6v-3H4zM14 4v3h6V4z"/>',
        'scan' => '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9.5 14.5l2 2 3.5-4"/>',
        'history' => '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/>',
        'devices' => '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
        'detections' => '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M12 8v5M12 16h.01"/>',
        'activity' => '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
        'reports' => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
        'users' => '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0M17 11a3 3 0 1 0 0-6M22 21a6 6 0 0 0-4-5.6"/>',
        'admins' => '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><circle cx="12" cy="10" r="2.5"/><path d="M8 16.5a4.5 4.5 0 0 1 8 0"/>',
        'audit-logs' => '<path d="M9 5h11M9 12h11M9 19h11M4 5h.01M4 12h.01M4 19h.01"/>',
        'logout' => '<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 17l5-5-5-5M15 12H3"/>',
    ];

    return '<svg class="h-5 w-5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        . ($paths[$key] ?? '<circle cx="12" cy="12" r="8"/>') . '</svg>';
}

$sidebarHome = $sidebarLinks['dashboard'][1] ?? 'dashboard.php';
$sidebarName = (string) ($user['full_name'] ?? '');
$sidebarInitials = strtoupper(implode('', array_map(
    static fn (string $part): string => mb_substr($part, 0, 1),
    array_slice(preg_split('/\s+/', trim($sidebarName)) ?: [], 0, 2)
))) ?: 'MD';
$sidebarH = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
?>
<aside class="no-print flex w-full shrink-0 flex-col border-b border-slate-200 bg-white lg:sticky lg:top-0 lg:h-screen lg:w-64 lg:border-b-0 lg:border-r">
    <a href="<?= $sidebarH($sidebarHome) ?>" class="flex items-center gap-3 px-5 py-5">
        <span class="grid h-10 w-10 place-items-center rounded-xl bg-blue-600 text-white shadow-sm shadow-blue-600/30">
            <svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>
        </span>
        <span class="leading-tight"><span class="block text-base font-bold tracking-tight text-slate-900">MalDetect</span><span class="block text-xs text-slate-500"><?= $sidebarH($sidebarWorkspace) ?></span></span>
    </a>
    <nav class="grid gap-1 px-3 pb-4 sm:grid-cols-4 lg:block lg:flex-1 lg:space-y-1 lg:overflow-y-auto" aria-label="<?= $sidebarH($sidebarWorkspace) ?> navigation">
        <?php foreach ($sidebarLinks as $key => [$label, $href]): ?>
            <?php $active = ($currentPage ?? '') === $key; ?>
            <a class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition <?= $active ? 'bg-blue-50 text-blue-700' : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900' ?>" href="<?= $sidebarH($href) ?>"<?= $active ? ' aria-current="page"' : '' ?>>
                <span class="<?= $active ? 'text-blue-600' : 'text-slate-400' ?>"><?= sidebar_icon($key) ?></span><?= $sidebarH($label) ?>
            </a>
        <?php endforeach; ?>
    </nav>
    <div class="border-t border-slate-200 p-3">
        <div class="flex items-center gap-3 rounded-lg px-2 py-2">
            <span class="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-slate-100 text-xs font-bold text-slate-700"><?= $sidebarH($sidebarInitials) ?></span>
            <span class="min-w-0 leading-tight"><span class="block truncate text-sm font-semibold text-slate-900"><?= $sidebarH($sidebarName) ?></span><span class="block text-xs capitalize text-slate-500"><?= $sidebarH((string) ($user['role'] ?? '')) ?></span></span>
        </div>
        <form method="post" action="../logout.php" class="mt-1"><input type="hidden" name="csrf_token" value="<?= $sidebarH(csrf_token()) ?>"><button class="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm font-medium text-slate-600 transition hover:bg-red-50 hover:text-red-700" type="submit"><span class="text-slate-400"><?= sidebar_icon('logout') ?></span>Logout</button></form>
    </div>
</aside>
