<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/scanner.php';
require_once __DIR__ . '/../config/agents.php';
require_role('admin');

$statistics = ['total' => 0, 'completed' => 0, 'scanning' => 0, 'failed' => 0, 'malicious' => 0, 'suspicious' => 0, 'no_threat' => 0];
$recentScans = [];
$dashboardError = false;
try {
    $pdo = database_connection();
        $userId = current_user()['id'];
        $summaryStatement = $pdo->prepare(
        "SELECT COUNT(*) AS total,
                SUM(scan_status = 'completed') AS completed,
                SUM(scan_status = 'scanning') AS scanning,
                SUM(scan_status = 'failed') AS failed,
                SUM(scan_result = 'MALICIOUS') AS malicious,
                SUM(scan_result = 'SUSPICIOUS') AS suspicious,
                SUM(scan_result = 'NO_THREAT_DETECTED') AS no_threat
            FROM scans
            WHERE user_id = :user_id"
        );
        $summaryStatement->execute(['user_id' => $userId]);
        $summary = $summaryStatement->fetch();
    foreach ($statistics as $key => $_value) {
        $statistics[$key] = (int) ($summary[$key] ?? 0);
    }
        $recentStatement = $pdo->prepare(
        'SELECT id, original_filename, scan_status, risk_level, created_at
            FROM scans WHERE user_id = :user_id
            ORDER BY created_at DESC, id DESC LIMIT 10'
        );
        $recentStatement->execute(['user_id' => $userId]);
        $recentScans = $recentStatement->fetchAll();
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    $dashboardError = true;
}

// Device statistics need the Phase 9 tables; the rest of the dashboard works without them.
$deviceStatistics = null;
$recentThreats = [];
try {
    $deviceStatistics = $pdo->query(
        "SELECT (SELECT COUNT(*) FROM devices WHERE is_active = 1) AS devices,
                (SELECT COUNT(*) FROM devices WHERE is_active = 1 AND " . agent_online_sql() . ") AS online,
                (SELECT COUNT(*) FROM device_detections WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)) AS downloads,
                (SELECT COUNT(*) FROM device_detections WHERE scan_result IN ('MALICIOUS', 'SUSPICIOUS') AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)) AS threats"
    )->fetch() ?: null;
    $recentThreats = $pdo->query(
        "SELECT device_detections.id, device_detections.file_name, device_detections.risk_level, device_detections.threat_name, device_detections.created_at, devices.name AS device_name
         FROM device_detections INNER JOIN devices ON devices.id = device_detections.device_id
         WHERE device_detections.scan_result IN ('MALICIOUS', 'SUSPICIOUS')
         ORDER BY device_detections.created_at DESC LIMIT 5"
    )->fetchAll();
} catch (Throwable $exception) {
    error_log('Device statistics unavailable: ' . $exception->getMessage());
}

$pageTitle = 'Admin Dashboard';
$basePath = '..';
$currentPage = 'dashboard';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
    <div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
    <main class="min-w-0 flex-1 p-6 sm:p-10">
        <header class="flex flex-col justify-between gap-5 border-b border-white/10 pb-8 sm:flex-row sm:items-end"><div><p class="mono text-xs tracking-[.2em] text-violet-300">OPERATIONAL CONSOLE</p><h1 class="mt-3 text-3xl font-bold">Admin Dashboard</h1><p class="mt-2 text-sm text-slate-400">Intelligent Malicious Software Detection System</p></div><div class="flex items-center gap-4"><div class="text-right"><p class="text-sm font-semibold"><?= htmlspecialchars($user['full_name'], ENT_QUOTES, 'UTF-8') ?></p><p class="mono text-[10px] uppercase tracking-wider text-slate-500">ADMIN</p></div><div class="grid h-11 w-11 place-items-center rounded-full bg-violet-300/15 text-violet-200">AD</div></div></header>
        <p class="mt-4 text-xs"><span data-live-indicator class="text-emerald-300">● Live</span></p>
        <div data-live-region="dashboard">
        <?php if ($dashboardError): ?><div class="mt-8 rounded-2xl border border-red-300/20 bg-red-400/10 p-5 text-sm text-red-200">Dashboard statistics are temporarily unavailable.</div><?php endif; ?>
        <section class="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <?php foreach ([['Total Scans', 'total', 'text-violet-200'], ['Completed', 'completed', 'text-emerald-300'], ['Scanning', 'scanning', 'text-amber-300'], ['Failed', 'failed', 'text-red-300'], ['Malicious', 'malicious', 'text-red-300'], ['Suspicious', 'suspicious', 'text-amber-300'], ['No Threat Detected', 'no_threat', 'text-emerald-300']] as [$label, $key, $color]): ?><article class="rounded-2xl border border-white/10 bg-white/[.04] p-6"><p class="text-sm text-slate-400"><?= htmlspecialchars($label, ENT_QUOTES, 'UTF-8') ?></p><p class="mt-5 text-4xl font-bold <?= $color ?>"><?= $statistics[$key] ?></p><p class="mt-3 mono text-[10px] uppercase tracking-wider text-slate-600">Live database count</p></article><?php endforeach; ?>
        </section>
        <?php if ($deviceStatistics !== null): ?>
        <section class="mt-8 rounded-2xl border border-white/10 bg-white/[.03] p-6 sm:p-8">
            <div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-center"><div><p class="mono text-xs tracking-[.18em] text-slate-500">ENDPOINT AGENTS</p><h2 class="mt-2 text-xl font-bold">Device Downloads</h2></div><a class="text-sm text-violet-300 hover:text-white" href="detections.php">View detections</a></div>
            <div class="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <?php foreach ([['Active Devices', 'devices', 'text-violet-200'], ['Online Now', 'online', 'text-emerald-300'], ['Downloads (24h)', 'downloads', 'text-slate-200'], ['Threats (24h)', 'threats', 'text-red-300']] as [$label, $key, $color]): ?><article class="rounded-2xl border border-white/10 bg-white/[.04] p-5"><p class="text-sm text-slate-400"><?= htmlspecialchars($label, ENT_QUOTES, 'UTF-8') ?></p><p class="mt-3 text-3xl font-bold <?= $color ?>"><?= (int) $deviceStatistics[$key] ?></p></article><?php endforeach; ?>
            </div>
            <?php if ($recentThreats): ?><ul class="mt-6 divide-y divide-white/5 text-sm"><?php foreach ($recentThreats as $threat): ?><li class="flex flex-col justify-between gap-1 py-3 sm:flex-row"><span><strong class="text-red-300"><?= htmlspecialchars((string) $threat['risk_level'], ENT_QUOTES, 'UTF-8') ?></strong> · <a class="text-white hover:text-violet-200 hover:underline" href="view_detection.php?id=<?= (int) $threat['id'] ?>"><?= htmlspecialchars($threat['file_name'], ENT_QUOTES, 'UTF-8') ?></a> <span class="text-slate-500">on <?= htmlspecialchars($threat['device_name'], ENT_QUOTES, 'UTF-8') ?></span></span><span class="text-slate-500"><?= htmlspecialchars($threat['created_at'], ENT_QUOTES, 'UTF-8') ?></span></li><?php endforeach; ?></ul><?php endif; ?>
        </section>
        <?php endif; ?>
        <section class="mt-8 rounded-2xl border border-white/10 bg-white/[.03] p-6 sm:p-8"><div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-center"><div><p class="mono text-xs tracking-[.18em] text-slate-500">ACTIVITY FEED</p><h2 class="mt-2 text-xl font-bold">Recent Scan Activity</h2></div><a class="text-sm text-violet-300 hover:text-white" href="history.php">View history</a></div>
            <?php if (!$recentScans): ?><div class="mt-8 rounded-xl border border-dashed border-white/10 px-6 py-12 text-center text-slate-500">No scans have been performed.</div><?php else: ?><div class="mt-6 overflow-x-auto"><table class="w-full min-w-[620px] text-left text-sm"><thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-4 py-3">File</th><th class="px-4 py-3">Status</th><th class="px-4 py-3">Risk</th><th class="px-4 py-3">Date</th><th class="px-4 py-3">Action</th></tr></thead><tbody class="divide-y divide-white/5"><?php foreach ($recentScans as $scan): ?><tr><td class="max-w-[220px] truncate px-4 py-4 font-semibold text-white"><?= htmlspecialchars($scan['original_filename'], ENT_QUOTES, 'UTF-8') ?></td><td class="px-4 py-4 text-amber-200"><?= htmlspecialchars(ucfirst($scan['scan_status']), ENT_QUOTES, 'UTF-8') ?></td><td class="px-4 py-4 text-slate-300"><?= htmlspecialchars((string) ($scan['risk_level'] ?: 'Pending'), ENT_QUOTES, 'UTF-8') ?></td><td class="whitespace-nowrap px-4 py-4 text-slate-500"><?= htmlspecialchars($scan['created_at'], ENT_QUOTES, 'UTF-8') ?></td><td class="px-4 py-4"><a class="text-violet-300 hover:text-white" href="view_scan.php?id=<?= (int) $scan['id'] ?>">View</a></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?>
        </section>
        </div>
    </main>
</div>
<?php require __DIR__ . '/../includes/live_refresh.php'; ?>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
