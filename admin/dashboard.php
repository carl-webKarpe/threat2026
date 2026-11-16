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
// The last 7 days, oldest first: date => [downloads, threats, file activity].
$days = [];
for ($offset = 6; $offset >= 0; $offset--) {
    $days[date('Y-m-d', strtotime("-{$offset} days"))] = [0, 0, 0];
}
$activityToday = null;
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
    $perDay = $pdo->query(
        "SELECT DATE(created_at) AS day, COUNT(*) AS downloads, SUM(scan_result IN ('MALICIOUS', 'SUSPICIOUS')) AS threats
         FROM device_detections WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY) GROUP BY DATE(created_at)"
    )->fetchAll();
    foreach ($perDay as $row) {
        if (isset($days[$row['day']])) {
            $days[$row['day']][0] = (int) $row['downloads'];
            $days[$row['day']][1] = (int) $row['threats'];
        }
    }
} catch (Throwable $exception) {
    error_log('Device statistics unavailable: ' . $exception->getMessage());
}
// File activity per day (Phase 13). Its times are stored in UTC, so they are moved to the server's time zone.
try {
    $zone = (new DateTimeImmutable())->format('P');
    $activityPerDay = $pdo->prepare(
        "SELECT DATE(CONVERT_TZ(detected_at_utc, '+00:00', :zone)) AS day, COUNT(*) AS events FROM file_activity_events
         WHERE detected_at_utc >= UTC_TIMESTAMP() - INTERVAL 8 DAY GROUP BY day"
    );
    $activityPerDay->execute(['zone' => $zone]);
    foreach ($activityPerDay as $row) {
        if (isset($days[$row['day']])) {
            $days[$row['day']][2] = (int) $row['events'];
        }
    }
    $activityToday = (int) $pdo->query('SELECT COUNT(*) FROM file_activity_events WHERE detected_at_utc >= UTC_TIMESTAMP() - INTERVAL 1 DAY')->fetchColumn();
} catch (Throwable $exception) {
    error_log('File activity statistics unavailable: ' . $exception->getMessage());
}
$maxDownloads = max(1, ...array_column(array_values($days), 0));
$maxActivity = max(1, ...array_column(array_values($days), 2));

$h = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
/** Small outline icon for the summary cards. */
$icon = static function (string $name): string {
    $paths = [
        'devices' => '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
        'download' => '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
        'threat' => '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M12 8v5M12 16h.01"/>',
        'activity' => '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    ];

    return '<svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $paths[$name] . '</svg>';
};
$riskBadge = static fn (?string $risk): string => match ($risk) {
    'Malicious' => 'bg-red-50 text-red-700 ring-red-200',
    'Suspicious' => 'bg-amber-50 text-amber-700 ring-amber-200',
    'No Threat Detected' => 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    default => 'bg-slate-100 text-slate-600 ring-slate-200',
};

$pageTitle = 'Admin Dashboard';
$basePath = '..';
$currentPage = 'dashboard';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
    <div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
    <main class="min-w-0 flex-1 p-6 sm:p-8 lg:p-10">
        <header class="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
            <div>
                <p class="text-sm text-slate-500"><?= $h(date('l, F j, Y')) ?></p>
                <h1 class="mt-1 text-3xl font-bold tracking-tight text-slate-900">Welcome back, <?= $h(strtok($user['full_name'], ' ') ?: $user['full_name']) ?></h1>
                <p class="mt-1 text-sm text-slate-500">Overview of your monitored devices, threats and file activity.</p>
            </div>
            <div class="flex items-center gap-3">
                <span data-live-indicator class="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-600 ring-1 ring-emerald-200">● Live</span>
                <a href="scan.php" class="rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-700">Scan a file</a>
            </div>
        </header>

        <div data-live-region="dashboard">
        <?php if ($dashboardError): ?><div class="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">Dashboard statistics are temporarily unavailable.</div><?php endif; ?>

        <?php if ($deviceStatistics !== null): ?>
        <section class="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="Endpoint summary">
            <?php foreach ([
                ['Devices online', (int) $deviceStatistics['online'] . ' / ' . (int) $deviceStatistics['devices'], 'devices', 'bg-blue-50 text-blue-600', 'devices.php', 'Active devices reporting now'],
                ['Downloads (24h)', (int) $deviceStatistics['downloads'], 'download', 'bg-sky-50 text-sky-600', 'detections.php', 'Files checked with VirusTotal'],
                ['Threats (24h)', (int) $deviceStatistics['threats'], 'threat', (int) $deviceStatistics['threats'] > 0 ? 'bg-red-50 text-red-600' : 'bg-emerald-50 text-emerald-600', 'detections.php?result=MALICIOUS', 'Malicious or suspicious downloads'],
                ['File activity (24h)', $activityToday ?? '—', 'activity', 'bg-violet-50 text-violet-600', 'activity.php', 'Created, changed, deleted, moved'],
            ] as [$label, $value, $iconName, $iconClass, $link, $hint]): ?>
                <a href="<?= $h($link) ?>" class="group rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-blue-300 hover:shadow">
                    <div class="flex items-start justify-between"><p class="text-sm font-medium text-slate-500"><?= $h($label) ?></p><span class="grid h-9 w-9 place-items-center rounded-lg <?= $iconClass ?>"><?= $icon($iconName) ?></span></div>
                    <p class="mt-3 text-3xl font-bold tracking-tight text-slate-900"><?= $h($value) ?></p>
                    <p class="mt-1 text-xs text-slate-400"><?= $h($hint) ?></p>
                </a>
            <?php endforeach; ?>
        </section>

        <section class="mt-6 grid gap-6 xl:grid-cols-3">
            <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm xl:col-span-2">
                <div class="flex flex-wrap items-center justify-between gap-3"><div><h2 class="text-base font-semibold text-slate-900">Downloads and threats</h2><p class="text-sm text-slate-500">Last 7 days, all devices</p></div>
                    <div class="flex items-center gap-4 text-xs text-slate-500"><span class="flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-sm bg-blue-500"></span>Downloads</span><span class="flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-sm bg-red-500"></span>Threats</span></div></div>
                <div class="mt-6 flex h-60 items-end gap-3" role="img" aria-label="Downloads and threats per day for the last 7 days">
                    <?php foreach ($days as $day => [$downloads, $threats]): ?>
                        <div class="flex h-full flex-1 flex-col items-center justify-end gap-2">
                            <div class="flex h-full w-full items-end justify-center gap-1" title="<?= $h(date('D, M j', strtotime($day)) . ": {$downloads} download(s), {$threats} threat(s)") ?>">
                                <div class="w-1/3 max-w-[22px] rounded-t bg-blue-500" style="height: <?= max(2, (int) round($downloads / $maxDownloads * 100)) ?>%"></div>
                                <div class="w-1/3 max-w-[22px] rounded-t bg-red-500" style="height: <?= $threats > 0 ? max(2, (int) round($threats / $maxDownloads * 100)) : 0 ?>%"></div>
                            </div>
                            <span class="text-xs text-slate-500"><?= $h(date('D', strtotime($day))) ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
                <div class="flex items-center justify-between"><div><h2 class="text-base font-semibold text-slate-900">Recent threats</h2><p class="text-sm text-slate-500">Latest on any device</p></div><a class="text-sm font-medium text-blue-600 hover:text-blue-800" href="detections.php">View all</a></div>
                <?php if (!$recentThreats): ?>
                    <div class="mt-6 rounded-lg border border-dashed border-emerald-200 bg-emerald-50 px-4 py-8 text-center text-sm text-emerald-700">No threats found. All clear.</div>
                <?php else: ?>
                    <ul class="mt-4 divide-y divide-slate-100">
                        <?php foreach ($recentThreats as $threat): ?>
                            <li class="py-3"><div class="flex items-start justify-between gap-3"><a class="min-w-0 truncate text-sm font-semibold text-slate-900 hover:text-blue-700" href="view_detection.php?id=<?= (int) $threat['id'] ?>"><?= $h($threat['file_name']) ?></a><span class="shrink-0 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold ring-1 <?= $riskBadge($threat['risk_level']) ?>"><?= $h($threat['risk_level']) ?></span></div><p class="mt-0.5 truncate text-xs text-slate-500"><?= $h($threat['device_name']) ?> · <?= $h($threat['created_at']) ?><?= $threat['threat_name'] ? ' · ' . $h($threat['threat_name']) : '' ?></p></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        </section>

        <section class="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div class="flex flex-wrap items-center justify-between gap-3"><div><h2 class="text-base font-semibold text-slate-900">File activity</h2><p class="text-sm text-slate-500">Events per day on all monitored folders</p></div><a class="text-sm font-medium text-blue-600 hover:text-blue-800" href="activity.php">Open File Activity</a></div>
            <div class="mt-5 grid grid-cols-7 gap-3" role="img" aria-label="File activity events per day for the last 7 days">
                <?php foreach ($days as $day => [, , $events]): ?>
                    <div class="text-center" title="<?= $h(date('D, M j', strtotime($day)) . ": {$events} event(s)") ?>">
                        <div class="flex h-20 items-end justify-center rounded-lg bg-slate-50 px-2"><div class="w-full max-w-[36px] rounded-t bg-violet-500" style="height: <?= $events > 0 ? max(4, (int) round($events / $maxActivity * 100)) : 0 ?>%"></div></div>
                        <p class="mt-2 text-sm font-semibold text-slate-900"><?= $events ?></p><p class="text-xs text-slate-500"><?= $h(date('D', strtotime($day))) ?></p>
                    </div>
                <?php endforeach; ?>
            </div>
        </section>
        <?php endif; ?>

        <section class="mt-6 grid gap-6 xl:grid-cols-3">
            <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
                <h2 class="text-base font-semibold text-slate-900">Your file scans</h2><p class="text-sm text-slate-500">Files you uploaded on Scan File</p>
                <dl class="mt-5 grid grid-cols-2 gap-3">
                    <?php foreach ([['Total', 'total', 'text-slate-900'], ['Completed', 'completed', 'text-emerald-600'], ['Scanning', 'scanning', 'text-amber-600'], ['Failed', 'failed', 'text-slate-500'], ['Malicious', 'malicious', 'text-red-600'], ['Suspicious', 'suspicious', 'text-amber-600'], ['No threat', 'no_threat', 'text-emerald-600']] as [$label, $key, $color]): ?>
                        <div class="rounded-lg bg-slate-50 px-3 py-2.5"><dt class="text-xs text-slate-500"><?= $h($label) ?></dt><dd class="mt-0.5 text-xl font-bold <?= $color ?>"><?= $statistics[$key] ?></dd></div>
                    <?php endforeach; ?>
                </dl>
            </div>
            <div class="rounded-xl border border-slate-200 bg-white shadow-sm xl:col-span-2">
                <div class="flex items-center justify-between p-6 pb-4"><div><h2 class="text-base font-semibold text-slate-900">Recent scan activity</h2><p class="text-sm text-slate-500">Your last 10 uploads</p></div><a class="text-sm font-medium text-blue-600 hover:text-blue-800" href="history.php">View history</a></div>
                <?php if (!$recentScans): ?>
                    <div class="mx-6 mb-6 rounded-lg border border-dashed border-slate-200 px-6 py-10 text-center text-sm text-slate-500">No scans have been performed. <a class="font-medium text-blue-600" href="scan.php">Scan a file</a></div>
                <?php else: ?>
                    <div class="overflow-x-auto"><table class="w-full min-w-[560px] text-left text-sm">
                        <thead class="border-y border-slate-200 text-xs font-semibold uppercase tracking-wider text-slate-500"><tr><th class="px-6 py-3">File</th><th class="px-6 py-3">Status</th><th class="px-6 py-3">Result</th><th class="px-6 py-3">Date</th><th class="px-6 py-3"></th></tr></thead>
                        <tbody class="divide-y divide-slate-100">
                            <?php foreach ($recentScans as $scan): ?>
                                <tr class="hover:bg-slate-50"><td class="max-w-[220px] truncate px-6 py-3 font-medium text-slate-900"><?= $h($scan['original_filename']) ?></td><td class="px-6 py-3 text-slate-600"><?= $h(ucfirst($scan['scan_status'])) ?></td><td class="px-6 py-3"><span class="whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold ring-1 <?= $riskBadge($scan['risk_level']) ?>"><?= $h($scan['risk_level'] ?: 'Pending') ?></span></td><td class="whitespace-nowrap px-6 py-3 text-slate-500"><?= $h($scan['created_at']) ?></td><td class="px-6 py-3 text-right"><a class="font-medium text-blue-600 hover:text-blue-800" href="view_scan.php?id=<?= (int) $scan['id'] ?>">View</a></td></tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table></div>
                <?php endif; ?>
            </div>
        </section>
        </div>
    </main>
</div>
<?php require __DIR__ . '/../includes/live_refresh.php'; ?>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
