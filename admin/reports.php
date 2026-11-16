<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/agents.php';
require_role('admin');

// ---- Filters (shared by the page, the CSV export and the printed/PDF report) ----
$today = new DateTimeImmutable('today');
$parseDate = static function (string $value, DateTimeImmutable $fallback): DateTimeImmutable {
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
    return $date !== false && $date->format('Y-m-d') === $value ? $date : $fallback;
};
$from = $parseDate((string) ($_GET['from'] ?? ''), $today->modify('-6 days'));
$to = $parseDate((string) ($_GET['to'] ?? ''), $today);
if ($from > $to) {
    [$from, $to] = [$to, $from];
}
$deviceFilter = filter_input(INPUT_GET, 'device', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$resultFilter = (string) ($_GET['result'] ?? '');
$triggerFilter = (string) ($_GET['trigger'] ?? '');
$allowedResults = ['THREATS' => 'Threats only (Malicious + Suspicious)', 'MALICIOUS' => 'Malicious', 'SUSPICIOUS' => 'Suspicious', 'NO_THREAT_DETECTED' => 'No Threat Detected', 'UNKNOWN' => 'Unknown to VirusTotal', 'PENDING' => 'Pending'];
$allowedTriggers = ['download' => 'New downloads', 'manual_scan' => 'Manual scans'];

$where = ['d.created_at >= :from', 'd.created_at < :to_exclusive'];
$parameters = ['from' => $from->format('Y-m-d 00:00:00'), 'to_exclusive' => $to->modify('+1 day')->format('Y-m-d 00:00:00')];
if (is_int($deviceFilter)) {
    $where[] = 'd.device_id = :device_id';
    $parameters['device_id'] = $deviceFilter;
}
if ($resultFilter === 'THREATS') {
    $where[] = "d.scan_result IN ('MALICIOUS', 'SUSPICIOUS')";
} elseif ($resultFilter === 'PENDING') {
    $where[] = "d.scan_status IN ('pending', 'analyzing')";
} elseif (array_key_exists($resultFilter, $allowedResults)) {
    $where[] = 'd.scan_result = :result';
    $parameters['result'] = $resultFilter;
}
if (array_key_exists($triggerFilter, $allowedTriggers)) {
    $where[] = 'd.trigger_type = :trigger_type';
    $parameters['trigger_type'] = $triggerFilter;
}
$whereSql = ' WHERE ' . implode(' AND ', $where);
$fromSql = ' FROM device_detections AS d INNER JOIN devices AS v ON v.id = d.device_id';

$query = array_filter([
    'from' => $from->format('Y-m-d'),
    'to' => $to->format('Y-m-d'),
    'device' => is_int($deviceFilter) ? (string) $deviceFilter : '',
    'result' => $resultFilter,
    'trigger' => $triggerFilter,
], static fn (string $value): bool => $value !== '');

// ---- CSV export ----
if (($_GET['export'] ?? '') === 'csv') {
    try {
        $statement = database_connection()->prepare(
            'SELECT d.id, d.created_at, v.name AS device_name, v.hostname, d.trigger_type, d.file_name, d.file_path, d.file_size,
                    d.sha256_hash, d.scan_status, d.scan_result, d.risk_level, d.threat_name, d.malicious_count, d.suspicious_count,
                    d.harmless_count, d.undetected_count, d.total_engines, d.source_url, d.downloaded_at, d.alert_sent_at'
            . $fromSql . $whereSql . ' ORDER BY d.created_at DESC, d.id DESC'
        );
        $statement->execute($parameters);
    } catch (Throwable $exception) {
        error_log('Report export failed: ' . $exception->getMessage());
        http_response_code(500);
        exit('The report could not be created. Make sure all database migrations have been run.');
    }

    // Spreadsheet programs run cells that start with these characters as formulas; prefix them.
    $cell = static function (mixed $value): string {
        $text = (string) ($value ?? '');
        return $text !== '' && in_array($text[0], ['=', '+', '-', '@', "\t", "\r"], true) ? "'" . $text : $text;
    };
    $fileName = 'maldetect-report-' . $from->format('Ymd') . '-' . $to->format('Ymd') . '.csv';
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $fileName . '"');
    header('Cache-Control: no-store');
    $output = fopen('php://output', 'wb');
    fwrite($output, "\xEF\xBB\xBF"); // UTF-8 byte order mark, so Excel shows non-English file names correctly.
    fputcsv($output, ['Detection ID', 'Reported At', 'Device', 'Computer Name', 'Found By', 'File Name', 'File Path', 'File Size (bytes)', 'SHA-256', 'Status', 'Result', 'Risk Level', 'Threat Name', 'Malicious', 'Suspicious', 'Harmless', 'Undetected', 'Total Engines', 'Downloaded From', 'Downloaded At (device clock)', 'Alert Email Sent At']);
    while ($row = $statement->fetch()) {
        fputcsv($output, array_map($cell, [
            $row['id'], $row['created_at'], $row['device_name'], $row['hostname'],
            $row['trigger_type'] === 'manual_scan' ? 'Manual scan' : 'New download',
            $row['file_name'], $row['file_path'], $row['file_size'], $row['sha256_hash'], $row['scan_status'], $row['scan_result'],
            $row['risk_level'], $row['threat_name'], $row['malicious_count'], $row['suspicious_count'], $row['harmless_count'],
            $row['undetected_count'], $row['total_engines'], $row['source_url'], $row['downloaded_at'], $row['alert_sent_at'],
        ]));
    }
    fclose($output);
    exit;
}

// ---- Report data ----
$summary = [];
$byDevice = [];
$topThreats = [];
$devices = [];
$loadError = false;
try {
    $pdo = database_connection();
    $devices = $pdo->query('SELECT id, name FROM devices ORDER BY name')->fetchAll();
    $statement = $pdo->prepare(
        "SELECT COUNT(*) AS total,
                SUM(d.scan_result = 'MALICIOUS') AS malicious,
                SUM(d.scan_result = 'SUSPICIOUS') AS suspicious,
                SUM(d.scan_result = 'NO_THREAT_DETECTED') AS clean,
                SUM(d.scan_status IN ('pending', 'analyzing')) AS pending,
                SUM(d.scan_result = 'UNKNOWN' OR d.scan_status = 'not_found') AS unknown,
                SUM(d.scan_status = 'failed') AS failed,
                COUNT(DISTINCT d.device_id) AS devices"
        . $fromSql . $whereSql
    );
    $statement->execute($parameters);
    $summary = array_map('intval', $statement->fetch() ?: []);

    $statement = $pdo->prepare(
        "SELECT v.name, v.hostname, COUNT(*) AS total,
                SUM(d.scan_result = 'MALICIOUS') AS malicious, SUM(d.scan_result = 'SUSPICIOUS') AS suspicious,
                SUM(d.scan_result = 'NO_THREAT_DETECTED') AS clean, MAX(d.created_at) AS last_detection"
        . $fromSql . $whereSql . ' GROUP BY v.id, v.name, v.hostname ORDER BY malicious DESC, suspicious DESC, total DESC'
    );
    $statement->execute($parameters);
    $byDevice = $statement->fetchAll();

    $statement = $pdo->prepare(
        "SELECT COALESCE(NULLIF(d.threat_name, ''), '(not named by the engines)') AS threat, d.scan_result,
                COUNT(*) AS detections, COUNT(DISTINCT d.device_id) AS device_count, MAX(d.created_at) AS last_seen"
        . $fromSql . $whereSql . " AND d.scan_result IN ('MALICIOUS', 'SUSPICIOUS')
         GROUP BY threat, d.scan_result ORDER BY detections DESC LIMIT 10"
    );
    $statement->execute($parameters);
    $topThreats = $statement->fetchAll();
} catch (Throwable $exception) {
    error_log('Report failed: ' . $exception->getMessage());
    $loadError = true;
}

$h = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
$deviceName = '';
foreach ($devices as $device) {
    if ((int) $device['id'] === $deviceFilter) {
        $deviceName = (string) $device['name'];
    }
}
$filterSummary = $from->format('M j, Y') . ' – ' . $to->format('M j, Y')
    . ' · ' . ($deviceName !== '' ? 'Device: ' . $deviceName : 'All devices')
    . ($resultFilter !== '' && isset($allowedResults[$resultFilter]) ? ' · ' . $allowedResults[$resultFilter] : '')
    . ($triggerFilter !== '' && isset($allowedTriggers[$triggerFilter]) ? ' · ' . $allowedTriggers[$triggerFilter] : '');

$pageTitle = 'Reports';
$currentPage = 'reports';
require_once __DIR__ . '/../includes/header.php';
?>
<style media="print">
    @page { margin: 14mm; }
    body { background: #fff !important; color: #111827 !important; }
    aside, .no-print, footer { display: none !important; }
    main { padding: 0 !important; }
    main * { color: #111827 !important; border-color: #d1d5db !important; background: transparent !important; }
    .print-only { display: block !important; }
    table { font-size: 11px; }
    section, tr { break-inside: avoid; }
</style>
<div class="flex min-h-screen flex-col lg:flex-row">
	<div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
	<main class="min-w-0 flex-1 p-6 sm:p-10">
		<p class="mono text-xs tracking-[.2em] text-violet-300">REPORTS</p>
		<h1 class="mt-3 text-3xl font-bold">Detection Report</h1>
		<p class="mt-2 text-slate-400"><?= $h($filterSummary) ?></p>
		<p class="print-only mt-1 hidden text-xs">Generated by MalDetect on <?= $h(date('M j, Y g:i A')) ?> by <?= $h($user['full_name']) ?>.</p>

		<form class="no-print mt-8 grid gap-3 rounded-2xl border border-white/10 bg-white/[.03] p-5 sm:grid-cols-5" method="get">
			<label class="text-sm text-slate-400">From<input class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 [color-scheme:dark]" type="date" name="from" value="<?= $h($from->format('Y-m-d')) ?>"></label>
			<label class="text-sm text-slate-400">To<input class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 [color-scheme:dark]" type="date" name="to" value="<?= $h($to->format('Y-m-d')) ?>"></label>
			<label class="text-sm text-slate-400">Device<select class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100" name="device"><option value="">All</option><?php foreach ($devices as $device): ?><option value="<?= (int) $device['id'] ?>" <?= $deviceFilter === (int) $device['id'] ? 'selected' : '' ?>><?= $h($device['name']) ?></option><?php endforeach; ?></select></label>
			<label class="text-sm text-slate-400">Result<select class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100" name="result"><option value="">All</option><?php foreach ($allowedResults as $value => $label): ?><option value="<?= $h($value) ?>" <?= $resultFilter === $value ? 'selected' : '' ?>><?= $h($label) ?></option><?php endforeach; ?></select></label>
			<label class="text-sm text-slate-400">Source<select class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100" name="trigger"><option value="">All</option><?php foreach ($allowedTriggers as $value => $label): ?><option value="<?= $h($value) ?>" <?= $triggerFilter === $value ? 'selected' : '' ?>><?= $h($label) ?></option><?php endforeach; ?></select></label>
			<div class="flex flex-wrap gap-3 sm:col-span-5 sm:justify-end">
				<button class="rounded-xl bg-violet-300 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-violet-200" type="submit">Apply Filters</button>
				<a class="rounded-xl border border-emerald-300/40 px-5 py-3 text-sm font-bold text-emerald-200 hover:bg-emerald-300/10" href="reports.php?<?= $h(http_build_query($query + ['export' => 'csv'])) ?>">Download CSV</a>
				<button class="rounded-xl border border-white/15 px-5 py-3 text-sm font-bold text-slate-200 hover:bg-white/5" type="button" onclick="window.print()">Print / Save as PDF</button>
			</div>
		</form>

		<?php if ($loadError): ?>
			<div class="mt-8 rounded-2xl border border-red-300/20 bg-red-400/10 p-5 text-sm text-red-200">The report is unavailable. Run the latest database migrations (see SETUP-GUIDE.md).</div>
		<?php else: ?>
			<section class="mt-8 grid gap-4 sm:grid-cols-3 xl:grid-cols-6">
				<?php foreach ([['Total Detections', 'total', 'text-violet-200'], ['Malicious', 'malicious', 'text-red-300'], ['Suspicious', 'suspicious', 'text-amber-300'], ['No Threat', 'clean', 'text-emerald-300'], ['Unknown / Pending', 'unknown_pending', 'text-slate-300'], ['Devices', 'devices', 'text-violet-200']] as [$label, $key, $color]): ?>
					<article class="rounded-2xl border border-white/10 bg-white/[.04] p-5"><p class="text-sm text-slate-400"><?= $h($label) ?></p><p class="mt-3 text-3xl font-bold <?= $color ?>"><?= $key === 'unknown_pending' ? ($summary['unknown'] ?? 0) + ($summary['pending'] ?? 0) : (int) ($summary[$key] ?? 0) ?></p></article>
				<?php endforeach; ?>
			</section>

			<section class="mt-8 rounded-2xl border border-white/10 bg-white/[.03] p-6">
				<h2 class="text-xl font-bold">Detections by Device</h2>
				<?php if (!$byDevice): ?><p class="mt-4 text-sm text-slate-500">No detections match these filters.</p><?php else: ?>
				<div class="mt-4 overflow-x-auto"><table class="w-full min-w-[700px] text-left text-sm">
					<thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-4 py-3">Device</th><th class="px-4 py-3">Total</th><th class="px-4 py-3">Malicious</th><th class="px-4 py-3">Suspicious</th><th class="px-4 py-3">No Threat</th><th class="px-4 py-3">Last Detection</th></tr></thead>
					<tbody class="divide-y divide-white/5"><?php foreach ($byDevice as $row): ?><tr class="text-slate-300"><td class="px-4 py-3"><span class="font-semibold text-white"><?= $h($row['name']) ?></span> <span class="text-xs text-slate-500"><?= $h($row['hostname'] ?? '') ?></span></td><td class="px-4 py-3"><?= (int) $row['total'] ?></td><td class="px-4 py-3 <?= (int) $row['malicious'] ? 'font-bold text-red-300' : '' ?>"><?= (int) $row['malicious'] ?></td><td class="px-4 py-3 <?= (int) $row['suspicious'] ? 'font-bold text-amber-300' : '' ?>"><?= (int) $row['suspicious'] ?></td><td class="px-4 py-3"><?= (int) $row['clean'] ?></td><td class="whitespace-nowrap px-4 py-3 text-slate-500"><?= $h($row['last_detection']) ?></td></tr><?php endforeach; ?></tbody>
				</table></div>
				<?php endif; ?>
			</section>

			<section class="mt-8 rounded-2xl border border-white/10 bg-white/[.03] p-6">
				<h2 class="text-xl font-bold">Top Threats</h2>
				<?php if (!$topThreats): ?><p class="mt-4 text-sm text-slate-500">No malicious or suspicious files in this period.</p><?php else: ?>
				<div class="mt-4 overflow-x-auto"><table class="w-full min-w-[700px] text-left text-sm">
					<thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-4 py-3">Threat Name</th><th class="px-4 py-3">Result</th><th class="px-4 py-3">Detections</th><th class="px-4 py-3">Devices</th><th class="px-4 py-3">Last Seen</th></tr></thead>
					<tbody class="divide-y divide-white/5"><?php foreach ($topThreats as $row): ?><tr class="text-slate-300"><td class="break-all px-4 py-3 font-semibold text-white"><?= $h($row['threat']) ?></td><td class="px-4 py-3 <?= $row['scan_result'] === 'MALICIOUS' ? 'text-red-300' : 'text-amber-300' ?>"><?= $h(ucfirst(strtolower((string) $row['scan_result']))) ?></td><td class="px-4 py-3"><?= (int) $row['detections'] ?></td><td class="px-4 py-3"><?= (int) $row['device_count'] ?></td><td class="whitespace-nowrap px-4 py-3 text-slate-500"><?= $h($row['last_seen']) ?></td></tr><?php endforeach; ?></tbody>
				</table></div>
				<?php endif; ?>
			</section>
			<p class="no-print mt-6 text-xs text-slate-500">The CSV contains every detection that matches the filters, one row per file. "Print / Save as PDF" prints this summary; choose <strong>Save as PDF</strong> as the printer to get a PDF file.</p>
		<?php endif; ?>
	</main>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
