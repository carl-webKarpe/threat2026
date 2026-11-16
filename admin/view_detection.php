<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/agents.php';
require_role('admin');

$detectionId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$detection = null;
$error = '';
if (!is_int($detectionId)) {
    $error = 'Invalid detection identifier.';
} else {
    try {
        $statement = database_connection()->prepare(
            'SELECT device_detections.*, devices.name AS device_name, devices.hostname, devices.os_info, devices.last_ip
             FROM device_detections INNER JOIN devices ON devices.id = device_detections.device_id
             WHERE device_detections.id = :id LIMIT 1'
        );
        $statement->execute(['id' => $detectionId]);
        $detection = $statement->fetch() ?: null;
        if ($detection === null) {
            $error = 'Detection not found.';
        }
    } catch (Throwable $exception) {
        error_log($exception->getMessage());
        $error = 'This detection is temporarily unavailable.';
    }
}

$h = static fn (mixed $value, string $fallback = 'Not available'): string
    => htmlspecialchars($value === null || $value === '' ? $fallback : (string) $value, ENT_QUOTES, 'UTF-8');
$statusLabels = [
    'pending' => 'Waiting for VirusTotal',
    'not_found' => 'Unknown to VirusTotal',
    'analyzing' => 'Being analysed by VirusTotal',
    'completed' => 'Completed',
    'failed' => 'Scan failed',
];
$resultStyles = [
    'MALICIOUS' => 'border-red-300 bg-red-50 text-red-700',
    'SUSPICIOUS' => 'border-amber-300 bg-amber-50 text-amber-700',
    'NO_THREAT_DETECTED' => 'border-emerald-300 bg-emerald-50 text-emerald-700',
];
$isFinal = $detection !== null && in_array($detection['scan_status'], ['completed', 'failed', 'not_found'], true);

$pageTitle = 'Detection Details';
$currentPage = 'detections';
require_once __DIR__ . '/../includes/header.php';
?>
<style media="print">
    body { background: #fff !important; color: #111827 !important; }
    aside, .no-print, footer { display: none !important; }
    main { padding: 0 !important; }
    main, section, dl, dd, h1, h2, p, dt, span { color: #111827 !important; }
    section { max-width: none !important; border: 0 !important; background: #fff !important; padding: 0 !important; }
    dl { break-inside: avoid; }
    dd { overflow-wrap: anywhere; }
</style>
<div class="flex min-h-screen flex-col lg:flex-row">
    <div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
    <main class="min-w-0 flex-1 p-6 sm:p-10">
        <div class="no-print flex flex-wrap items-center justify-between gap-4">
            <a class="text-sm text-blue-700 hover:text-blue-700" href="detections.php">&larr; Back to Device Detections</a>
            <?php if ($error === ''): ?><button class="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700" type="button" onclick="window.print()">Print Detection Details</button><?php endif; ?>
        </div>
        <p class="mt-8 text-xs font-semibold uppercase tracking-wider text-blue-700">DEVICE DETECTION</p>
        <div class="mt-3 flex flex-wrap items-baseline gap-4"><h1 class="text-3xl font-bold tracking-tight text-slate-900">Detection Details</h1><?php if ($error === '' && !$isFinal): ?><span data-live-indicator class="no-print text-xs text-emerald-600">● Live</span><?php endif; ?></div>
        <?php if ($error !== ''): ?>
            <div class="mt-8 rounded-xl border border-red-200 bg-red-50 p-5 text-red-700"><?= $h($error) ?></div>
        <?php else: ?>
            <div data-live-region="detection">
            <section class="mt-8 max-w-5xl rounded-xl border border-slate-200 bg-white shadow-sm p-6 sm:p-8">
                <div class="flex flex-col justify-between gap-4 border-b border-slate-200 pb-6 sm:flex-row sm:items-start">
                    <div class="min-w-0">
                        <p class="text-xs uppercase tracking-wider text-slate-500">File Name</p>
                        <h2 class="mt-2 break-words text-2xl font-bold"><?= $h($detection['file_name']) ?></h2>
                        <p class="mt-2 text-sm text-slate-500">Detection #<?= (int) $detection['id'] ?> · <?= ($detection['trigger_type'] ?? 'download') === 'manual_scan' ? 'Found by a manual scan' : 'New download' ?></p>
                    </div>
                    <span class="shrink-0 rounded-full border px-4 py-1.5 text-sm font-bold <?= $resultStyles[$detection['scan_result'] ?? ''] ?? 'border-slate-300 text-slate-700' ?>"><?= $h($detection['risk_level'], $statusLabels[$detection['scan_status']] ?? ucfirst((string) $detection['scan_status'])) ?></span>
                </div>

                <h3 class="mt-7 text-xs font-semibold uppercase tracking-wider text-slate-500">VERDICT</h3>
                <dl class="mt-4 grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <div><dt class="text-slate-500">Status</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($statusLabels[$detection['scan_status']] ?? $detection['scan_status']) ?></dd></div>
                    <div><dt class="text-slate-500">Result</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($detection['scan_result'], 'Pending') ?></dd></div>
                    <div><dt class="text-slate-500">Threat Name</dt><dd class="mt-1 break-words font-semibold text-slate-900"><?= $h($detection['threat_name'], 'None reported') ?></dd></div>
                    <div><dt class="text-slate-500">Malicious</dt><dd class="mt-1 font-semibold text-red-700"><?= $h($detection['malicious_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Suspicious</dt><dd class="mt-1 font-semibold text-amber-700"><?= $h($detection['suspicious_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Harmless</dt><dd class="mt-1 font-semibold text-emerald-700"><?= $h($detection['harmless_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Undetected</dt><dd class="mt-1 font-semibold text-slate-700"><?= $h($detection['undetected_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Total Engines</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($detection['total_engines']) ?></dd></div>
                    <div><dt class="text-slate-500">Safety Indicator</dt><dd class="mt-1 font-semibold text-slate-900"><?= $detection['safety_percentage'] === null ? 'Not available' : $h(number_format((float) $detection['safety_percentage'], 2) . '%') ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-slate-500">Analysis Summary</dt><dd class="mt-1 text-slate-700"><?= $h($detection['scan_summary']) ?></dd></div>
                </dl>

                <h3 class="mt-8 text-xs font-semibold uppercase tracking-wider text-slate-500">FILE</h3>
                <dl class="mt-4 grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <div><dt class="text-slate-500">File Size</dt><dd class="mt-1 font-semibold text-slate-900"><?= $detection['file_size'] === null ? 'Not available' : $h(scanner_format_size((int) $detection['file_size'])) ?></dd></div>
                    <div class="sm:col-span-2"><dt class="text-slate-500">Path on the Device</dt><dd class="mt-1 break-all font-mono text-xs text-slate-700"><?= $h($detection['file_path']) ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-slate-500">SHA-256 Hash</dt><dd class="mt-1 break-all font-mono text-xs text-blue-700"><?= $h($detection['sha256_hash']) ?> <a class="no-print ml-2 font-sans text-blue-700 underline hover:text-blue-700" href="https://www.virustotal.com/gui/file/<?= $h($detection['sha256_hash']) ?>" target="_blank" rel="noopener noreferrer">View on VirusTotal</a></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-slate-500">Downloaded From</dt><dd class="mt-1 break-all font-mono text-xs text-slate-700"><?= $h($detection['source_url'], 'Unknown') ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-slate-500">Referring Page</dt><dd class="mt-1 break-all font-mono text-xs text-slate-700"><?= $h($detection['referrer_url'], 'Unknown') ?></dd></div>
                </dl>
                <p class="mt-3 text-xs text-slate-500">Download addresses are shown as plain text on purpose, so they cannot be opened by accident.</p>

                <h3 class="mt-8 text-xs font-semibold uppercase tracking-wider text-slate-500">DEVICE AND TIMELINE</h3>
                <dl class="mt-4 grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <div><dt class="text-slate-500">Device</dt><dd class="mt-1 font-semibold text-slate-900"><a class="hover:text-blue-800 hover:underline" href="detections.php?device=<?= (int) $detection['device_id'] ?>"><?= $h($detection['device_name']) ?></a></dd></div>
                    <div><dt class="text-slate-500">Computer Name</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($detection['hostname']) ?></dd></div>
                    <div><dt class="text-slate-500">Operating System / IP</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($detection['os_info']) ?><span class="block text-xs font-normal text-slate-500"><?= $h($detection['last_ip'], '') ?></span></dd></div>
                    <div><dt class="text-slate-500">Downloaded At (device clock)</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($detection['downloaded_at']) ?></dd></div>
                    <div><dt class="text-slate-500">Reported to MalDetect</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($detection['created_at']) ?></dd></div>
                    <div><dt class="text-slate-500">Last Checked with VirusTotal</dt><dd class="mt-1 font-semibold text-slate-900"><?= $h($detection['checked_at'], 'Not yet') ?></dd></div>
                    <?php if (in_array($detection['scan_result'], ['MALICIOUS', 'SUSPICIOUS'], true)): ?>
                    <div><dt class="text-slate-500">Admin Alert Email</dt><dd class="mt-1 font-semibold text-slate-900"><?= array_key_exists('alert_sent_at', $detection) ? $h($detection['alert_sent_at'] !== null ? 'Sent ' . $detection['alert_sent_at'] : null, 'Not sent') : 'Run phase11_threat_alerts.sql' ?></dd></div>
                    <?php endif; ?>
                </dl>
                <p class="mt-7 text-xs text-slate-500">The safety indicator is calculated by MalDetect from VirusTotal engine statistics; it is not an official VirusTotal safety score.</p>
            </section>
            </div>
        <?php endif; ?>
    </main>
</div>
<?php if ($error === '' && !$isFinal) {
    require __DIR__ . '/../includes/live_refresh.php';
} ?>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
