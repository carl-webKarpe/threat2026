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
    'MALICIOUS' => 'border-red-500/40 bg-red-500/10 text-red-400',
    'SUSPICIOUS' => 'border-amber-500/40 bg-amber-500/10 text-amber-400',
    'NO_THREAT_DETECTED' => 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
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
            <a class="text-sm text-accent-light hover:text-white" href="detections.php">&larr; Back to Device Detections</a>
            <?php if ($error === ''): ?><button class="rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-dark" type="button" onclick="window.print()">Print Detection Details</button><?php endif; ?>
        </div>
        <p class="mt-8 text-[11px] font-medium uppercase tracking-[.3em] text-accent-light">DEVICE DETECTION</p>
        <div class="mt-3 flex flex-wrap items-baseline gap-4"><h1 class="font-display text-2xl uppercase tracking-[.08em] text-white sm:text-3xl">Detection Details</h1><?php if ($error === '' && !$isFinal): ?><span data-live-indicator class="no-print text-xs text-emerald-400">● Live</span><?php endif; ?></div>
        <?php if ($error !== ''): ?>
            <div class="mt-8 rounded-xl border border-red-500/30 bg-red-500/10 p-5 text-red-400"><?= $h($error) ?></div>
        <?php else: ?>
            <div data-live-region="detection">
            <section class="mt-8 max-w-5xl rounded-xl border border-white/10 bg-panel shadow-sm p-6 sm:p-8">
                <div class="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 sm:flex-row sm:items-start">
                    <div class="min-w-0">
                        <p class="text-xs uppercase tracking-wider text-neutral-400">File Name</p>
                        <h2 class="mt-2 break-words text-2xl font-bold"><?= $h($detection['file_name']) ?></h2>
                        <p class="mt-2 text-sm text-neutral-400">Detection #<?= (int) $detection['id'] ?> · <?= ($detection['trigger_type'] ?? 'download') === 'manual_scan' ? 'Found by a manual scan' : 'New download' ?></p>
                    </div>
                    <span class="shrink-0 rounded-full border px-4 py-1.5 text-sm font-bold <?= $resultStyles[$detection['scan_result'] ?? ''] ?? 'border-white/15 text-neutral-300' ?>"><?= $h($detection['risk_level'], $statusLabels[$detection['scan_status']] ?? ucfirst((string) $detection['scan_status'])) ?></span>
                </div>

                <h3 class="mt-7 text-xs font-semibold uppercase tracking-wider text-neutral-400">VERDICT</h3>
                <dl class="mt-4 grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <div><dt class="text-neutral-400">Status</dt><dd class="mt-1 font-semibold text-white"><?= $h($statusLabels[$detection['scan_status']] ?? $detection['scan_status']) ?></dd></div>
                    <div><dt class="text-neutral-400">Result</dt><dd class="mt-1 font-semibold text-white"><?= $h($detection['scan_result'], 'Pending') ?></dd></div>
                    <div><dt class="text-neutral-400">Threat Name</dt><dd class="mt-1 break-words font-semibold text-white"><?= $h($detection['threat_name'], 'None reported') ?></dd></div>
                    <div><dt class="text-neutral-400">Malicious</dt><dd class="mt-1 font-semibold text-red-400"><?= $h($detection['malicious_count']) ?></dd></div>
                    <div><dt class="text-neutral-400">Suspicious</dt><dd class="mt-1 font-semibold text-amber-400"><?= $h($detection['suspicious_count']) ?></dd></div>
                    <div><dt class="text-neutral-400">Harmless</dt><dd class="mt-1 font-semibold text-emerald-400"><?= $h($detection['harmless_count']) ?></dd></div>
                    <div><dt class="text-neutral-400">Undetected</dt><dd class="mt-1 font-semibold text-neutral-300"><?= $h($detection['undetected_count']) ?></dd></div>
                    <div><dt class="text-neutral-400">Total Engines</dt><dd class="mt-1 font-semibold text-white"><?= $h($detection['total_engines']) ?></dd></div>
                    <div><dt class="text-neutral-400">Safety Indicator</dt><dd class="mt-1 font-semibold text-white"><?= $detection['safety_percentage'] === null ? 'Not available' : $h(number_format((float) $detection['safety_percentage'], 2) . '%') ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-neutral-400">Analysis Summary</dt><dd class="mt-1 text-neutral-300"><?= $h($detection['scan_summary']) ?></dd></div>
                </dl>

                <h3 class="mt-8 text-xs font-semibold uppercase tracking-wider text-neutral-400">FILE</h3>
                <dl class="mt-4 grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <div><dt class="text-neutral-400">File Size</dt><dd class="mt-1 font-semibold text-white"><?= $detection['file_size'] === null ? 'Not available' : $h(scanner_format_size((int) $detection['file_size'])) ?></dd></div>
                    <div class="sm:col-span-2"><dt class="text-neutral-400">Path on the Device</dt><dd class="mt-1 break-all font-mono text-xs text-neutral-300"><?= $h($detection['file_path']) ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-neutral-400">SHA-256 Hash</dt><dd class="mt-1 break-all font-mono text-xs text-accent-light"><?= $h($detection['sha256_hash']) ?> <a class="no-print ml-2 font-sans text-accent-light underline hover:text-white" href="https://www.virustotal.com/gui/file/<?= $h($detection['sha256_hash']) ?>" target="_blank" rel="noopener noreferrer">View on VirusTotal</a></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-neutral-400">Downloaded From</dt><dd class="mt-1 break-all font-mono text-xs text-neutral-300"><?= $h($detection['source_url'], 'Unknown') ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-neutral-400">Referring Page</dt><dd class="mt-1 break-all font-mono text-xs text-neutral-300"><?= $h($detection['referrer_url'], 'Unknown') ?></dd></div>
                </dl>
                <p class="mt-3 text-xs text-neutral-400">Download addresses are shown as plain text on purpose, so they cannot be opened by accident.</p>

                <h3 class="mt-8 text-xs font-semibold uppercase tracking-wider text-neutral-400">DEVICE AND TIMELINE</h3>
                <dl class="mt-4 grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <div><dt class="text-neutral-400">Device</dt><dd class="mt-1 font-semibold text-white"><a class="hover:text-white hover:underline" href="detections.php?device=<?= (int) $detection['device_id'] ?>"><?= $h($detection['device_name']) ?></a></dd></div>
                    <div><dt class="text-neutral-400">Computer Name</dt><dd class="mt-1 font-semibold text-white"><?= $h($detection['hostname']) ?></dd></div>
                    <div><dt class="text-neutral-400">Operating System / IP</dt><dd class="mt-1 font-semibold text-white"><?= $h($detection['os_info']) ?><span class="block text-xs font-normal text-neutral-400"><?= $h($detection['last_ip'], '') ?></span></dd></div>
                    <div><dt class="text-neutral-400">Downloaded At (device clock)</dt><dd class="mt-1 font-semibold text-white"><?= $h($detection['downloaded_at']) ?></dd></div>
                    <div><dt class="text-neutral-400">Reported to JunMalware</dt><dd class="mt-1 font-semibold text-white"><?= $h($detection['created_at']) ?></dd></div>
                    <div><dt class="text-neutral-400">Last Checked with VirusTotal</dt><dd class="mt-1 font-semibold text-white"><?= $h($detection['checked_at'], 'Not yet') ?></dd></div>
                    <?php if (in_array($detection['scan_result'], ['MALICIOUS', 'SUSPICIOUS'], true)): ?>
                    <div><dt class="text-neutral-400">Admin Alert Email</dt><dd class="mt-1 font-semibold text-white"><?= array_key_exists('alert_sent_at', $detection) ? $h($detection['alert_sent_at'] !== null ? 'Sent ' . $detection['alert_sent_at'] : null, 'Not sent') : 'Run phase11_threat_alerts.sql' ?></dd></div>
                    <?php endif; ?>
                </dl>
                <p class="mt-7 text-xs text-neutral-400">The safety indicator is calculated by JunMalware from VirusTotal engine statistics; it is not an official VirusTotal safety score.</p>
            </section>
            </div>
        <?php endif; ?>
    </main>
</div>
<?php if ($error === '' && !$isFinal) {
    require __DIR__ . '/../includes/live_refresh.php';
} ?>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
