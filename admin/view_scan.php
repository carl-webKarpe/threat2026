<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/scanner.php';
require_role('admin');

$scanId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$scan = false;
$error = '';
if (!is_int($scanId)) {
    $error = 'Invalid scan identifier.';
} else {
    try {
        $statement = database_connection()->prepare(
            'SELECT id, original_filename, file_size, mime_type, sha256_hash, scan_status, threat_name,
                    safety_percentage, risk_level, detection_count, malicious_count, suspicious_count,
                    harmless_count, undetected_count, total_engines, scan_result, scan_summary, created_at, updated_at
               FROM scans WHERE id = :id AND user_id = :user_id LIMIT 1'
        );
           $statement->execute(['id' => $scanId, 'user_id' => current_user()['id']]);
        $scan = $statement->fetch();
        if (!$scan) {
            $error = 'Scan record not found.';
        }
    } catch (Throwable $exception) {
        error_log($exception->getMessage());
        $error = 'Scan result is temporarily unavailable.';
    }
}

$pageTitle = 'Scan Result';
$currentPage = 'history';
require_once __DIR__ . '/../includes/header.php';
function scan_value(mixed $value, string $fallback = 'Not available'): string
{
    return htmlspecialchars($value === null || $value === '' ? $fallback : (string) $value, ENT_QUOTES, 'UTF-8');
}
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
            <a class="text-sm text-blue-700 hover:text-blue-700" href="history.php">&larr; Back to Scan History</a>
            <?php if ($error === ''): ?><button class="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700" type="button" onclick="window.print()">Print Scan Details</button><?php endif; ?>
        </div>
        <p class="mt-8 text-xs font-semibold uppercase tracking-wider text-blue-700">SCAN RESULT</p>
        <h1 class="mt-3 text-3xl font-bold tracking-tight text-slate-900">Scan Details</h1>
        <?php if ($error !== ''): ?>
            <div class="mt-8 rounded-xl border border-red-200 bg-red-50 p-5 text-red-700"><?= scan_value($error) ?></div>
        <?php else: ?>
            <section class="mt-8 max-w-5xl rounded-xl border border-slate-200 bg-white shadow-sm p-6 sm:p-8">
                <div class="flex flex-col justify-between gap-4 border-b border-slate-200 pb-6 sm:flex-row sm:items-start">
                    <div><p class="text-xs uppercase tracking-wider text-slate-500">File Name</p><h2 class="mt-2 break-words text-2xl font-bold"><?= scan_value($scan['original_filename']) ?></h2><p class="mt-2 text-sm text-slate-500">Scan ID #<?= (int) $scan['id'] ?></p></div>
                    <span class="rounded-full border border-blue-200 px-3 py-1 text-xs font-semibold text-blue-700"><?= scan_value(ucwords(str_replace('_', ' ', $scan['scan_status']))) ?></span>
                </div>
                <dl class="mt-7 grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <div><dt class="text-slate-500">Result</dt><dd class="mt-1 font-semibold text-slate-900"><?= scan_value($scan['scan_result']) ?></dd></div>
                    <div><dt class="text-slate-500">Risk Level</dt><dd class="mt-1 font-semibold text-slate-900"><?= scan_value($scan['risk_level']) ?></dd></div>
                    <div><dt class="text-slate-500">Safety Indicator</dt><dd class="mt-1 font-semibold text-slate-900"><?= $scan['safety_percentage'] === null ? 'Not available' : scan_value(number_format((float) $scan['safety_percentage'], 2) . '%') ?></dd></div>
                    <div><dt class="text-slate-500">File Size</dt><dd class="mt-1 font-semibold text-slate-900"><?= scan_value(scanner_format_size((int) $scan['file_size'])) ?></dd></div>
                    <div><dt class="text-slate-500">File Type</dt><dd class="mt-1 break-words font-semibold text-slate-900"><?= scan_value($scan['mime_type']) ?></dd></div>
                    <div><dt class="text-slate-500">Scan Date</dt><dd class="mt-1 font-semibold text-slate-900"><?= scan_value($scan['updated_at']) ?></dd></div>
                    <div><dt class="text-slate-500">Malicious</dt><dd class="mt-1 font-semibold text-red-700"><?= scan_value($scan['malicious_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Suspicious</dt><dd class="mt-1 font-semibold text-amber-700"><?= scan_value($scan['suspicious_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Harmless</dt><dd class="mt-1 font-semibold text-emerald-700"><?= scan_value($scan['harmless_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Undetected</dt><dd class="mt-1 font-semibold text-slate-700"><?= scan_value($scan['undetected_count']) ?></dd></div>
                    <div><dt class="text-slate-500">Total Engines</dt><dd class="mt-1 font-semibold text-slate-900"><?= scan_value($scan['total_engines']) ?></dd></div>
                    <div><dt class="text-slate-500">Detection Count</dt><dd class="mt-1 font-semibold text-slate-900"><?= scan_value($scan['detection_count']) ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-slate-500">SHA-256 Hash</dt><dd class="mt-1 break-all font-mono text-xs text-blue-700"><?= scan_value($scan['sha256_hash']) ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-slate-500">Threat Information</dt><dd class="mt-1 text-slate-700"><?= scan_value($scan['threat_name']) ?></dd></div>
                    <div class="sm:col-span-2 lg:col-span-3"><dt class="text-slate-500">Analysis Summary</dt><dd class="mt-1 text-slate-700"><?= scan_value($scan['scan_summary']) ?></dd></div>
                </dl>
                <p class="mt-7 text-xs text-slate-500">The safety indicator is calculated by MalDetect from VirusTotal engine statistics; it is not an official VirusTotal safety score.</p>
            </section>
        <?php endif; ?>
    </main>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
