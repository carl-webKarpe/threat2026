<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/agents.php';
require_role('admin');

$deviceFilter = filter_input(INPUT_GET, 'device', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$resultFilter = trim((string) ($_GET['result'] ?? ''));
$search = trim((string) ($_GET['search'] ?? ''));
$allowedResults = ['MALICIOUS' => 'Malicious', 'SUSPICIOUS' => 'Suspicious', 'NO_THREAT_DETECTED' => 'No Threat Detected', 'UNKNOWN' => 'Unknown to VirusTotal', 'SCAN_FAILED' => 'Scan Failed', 'PENDING' => 'Pending'];

$where = [];
$parameters = [];
if (is_int($deviceFilter)) {
    $where[] = 'device_detections.device_id = :device_id';
    $parameters['device_id'] = $deviceFilter;
}
if ($resultFilter === 'PENDING') {
    $where[] = "device_detections.scan_status IN ('pending', 'analyzing')";
} elseif (array_key_exists($resultFilter, $allowedResults)) {
    $where[] = 'device_detections.scan_result = :result';
    $parameters['result'] = $resultFilter;
}
if ($search !== '') {
    $where[] = '(device_detections.file_name LIKE :search OR device_detections.sha256_hash = :sha256)';
    $parameters['search'] = '%' . $search . '%';
    $parameters['sha256'] = strtolower($search);
}
$whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 25;
$detections = [];
$devices = [];
$total = 0;
$pages = 1;
$loadError = false;

try {
    $pdo = database_connection();
    $devices = $pdo->query('SELECT id, name FROM devices ORDER BY name')->fetchAll();
    $count = $pdo->prepare('SELECT COUNT(*) FROM device_detections' . $whereSql);
    $count->execute($parameters);
    $total = (int) $count->fetchColumn();
    $pages = max(1, (int) ceil($total / $perPage));
    $page = min($page, $pages);
    $statement = $pdo->prepare(
        'SELECT device_detections.*, devices.name AS device_name, devices.hostname
         FROM device_detections INNER JOIN devices ON devices.id = device_detections.device_id' . $whereSql . '
         ORDER BY device_detections.created_at DESC, device_detections.id DESC LIMIT :limit OFFSET :offset'
    );
    foreach ($parameters as $name => $value) {
        $statement->bindValue(':' . $name, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
    }
    $statement->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $statement->bindValue(':offset', ($page - 1) * $perPage, PDO::PARAM_INT);
    $statement->execute();
    $detections = $statement->fetchAll();
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    $loadError = true;
}

$query = array_filter(['device' => is_int($deviceFilter) ? (string) $deviceFilter : '', 'result' => $resultFilter, 'search' => $search], static fn (string $value): bool => $value !== '');
$pageUrl = static fn (int $number): string => 'detections.php?' . http_build_query($query + ['page' => $number]);
$h = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
$resultClass = static fn (?string $result): string => match ($result) {
    'MALICIOUS' => 'text-red-300',
    'SUSPICIOUS' => 'text-amber-300',
    'NO_THREAT_DETECTED' => 'text-emerald-300',
    default => 'text-slate-300',
};
$pageTitle = 'Device Detections';
$currentPage = 'detections';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
	<div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
	<main class="min-w-0 flex-1 p-6 sm:p-10">
		<p class="mono text-xs tracking-[.2em] text-violet-300">ENDPOINT ACTIVITY</p>
		<h1 class="mt-3 text-3xl font-bold">Device Detections</h1>
		<p class="mt-2 text-slate-400">Files downloaded on registered devices and their VirusTotal verdicts.</p>
		<form class="mt-8 grid gap-3 rounded-2xl border border-white/10 bg-white/[.03] p-5 sm:grid-cols-4" method="get">
			<label class="text-sm text-slate-400 sm:col-span-2">File name or SHA-256<input class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 outline-none focus:border-violet-300/50" type="search" name="search" value="<?= $h($search) ?>"></label>
			<label class="text-sm text-slate-400">Device<select class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100" name="device"><option value="">All</option><?php foreach ($devices as $device): ?><option value="<?= (int) $device['id'] ?>" <?= $deviceFilter === (int) $device['id'] ? 'selected' : '' ?>><?= $h($device['name']) ?></option><?php endforeach; ?></select></label>
			<label class="text-sm text-slate-400">Result<select class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100" name="result"><option value="">All</option><?php foreach ($allowedResults as $value => $label): ?><option value="<?= $h($value) ?>" <?= $resultFilter === $value ? 'selected' : '' ?>><?= $h($label) ?></option><?php endforeach; ?></select></label>
			<button class="rounded-xl bg-violet-300 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-violet-200 sm:col-span-4 sm:justify-self-end" type="submit">Apply Filters</button>
		</form>
		<?php if ($loadError): ?>
			<div class="mt-8 rounded-2xl border border-red-300/20 bg-red-400/10 p-5 text-sm text-red-200">Detections are unavailable. Run database/migrations/phase9_devices.sql first.</div>
		<?php elseif (!$detections): ?>
			<div class="mt-10 rounded-2xl border border-white/10 bg-white/[.03] p-12 text-center text-slate-500">No downloads have been reported yet.</div>
		<?php else: ?>
			<div class="mt-8 overflow-x-auto rounded-2xl border border-white/10 bg-white/[.03]"><table class="w-full min-w-[1100px] text-left text-sm">
				<thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-5 py-4">File</th><th class="px-5 py-4">Device</th><th class="px-5 py-4">Source</th><th class="px-5 py-4">Result</th><th class="px-5 py-4">Engines</th><th class="px-5 py-4">Reported</th><th class="px-5 py-4">VirusTotal</th></tr></thead>
				<tbody class="divide-y divide-white/5">
				<?php foreach ($detections as $detection): ?>
					<tr class="text-slate-300">
						<td class="px-5 py-4"><p class="max-w-[220px] truncate font-semibold text-white" title="<?= $h($detection['file_path'] ?? $detection['file_name']) ?>"><?= $h($detection['file_name']) ?></p><p class="mt-1 text-xs text-slate-500"><?= $detection['file_size'] === null ? '' : $h(scanner_format_size((int) $detection['file_size'])) ?></p></td>
						<td class="px-5 py-4"><?= $h($detection['device_name']) ?><p class="mt-1 text-xs text-slate-500"><?= $h($detection['hostname'] ?? '') ?></p></td>
						<td class="max-w-[220px] truncate px-5 py-4 text-xs text-slate-400" title="<?= $h($detection['source_url'] ?? '') ?>"><?= $h($detection['source_url'] ?: 'Unknown') ?></td>
						<td class="px-5 py-4"><p class="font-semibold <?= $resultClass($detection['scan_result']) ?>"><?= $h($detection['risk_level'] ?: ucfirst((string) $detection['scan_status'])) ?></p><p class="mt-1 max-w-[220px] truncate text-xs text-slate-500"><?= $h($detection['threat_name'] ?? '') ?></p></td>
						<td class="whitespace-nowrap px-5 py-4 text-slate-400"><?= $detection['total_engines'] === null ? '—' : (int) $detection['detection_count'] . ' / ' . (int) $detection['total_engines'] ?></td>
						<td class="whitespace-nowrap px-5 py-4 text-slate-500"><?= $h($detection['created_at']) ?></td>
						<td class="px-5 py-4"><a class="font-mono text-xs text-violet-300 hover:text-white" href="https://www.virustotal.com/gui/file/<?= $h($detection['sha256_hash']) ?>" target="_blank" rel="noopener noreferrer"><?= $h(substr($detection['sha256_hash'], 0, 12)) ?>…</a></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table></div>
			<?php if ($pages > 1): ?><nav class="mt-6 flex items-center justify-between text-sm" aria-label="Detection pages"><span class="text-slate-500">Page <?= $page ?> of <?= $pages ?> (<?= $total ?> downloads)</span><div class="flex gap-2"><?php if ($page > 1): ?><a class="rounded-lg border border-white/10 px-3 py-2 text-slate-300" href="<?= $h($pageUrl($page - 1)) ?>">Previous</a><?php endif; ?><?php if ($page < $pages): ?><a class="rounded-lg border border-white/10 px-3 py-2 text-slate-300" href="<?= $h($pageUrl($page + 1)) ?>">Next</a><?php endif; ?></div></nav><?php endif; ?>
		<?php endif; ?>
	</main>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
