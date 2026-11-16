<?php
declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/scanner.php';
require_role('admin');

$search = trim((string) ($_GET['search'] ?? ''));
$status = trim((string) ($_GET['status'] ?? ''));
$risk = trim((string) ($_GET['risk'] ?? ''));
$allowedStatuses = ['queued', 'scanning', 'completed', 'failed'];
$allowedRisks = ['No Threat Detected', 'Suspicious', 'Malicious', 'Scan Failed', 'Unknown'];
$where = [];
$parameters = [];
$where[] = 'user_id = :user_id';
$parameters['user_id'] = current_user()['id'];
if ($search !== '') {
	$where[] = 'original_filename LIKE :search';
	$parameters['search'] = '%' . $search . '%';
}
if (in_array($status, $allowedStatuses, true)) {
	$where[] = 'scan_status = :status';
	$parameters['status'] = $status;
}
if (in_array($risk, $allowedRisks, true)) {
	$where[] = 'risk_level = :risk';
	$parameters['risk'] = $risk;
}
$whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 10;
$scans = [];
$total = 0;
$historyError = false;

try {
	$pdo = database_connection();
	$countStatement = $pdo->prepare('SELECT COUNT(*) FROM scans' . $whereSql);
	$countStatement->execute($parameters);
	$total = (int) $countStatement->fetchColumn();
	$pages = max(1, (int) ceil($total / $perPage));
	$page = min($page, $pages);
	$offset = ($page - 1) * $perPage;
	$statement = $pdo->prepare(
		'SELECT id, original_filename, file_size, mime_type, sha256_hash, scan_status, scan_result,
				risk_level, detection_count, created_at
		 FROM scans' . $whereSql . ' ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset'
	);
	foreach ($parameters as $name => $value) {
		$statement->bindValue(':' . $name, $value, PDO::PARAM_STR);
	}
	$statement->bindValue(':limit', $perPage, PDO::PARAM_INT);
	$statement->bindValue(':offset', $offset, PDO::PARAM_INT);
	$statement->execute();
	$scans = $statement->fetchAll();
} catch (Throwable $exception) {
	error_log($exception->getMessage());
	$pages = 1;
	$historyError = true;
}

$query = ['search' => $search, 'status' => $status, 'risk' => $risk];
$queryString = http_build_query(array_filter($query, static fn (string $value): bool => $value !== ''));
$pageUrl = static function (int $number) use ($queryString): string {
	return 'history.php?' . ($queryString !== '' ? $queryString . '&' : '') . 'page=' . $number;
};
$pageTitle = 'Scan History';
$currentPage = 'history';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
	<div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
	<main class="min-w-0 flex-1 p-6 sm:p-10">
		<p class="text-xs font-semibold uppercase tracking-wider text-blue-700">AUDIT TRAIL</p>
		<h1 class="mt-3 text-3xl font-bold tracking-tight text-slate-900">Scan History</h1>
		<p class="mt-2 text-slate-500">Real VirusTotal analysis records and engine results.</p>
		<form class="mt-8 grid gap-3 rounded-xl border border-slate-200 bg-white shadow-sm p-5 sm:grid-cols-4" method="get">
			<label class="text-sm text-slate-500 sm:col-span-2">Search filename<input class="mt-2 w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 outline-none focus:border-blue-500" type="search" name="search" value="<?= htmlspecialchars($search, ENT_QUOTES, 'UTF-8') ?>" placeholder="pizza.jpg"></label>
			<label class="text-sm text-slate-500">Status<select class="mt-2 w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 outline-none focus:border-blue-500" name="status"><option value="">All</option><?php foreach ($allowedStatuses as $option): ?><option value="<?= htmlspecialchars($option, ENT_QUOTES, 'UTF-8') ?>" <?= $status === $option ? 'selected' : '' ?>><?= htmlspecialchars(ucfirst($option), ENT_QUOTES, 'UTF-8') ?></option><?php endforeach; ?></select></label>
			<label class="text-sm text-slate-500">Risk<select class="mt-2 w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 outline-none focus:border-blue-500" name="risk"><option value="">All</option><?php foreach ($allowedRisks as $option): ?><option value="<?= htmlspecialchars($option, ENT_QUOTES, 'UTF-8') ?>" <?= $risk === $option ? 'selected' : '' ?>><?= htmlspecialchars($option, ENT_QUOTES, 'UTF-8') ?></option><?php endforeach; ?></select></label>
			<button class="rounded-lg bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 sm:col-span-4 sm:justify-self-end" type="submit">Apply Filters</button>
		</form>
		<?php if ($historyError): ?>
			<div class="mt-8 rounded-xl border border-red-200 bg-red-50 p-5 text-sm text-red-700">Scan history is temporarily unavailable.</div>
		<?php elseif (!$scans): ?>
			<div class="mt-10 rounded-xl border border-slate-200 bg-white shadow-sm p-12 text-center text-slate-500">No scan records match these filters.</div>
		<?php else: ?>
			<div class="mt-8 overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm"><table class="w-full min-w-[980px] text-left text-sm"><thead class="border-b border-slate-200 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-5 py-4">ID</th><th class="px-5 py-4">File</th><th class="px-5 py-4">Type</th><th class="px-5 py-4">Result</th><th class="px-5 py-4">Status</th><th class="px-5 py-4">SHA-256</th><th class="px-5 py-4">Scan Date</th><th class="px-5 py-4">Action</th></tr></thead><tbody class="divide-y divide-slate-100">
			<?php foreach ($scans as $scan): ?><tr class="text-slate-700"><td class="px-5 py-4 text-slate-500">#<?= (int) $scan['id'] ?></td><td class="px-5 py-4"><p class="max-w-[180px] truncate font-semibold text-slate-900"><?= htmlspecialchars($scan['original_filename'], ENT_QUOTES, 'UTF-8') ?></p><p class="mt-1 text-xs text-slate-500"><?= htmlspecialchars(scanner_format_size((int) $scan['file_size']), ENT_QUOTES, 'UTF-8') ?></p></td><td class="px-5 py-4 text-slate-500"><?= htmlspecialchars($scan['mime_type'], ENT_QUOTES, 'UTF-8') ?></td><td class="px-5 py-4"><p class="font-semibold text-slate-900"><?= htmlspecialchars((string) ($scan['scan_result'] ?: 'Not available'), ENT_QUOTES, 'UTF-8') ?></p><p class="mt-1 text-xs text-slate-500"><?= htmlspecialchars((string) ($scan['risk_level'] ?: 'Pending'), ENT_QUOTES, 'UTF-8') ?></p></td><td class="px-5 py-4 text-amber-700"><?= htmlspecialchars(ucfirst($scan['scan_status']), ENT_QUOTES, 'UTF-8') ?></td><td class="max-w-[170px] truncate px-5 py-4 font-mono text-xs text-blue-700"><?= htmlspecialchars($scan['sha256_hash'], ENT_QUOTES, 'UTF-8') ?></td><td class="whitespace-nowrap px-5 py-4 text-slate-500"><?= htmlspecialchars($scan['created_at'], ENT_QUOTES, 'UTF-8') ?></td><td class="px-5 py-4"><a class="text-blue-700 hover:text-blue-700" href="view_scan.php?id=<?= (int) $scan['id'] ?>">View Result</a></td></tr><?php endforeach; ?>
			</tbody></table></div>
			<?php if ($pages > 1): ?><nav class="mt-6 flex items-center justify-between text-sm" aria-label="Scan history pages"><span class="text-slate-500">Page <?= $page ?> of <?= $pages ?> (<?= $total ?> scans)</span><div class="flex gap-2"><?php if ($page > 1): ?><a class="rounded-lg border border-slate-200 px-3 py-2 text-slate-700 hover:border-blue-300" href="<?= htmlspecialchars($pageUrl($page - 1), ENT_QUOTES, 'UTF-8') ?>">Previous</a><?php endif; ?><?php if ($page < $pages): ?><a class="rounded-lg border border-slate-200 px-3 py-2 text-slate-700 hover:border-blue-300" href="<?= htmlspecialchars($pageUrl($page + 1), ENT_QUOTES, 'UTF-8') ?>">Next</a><?php endif; ?></div></nav><?php endif; ?>
		<?php endif; ?>
	</main>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
