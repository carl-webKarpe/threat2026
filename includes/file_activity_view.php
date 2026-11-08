<?php

declare(strict_types=1);

// File activity page, shared by admin/activity.php and superadmin/activity.php.
// Before including: $activitySidebar (sidebar file), $activityCanEdit (true shows the folder and ignore-list form; the page
// itself must handle that POST), optional $activityNotice / $activityError. Times are stored in UTC and shown in
// the server's time zone, with the UTC time on hover.

require_once __DIR__ . '/../config/agents.php';
require_once __DIR__ . '/../auth/csrf.php';

$activityCanEdit = (bool) ($activityCanEdit ?? false);
$activityNotice = (string) ($activityNotice ?? '');
$activityError = (string) ($activityError ?? '');

$deviceFilter = filter_input(INPUT_GET, 'device', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$typeFilter = (string) ($_GET['type'] ?? '');
$sourceFilter = (string) ($_GET['source'] ?? '');
$nameFilter = trim((string) ($_GET['name'] ?? ''));
$folderFilter = trim((string) ($_GET['folder'] ?? ''));
$fromFilter = (string) ($_GET['from'] ?? '');
$toFilter = (string) ($_GET['to'] ?? '');
$typeLabels = [
    'FILE_CREATED' => 'File created', 'FILE_MODIFIED' => 'File modified', 'FILE_DELETED' => 'File deleted',
    'FILE_RENAMED' => 'File renamed', 'FILE_MOVED' => 'File moved', 'FOLDER_CREATED' => 'Folder created',
    'FOLDER_DELETED' => 'Folder deleted', 'FOLDER_RENAMED' => 'Folder renamed', 'FOLDER_MOVED' => 'Folder moved',
];
$sourceLabels = ['realtime' => 'Real time', 'reconciliation' => 'Found later (reconciliation)'];
$timeSourceLabels = ['realtime' => 'reported by Windows', 'file_metadata' => 'file time stamp', 'recycle_bin' => 'Recycle Bin record'];

$localZone = new DateTimeZone(date_default_timezone_get());
$utcZone = new DateTimeZone('UTC');
/** UTC bound for a local date from the filter (start of the day, or start of the next day). */
$dateBound = static function (string $date, bool $endOfDay) use ($localZone, $utcZone): ?string {
    $day = DateTimeImmutable::createFromFormat('!Y-m-d', $date, $localZone);
    if ($day === false || $day->format('Y-m-d') !== $date) {
        return null;
    }
    return ($endOfDay ? $day->modify('+1 day') : $day)->setTimezone($utcZone)->format('Y-m-d H:i:s');
};
$likeValue = static fn (string $text): string => '%' . addcslashes($text, '\\%_') . '%';

$where = [];
$parameters = [];
if (is_int($deviceFilter)) {
    $where[] = 'file_activity_events.device_id = :device_id';
    $parameters['device_id'] = $deviceFilter;
}
if (in_array($typeFilter, AGENT_ACTIVITY_EVENT_TYPES, true)) {
    $where[] = 'file_activity_events.event_type = :event_type';
    $parameters['event_type'] = $typeFilter;
} else {
    $typeFilter = '';
}
if (isset($sourceLabels[$sourceFilter])) {
    $where[] = 'file_activity_events.source = :source';
    $parameters['source'] = $sourceFilter;
} else {
    $sourceFilter = '';
}
if ($nameFilter !== '') {
    $where[] = '(file_activity_events.old_name LIKE :name_old OR file_activity_events.new_name LIKE :name_new)';
    $parameters['name_old'] = $parameters['name_new'] = $likeValue(mb_substr($nameFilter, 0, 255));
}
if ($folderFilter !== '') {
    $where[] = '(file_activity_events.old_path LIKE :folder_old OR file_activity_events.new_path LIKE :folder_new)';
    $parameters['folder_old'] = $parameters['folder_new'] = $likeValue(mb_substr($folderFilter, 0, 1024));
}
if ($fromFilter !== '' && ($from = $dateBound($fromFilter, false)) !== null) {
    $where[] = 'file_activity_events.detected_at_utc >= :from_time';
    $parameters['from_time'] = $from;
} else {
    $fromFilter = '';
}
if ($toFilter !== '' && ($to = $dateBound($toFilter, true)) !== null) {
    $where[] = 'file_activity_events.detected_at_utc < :to_time';
    $parameters['to_time'] = $to;
} else {
    $toFilter = '';
}
$whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';

$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 50;
$activityEvents = [];
$activityDevices = [];
$selectedDevice = null;
$total = 0;
$pages = 1;
$loadError = false;

try {
    $pdo = database_connection();
    $activityDevices = $pdo->query('SELECT id, name, hostname, activity_folders, activity_status, activity_status_at FROM devices ORDER BY name')->fetchAll();
    foreach ($activityDevices as $device) {
        if ((int) $device['id'] === $deviceFilter) {
            $selectedDevice = $device;
        }
    }
    $count = $pdo->prepare('SELECT COUNT(*) FROM file_activity_events' . $whereSql);
    $count->execute($parameters);
    $total = (int) $count->fetchColumn();
    $pages = max(1, (int) ceil($total / $perPage));
    $page = min($page, $pages);
    $statement = $pdo->prepare(
        'SELECT file_activity_events.*, devices.name AS device_name, devices.hostname
         FROM file_activity_events INNER JOIN devices ON devices.id = file_activity_events.device_id' . $whereSql . '
         ORDER BY file_activity_events.detected_at_utc DESC, file_activity_events.id DESC LIMIT :limit OFFSET :offset'
    );
    foreach ($parameters as $name => $value) {
        $statement->bindValue(':' . $name, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
    }
    $statement->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $statement->bindValue(':offset', ($page - 1) * $perPage, PDO::PARAM_INT);
    $statement->execute();
    $activityEvents = $statement->fetchAll();
} catch (Throwable $exception) {
    error_log('File activity page: ' . $exception->getMessage());
    $loadError = true;
}

// For one PC: its ignore list, and where its events come from (busiest folders and file types), so noise from
// a program that writes many files can be found and ignored. Counts the latest events matching the filters.
$ignoreText = null;
$busyFolders = [];
$busyTypes = [];
$busySample = 0;
if (is_array($selectedDevice) && !$loadError) {
    try {
        $ignore = $pdo->prepare('SELECT activity_ignore FROM devices WHERE id = :id');
        $ignore->execute(['id' => $selectedDevice['id']]);
        $ignoreText = (string) ($ignore->fetchColumn() ?: '');
    } catch (PDOException $exception) {
        $ignoreText = null; // Phase 14 not installed yet
    }
    $sample = $pdo->prepare(
        'SELECT COALESCE(new_path, old_path) AS path, COALESCE(new_extension, old_extension) AS extension, is_directory
         FROM file_activity_events' . $whereSql . ' ORDER BY detected_at_utc DESC LIMIT 20000'
    );
    $sample->execute($parameters);
    foreach ($sample as $row) {
        $busySample++;
        $path = (string) $row['path'];
        $position = max((int) strrpos($path, '\\'), (int) strrpos($path, '/'));
        $folder = $position > 0 ? substr($path, 0, $position) : $path;
        $busyFolders[$folder] = ($busyFolders[$folder] ?? 0) + 1;
        if (!(int) $row['is_directory'] && $row['extension'] !== null) {
            $busyTypes[$row['extension']] = ($busyTypes[$row['extension']] ?? 0) + 1;
        }
    }
    arsort($busyFolders);
    arsort($busyTypes);
    $busyFolders = array_slice($busyFolders, 0, 8, true);
    $busyTypes = array_slice($busyTypes, 0, 8, true);
}

$h = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
/** Local time for display, from a UTC DATETIME(3) value. */
$localTime = static function (?string $utc) use ($localZone, $utcZone): string {
    if ($utc === null || $utc === '') {
        return '';
    }
    return (new DateTimeImmutable($utc, $utcZone))->setTimezone($localZone)->format('Y-m-d H:i:s');
};
$utcTitle = static fn (?string $utc): string => $utc ? $utc . ' UTC' : '';
$typeClass = static fn (string $type): string => match (substr($type, strpos($type, '_') + 1)) {
    'DELETED' => 'border-red-300/30 text-red-200',
    'RENAMED' => 'border-sky-300/30 text-sky-200',
    'MOVED' => 'border-violet-300/30 text-violet-200',
    'CREATED' => 'border-emerald-300/30 text-emerald-200',
    default => 'border-amber-300/30 text-amber-200',
};
$folderOf = static function (?string $path): string {
    if ($path === null) {
        return '';
    }
    $position = max((int) strrpos($path, '\\'), (int) strrpos($path, '/'));
    return $position > 0 ? substr($path, 0, $position) : '';
};
$query = array_filter([
    'device' => is_int($deviceFilter) ? (string) $deviceFilter : '', 'type' => $typeFilter, 'source' => $sourceFilter,
    'name' => $nameFilter, 'folder' => $folderFilter, 'from' => $fromFilter, 'to' => $toFilter,
], static fn (string $value): bool => $value !== '');
$pageUrl = static fn (int $number): string => 'activity.php?' . http_build_query($query + ['page' => $number]);
$folderStatus = is_array($selectedDevice) ? json_decode((string) ($selectedDevice['activity_status'] ?? ''), true) : null;
$statusClass = static fn (string $status): string => match ($status) {
    'watching' => 'text-emerald-300',
    'polling' => 'text-amber-200',
    default => 'text-red-300',
};
$inputClass = 'mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 outline-none focus:border-violet-300/50';

$pageTitle = 'File Activity';
$currentPage = 'activity';
require_once __DIR__ . '/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
	<div><?php require $activitySidebar; ?></div>
	<main class="min-w-0 flex-1 p-6 sm:p-10">
		<p class="mono text-xs tracking-[.2em] text-violet-300">ENDPOINT ACTIVITY</p>
		<div class="mt-3 flex flex-wrap items-baseline gap-4"><h1 class="text-3xl font-bold">File Activity</h1><span data-live-indicator class="text-xs text-emerald-300">● Live</span></div>
		<p class="mt-2 max-w-3xl text-slate-400">Files and folders created, modified, deleted, renamed or moved in the monitored folders of each device (Desktop, Documents, Downloads, Pictures, Videos, Music and extra folders). Only names, paths, sizes and times are recorded, never file contents. Times are shown in the server's time zone (<?= $h($localZone->getName()) ?>); hover a time for UTC.</p>

		<?php if ($activityNotice !== ''): ?><p class="mt-6 rounded-xl border border-emerald-300/20 bg-emerald-300/10 px-4 py-3 text-sm text-emerald-200" role="status"><?= $h($activityNotice) ?></p><?php endif; ?>
		<?php if ($activityError !== ''): ?><p class="mt-6 rounded-xl border border-red-300/20 bg-red-400/10 px-4 py-3 text-sm text-red-200" role="alert"><?= $h($activityError) ?></p><?php endif; ?>

		<form class="mt-8 grid gap-3 rounded-2xl border border-white/10 bg-white/[.03] p-5 sm:grid-cols-4" method="get">
			<label class="text-sm text-slate-400">Device (PC)<select class="<?= $inputClass ?>" name="device"><option value="">All</option><?php foreach ($activityDevices as $device): ?><option value="<?= (int) $device['id'] ?>" <?= $deviceFilter === (int) $device['id'] ? 'selected' : '' ?>><?= $h($device['name']) ?></option><?php endforeach; ?></select></label>
			<label class="text-sm text-slate-400">Event type<select class="<?= $inputClass ?>" name="type"><option value="">All</option><?php foreach ($typeLabels as $value => $label): ?><option value="<?= $h($value) ?>" <?= $typeFilter === $value ? 'selected' : '' ?>><?= $h($label) ?></option><?php endforeach; ?></select></label>
			<label class="text-sm text-slate-400">File name<input class="<?= $inputClass ?>" type="search" name="name" value="<?= $h($nameFilter) ?>" placeholder="e.g. report.docx"></label>
			<label class="text-sm text-slate-400">Folder path contains<input class="<?= $inputClass ?>" type="search" name="folder" value="<?= $h($folderFilter) ?>" placeholder="e.g. Documents\Projects"></label>
			<label class="text-sm text-slate-400">Detected from<input class="<?= $inputClass ?>" type="date" name="from" value="<?= $h($fromFilter) ?>"></label>
			<label class="text-sm text-slate-400">Detected to<input class="<?= $inputClass ?>" type="date" name="to" value="<?= $h($toFilter) ?>"></label>
			<label class="text-sm text-slate-400">Source<select class="<?= $inputClass ?>" name="source"><option value="">All</option><?php foreach ($sourceLabels as $value => $label): ?><option value="<?= $h($value) ?>" <?= $sourceFilter === $value ? 'selected' : '' ?>><?= $h($label) ?></option><?php endforeach; ?></select></label>
			<div class="flex items-end justify-end gap-3"><a class="rounded-xl border border-white/10 px-5 py-3 text-sm text-slate-300 hover:bg-white/5" href="activity.php">Clear</a><button class="rounded-xl bg-violet-300 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-violet-200" type="submit">Apply Filters</button></div>
		</form>

		<?php if (is_array($selectedDevice)): ?>
			<section class="mt-8 rounded-2xl border border-white/10 bg-white/[.03] p-5">
				<div data-live-region="activity-folders">
				<div class="flex flex-wrap items-baseline justify-between gap-3"><h2 class="text-lg font-semibold">Monitored folders on <?= $h($selectedDevice['name']) ?></h2><p class="text-xs text-slate-500"><?= $selectedDevice['activity_status_at'] ? 'Reported by the agent at ' . $h($selectedDevice['activity_status_at']) : 'The agent has not reported its folders yet (it needs agent version 1.4.0 or newer).' ?></p></div>
				<?php if (is_array($folderStatus)): ?>
					<p class="mt-2 text-sm text-slate-400">Mode: <span class="<?= ($folderStatus['mode'] ?? '') === 'realtime' ? 'text-emerald-300' : 'text-amber-200' ?>"><?= $h(['realtime' => 'Real time', 'polling' => 'Polling (watchdog not installed)', 'off' => 'Off'][$folderStatus['mode'] ?? 'off'] ?? 'Off') ?></span><?= isset($folderStatus['queued']) && (int) $folderStatus['queued'] > 0 ? ' · ' . (int) $folderStatus['queued'] . ' event(s) waiting to be sent' : '' ?></p>
					<?php if (!empty($folderStatus['message'])): ?><p class="mt-2 text-sm text-amber-200"><?= $h($folderStatus['message']) ?></p><?php endif; ?>
					<ul class="mt-4 grid gap-2 text-sm sm:grid-cols-2">
						<?php foreach ($folderStatus['folders'] ?? [] as $folder): ?>
							<li class="rounded-xl border border-white/5 bg-slate-950/40 px-4 py-3"><p><span class="font-semibold text-white"><?= $h($folder['label'] ?? '') ?></span> <span class="<?= $statusClass((string) ($folder['status'] ?? '')) ?>"><?= $h(ucfirst((string) ($folder['status'] ?? ''))) ?></span></p><p class="mt-1 break-all font-mono text-xs text-slate-500"><?= $h($folder['path'] ?? '') ?></p><?php if (!empty($folder['message'])): ?><p class="mt-1 text-xs text-amber-200"><?= $h($folder['message']) ?></p><?php endif; ?></li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
				</div>
				<?php if ($busySample > 0): ?>
					<div class="mt-5 grid gap-4 lg:grid-cols-2">
						<div><h3 class="text-sm font-semibold text-white">Busiest folders</h3><p class="text-xs text-slate-500">Where the latest <?= $busySample ?> matching event(s) of this PC happened.</p>
							<ul class="mt-2 grid gap-1 text-xs">
								<?php foreach ($busyFolders as $folder => $count): ?>
									<li class="flex items-center gap-3 rounded-lg bg-slate-950/40 px-3 py-2"><span class="w-14 shrink-0 text-right font-mono text-slate-300"><?= (int) $count ?></span><span class="min-w-0 flex-1 break-all font-mono text-slate-400"><?= $h($folder) ?></span><?php if ($activityCanEdit && $ignoreText !== null): ?><button type="button" class="shrink-0 text-amber-200 hover:text-white" data-ignore-add="<?= $h($folder) ?>">Ignore</button><?php endif; ?></li>
								<?php endforeach; ?>
							</ul>
						</div>
						<div><h3 class="text-sm font-semibold text-white">Busiest file types</h3><p class="text-xs text-slate-500">File extensions in the same events.</p>
							<ul class="mt-2 grid gap-1 text-xs">
								<?php foreach ($busyTypes as $extension => $count): ?>
									<li class="flex items-center gap-3 rounded-lg bg-slate-950/40 px-3 py-2"><span class="w-14 shrink-0 text-right font-mono text-slate-300"><?= (int) $count ?></span><span class="min-w-0 flex-1 font-mono text-slate-400">*.<?= $h($extension) ?></span><?php if ($activityCanEdit && $ignoreText !== null): ?><button type="button" class="shrink-0 text-amber-200 hover:text-white" data-ignore-add="*.<?= $h($extension) ?>">Ignore</button><?php endif; ?></li>
								<?php endforeach; ?>
								<?php if (!$busyTypes): ?><li class="px-3 py-2 text-slate-500">No files with an extension.</li><?php endif; ?>
							</ul>
						</div>
					</div>
				<?php endif; ?>
				<?php if ($activityCanEdit): ?>
					<form method="post" class="mt-5 grid gap-4 lg:grid-cols-2">
						<input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="action" value="save_folders"><input type="hidden" name="id" value="<?= (int) $selectedDevice['id'] ?>">
						<label class="text-sm text-slate-400">Extra folders to monitor on this PC (one full path per line, for example <code>D:\Lab\Projects</code> or <code>\\server\class</code>; at most <?= AGENT_MAX_EXTRA_FOLDERS ?>)<textarea name="folders" rows="4" class="<?= $inputClass ?> font-mono text-xs"><?= $h($selectedDevice['activity_folders'] ?? '') ?></textarea></label>
						<?php if ($ignoreText !== null): ?>
							<label class="text-sm text-slate-400">Ignore on this PC (one per line: a name such as <code>*.log</code> or <code>node_modules</code>, or a full folder path such as <code>C:\Users\me\Documents\Cache</code>; at most <?= AGENT_MAX_IGNORE_PATTERNS ?>)<textarea name="ignore" rows="4" class="<?= $inputClass ?> font-mono text-xs" data-ignore-list><?= $h($ignoreText) ?></textarea></label>
						<?php else: ?>
							<p class="text-sm text-amber-200">To ignore files and folders on this PC, run database/migrations/phase14_activity_ignore.sql first (SETUP-GUIDE.md, Change 20).</p>
						<?php endif; ?>
						<div class="lg:col-span-2"><button class="rounded-xl border border-violet-300/40 px-5 py-3 text-sm font-bold text-violet-200 hover:bg-violet-300/10" type="submit">Save Settings</button>
						<span class="ml-3 text-xs text-slate-500">The agent picks them up within a minute. Ignoring affects new events only; earlier events stay in the list.</span></div>
					</form>
					<script>
					document.addEventListener('click', (event) => {
						const button = event.target.closest('[data-ignore-add]');
						const list = document.querySelector('[data-ignore-list]');
						if (!button || !list) return;
						const lines = list.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
						if (!lines.includes(button.dataset.ignoreAdd)) lines.push(button.dataset.ignoreAdd);
						list.value = lines.join('\n');
						button.textContent = 'Added — click Save Settings';
						list.scrollIntoView({ behavior: 'smooth', block: 'center' });
					});
					</script>
				<?php elseif ($ignoreText !== null && trim($ignoreText) !== ''): ?>
					<div class="mt-5 text-sm text-slate-400">Ignored on this PC:<pre class="mt-2 whitespace-pre-wrap rounded-xl bg-slate-950/60 p-3 font-mono text-xs text-slate-300"><?= $h($ignoreText) ?></pre></div>
				<?php endif; ?>
			</section>
		<?php endif; ?>

		<div data-live-region="activity">
		<?php if ($loadError): ?>
			<div class="mt-8 rounded-2xl border border-red-300/20 bg-red-400/10 p-5 text-sm text-red-200">File activity is unavailable. Run database/migrations/phase13_file_activity.sql first (SETUP-GUIDE.md, Change 19).</div>
		<?php elseif (!$activityEvents): ?>
			<div class="mt-10 rounded-2xl border border-white/10 bg-white/[.03] p-12 text-center text-slate-500"><?= $query ? 'No file activity matches these filters.' : 'No file activity has been reported yet.' ?></div>
		<?php else: ?>
			<div class="mt-8 overflow-x-auto rounded-2xl border border-white/10 bg-white/[.03]"><table class="w-full min-w-[1150px] text-left text-sm">
				<thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-5 py-4">Event</th><th class="px-5 py-4">File</th><th class="px-5 py-4">Device</th><th class="px-5 py-4">Happened</th><th class="px-5 py-4">Detected / Received</th></tr></thead>
				<tbody class="divide-y divide-white/5">
				<?php foreach ($activityEvents as $event): ?>
					<?php
                    $isChange = $event['old_path'] !== null && $event['new_path'] !== null && preg_match('/_(RENAMED|MOVED)$/', $event['event_type']) === 1;
                    $name = $isChange ? $event['old_name'] . ' → ' . $event['new_name'] : ($event['new_name'] ?? $event['old_name']);
                    $path = $isChange
                        ? ($folderOf($event['old_path']) === $folderOf($event['new_path']) ? $event['new_path'] : $event['old_path'] . ' → ' . $event['new_path'])
                        : ($event['new_path'] ?? $event['old_path']);
                    ?>
					<tr class="align-top text-slate-300" data-row-id="<?= (int) $event['id'] ?>">
						<td class="whitespace-nowrap px-5 py-4"><span class="rounded-full border px-2 py-0.5 font-mono text-[11px] <?= $typeClass($event['event_type']) ?>"><?= $h($event['event_type']) ?></span><?php if ($event['source'] === 'reconciliation'): ?><p class="mt-2 text-[11px] uppercase tracking-wider text-amber-200" title="Found by comparing the folder with the agent's saved file list, for example after the agent was off.">Found later</p><?php endif; ?></td>
						<td class="px-5 py-4"><p class="max-w-[420px] break-words font-semibold text-white"><?= $h($name) ?></p><p class="mt-1 max-w-[420px] break-all font-mono text-xs text-slate-500"><?= $h($path) ?></p><p class="mt-1 text-xs text-slate-500"><?= $h(implode(' · ', array_filter([$event['folder_label'], $event['file_size'] !== null ? scanner_format_size((int) $event['file_size']) : null, $event['user_account'] ? 'User ' . $event['user_account'] : null]))) ?></p><?php if ($event['details']): ?><p class="mt-1 max-w-[420px] text-xs text-slate-400"><?= $h($event['details']) ?></p><?php endif; ?></td>
						<td class="px-5 py-4"><?= $h($event['device_name']) ?><p class="mt-1 text-xs text-slate-500"><?= $h($event['hostname'] ?? '') ?></p></td>
						<td class="whitespace-nowrap px-5 py-4"><?php if ($event['event_time_utc'] !== null): ?><span title="<?= $h($utcTitle($event['event_time_utc'])) ?>"><?= $h($localTime($event['event_time_utc'])) ?></span><p class="text-xs text-slate-500"><?= $h($timeSourceLabels[$event['time_source']] ?? (string) $event['time_source']) ?></p><?php else: ?><span class="text-slate-400">Exact time unknown</span><p class="text-xs text-slate-500" title="<?= $h($utcTitle($event['window_start_utc']) . ' – ' . $utcTitle($event['detected_at_utc'])) ?>"><?= $event['window_start_utc'] ? 'between ' . $h($localTime($event['window_start_utc'])) . '<br>and ' . $h($localTime($event['detected_at_utc'])) : 'before ' . $h($localTime($event['detected_at_utc'])) ?></p><?php endif; ?></td>
						<td class="whitespace-nowrap px-5 py-4 text-xs text-slate-500"><span title="<?= $h($utcTitle($event['detected_at_utc'])) ?>">Agent: <?= $h($localTime($event['detected_at_utc'])) ?></span><br><span title="<?= $h($utcTitle($event['received_at_utc'])) ?>">Server: <?= $h($localTime($event['received_at_utc'])) ?></span></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table></div>
			<nav class="mt-6 flex items-center justify-between text-sm" aria-label="File activity pages"><span class="text-slate-500">Page <?= $page ?> of <?= $pages ?> (<?= $total ?> events)</span><div class="flex gap-2"><?php if ($page > 1): ?><a class="rounded-lg border border-white/10 px-3 py-2 text-slate-300" href="<?= $h($pageUrl($page - 1)) ?>">Previous</a><?php endif; ?><?php if ($page < $pages): ?><a class="rounded-lg border border-white/10 px-3 py-2 text-slate-300" href="<?= $h($pageUrl($page + 1)) ?>">Next</a><?php endif; ?></div></nav>
		<?php endif; ?>
		</div>
	</main>
</div>
<?php require __DIR__ . '/live_refresh.php'; ?>
<?php require_once __DIR__ . '/footer.php'; ?>
