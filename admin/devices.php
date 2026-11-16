<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_once __DIR__ . '/../config/agents.php';
require_once __DIR__ . '/../config/server.php';
require_role('admin');

$pdo = database_connection();
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $error = 'The request could not be verified. Please try again.';
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $deviceId = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        try {
            if ($action === 'register') {
                $name = trim((string) ($_POST['name'] ?? ''));
                if ($name === '' || mb_strlen($name) > 100) {
                    throw new InvalidArgumentException('Device name is required and must be 100 characters or fewer.');
                }
                $token = agent_generate_token();
                $insert = $pdo->prepare(
                    'INSERT INTO devices (name, token_hash, token_prefix, created_by) VALUES (:name, :token_hash, :token_prefix, :created_by)'
                );
                $insert->execute(['name' => $name, 'token_hash' => $token['hash'], 'token_prefix' => $token['prefix'], 'created_by' => current_user()['id']]);
                $_SESSION['device_token_flash'] = ['name' => $name, 'token' => $token['token']];
            } elseif ($action === 'toggle' && is_int($deviceId)) {
                $toggle = $pdo->prepare('UPDATE devices SET is_active = 1 - is_active WHERE id = :id');
                $toggle->execute(['id' => $deviceId]);
            } elseif ($action === 'rotate' && is_int($deviceId)) {
                $token = agent_generate_token();
                $rotate = $pdo->prepare('UPDATE devices SET token_hash = :token_hash, token_prefix = :token_prefix WHERE id = :id');
                $rotate->execute(['token_hash' => $token['hash'], 'token_prefix' => $token['prefix'], 'id' => $deviceId]);
                $name = $pdo->prepare('SELECT name FROM devices WHERE id = :id');
                $name->execute(['id' => $deviceId]);
                $_SESSION['device_token_flash'] = ['name' => (string) $name->fetchColumn(), 'token' => $token['token']];
            } elseif ($action === 'rename' && is_int($deviceId)) {
                // Only the label changes; the token stays the same, so the agent keeps working.
                $newName = trim((string) ($_POST['new_name'] ?? ''));
                if ($newName === '' || mb_strlen($newName) > 100) {
                    throw new InvalidArgumentException('Device name is required and must be 100 characters or fewer.');
                }
                $duplicate = $pdo->prepare('SELECT COUNT(*) FROM devices WHERE name = :name AND id <> :id');
                $duplicate->execute(['name' => $newName, 'id' => $deviceId]);
                if ((int) $duplicate->fetchColumn() > 0) {
                    throw new InvalidArgumentException('Another device already uses the name ' . $newName . '.');
                }
                $old = $pdo->prepare('SELECT name FROM devices WHERE id = :id');
                $old->execute(['id' => $deviceId]);
                $oldName = $old->fetchColumn();
                if ($oldName === false) {
                    throw new InvalidArgumentException('Device not found.');
                }
                $rename = $pdo->prepare('UPDATE devices SET name = :name WHERE id = :id');
                $rename->execute(['name' => $newName, 'id' => $deviceId]);
                $_SESSION['device_flash'] = 'Renamed ' . $oldName . ' to ' . $newName . '. Its token did not change.';
            } elseif ($action === 'delete' && is_int($deviceId)) {
                // Detections and scan commands of the device are removed with it (ON DELETE CASCADE).
                $device = $pdo->prepare('SELECT name FROM devices WHERE id = :id');
                $device->execute(['id' => $deviceId]);
                $name = $device->fetchColumn();
                if ($name === false) {
                    throw new InvalidArgumentException('Device not found.');
                }
                $delete = $pdo->prepare('DELETE FROM devices WHERE id = :id');
                $delete->execute(['id' => $deviceId]);
                $_SESSION['device_flash'] = 'Device ' . $name . ' and its detections were deleted. Its agent can no longer connect.';
            } elseif ($action === 'scan' && is_int($deviceId)) {
                $device = $pdo->prepare('SELECT name, is_active FROM devices WHERE id = :id');
                $device->execute(['id' => $deviceId]);
                $device = $device->fetch();
                if (!is_array($device) || (int) $device['is_active'] !== 1) {
                    throw new InvalidArgumentException('Only active devices can be scanned.');
                }
                $_SESSION['device_flash'] = agent_queue_command($pdo, $deviceId, 'scan_downloads', current_user()['id'])
                    ? 'Scan requested for ' . $device['name'] . '. It starts the next time the agent checks in (within seconds if the device is online).'
                    : 'A scan for ' . $device['name'] . ' is already waiting or running.';
            } elseif ($action === 'scan_all') {
                $online = $pdo->query(
                    'SELECT id FROM devices WHERE is_active = 1 AND ' . agent_online_sql()
                )->fetchAll(PDO::FETCH_COLUMN);
                $queued = 0;
                foreach ($online as $onlineId) {
                    $queued += agent_queue_command($pdo, (int) $onlineId, 'scan_downloads', current_user()['id']) ? 1 : 0;
                }
                $_SESSION['device_flash'] = $online
                    ? "Scan requested for {$queued} online device(s)." . ($queued < count($online) ? ' The others already have a scan waiting or running.' : '')
                    : 'No devices are online right now.';
            } else {
                throw new InvalidArgumentException('Invalid device action.');
            }
            header('Location: devices.php');
            exit;
        } catch (InvalidArgumentException $exception) {
            $error = $exception->getMessage();
        } catch (Throwable $exception) {
            error_log('Device action failed: ' . $exception->getMessage());
            $error = 'The device action could not be completed.';
        }
    }
}

// The token is shown exactly once, right after it is created.
$newToken = $_SESSION['device_token_flash'] ?? null;
$flash = (string) ($_SESSION['device_flash'] ?? '');
unset($_SESSION['device_token_flash'], $_SESSION['device_flash']);

$devices = [];
try {
    $devices = $pdo->query(
        "SELECT devices.id, devices.name, devices.hostname, devices.os_info, devices.agent_version, devices.token_prefix,
                devices.is_active, devices.last_seen_at, devices.last_ip, devices.created_at,
                " . agent_online_sql() . " AS is_online,
                (SELECT COUNT(*) FROM device_detections WHERE device_id = devices.id) AS detection_count,
                (SELECT COUNT(*) FROM device_detections WHERE device_id = devices.id AND scan_result IN ('MALICIOUS', 'SUSPICIOUS')) AS threat_count
         FROM devices ORDER BY devices.created_at DESC"
    )->fetchAll();
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    $error = $error ?: 'Devices are unavailable. Run the latest database migrations (see SETUP-GUIDE.md).';
}

// File activity per device, for the "File Activity" column. Needs the Phase 13 table and columns.
$activity = [];
try {
    $rows = $pdo->query(
        'SELECT devices.id, devices.activity_status,
                (SELECT COUNT(*) FROM file_activity_events WHERE device_id = devices.id) AS event_count
         FROM devices'
    )->fetchAll();
    foreach ($rows as $row) {
        $status = json_decode((string) ($row['activity_status'] ?? ''), true);
        $folders = is_array($status) ? ($status['folders'] ?? []) : [];
        $problems = count(array_filter($folders, static fn (array $folder): bool => !in_array($folder['status'] ?? '', ['watching', 'polling'], true)));
        $activity[(int) $row['id']] = [
            'events' => (int) $row['event_count'],
            'summary' => is_array($status)
                ? ($problems ? "{$problems} folder(s) not monitored" : count($folders) . ' folders') . (($status['mode'] ?? '') === 'polling' ? ' · polling' : '')
                : 'Not reported',
            'problem' => $problems > 0 || (is_array($status) && ($status['mode'] ?? '') !== 'realtime'),
        ];
    }
} catch (Throwable $exception) {
    error_log('File activity unavailable: ' . $exception->getMessage());
}

// Latest command per device, for the "Last Scan" column. Needs the Phase 10 tables.
$lastCommands = [];
$commandsAvailable = true;
try {
    $rows = $pdo->query(
        'SELECT device_commands.* FROM device_commands
         INNER JOIN (SELECT device_id, MAX(id) AS id FROM device_commands GROUP BY device_id) AS latest ON latest.id = device_commands.id'
    )->fetchAll();
    foreach ($rows as $row) {
        $lastCommands[(int) $row['device_id']] = $row;
    }
} catch (Throwable $exception) {
    error_log('Device commands unavailable: ' . $exception->getMessage());
    $commandsAvailable = false;
}

/** @param array<string, mixed>|null $command */
$scanStatus = static function (?array $command): array {
    if ($command === null) {
        return ['Never scanned', 'text-neutral-400', ''];
    }
    return match ($command['status']) {
        'pending' => ['Waiting for device…', 'text-amber-400', 'Requested ' . $command['created_at']],
        'sent' => ['Scanning…', 'text-accent-light', 'Started ' . $command['picked_up_at']],
        'completed' => ['Done · ' . (int) $command['files_reported'] . ' file(s)', 'text-emerald-400', (string) $command['completed_at']],
        'expired' => ['Expired', 'text-neutral-400', 'Device was offline'],
        default => ['Failed', 'text-red-400', (string) ($command['result_message'] ?? '')],
    };
};

// The address the monitored PCs use (config/server.php), not the one in this browser, which may be localhost.
$serverUrl = maldetect_server_url();
$h = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
$pageTitle = 'Devices';
$currentPage = 'devices';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
	<div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
	<main class="min-w-0 flex-1 p-6 sm:p-10">
		<p class="text-[11px] font-medium uppercase tracking-[.3em] text-accent-light">ENDPOINT AGENTS</p>
		<div class="mt-3 flex flex-wrap items-baseline gap-4"><h1 class="font-display text-2xl uppercase tracking-[.08em] text-white sm:text-3xl">Devices</h1><span data-live-indicator class="text-xs text-emerald-400">● Live</span></div>
		<p class="mt-2 max-w-3xl text-neutral-400">Register each PC or laptop, then run the JunMalware agent on it with the device token. The agent reports every downloaded file and JunMalware checks it with VirusTotal.</p>

		<?php if ($flash !== ''): ?><p class="mt-6 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400" role="status"><?= $h($flash) ?></p><?php endif; ?>
		<?php if (!$commandsAvailable): ?><p class="mt-6 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-400">"Scan now" needs the Phase 10 tables. Run database/migrations/phase10_device_scans.sql.</p><?php endif; ?>
		<?php if ($error !== ''): ?><p class="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400" role="alert"><?= $h($error) ?></p><?php endif; ?>

		<?php if (is_array($newToken)): ?>
			<section class="mt-6 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-6">
				<p class="text-xs font-semibold uppercase tracking-wider text-emerald-400">DEVICE TOKEN FOR <?= $h(strtoupper($newToken['name'])) ?></p>
				<p class="mt-2 text-sm text-neutral-300">Copy it now. It is shown only once; if it is lost, use "New token".</p>
				<pre class="mt-4 overflow-x-auto rounded-lg bg-panel2 p-4 font-mono text-xs text-emerald-400"><?= $h($newToken['token']) ?></pre>
				<p class="mt-4 text-sm text-neutral-400">Install command (on that PC, in PowerShell as Administrator, inside the copied <code>dist</code> folder):</p>
				<pre class="mt-2 overflow-x-auto rounded-lg bg-panel2 p-4 font-mono text-xs text-neutral-100">powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -ServerUrl <?= $h($serverUrl) ?> -Token <?= $h($newToken['token']) ?></pre>
				<p class="mt-4 text-sm text-neutral-400">Or the agent config (<code>config.json</code> on that PC, when the agent runs with Python):</p>
				<pre class="mt-2 overflow-x-auto rounded-lg bg-panel2 p-4 font-mono text-xs text-neutral-100"><?= $h(json_encode(['server_url' => $serverUrl, 'device_token' => $newToken['token']], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
			</section>
		<?php endif; ?>

		<form method="post" class="mt-8 flex max-w-2xl flex-col gap-3 rounded-xl border border-white/10 bg-panel shadow-sm p-5 sm:flex-row sm:items-end">
			<input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="action" value="register">
			<label class="flex-1 text-sm text-neutral-400">Device name<input name="name" required maxlength="100" placeholder="Front desk laptop" class="mt-2 w-full rounded-lg border border-white/15 bg-panel px-4 py-3 text-white outline-none focus:border-accent"></label>
			<button class="rounded-lg bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm hover:bg-accent-dark" type="submit">Register Device</button>
		</form>

		<?php if ($commandsAvailable && $devices): ?>
		<form method="post" class="mt-6" onsubmit="return confirm('Scan the Downloads folder of every online device?')">
			<input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="action" value="scan_all">
			<button class="rounded-lg border border-accent/60 px-5 py-3 text-sm font-bold text-accent-light hover:bg-accent/15" type="submit">Scan All Online Devices</button>
		</form>
		<?php endif; ?>

		<div class="mt-8 overflow-x-auto rounded-xl border border-white/10 bg-panel shadow-sm" data-live-region="devices">
			<table class="w-full min-w-[1320px] text-left text-sm">
				<thead class="border-b border-white/10 text-xs uppercase tracking-wider text-neutral-400"><tr><th class="px-5 py-4">Device</th><th class="px-5 py-4">Status</th><th class="px-5 py-4">Last Seen</th><th class="px-5 py-4">Downloads</th><th class="px-5 py-4">Threats</th><th class="px-5 py-4">Last Scan</th><th class="px-5 py-4">File Activity</th><th class="px-5 py-4">Token</th><th class="px-5 py-4">Actions</th></tr></thead>
				<tbody class="divide-y divide-white/5">
				<?php foreach ($devices as $device): ?>
					<tr class="text-neutral-300" data-row-id="<?= (int) $device['id'] ?>">
						<td class="px-5 py-4"><p class="font-semibold text-white"><?= $h($device['name']) ?></p><p class="mt-1 text-xs text-neutral-400"><?= $h($device['hostname'] ?: 'Agent not connected yet') ?><?= $device['os_info'] ? ' · ' . $h($device['os_info']) : '' ?></p></td>
						<td class="px-5 py-4"><?php if (!(int) $device['is_active']): ?><span class="text-red-400">Disabled</span><?php elseif ((int) $device['is_online']): ?><span class="text-emerald-400">● Online</span><?php else: ?><span class="text-neutral-400">○ Offline</span><?php endif; ?></td>
						<td class="whitespace-nowrap px-5 py-4 text-neutral-400"><?= $h($device['last_seen_at'] ?: 'Never') ?><p class="text-xs text-neutral-500"><?= $h($device['last_ip'] ?? '') ?></p></td>
						<td class="px-5 py-4"><a class="text-accent-light hover:text-white" href="detections.php?device=<?= (int) $device['id'] ?>"><?= (int) $device['detection_count'] ?></a></td>
						<td class="px-5 py-4 <?= (int) $device['threat_count'] > 0 ? 'font-bold text-red-400' : 'text-neutral-400' ?>"><?= (int) $device['threat_count'] ?></td>
						<?php [$scanLabel, $scanClass, $scanDetail] = $scanStatus($lastCommands[(int) $device['id']] ?? null); ?>
						<td class="whitespace-nowrap px-5 py-4"><span class="<?= $scanClass ?>"><?= $h($scanLabel) ?></span><p class="max-w-[200px] truncate text-xs text-neutral-500" title="<?= $h($scanDetail) ?>"><?= $h($scanDetail) ?></p></td>
						<?php $deviceActivity = $activity[(int) $device['id']] ?? null; ?>
						<td class="px-5 py-4"><?php if ($deviceActivity === null): ?><span class="text-xs text-neutral-500">Run phase13 migration</span><?php else: ?><a class="whitespace-nowrap text-accent-light hover:text-white" href="activity.php?device=<?= (int) $device['id'] ?>"><?= $deviceActivity['events'] ?> events</a><p class="max-w-[150px] text-xs <?= $deviceActivity['problem'] ? 'text-amber-400' : 'text-neutral-500' ?>"><?= $h($deviceActivity['summary']) ?></p><?php endif; ?></td>
						<td class="px-5 py-4 font-mono text-xs text-neutral-400">mdt_<?= $h($device['token_prefix']) ?>…</td>
						<td class="px-5 py-4"><div class="flex flex-wrap gap-3">
							<?php if ($commandsAvailable && (int) $device['is_active']): ?><form method="post"><input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $device['id'] ?>"><input type="hidden" name="action" value="scan"><button class="font-semibold text-emerald-400 hover:text-white">Scan Downloads</button></form><?php endif; ?>
							<form method="post"><input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $device['id'] ?>"><input type="hidden" name="action" value="toggle"><button class="<?= (int) $device['is_active'] ? 'text-red-400' : 'text-emerald-400' ?>"><?= (int) $device['is_active'] ? 'Disable' : 'Enable' ?></button></form>
							<form method="post" onsubmit="return confirm('Create a new token? The old token stops working immediately.')"><input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $device['id'] ?>"><input type="hidden" name="action" value="rotate"><button class="text-accent-light hover:text-white">New token</button></form>
							<form method="post" data-device-name="<?= $h($device['name']) ?>" onsubmit="const name = window.prompt('New name for ' + this.dataset.deviceName + ':', this.dataset.deviceName); if (name === null || name.trim() === '' || name.trim() === this.dataset.deviceName) return false; this.elements.new_name.value = name.trim(); return true;"><input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $device['id'] ?>"><input type="hidden" name="action" value="rename"><input type="hidden" name="new_name" value=""><button class="text-sky-400 hover:text-white">Rename</button></form>
							<form method="post" onsubmit="return confirm(<?= $h(json_encode('Delete ' . $device['name'] . '? This also deletes its ' . (int) $device['detection_count'] . ' detection(s), scan history and file activity. This cannot be undone.')) ?>)"><input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $device['id'] ?>"><input type="hidden" name="action" value="delete"><button class="text-red-400 hover:text-red-300">Delete</button></form>
						</div></td>
					</tr>
				<?php endforeach; ?>
				<?php if (!$devices): ?><tr><td colspan="9" class="px-5 py-12 text-center text-neutral-400">No devices registered yet.</td></tr><?php endif; ?>
				</tbody>
			</table>
		</div>
	</main>
</div>
<?php require __DIR__ . '/../includes/live_refresh.php'; ?>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
