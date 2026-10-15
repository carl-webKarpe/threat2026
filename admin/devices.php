<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_once __DIR__ . '/../config/agents.php';
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
unset($_SESSION['device_token_flash']);

$devices = [];
try {
    $devices = $pdo->query(
        "SELECT devices.id, devices.name, devices.hostname, devices.os_info, devices.agent_version, devices.token_prefix,
                devices.is_active, devices.last_seen_at, devices.last_ip, devices.created_at,
                devices.last_seen_at >= DATE_SUB(NOW(), INTERVAL " . AGENT_ONLINE_WINDOW . " SECOND) AS is_online,
                (SELECT COUNT(*) FROM device_detections WHERE device_id = devices.id) AS detection_count,
                (SELECT COUNT(*) FROM device_detections WHERE device_id = devices.id AND scan_result IN ('MALICIOUS', 'SUSPICIOUS')) AS threat_count
         FROM devices ORDER BY devices.created_at DESC"
    )->fetchAll();
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    $error = $error ?: 'Devices are unavailable. Run database/migrations/phase9_devices.sql first.';
}

$serverUrl = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off' ? 'https' : 'http')
    . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . rtrim(dirname(dirname((string) $_SERVER['SCRIPT_NAME'])), '/\\');
$h = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
$pageTitle = 'Devices';
$currentPage = 'devices';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
	<div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
	<main class="min-w-0 flex-1 p-6 sm:p-10">
		<p class="mono text-xs tracking-[.2em] text-violet-300">ENDPOINT AGENTS</p>
		<h1 class="mt-3 text-3xl font-bold">Devices</h1>
		<p class="mt-2 max-w-3xl text-slate-400">Register each PC or laptop, then run the MalDetect agent on it with the device token. The agent reports every downloaded file and MalDetect checks it with VirusTotal.</p>

		<?php if ($error !== ''): ?><p class="mt-6 rounded-xl border border-red-300/20 bg-red-400/10 px-4 py-3 text-sm text-red-200" role="alert"><?= $h($error) ?></p><?php endif; ?>

		<?php if (is_array($newToken)): ?>
			<section class="mt-6 rounded-2xl border border-emerald-300/30 bg-emerald-300/[.06] p-6">
				<p class="mono text-xs tracking-[.18em] text-emerald-300">DEVICE TOKEN FOR <?= $h(strtoupper($newToken['name'])) ?></p>
				<p class="mt-2 text-sm text-slate-300">Copy it now. It is shown only once; if it is lost, use "New token".</p>
				<pre class="mt-4 overflow-x-auto rounded-xl bg-slate-950/80 p-4 font-mono text-xs text-emerald-200"><?= $h($newToken['token']) ?></pre>
				<p class="mt-4 text-sm text-slate-400">Agent config (<code>agent/config.json</code> on that PC):</p>
				<pre class="mt-2 overflow-x-auto rounded-xl bg-slate-950/80 p-4 font-mono text-xs text-slate-200"><?= $h(json_encode(['server_url' => $serverUrl, 'device_token' => $newToken['token']], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
			</section>
		<?php endif; ?>

		<form method="post" class="mt-8 flex max-w-2xl flex-col gap-3 rounded-2xl border border-white/10 bg-white/[.03] p-5 sm:flex-row sm:items-end">
			<input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="action" value="register">
			<label class="flex-1 text-sm text-slate-400">Device name<input name="name" required maxlength="100" placeholder="Front desk laptop" class="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 outline-none focus:border-violet-300/50"></label>
			<button class="rounded-xl bg-violet-300 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-violet-200" type="submit">Register Device</button>
		</form>

		<div class="mt-8 overflow-x-auto rounded-2xl border border-white/10 bg-white/[.03]">
			<table class="w-full min-w-[980px] text-left text-sm">
				<thead class="border-b border-white/10 text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-5 py-4">Device</th><th class="px-5 py-4">Status</th><th class="px-5 py-4">Last Seen</th><th class="px-5 py-4">Downloads</th><th class="px-5 py-4">Threats</th><th class="px-5 py-4">Token</th><th class="px-5 py-4">Actions</th></tr></thead>
				<tbody class="divide-y divide-white/5">
				<?php foreach ($devices as $device): ?>
					<tr class="text-slate-300">
						<td class="px-5 py-4"><p class="font-semibold text-white"><?= $h($device['name']) ?></p><p class="mt-1 text-xs text-slate-500"><?= $h($device['hostname'] ?: 'Agent not connected yet') ?><?= $device['os_info'] ? ' · ' . $h($device['os_info']) : '' ?></p></td>
						<td class="px-5 py-4"><?php if (!(int) $device['is_active']): ?><span class="text-red-200">Disabled</span><?php elseif ((int) $device['is_online']): ?><span class="text-emerald-300">● Online</span><?php else: ?><span class="text-slate-500">○ Offline</span><?php endif; ?></td>
						<td class="whitespace-nowrap px-5 py-4 text-slate-400"><?= $h($device['last_seen_at'] ?: 'Never') ?><p class="text-xs text-slate-600"><?= $h($device['last_ip'] ?? '') ?></p></td>
						<td class="px-5 py-4"><a class="text-violet-300 hover:text-white" href="detections.php?device=<?= (int) $device['id'] ?>"><?= (int) $device['detection_count'] ?></a></td>
						<td class="px-5 py-4 <?= (int) $device['threat_count'] > 0 ? 'font-bold text-red-300' : 'text-slate-500' ?>"><?= (int) $device['threat_count'] ?></td>
						<td class="px-5 py-4 font-mono text-xs text-slate-500">mdt_<?= $h($device['token_prefix']) ?>…</td>
						<td class="px-5 py-4"><div class="flex gap-3">
							<form method="post"><input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $device['id'] ?>"><input type="hidden" name="action" value="toggle"><button class="<?= (int) $device['is_active'] ? 'text-red-200' : 'text-emerald-200' ?>"><?= (int) $device['is_active'] ? 'Disable' : 'Enable' ?></button></form>
							<form method="post" onsubmit="return confirm('Create a new token? The old token stops working immediately.')"><input type="hidden" name="csrf_token" value="<?= $h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $device['id'] ?>"><input type="hidden" name="action" value="rotate"><button class="text-violet-300 hover:text-white">New token</button></form>
						</div></td>
					</tr>
				<?php endforeach; ?>
				<?php if (!$devices): ?><tr><td colspan="7" class="px-5 py-12 text-center text-slate-500">No devices registered yet.</td></tr><?php endif; ?>
				</tbody>
			</table>
		</div>
	</main>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
