<?php

declare(strict_types=1);

// GET. Header: X-Device-Token.
// Returns the commands an admin queued for this device (for example "Scan now") and marks them as sent.
// Response: {"success": true, "commands": [{"id": 5, "type": "scan_downloads"}]}

require_once __DIR__ . '/../../config/agents.php';

agent_require_method('GET');

try {
    $pdo = database_connection();
    $device = agent_authenticate($pdo);

    $pdo->beginTransaction();
    $expire = $pdo->prepare(
        "UPDATE device_commands SET status = 'expired', completed_at = CURRENT_TIMESTAMP,
         result_message = 'The device did not pick up the command in time.'
         WHERE device_id = :device_id AND status = 'pending'
           AND created_at < DATE_SUB(NOW(), INTERVAL " . AGENT_COMMAND_EXPIRY_HOURS . " HOUR)"
    );
    $expire->execute(['device_id' => $device['id']]);

    $pending = $pdo->prepare(
        "SELECT id, command_type FROM device_commands
         WHERE device_id = :device_id AND status = 'pending' ORDER BY id LIMIT 5 FOR UPDATE"
    );
    $pending->execute(['device_id' => $device['id']]);
    $commands = $pending->fetchAll();

    $markSent = $pdo->prepare("UPDATE device_commands SET status = 'sent', picked_up_at = CURRENT_TIMESTAMP WHERE id = :id");
    foreach ($commands as $command) {
        $markSent->execute(['id' => $command['id']]);
    }
    $pdo->commit();
} catch (Throwable $exception) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Agent command fetch failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

agent_json_response([
    'success' => true,
    'commands' => array_map(
        static fn (array $command): array => ['id' => (int) $command['id'], 'type' => (string) $command['command_type']],
        $commands,
    ),
]);
