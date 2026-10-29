<?php

declare(strict_types=1);

// POST, JSON body: {"hostname": "...", "os": "...", "agent_version": "...", "stopping": false}
// "stopping": true is sent once when the agent shuts down, so the device shows Offline right away.
// Optional "activity": {"mode": "realtime", "queued": 0, "folders": [{"label", "path", "status", "message"}]}
// is the file activity monitor's status; the response's "activity.extra_folders" lists the admin's extra folders.
// Header: X-Device-Token: <device token from Admin > Devices>

require_once __DIR__ . '/../../config/agents.php';

/**
 * Keeps only the expected, size-limited fields of the agent's file activity status.
 *
 * @param array<mixed> $activity
 * @return array<string, mixed>
 */
function heartbeat_activity_status(array $activity): array
{
    $folders = [];
    foreach (array_slice(is_array($activity['folders'] ?? null) ? $activity['folders'] : [], 0, 50) as $folder) {
        if (!is_array($folder)) {
            continue;
        }
        $status = (string) ($folder['status'] ?? '');
        $folders[] = [
            'label' => agent_clean_text($folder['label'] ?? null, 50),
            'path' => agent_clean_text($folder['path'] ?? null, 1024),
            'status' => in_array($status, ['watching', 'polling', 'unavailable', 'error'], true) ? $status : 'error',
            'message' => agent_clean_text($folder['message'] ?? null, 300),
        ];
    }
    $mode = (string) ($activity['mode'] ?? '');
    $queued = filter_var($activity['queued'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);

    return [
        'mode' => in_array($mode, ['realtime', 'polling', 'off'], true) ? $mode : 'off',
        'queued' => is_int($queued) ? $queued : null,
        'message' => agent_clean_text($activity['message'] ?? null, 300),
        'folders' => $folders,
    ];
}

agent_require_method('POST');

try {
    $pdo = database_connection();
    $device = agent_authenticate($pdo);
    $body = agent_json_body();
    $statement = $pdo->prepare(
        'UPDATE devices SET hostname = COALESCE(:hostname, hostname), os_info = COALESCE(:os_info, os_info),
         agent_version = COALESCE(:agent_version, agent_version) WHERE id = :id'
    );
    $statement->execute([
        'hostname' => agent_clean_text($body['hostname'] ?? null, 255),
        'os_info' => agent_clean_text($body['os'] ?? null, 255),
        'agent_version' => agent_clean_text($body['agent_version'] ?? null, 50),
        'id' => $device['id'],
    ]);
    if (($body['stopping'] ?? false) === true) {
        $stopped = $pdo->prepare('UPDATE devices SET agent_stopped_at = CURRENT_TIMESTAMP WHERE id = :id');
        $stopped->execute(['id' => $device['id']]);
    }

    $extraFolders = [];
    try {
        if (is_array($body['activity'] ?? null)) {
            $statusUpdate = $pdo->prepare(
                'UPDATE devices SET activity_status = :status, activity_status_at = CURRENT_TIMESTAMP WHERE id = :id'
            );
            $statusUpdate->execute([
                'status' => json_encode(heartbeat_activity_status($body['activity']), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                'id' => $device['id'],
            ]);
        }
        $folders = $pdo->prepare('SELECT activity_folders FROM devices WHERE id = :id');
        $folders->execute(['id' => $device['id']]);
        $extraFolders = agent_parse_extra_folders($folders->fetchColumn() ?: null);
    } catch (PDOException $exception) {
        // Database without the Phase 13 columns: file activity status is simply not stored.
    }
} catch (Throwable $exception) {
    error_log('Agent heartbeat failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

agent_json_response([
    'success' => true,
    'device' => ['id' => (int) $device['id'], 'name' => (string) $device['name']],
    'server_time' => gmdate('c'),
    'max_upload_bytes' => MAX_UPLOAD_SIZE,
    'activity' => ['extra_folders' => $extraFolders],
]);
