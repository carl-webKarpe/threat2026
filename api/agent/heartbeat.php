<?php

declare(strict_types=1);

// POST, JSON body: {"hostname": "...", "os": "...", "agent_version": "..."}
// Header: X-Device-Token: <device token from Admin > Devices>

require_once __DIR__ . '/../../config/agents.php';

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
} catch (Throwable $exception) {
    error_log('Agent heartbeat failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

agent_json_response([
    'success' => true,
    'device' => ['id' => (int) $device['id'], 'name' => (string) $device['name']],
    'server_time' => gmdate('c'),
    'max_upload_bytes' => MAX_UPLOAD_SIZE,
]);
