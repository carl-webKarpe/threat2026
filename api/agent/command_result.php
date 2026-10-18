<?php

declare(strict_types=1);

// POST, JSON body: {"id": 5, "status": "completed" | "failed", "files_reported": 12, "message": "..."}
// Header: X-Device-Token. Reports the outcome of a command from commands.php.

require_once __DIR__ . '/../../config/agents.php';

agent_require_method('POST');

try {
    $pdo = database_connection();
    $device = agent_authenticate($pdo);
    $body = agent_json_body();

    $commandId = filter_var($body['id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    $status = (string) ($body['status'] ?? '');
    $filesReported = filter_var($body['files_reported'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
    if (!is_int($commandId) || !in_array($status, ['completed', 'failed'], true)) {
        agent_json_response(['success' => false, 'message' => 'id and a status of completed or failed are required.'], 422);
    }

    $update = $pdo->prepare(
        "UPDATE device_commands SET status = :status, files_reported = :files_reported, result_message = :message,
         completed_at = CURRENT_TIMESTAMP
         WHERE id = :id AND device_id = :device_id AND status IN ('pending', 'sent')"
    );
    $update->execute([
        'status' => $status,
        'files_reported' => is_int($filesReported) ? $filesReported : null,
        'message' => agent_clean_text($body['message'] ?? null, 255),
        'id' => $commandId,
        'device_id' => $device['id'],
    ]);
    if ($update->rowCount() === 0) {
        agent_json_response(['success' => false, 'message' => 'Command not found or already finished.'], 404);
    }
} catch (Throwable $exception) {
    error_log('Agent command result failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

agent_json_response(['success' => true]);
