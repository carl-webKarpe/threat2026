<?php

declare(strict_types=1);

// GET result.php?id=<detection id>. Header: X-Device-Token.
// Checks VirusTotal again when due (at most once per SCANNER_STATUS_CHECK_INTERVAL seconds per detection).

require_once __DIR__ . '/../../config/agents.php';

agent_require_method('GET');

$detectionId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
if (!is_int($detectionId)) {
    agent_json_response(['success' => false, 'message' => 'Invalid detection identifier.'], 422);
}

try {
    $pdo = database_connection();
    $device = agent_authenticate($pdo);
    $detection = agent_find_detection($pdo, $detectionId, (int) $device['id']);
    if ($detection === null) {
        agent_json_response(['success' => false, 'message' => 'Detection not found.'], 404);
    }
    agent_refresh_detection($pdo, $detection);
    $detection = agent_find_detection($pdo, $detectionId, (int) $device['id']);
} catch (Throwable $exception) {
    error_log('Agent result lookup failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

agent_json_response(['success' => true, 'detection' => agent_detection_payload($detection)]);
