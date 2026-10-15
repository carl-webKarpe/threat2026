<?php

declare(strict_types=1);

// POST, JSON body:
// {"file_name": "setup.exe", "sha256": "<64 hex>", "file_size": 123, "file_path": "C:\\Users\\me\\Downloads\\setup.exe",
//  "source_url": "https://...", "referrer_url": "https://...", "downloaded_at": "2026-10-15T08:30:00Z"}
// Only file_name and sha256 are required. Header: X-Device-Token.
// Responds with the detection; when is_final is false, ask again with result.php?id=<id>.

require_once __DIR__ . '/../../config/agents.php';

agent_require_method('POST');

try {
    $pdo = database_connection();
    $device = agent_authenticate($pdo);
    $body = agent_json_body();

    $sha256 = strtolower(trim((string) ($body['sha256'] ?? '')));
    $fileName = agent_clean_text($body['file_name'] ?? null, 255);
    if (!preg_match('/^[a-f0-9]{64}$/', $sha256) || $fileName === null) {
        agent_json_response(['success' => false, 'message' => 'file_name and a 64-character sha256 are required.'], 422);
    }
    $fileSize = filter_var($body['file_size'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
    $downloadedAt = null;
    if (is_string($body['downloaded_at'] ?? null) && ($timestamp = strtotime($body['downloaded_at'])) !== false) {
        $downloadedAt = date('Y-m-d H:i:s', $timestamp);
    }

    $recent = $pdo->prepare(
        'SELECT COUNT(*) FROM device_detections WHERE device_id = :device_id AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)'
    );
    $recent->execute(['device_id' => $device['id']]);
    if ((int) $recent->fetchColumn() >= AGENT_MAX_REPORTS_PER_HOUR) {
        agent_json_response(['success' => false, 'message' => 'Too many reports from this device. Try again later.'], 429);
    }

    $insert = $pdo->prepare(
        'INSERT INTO device_detections (device_id, file_name, file_path, file_size, sha256_hash, source_url, referrer_url, downloaded_at)
         VALUES (:device_id, :file_name, :file_path, :file_size, :sha256_hash, :source_url, :referrer_url, :downloaded_at)'
    );
    $insert->execute([
        'device_id' => $device['id'],
        'file_name' => $fileName,
        'file_path' => agent_clean_text($body['file_path'] ?? null, 1024),
        'file_size' => is_int($fileSize) ? $fileSize : null,
        'sha256_hash' => $sha256,
        'source_url' => agent_clean_url($body['source_url'] ?? null),
        'referrer_url' => agent_clean_url($body['referrer_url'] ?? null),
        'downloaded_at' => $downloadedAt,
    ]);
    $detectionId = (int) $pdo->lastInsertId();

    $detection = agent_find_detection($pdo, $detectionId, (int) $device['id']);
    agent_refresh_detection($pdo, $detection, true);
    $detection = agent_find_detection($pdo, $detectionId, (int) $device['id']);
} catch (Throwable $exception) {
    error_log('Agent report failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

agent_json_response(['success' => true, 'detection' => agent_detection_payload($detection)], 201);
