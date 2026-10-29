<?php

declare(strict_types=1);

// POST multipart/form-data: detection_id=<id>, file=<the downloaded file>. Header: X-Device-Token.
// Only accepted when the detection status is "not_found" (VirusTotal has never seen the file).
// The file is forwarded to VirusTotal, then deleted from this server.

require_once __DIR__ . '/../../config/agents.php';

agent_require_method('POST');

try {
    $pdo = database_connection();
    $device = agent_authenticate($pdo);
} catch (Throwable $exception) {
    error_log('Agent upload authentication failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

$detectionId = filter_input(INPUT_POST, 'detection_id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$file = $_FILES['file'] ?? null;
if (!is_int($detectionId) || !is_array($file) || (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
    agent_json_response(['success' => false, 'message' => 'detection_id and a successfully uploaded file are required.'], 422);
}
$temporaryPath = (string) ($file['tmp_name'] ?? '');
$fileSize = (int) ($file['size'] ?? 0);
if (!is_uploaded_file($temporaryPath) || $fileSize < 1 || $fileSize > MAX_UPLOAD_SIZE) {
    agent_json_response(['success' => false, 'message' => 'The file is empty or larger than ' . scanner_format_size(MAX_UPLOAD_SIZE) . '.'], 413);
}

$detection = agent_find_detection($pdo, $detectionId, (int) $device['id']);
if ($detection === null) {
    agent_json_response(['success' => false, 'message' => 'Detection not found.'], 404);
}
if ($detection['scan_status'] !== 'not_found') {
    agent_json_response(['success' => true, 'detection' => agent_detection_payload($detection)]);
}
if (!hash_equals((string) $detection['sha256_hash'], (string) hash_file('sha256', $temporaryPath))) {
    agent_json_response(['success' => false, 'message' => 'The uploaded file does not match the reported SHA-256.'], 422);
}

if (!virustotal_reserve_request($pdo)) {
    agent_json_response(['success' => false, 'message' => 'VirusTotal request limit reached. Try again later.', 'retryable' => true], 429);
}

try {
    $uploadDirectory = scanner_upload_directory();
} catch (RuntimeException $exception) {
    error_log('Upload storage misconfigured: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server upload storage is not configured correctly (MALDETECT_UPLOAD_DIR).'], 500);
}
$storedPath = $uploadDirectory . DIRECTORY_SEPARATOR . bin2hex(random_bytes(32)) . '.bin';
try {
    if (!is_dir($uploadDirectory)) {
        mkdir($uploadDirectory, 0750, true);
    }
    if (!move_uploaded_file($temporaryPath, $storedPath)) {
        throw new RuntimeException('The uploaded file could not be stored.');
    }
    $mimeType = (new finfo(FILEINFO_MIME_TYPE))->file($storedPath) ?: 'application/octet-stream';
    $response = virustotal_upload($storedPath, (string) $detection['file_name'], $mimeType);
    $analysisId = $response['data']['id'] ?? null;
    if (!is_string($analysisId) || $analysisId === '') {
        throw new RuntimeException('VirusTotal did not return an analysis ID.');
    }
    $update = $pdo->prepare(
        "UPDATE device_detections SET scan_status = 'analyzing', analysis_id = :analysis_id, scan_result = NULL, risk_level = NULL,
         scan_summary = 'Uploaded to VirusTotal; waiting for the analysis.', checked_at = CURRENT_TIMESTAMP, lookup_attempts = 0
         WHERE id = :id"
    );
    $update->execute(['analysis_id' => $analysisId, 'id' => $detectionId]);
} catch (Throwable $exception) {
    if (is_file($storedPath)) {
        unlink($storedPath);
    }
    agent_log_virustotal_error('Agent file upload to VirusTotal failed', $exception);
    $isRateLimited = $exception instanceof VirusTotalApiException && $exception->httpStatus === 429;
    agent_json_response(
        ['success' => false, 'message' => $isRateLimited ? 'VirusTotal request limit reached. Try again later.' : 'Unable to start the malware analysis.', 'retryable' => agent_is_transient_error($exception)],
        $isRateLimited ? 429 : 502,
    );
}
if (is_file($storedPath)) {
    unlink($storedPath);
}

agent_json_response(['success' => true, 'detection' => agent_detection_payload(agent_find_detection($pdo, $detectionId, (int) $device['id']))]);
