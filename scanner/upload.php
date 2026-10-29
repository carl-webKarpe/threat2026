<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/scanner.php';
require_once __DIR__ . '/../config/virustotal.php';

function scanner_json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

require_role('admin');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    scanner_json_response(['success' => false, 'message' => 'Only file uploads are accepted.'], 405);
}

if (!verify_csrf_token($_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['csrf_token'] ?? null)) {
    scanner_json_response(['success' => false, 'message' => 'Your session has expired. Refresh the page and try again.'], 419);
}

if (($_POST['privacy_acknowledged'] ?? '') !== '1') {
    scanner_json_response(['success' => false, 'message' => 'Please acknowledge that this file will be submitted to VirusTotal.'], 422);
}

if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
    scanner_json_response(['success' => false, 'message' => 'Please select a file.'], 422);
}

$file = $_FILES['file'];
$uploadErrors = [
    UPLOAD_ERR_INI_SIZE => 'The file exceeds the server upload limit.',
    UPLOAD_ERR_FORM_SIZE => 'The file exceeds the maximum allowed size.',
    UPLOAD_ERR_PARTIAL => 'The upload was interrupted. Please try again.',
    UPLOAD_ERR_NO_FILE => 'Please select a file.',
    UPLOAD_ERR_NO_TMP_DIR => 'The upload service is temporarily unavailable.',
    UPLOAD_ERR_CANT_WRITE => 'The file could not be stored.',
    UPLOAD_ERR_EXTENSION => 'The upload was blocked by a server extension.',
];
$uploadError = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);
if ($uploadError !== UPLOAD_ERR_OK) {
    scanner_json_response(['success' => false, 'message' => $uploadErrors[$uploadError] ?? 'The upload failed.'], 422);
}

$temporaryPath = (string) ($file['tmp_name'] ?? '');
$fileSize = (int) ($file['size'] ?? 0);
$originalFilename = basename((string) ($file['name'] ?? ''));
$extension = strtolower((string) pathinfo($originalFilename, PATHINFO_EXTENSION));

if ($originalFilename === '' || strlen($originalFilename) > 255) {
    scanner_json_response(['success' => false, 'message' => 'The file name is invalid or too long.'], 422);
}
if ($fileSize < 1 || $fileSize > MAX_UPLOAD_SIZE) {
    scanner_json_response(['success' => false, 'message' => 'File size exceeds the maximum allowed size of ' . scanner_format_size(MAX_UPLOAD_SIZE) . '.'], 422);
}
if (!in_array($extension, scanner_allowed_extensions(), true) || !is_uploaded_file($temporaryPath)) {
    scanner_json_response(['success' => false, 'message' => 'This file type is not supported.'], 422);
}

$fileInfo = new finfo(FILEINFO_MIME_TYPE);
$mimeType = $fileInfo->file($temporaryPath);
if (!is_string($mimeType) || !in_array($mimeType, ALLOWED_FILE_TYPES[$extension], true)) {
    scanner_json_response(['success' => false, 'message' => 'The file content does not match a supported file type.'], 422);
}

$hash = hash_file('sha256', $temporaryPath);
if (!is_string($hash)) {
    scanner_json_response(['success' => false, 'message' => 'The file could not be fingerprinted.'], 422);
}

try {
    $pdo = database_connection();
    $activeScan = $pdo->prepare(
        'SELECT id, original_filename, file_size, mime_type, sha256_hash, scan_status
         FROM scans
         WHERE user_id = :user_id AND sha256_hash = :sha256_hash AND scan_status IN (\'queued\', \'scanning\')
         ORDER BY id DESC LIMIT 1'
    );
    $activeScan->execute(['user_id' => current_user()['id'], 'sha256_hash' => $hash]);
    $existingScan = $activeScan->fetch();
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    scanner_json_response(['success' => false, 'message' => 'The scan service is temporarily unavailable.'], 500);
}
if (is_array($existingScan)) {
    scanner_json_response([
        'success' => true,
        'message' => 'An active scan already exists for this file.',
        'scan' => [
            'id' => (int) $existingScan['id'],
            'filename' => (string) $existingScan['original_filename'],
            'size' => scanner_format_size((int) $existingScan['file_size']),
            'mime_type' => (string) $existingScan['mime_type'],
            'sha256' => (string) $existingScan['sha256_hash'],
            'status' => (string) $existingScan['scan_status'],
        ],
    ]);
}

$existingReport = null;
try {
    $report = virustotal_file_report($hash);
    $reportAttributes = $report['data']['attributes'] ?? null;
    if (is_array($reportAttributes) && is_array($reportAttributes['last_analysis_stats'] ?? null)) {
        $existingReport = $reportAttributes;
    }
} catch (VirusTotalApiException $exception) {
    if ($exception->httpStatus !== 404) {
        error_log(sprintf(
            'VirusTotal hash lookup failed: HTTP %d; API code: %s; API message: %s; cURL error: %s',
            $exception->httpStatus,
            $exception->apiCode ?: 'none',
            $exception->apiMessage ?: $exception->getMessage(),
            $exception->curlMessage ?: 'none',
        ));
        scanner_json_response([
            'success' => false,
            'message' => 'Unable to check whether VirusTotal already has this file.',
            'http_status' => $exception->httpStatus,
        ], $exception->httpStatus === 429 ? 429 : 502);
    }
}

$storedFilename = bin2hex(random_bytes(32)) . '.' . $extension;
try {
    $uploadDirectory = scanner_upload_directory();
} catch (RuntimeException $exception) {
    error_log('Upload storage misconfigured: ' . $exception->getMessage());
    scanner_json_response(['success' => false, 'message' => 'The upload storage is not configured correctly. Ask the administrator to check MALDETECT_UPLOAD_DIR.'], 500);
}
$storedPath = $uploadDirectory . DIRECTORY_SEPARATOR . $storedFilename;
$createdDirectory = false;

try {
    if (!is_dir($uploadDirectory)) {
        $createdDirectory = mkdir($uploadDirectory, 0750, true);
    }
    if (!is_dir($uploadDirectory) || !is_writable($uploadDirectory) || !move_uploaded_file($temporaryPath, $storedPath)) {
        scanner_json_response(['success' => false, 'message' => 'The file could not be stored.'], 500);
    }
    if (!file_exists($storedPath) || !is_readable($storedPath)) {
        scanner_json_response(['success' => false, 'message' => 'The stored file could not be read.'], 500);
    }

    $statement = $pdo->prepare(
        'INSERT INTO scans (user_id, original_filename, stored_filename, file_size, mime_type, sha256_hash, scan_status)
         VALUES (:user_id, :original_filename, :stored_filename, :file_size, :mime_type, :sha256_hash, :scan_status)'
    );
    $statement->execute([
        'user_id' => current_user()['id'],
        'original_filename' => $originalFilename,
        'stored_filename' => $storedFilename,
        'file_size' => $fileSize,
        'mime_type' => $mimeType,
        'sha256_hash' => $hash,
        'scan_status' => 'queued',
    ]);

    $scanId = (int) $pdo->lastInsertId();
    try {
        if ($existingReport !== null) {
            $interpreted = scanner_interpret_analysis($existingReport);
            $update = $pdo->prepare(
                'UPDATE scans SET scan_status = :scan_status, scan_result = :scan_result, threat_name = :threat_name,
                 safety_percentage = :safety_percentage, risk_level = :risk_level,
                 detection_count = :detection_count, malicious_count = :malicious_count, suspicious_count = :suspicious_count,
                 harmless_count = :harmless_count, undetected_count = :undetected_count, total_engines = :total_engines,
                 scan_summary = :scan_summary WHERE id = :id AND user_id = :user_id'
            );
            $update->execute([
                'scan_status' => 'completed',
                'scan_result' => $interpreted['scan_result'],
                'threat_name' => $interpreted['threat_name'],
                'safety_percentage' => $interpreted['safety_percentage'],
                'risk_level' => $interpreted['risk_level'],
                'detection_count' => $interpreted['detection_count'],
                'malicious_count' => $interpreted['malicious_count'],
                'suspicious_count' => $interpreted['suspicious_count'],
                'harmless_count' => $interpreted['harmless_count'],
                'undetected_count' => $interpreted['undetected_count'],
                'total_engines' => $interpreted['total_engines'],
                'scan_summary' => $interpreted['scan_summary'],
                'id' => $scanId,
                'user_id' => current_user()['id'],
            ]);
        } else {
            $analysisResponse = virustotal_upload($storedPath, $originalFilename, $mimeType);
            $analysisId = $analysisResponse['data']['id'] ?? null;
            if (!is_string($analysisId) || $analysisId === '') {
                throw new RuntimeException('VirusTotal did not return an analysis ID.');
            }

            $update = $pdo->prepare(
                'UPDATE scans SET analysis_id = :analysis_id, scan_status = :scan_status WHERE id = :id AND user_id = :user_id'
            );
            $update->execute([
                'analysis_id' => $analysisId,
                'scan_status' => 'scanning',
                'id' => $scanId,
                'user_id' => current_user()['id'],
            ]);
        }
    } catch (Throwable $apiException) {
        try {
            $failed = $pdo->prepare('UPDATE scans SET scan_status = :scan_status, scan_result = :scan_result, risk_level = :risk_level, scan_summary = :scan_summary WHERE id = :id');
            $failed->execute([
                'scan_status' => 'failed',
                'scan_result' => 'SCAN_FAILED',
                'risk_level' => 'Scan Failed',
                'scan_summary' => 'Malware analysis could not be started.',
                'id' => $scanId,
            ]);
        } catch (Throwable $databaseException) {
            error_log($databaseException->getMessage());
        }
        if ($apiException instanceof VirusTotalApiException) {
            error_log(sprintf(
                'VirusTotal upload failed: HTTP %d; API code: %s; API message: %s; cURL error: %s',
                $apiException->httpStatus,
                $apiException->apiCode ?: 'none',
                $apiException->apiMessage ?: $apiException->getMessage(),
                $apiException->curlMessage ?: 'none',
            ));
        } else {
            error_log($apiException->getMessage());
        }
        if (is_file($storedPath)) {
            unlink($storedPath);
        }
        $response = [
            'success' => false,
            'message' => 'Unable to start the malware analysis. Please try again.',
        ];
        scanner_json_response($response, 502);
    }

    // VirusTotal now holds the file (or already had it), so the local copy is no longer needed.
    if (is_file($storedPath)) {
        unlink($storedPath);
    }
} catch (Throwable $exception) {
    if (is_file($storedPath)) {
        unlink($storedPath);
    }
    if ($createdDirectory && is_dir($uploadDirectory) && count(scandir($uploadDirectory)) === 2) {
        rmdir($uploadDirectory);
    }
    error_log($exception->getMessage());
    scanner_json_response(['success' => false, 'message' => 'The file was uploaded but could not be recorded.'], 500);
}

scanner_json_response([
    'success' => true,
    'message' => 'File uploaded successfully.',
    'scan' => [
        'id' => $scanId,
        'filename' => $originalFilename,
        'size' => scanner_format_size($fileSize),
        'mime_type' => $mimeType,
        'sha256' => $hash,
        'status' => $existingReport !== null ? 'completed' : 'scanning',
    ],
]);