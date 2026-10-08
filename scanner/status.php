<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/scanner.php';
require_once __DIR__ . '/../config/virustotal.php';

function scanner_status_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

require_role('admin');

$scanId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
if (!is_int($scanId)) {
    scanner_status_response(['success' => false, 'message' => 'Invalid scan identifier.'], 422);
}

$userId = current_user()['id'];
try {
    $pdo = database_connection();
    $statement = $pdo->prepare(
        'SELECT id, original_filename, file_size, mime_type, sha256_hash, scan_status, analysis_id,
            threat_name, safety_percentage, risk_level, detection_count, malicious_count, suspicious_count,
            harmless_count, undetected_count, total_engines, scan_result, scan_summary, created_at, updated_at
         FROM scans WHERE id = :id AND user_id = :user_id LIMIT 1'
    );
    $statement->execute(['id' => $scanId, 'user_id' => $userId]);
    $scan = $statement->fetch();
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    scanner_status_response(['success' => false, 'message' => 'Scan status is temporarily unavailable.'], 500);
}

if (!$scan) {
    scanner_status_response(['success' => false, 'message' => 'Scan not found.'], 404);
}

if ($scan['scan_status'] === 'scanning' && is_string($scan['analysis_id']) && $scan['analysis_id'] !== '') {
    try {
        $analysis = virustotal_analysis($scan['analysis_id']);
        $attributes = $analysis['data']['attributes'] ?? null;
        $apiStatus = is_array($attributes) ? (string) ($attributes['status'] ?? '') : '';

        if ($apiStatus === 'completed') {
            $interpreted = scanner_interpret_analysis(is_array($attributes) ? $attributes : []);
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
                'user_id' => $userId,
            ]);
            $scan = array_merge($scan, $interpreted, ['scan_status' => 'completed']);
        } elseif (in_array($apiStatus, ['queued', 'in-progress'], true)) {
            $scan['scan_status'] = 'scanning';
        } else {
            throw new RuntimeException('VirusTotal returned an unknown analysis status.');
        }
    } catch (Throwable $exception) {
        if ($exception instanceof VirusTotalApiException) {
            error_log(sprintf(
                'VirusTotal status check failed: HTTP %d; API code: %s; API message: %s; cURL error: %s',
                $exception->httpStatus,
                $exception->apiCode ?: 'none',
                $exception->apiMessage ?: $exception->getMessage(),
                $exception->curlMessage ?: 'none',
            ));
        } else {
            error_log($exception->getMessage());
        }
        $isRateLimited = $exception instanceof VirusTotalApiException && $exception->httpStatus === 429;
        $isTransient = !$exception instanceof VirusTotalApiException
            || $exception->httpStatus === 0
            || $exception->httpStatus === 408
            || $exception->httpStatus >= 500;
        if ($isRateLimited || $isTransient) {
            scanner_status_response([
                'success' => false,
                'message' => $isRateLimited
                    ? 'VirusTotal request limit reached. Please try again later.'
                    : 'Connection interrupted. Checking scan status...',
                'retryable' => !$isRateLimited,
            ], $isRateLimited ? 429 : 503);
        }
        try {
            $failed = $pdo->prepare(
                'UPDATE scans SET scan_status = :scan_status, scan_result = :scan_result, risk_level = :risk_level, scan_summary = :scan_summary WHERE id = :id AND user_id = :user_id'
            );
            $failed->execute([
                'scan_status' => 'failed',
                'scan_result' => 'SCAN_FAILED',
                'risk_level' => 'Scan Failed',
                'scan_summary' => 'Malware analysis could not be completed.',
                'id' => $scanId,
                'user_id' => $userId,
            ]);
        } catch (Throwable $databaseException) {
            error_log($databaseException->getMessage());
        }
        $scan['scan_status'] = 'failed';
        $scan['scan_summary'] = 'Unable to complete the malware analysis. Please try again.';
    }
}

scanner_status_response([
    'success' => true,
    'scan' => [
        'id' => (int) $scan['id'],
        'filename' => (string) $scan['original_filename'],
        'size' => scanner_format_size((int) $scan['file_size']),
        'mime_type' => (string) $scan['mime_type'],
        'sha256' => (string) $scan['sha256_hash'],
        'status' => (string) $scan['scan_status'],
        'result' => $scan['scan_result'] ?? null,
        'threat_name' => $scan['threat_name'] ?? null,
        'risk_level' => $scan['risk_level'] ?? null,
        'safety_percentage' => $scan['safety_percentage'] === null ? null : (float) $scan['safety_percentage'],
        'detection_count' => $scan['detection_count'] === null ? null : (int) $scan['detection_count'],
        'malicious_count' => $scan['malicious_count'] === null ? null : (int) $scan['malicious_count'],
        'suspicious_count' => $scan['suspicious_count'] === null ? null : (int) $scan['suspicious_count'],
        'harmless_count' => $scan['harmless_count'] === null ? null : (int) $scan['harmless_count'],
        'undetected_count' => $scan['undetected_count'] === null ? null : (int) $scan['undetected_count'],
        'total_engines' => $scan['total_engines'] === null ? null : (int) $scan['total_engines'],
        'summary' => (string) ($scan['scan_summary'] ?? ''),
        'scanned_at' => (string) $scan['updated_at'],
    ],
]);