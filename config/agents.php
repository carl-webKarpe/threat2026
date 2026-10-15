<?php

declare(strict_types=1);

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/scanner.php';
require_once __DIR__ . '/virustotal.php';

/** A device counts as online when it sent any request within this many seconds. */
const AGENT_ONLINE_WINDOW = 300;

/** Maximum file reports a single device may send per hour. */
const AGENT_MAX_REPORTS_PER_HOUR = 200;

/** Reuse a VirusTotal verdict for the same SHA-256 for this many hours instead of asking again. */
const AGENT_VERDICT_CACHE_HOURS = 24;

/** Give up on a pending lookup after this many failed VirusTotal attempts. */
const AGENT_MAX_LOOKUP_ATTEMPTS = 10;

/** Columns copied from scanner_interpret_analysis() into device_detections. */
const AGENT_VERDICT_COLUMNS = [
    'scan_result', 'risk_level', 'threat_name', 'safety_percentage', 'detection_count', 'malicious_count',
    'suspicious_count', 'harmless_count', 'undetected_count', 'total_engines', 'scan_summary',
];

/** @return array{token: string, hash: string, prefix: string} */
function agent_generate_token(): array
{
    $token = 'mdt_' . bin2hex(random_bytes(32));

    return ['token' => $token, 'hash' => hash('sha256', $token), 'prefix' => substr($token, 4, 8)];
}

function agent_json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

/** @return array<string, mixed> */
function agent_json_body(): array
{
    $body = json_decode((string) file_get_contents('php://input'), true);
    if (!is_array($body)) {
        agent_json_response(['success' => false, 'message' => 'Request body must be a JSON object.'], 400);
    }

    return $body;
}

function agent_require_method(string $method): void
{
    if ($_SERVER['REQUEST_METHOD'] !== $method) {
        agent_json_response(['success' => false, 'message' => 'Method not allowed.'], 405);
    }
}

/**
 * Authenticates the calling agent from the X-Device-Token header and records that it was seen.
 * A custom header is used because Apache often strips the Authorization header before PHP sees it.
 *
 * @return array<string, mixed>
 */
function agent_authenticate(PDO $pdo): array
{
    $token = trim((string) ($_SERVER['HTTP_X_DEVICE_TOKEN'] ?? ''));
    if ($token === '' || strlen($token) > 200) {
        agent_json_response(['success' => false, 'message' => 'Missing device token.'], 401);
    }

    $statement = $pdo->prepare('SELECT id, name, is_active FROM devices WHERE token_hash = :token_hash LIMIT 1');
    $statement->execute(['token_hash' => hash('sha256', $token)]);
    $device = $statement->fetch();
    if (!is_array($device) || (int) $device['is_active'] !== 1) {
        agent_json_response(['success' => false, 'message' => 'Invalid or disabled device token.'], 401);
    }

    $seen = $pdo->prepare('UPDATE devices SET last_seen_at = CURRENT_TIMESTAMP, last_ip = :ip WHERE id = :id');
    $seen->execute([
        'ip' => filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: null,
        'id' => $device['id'],
    ]);

    return $device;
}

function agent_clean_text(mixed $value, int $maxLength): ?string
{
    if (!is_string($value)) {
        return null;
    }
    $value = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? '');
    if ($value === '') {
        return null;
    }

    return mb_substr($value, 0, $maxLength);
}

function agent_clean_url(mixed $value): ?string
{
    $url = agent_clean_text($value, 2048);
    if ($url === null || !preg_match('#^(https?|ftp)://#i', $url)) {
        return null;
    }

    return $url;
}

/** @param array<string, mixed> $verdict */
function agent_store_verdict(PDO $pdo, int $detectionId, array $verdict): void
{
    $assignments = ['scan_status = \'completed\'', 'checked_at = CURRENT_TIMESTAMP'];
    $parameters = ['id' => $detectionId];
    foreach (AGENT_VERDICT_COLUMNS as $column) {
        $assignments[] = $column . ' = :' . $column;
        $parameters[$column] = $verdict[$column] ?? null;
    }
    $statement = $pdo->prepare('UPDATE device_detections SET ' . implode(', ', $assignments) . ' WHERE id = :id');
    $statement->execute($parameters);
}

/**
 * Finds a recent verdict for the same file from an earlier device detection or admin scan,
 * so repeated downloads of one file do not spend VirusTotal requests.
 *
 * @return array<string, mixed>|null
 */
function agent_cached_verdict(PDO $pdo, string $sha256, int $excludeDetectionId = 0): ?array
{
    $columns = implode(', ', AGENT_VERDICT_COLUMNS);
    $statement = $pdo->prepare(
        "SELECT {$columns} FROM device_detections
         WHERE sha256_hash = :sha256 AND scan_status = 'completed' AND id <> :exclude_id
           AND checked_at >= DATE_SUB(NOW(), INTERVAL " . AGENT_VERDICT_CACHE_HOURS . " HOUR)
         ORDER BY checked_at DESC LIMIT 1"
    );
    $statement->execute(['sha256' => $sha256, 'exclude_id' => $excludeDetectionId]);
    $verdict = $statement->fetch();
    if (is_array($verdict)) {
        return $verdict;
    }

    $statement = $pdo->prepare(
        "SELECT {$columns} FROM scans
         WHERE sha256_hash = :sha256 AND scan_status = 'completed'
           AND updated_at >= DATE_SUB(NOW(), INTERVAL " . AGENT_VERDICT_CACHE_HOURS . " HOUR)
         ORDER BY updated_at DESC LIMIT 1"
    );
    $statement->execute(['sha256' => $sha256]);
    $verdict = $statement->fetch();

    return is_array($verdict) ? $verdict : null;
}

function agent_is_transient_error(Throwable $exception): bool
{
    return !$exception instanceof VirusTotalApiException
        || $exception->httpStatus === 0
        || $exception->httpStatus === 408
        || $exception->httpStatus === 429
        || $exception->httpStatus >= 500;
}

function agent_log_virustotal_error(string $context, Throwable $exception): void
{
    if ($exception instanceof VirusTotalApiException) {
        error_log(sprintf(
            '%s: HTTP %d; API code: %s; API message: %s; cURL error: %s',
            $context,
            $exception->httpStatus,
            $exception->apiCode ?: 'none',
            $exception->apiMessage ?: $exception->getMessage(),
            $exception->curlMessage ?: 'none',
        ));
    } else {
        error_log($context . ': ' . $exception->getMessage());
    }
}

/**
 * Advances one detection by at most one VirusTotal request:
 * pending -> completed | not_found (hash lookup), analyzing -> completed (analysis check).
 * Calls are throttled per detection by SCANNER_STATUS_CHECK_INTERVAL.
 *
 * @param array<string, mixed> $detection Row with at least id, sha256_hash, scan_status, analysis_id, checked_at, lookup_attempts.
 */
function agent_refresh_detection(PDO $pdo, array $detection, bool $force = false): void
{
    $id = (int) $detection['id'];
    $status = (string) $detection['scan_status'];
    if (!in_array($status, ['pending', 'analyzing'], true)) {
        return;
    }
    $lastChecked = $detection['checked_at'] !== null ? strtotime((string) $detection['checked_at']) : 0;
    if (!$force && time() - (int) $lastChecked < SCANNER_STATUS_CHECK_INTERVAL) {
        return;
    }

    if ($status === 'pending') {
        $cached = agent_cached_verdict($pdo, (string) $detection['sha256_hash'], $id);
        if ($cached !== null) {
            agent_store_verdict($pdo, $id, $cached);
            return;
        }
    }

    $markChecked = $pdo->prepare(
        'UPDATE device_detections SET checked_at = CURRENT_TIMESTAMP, lookup_attempts = lookup_attempts + 1 WHERE id = :id'
    );
    $markChecked->execute(['id' => $id]);

    try {
        if ($status === 'pending') {
            $report = virustotal_file_report((string) $detection['sha256_hash']);
            $attributes = $report['data']['attributes'] ?? null;
            if (!is_array($attributes) || !is_array($attributes['last_analysis_stats'] ?? null)) {
                throw new RuntimeException('VirusTotal file report has no analysis statistics.');
            }
            agent_store_verdict($pdo, $id, scanner_interpret_analysis($attributes));
            return;
        }

        $analysis = virustotal_analysis((string) $detection['analysis_id']);
        $attributes = $analysis['data']['attributes'] ?? null;
        $apiStatus = is_array($attributes) ? (string) ($attributes['status'] ?? '') : '';
        if ($apiStatus === 'completed') {
            agent_store_verdict($pdo, $id, scanner_interpret_analysis($attributes));
        } elseif (!in_array($apiStatus, ['queued', 'in-progress'], true)) {
            throw new RuntimeException('VirusTotal returned an unknown analysis status.');
        }
    } catch (Throwable $exception) {
        if ($status === 'pending' && $exception instanceof VirusTotalApiException && $exception->httpStatus === 404) {
            $notFound = $pdo->prepare(
                "UPDATE device_detections SET scan_status = 'not_found', scan_result = 'UNKNOWN', risk_level = 'Unknown',
                 scan_summary = 'VirusTotal has no record of this file. Upload it for a full analysis.' WHERE id = :id"
            );
            $notFound->execute(['id' => $id]);
            return;
        }

        agent_log_virustotal_error('VirusTotal device detection check failed', $exception);
        $attempts = (int) $detection['lookup_attempts'] + 1;
        if (agent_is_transient_error($exception) && $attempts < AGENT_MAX_LOOKUP_ATTEMPTS) {
            return;
        }
        $failed = $pdo->prepare(
            "UPDATE device_detections SET scan_status = 'failed', scan_result = 'SCAN_FAILED', risk_level = 'Scan Failed',
             scan_summary = 'Malware analysis could not be completed.' WHERE id = :id"
        );
        $failed->execute(['id' => $id]);
    }
}

/** @return array<string, mixed>|null */
function agent_find_detection(PDO $pdo, int $detectionId, int $deviceId): ?array
{
    $statement = $pdo->prepare('SELECT * FROM device_detections WHERE id = :id AND device_id = :device_id LIMIT 1');
    $statement->execute(['id' => $detectionId, 'device_id' => $deviceId]);
    $detection = $statement->fetch();

    return is_array($detection) ? $detection : null;
}

/**
 * @param array<string, mixed> $detection
 * @return array<string, mixed>
 */
function agent_detection_payload(array $detection): array
{
    $status = (string) $detection['scan_status'];
    $result = $detection['scan_result'] ?? null;

    return [
        'id' => (int) $detection['id'],
        'file_name' => (string) $detection['file_name'],
        'sha256' => (string) $detection['sha256_hash'],
        'status' => $status,
        'result' => $result,
        'risk_level' => $detection['risk_level'] ?? null,
        'threat_name' => $detection['threat_name'] ?? null,
        'malicious_count' => $detection['malicious_count'] === null ? null : (int) $detection['malicious_count'],
        'suspicious_count' => $detection['suspicious_count'] === null ? null : (int) $detection['suspicious_count'],
        'total_engines' => $detection['total_engines'] === null ? null : (int) $detection['total_engines'],
        'summary' => $detection['scan_summary'] ?? null,
        // True when the agent should alert the person using the PC.
        'is_threat' => in_array($result, ['MALICIOUS', 'SUSPICIOUS'], true),
        // True when VirusTotal does not know the file and the agent may upload it.
        'needs_upload' => $status === 'not_found',
        // True while the agent should ask again later via api/agent/result.php.
        'is_final' => in_array($status, ['completed', 'failed', 'not_found'], true),
    ];
}
