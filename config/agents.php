<?php

declare(strict_types=1);

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/scanner.php';
require_once __DIR__ . '/virustotal.php';

/**
 * A device counts as online when it sent any request within this many seconds (the agent checks in every
 * 60 s) and its agent did not say it was stopping. The window only matters when an agent ends without
 * saying goodbye: a crash, sleep, or a lost network.
 */
const AGENT_ONLINE_WINDOW = 180;

/** Maximum file reports a single device may send per hour ("Scan now" can report a whole Downloads folder). */
const AGENT_MAX_REPORTS_PER_HOUR = 500;

/** VirusTotal requests allowed per minute across all agents (public API key: 4). */
const VIRUSTOTAL_REQUESTS_PER_MINUTE = 4;

/** A "Scan now" command that no agent picks up within this many hours expires. */
const AGENT_COMMAND_EXPIRY_HOURS = 24;

/** Email active admins and superadmins when a device download is Malicious or Suspicious. */
const AGENT_THREAT_EMAIL_ALERTS = true;

/** Upper limit on alert emails per hour, so a folder full of threats cannot flood the inbox. */
const AGENT_MAX_ALERT_EMAILS_PER_HOUR = 30;

/** Commands an admin can send to a device. */
const AGENT_COMMAND_TYPES = ['scan_downloads' => 'Scan Downloads'];

/** Reuse a VirusTotal verdict for the same SHA-256 for this many hours instead of asking again. */
const AGENT_VERDICT_CACHE_HOURS = 24;

/** Give up on a pending lookup after this many failed VirusTotal attempts. */
const AGENT_MAX_LOOKUP_ATTEMPTS = 10;

/** Columns copied from scanner_interpret_analysis() into device_detections. */
const AGENT_VERDICT_COLUMNS = [
    'scan_result', 'risk_level', 'threat_name', 'safety_percentage', 'detection_count', 'malicious_count',
    'suspicious_count', 'harmless_count', 'undetected_count', 'total_engines', 'scan_summary',
];

/**
 * Reserves one VirusTotal request in the shared per-minute budget. Returns false when the budget is
 * used up; the caller then leaves the work pending and tries again later.
 */
function virustotal_reserve_request(PDO $pdo): bool
{
    try {
        if ((int) $pdo->query("SELECT GET_LOCK('maldetect_virustotal', 5)")->fetchColumn() !== 1) {
            return false;
        }
    } catch (Throwable $exception) {
        error_log('VirusTotal rate limit lock failed: ' . $exception->getMessage());
        return true;
    }

    try {
        $pdo->exec('DELETE FROM virustotal_requests WHERE requested_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)');
        $recent = (int) $pdo->query(
            'SELECT COUNT(*) FROM virustotal_requests WHERE requested_at > DATE_SUB(NOW(), INTERVAL 60 SECOND)'
        )->fetchColumn();
        if ($recent >= VIRUSTOTAL_REQUESTS_PER_MINUTE) {
            return false;
        }
        $pdo->exec('INSERT INTO virustotal_requests () VALUES ()');

        return true;
    } catch (Throwable $exception) {
        // Without the Phase 10 table, fall back to the per-detection throttle only.
        error_log('VirusTotal rate limit unavailable: ' . $exception->getMessage());
        return true;
    } finally {
        $pdo->query("SELECT RELEASE_LOCK('maldetect_virustotal')")->fetchColumn();
    }
}

/** SQL condition that is true for online devices. $table is the devices table name or alias. */
function agent_online_sql(string $table = 'devices'): string
{
    return "({$table}.last_seen_at >= DATE_SUB(NOW(), INTERVAL " . AGENT_ONLINE_WINDOW . " SECOND)"
        . " AND {$table}.agent_stopped_at IS NULL)";
}

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

    // Any request proves the agent is running, so it also clears a previous "stopping" notice.
    $seenParameters = [
        'ip' => filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: null,
        'id' => $device['id'],
    ];
    try {
        $seen = $pdo->prepare('UPDATE devices SET last_seen_at = CURRENT_TIMESTAMP, last_ip = :ip, agent_stopped_at = NULL WHERE id = :id');
        $seen->execute($seenParameters);
    } catch (PDOException $exception) {
        // Database without the Phase 12 column.
        $seen = $pdo->prepare('UPDATE devices SET last_seen_at = CURRENT_TIMESTAMP, last_ip = :ip WHERE id = :id');
        $seen->execute($seenParameters);
    }

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

    if (in_array($verdict['scan_result'] ?? null, ['MALICIOUS', 'SUSPICIOUS'], true)) {
        agent_send_threat_alert($pdo, $detectionId);
    }
}

/** Base URL of this MalDetect installation as seen by the current request, or null outside a web request. */
function agent_server_base_url(): ?string
{
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    if ($host === '' || !preg_match('/^[A-Za-z0-9.\-:\[\]]+$/', $host)) {
        return null;
    }
    $scheme = !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off' ? 'https' : 'http';
    // Alerts are sent from api/agent/*.php, two folders below the project root.
    $projectPath = rtrim(str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? ''), 3)), '/');

    return $scheme . '://' . $host . $projectPath;
}

/**
 * Emails a threat alert about one detection to every active admin and superadmin with a real address.
 * Sent at most once per detection (device_detections.alert_sent_at). Never throws.
 */
function agent_send_threat_alert(PDO $pdo, int $detectionId): void
{
    if (!AGENT_THREAT_EMAIL_ALERTS) {
        return;
    }
    try {
        $sentRecently = (int) $pdo->query(
            'SELECT COUNT(*) FROM device_detections WHERE alert_sent_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)'
        )->fetchColumn();
        if ($sentRecently >= AGENT_MAX_ALERT_EMAILS_PER_HOUR) {
            error_log("Threat alert for detection #{$detectionId} skipped: hourly email limit reached.");
            return;
        }
        // Claim the alert first so two requests can never email the same detection twice.
        $claim = $pdo->prepare('UPDATE device_detections SET alert_sent_at = CURRENT_TIMESTAMP WHERE id = :id AND alert_sent_at IS NULL');
        $claim->execute(['id' => $detectionId]);
        if ($claim->rowCount() !== 1) {
            return;
        }

        $statement = $pdo->prepare(
            'SELECT device_detections.*, devices.name AS device_name, devices.hostname, devices.last_ip
             FROM device_detections INNER JOIN devices ON devices.id = device_detections.device_id
             WHERE device_detections.id = :id'
        );
        $statement->execute(['id' => $detectionId]);
        $detection = $statement->fetch();
        $recipients = $pdo->query(
            "SELECT name, email FROM users WHERE role IN ('admin', 'superadmin') AND is_active = 1 AND email IS NOT NULL AND email <> ''"
        )->fetchAll();
        // Skip the placeholder addresses from the seed data; mail to them would only bounce.
        $recipients = array_values(array_filter(
            $recipients,
            static fn (array $user): bool => filter_var($user['email'], FILTER_VALIDATE_EMAIL) !== false
                && !preg_match('/\.(test|example|invalid|localhost)$/i', (string) $user['email']),
        ));
        if (!is_array($detection) || !$recipients) {
            error_log("Threat alert for detection #{$detectionId} not sent: no admin has a real email address.");
            return;
        }

        require_once __DIR__ . '/../auth/otp_functions.php';
        if (!class_exists(\PHPMailer\PHPMailer\PHPMailer::class)) {
            throw new RuntimeException('PHPMailer is not installed. Run composer install.');
        }
        $mailConfig = getMailConfig();

        $h = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
        $baseUrl = agent_server_base_url();
        $detailsUrl = $baseUrl !== null ? $baseUrl . '/admin/view_detection.php?id=' . $detectionId : null;
        $rows = [
            'File' => $detection['file_name'],
            'Device' => $detection['device_name'] . ($detection['hostname'] ? ' (' . $detection['hostname'] . ')' : ''),
            'Risk level' => $detection['risk_level'],
            'Threat name' => $detection['threat_name'] ?: 'Not named by the engines',
            'Engines' => (int) $detection['malicious_count'] . ' malicious, ' . (int) $detection['suspicious_count'] . ' suspicious, of ' . (int) $detection['total_engines'],
            'Found by' => ($detection['trigger_type'] ?? 'download') === 'manual_scan' ? 'Manual scan' : 'New download',
            'Downloaded from' => $detection['source_url'] ?: 'Unknown',
            'File path' => $detection['file_path'] ?: 'Unknown',
            'SHA-256' => $detection['sha256_hash'],
            'Reported at' => $detection['created_at'],
        ];
        $htmlRows = '';
        $textRows = '';
        foreach ($rows as $label => $value) {
            $htmlRows .= '<tr><td style="padding:6px 12px 6px 0;color:#64748b;vertical-align:top;white-space:nowrap">' . $h($label)
                . '</td><td style="padding:6px 0;color:#0f172a;word-break:break-all">' . $h($value) . '</td></tr>';
            $textRows .= $label . ': ' . $value . "\n";
        }
        $color = $detection['scan_result'] === 'MALICIOUS' ? '#dc2626' : '#d97706';
        $html = '<div style="font-family:Arial,sans-serif;max-width:600px">'
            . '<h2 style="color:' . $color . ';margin:0 0 8px">' . $h($detection['risk_level']) . ' file detected</h2>'
            . '<p style="color:#334155;margin:0 0 16px">MalDetect found a dangerous file on <strong>' . $h($detection['device_name']) . '</strong>.</p>'
            . '<table style="border-collapse:collapse;font-size:14px">' . $htmlRows . '</table>'
            . ($detailsUrl !== null ? '<p style="margin-top:20px"><a href="' . $h($detailsUrl) . '" style="color:#7c3aed">Open the detection in MalDetect</a></p>' : '')
            . '<p style="color:#94a3b8;font-size:12px;margin-top:24px">The link and URLs above come from the monitored device. Do not open the file or the download link.</p></div>';

        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $mailConfig['host'];
        $mail->SMTPAuth = true;
        $mail->Username = $mailConfig['username'];
        $mail->Password = $mailConfig['password'];
        $mail->SMTPSecure = $mailConfig['encryption'] === 'tls'
            ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS
            : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        $mail->Port = (int) $mailConfig['port'];
        $mail->Timeout = 15;
        $mail->CharSet = 'UTF-8';
        $mail->setFrom($mailConfig['from_email'], $mailConfig['from_name']);
        foreach ($recipients as $recipient) {
            $mail->addBCC($recipient['email'], (string) $recipient['name']);
        }
        $mail->isHTML(true);
        $mail->Subject = 'MalDetect alert: ' . $detection['risk_level'] . ' file on ' . $detection['device_name'];
        $mail->Body = $html;
        $mail->AltBody = "MalDetect found a dangerous file.\n\n" . $textRows . ($detailsUrl !== null ? "\nDetails: {$detailsUrl}\n" : '');
        $mail->send();
    } catch (Throwable $exception) {
        error_log("Threat alert email for detection #{$detectionId} failed: " . $exception->getMessage());
    }
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

    if (!virustotal_reserve_request($pdo)) {
        return;
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

/**
 * Queues a command for a device unless the same command is already waiting or running.
 * Returns true when a new command was queued.
 */
function agent_queue_command(PDO $pdo, int $deviceId, string $commandType, int $requestedBy): bool
{
    if (!array_key_exists($commandType, AGENT_COMMAND_TYPES)) {
        throw new InvalidArgumentException('Unknown device command.');
    }
    $existing = $pdo->prepare(
        "SELECT COUNT(*) FROM device_commands
         WHERE device_id = :device_id AND command_type = :command_type AND status IN ('pending', 'sent')
           AND created_at >= DATE_SUB(NOW(), INTERVAL " . AGENT_COMMAND_EXPIRY_HOURS . " HOUR)"
    );
    $existing->execute(['device_id' => $deviceId, 'command_type' => $commandType]);
    if ((int) $existing->fetchColumn() > 0) {
        return false;
    }
    $insert = $pdo->prepare(
        'INSERT INTO device_commands (device_id, command_type, requested_by) VALUES (:device_id, :command_type, :requested_by)'
    );
    $insert->execute(['device_id' => $deviceId, 'command_type' => $commandType, 'requested_by' => $requestedBy]);

    return true;
}
