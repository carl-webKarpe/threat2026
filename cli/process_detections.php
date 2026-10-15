<?php

declare(strict_types=1);

// Background worker that finishes device detections the agents have not polled to completion
// (for example after a VirusTotal rate limit). Run from the command line only:
//
//   php cli/process_detections.php          process what is due once, then exit (use with Task Scheduler / cron)
//   php cli/process_detections.php --loop   keep running
//
// It sends at most one VirusTotal request every 15 seconds, the public API limit of 4 per minute.

require_once __DIR__ . '/../config/agents.php';

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

const WORKER_REQUEST_SPACING_SECONDS = 15;
const WORKER_LOOP_IDLE_SECONDS = 30;

$loop = in_array('--loop', $argv, true);

do {
    try {
        $pdo = database_connection();
        $statement = $pdo->prepare(
            "SELECT id, sha256_hash, scan_status, analysis_id, checked_at, lookup_attempts
             FROM device_detections
             WHERE scan_status IN ('pending', 'analyzing')
               AND (checked_at IS NULL OR checked_at <= DATE_SUB(NOW(), INTERVAL :interval SECOND))
             ORDER BY checked_at IS NOT NULL, checked_at, id
             LIMIT 20"
        );
        $statement->bindValue(':interval', SCANNER_STATUS_CHECK_INTERVAL, PDO::PARAM_INT);
        $statement->execute();
        $due = $statement->fetchAll();
    } catch (Throwable $exception) {
        fwrite(STDERR, 'Database unavailable: ' . $exception->getMessage() . PHP_EOL);
        $due = [];
    }

    foreach ($due as $detection) {
        agent_refresh_detection($pdo, $detection, true);
        echo date('Y-m-d H:i:s') . " checked detection #{$detection['id']}" . PHP_EOL;
        sleep(WORKER_REQUEST_SPACING_SECONDS);
    }

    if ($loop && !$due) {
        sleep(WORKER_LOOP_IDLE_SECONDS);
    }
} while ($loop);
