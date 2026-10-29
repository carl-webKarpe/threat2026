<?php

declare(strict_types=1);

// POST, JSON body: {"events": [ ... up to 500 ... ]}. Header: X-Device-Token.
// One event (metadata only, never file contents):
// {"event_id": "<uuid made by the agent>", "event_type": "FILE_RENAMED", "source": "realtime",
//  "is_directory": false, "folder_label": "Documents",
//  "old_path": "C:\\Users\\me\\Documents\\report.docx", "new_path": "C:\\Users\\me\\Documents\\final_report.docx",
//  "file_size": 12345, "user_account": "me",
//  "event_time": "2026-10-29T05:14:15.123Z", "time_source": "realtime",
//  "detected_at": "2026-10-29T05:14:15.130Z", "window_start": null, "details": "..."}
// Responds with {"accepted": [...ids], "duplicates": [...ids], "rejected": [{"event_id", "reason"}]}.
// An event sent again (for example after a lost response) is reported as a duplicate and not stored twice.

require_once __DIR__ . '/../../config/agents.php';

const ACTIVITY_MAX_BATCH = 500;

/** Last part of a Windows or POSIX path. */
function activity_base_name(?string $path): ?string
{
    if ($path === null) {
        return null;
    }
    $parts = preg_split('#[\\\\/]#', rtrim($path, '\\/')) ?: [];
    $name = (string) end($parts);

    return $name === '' ? null : mb_substr($name, 0, 255);
}

/**
 * Checks one event and returns the row to store, or a string with the reason it was rejected.
 *
 * @return array<string, mixed>|string
 */
function activity_validate_event(mixed $event): array|string
{
    if (!is_array($event)) {
        return 'Event must be an object.';
    }
    $eventId = strtolower(trim((string) ($event['event_id'] ?? '')));
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $eventId)) {
        return 'event_id must be a UUID.';
    }
    $type = strtoupper(trim((string) ($event['event_type'] ?? '')));
    if (!in_array($type, AGENT_ACTIVITY_EVENT_TYPES, true)) {
        return 'Unknown event_type.';
    }
    $source = (string) ($event['source'] ?? 'realtime');
    if (!in_array($source, AGENT_ACTIVITY_SOURCES, true)) {
        return 'Unknown source.';
    }

    $oldPath = agent_clean_text($event['old_path'] ?? null, 1024);
    $newPath = agent_clean_text($event['new_path'] ?? null, 1024);
    $action = substr($type, strpos($type, '_') + 1);
    if (in_array($action, ['DELETED', 'RENAMED', 'MOVED'], true) && $oldPath === null) {
        return 'old_path is required for ' . $type . '.';
    }
    if (in_array($action, ['CREATED', 'MODIFIED', 'RENAMED', 'MOVED'], true) && $newPath === null) {
        return 'new_path is required for ' . $type . '.';
    }

    $detectedAt = agent_parse_utc_time($event['detected_at'] ?? null);
    if ($detectedAt === null) {
        return 'detected_at must be an ISO 8601 time with a time zone.';
    }
    // A time the agent does not know is sent as null and stays null; it is never replaced by a guess.
    $eventTime = agent_parse_utc_time($event['event_time'] ?? null);
    $fileSize = filter_var($event['file_size'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
    $oldName = activity_base_name($oldPath);
    $newName = activity_base_name($newPath);

    return [
        'event_uuid' => $eventId,
        'event_type' => $type,
        'source' => $source,
        'is_directory' => ($event['is_directory'] ?? false) === true || str_starts_with($type, 'FOLDER_') ? 1 : 0,
        'folder_label' => agent_clean_text($event['folder_label'] ?? null, 50),
        'old_path' => $oldPath,
        'old_name' => $oldName,
        'old_extension' => str_starts_with($type, 'FOLDER_') ? null : agent_file_extension($oldName),
        'new_path' => $newPath,
        'new_name' => $newName,
        'new_extension' => str_starts_with($type, 'FOLDER_') ? null : agent_file_extension($newName),
        'file_size' => is_int($fileSize) ? $fileSize : null,
        'user_account' => agent_clean_text($event['user_account'] ?? null, 255),
        'event_time_utc' => $eventTime,
        'time_source' => $eventTime === null ? null : agent_clean_text($event['time_source'] ?? 'realtime', 30),
        'detected_at_utc' => $detectedAt,
        'window_start_utc' => agent_parse_utc_time($event['window_start'] ?? null),
        'details' => agent_clean_text($event['details'] ?? null, 500),
    ];
}

agent_require_method('POST');

try {
    $pdo = database_connection();
    $device = agent_authenticate($pdo);
    $body = agent_json_body();
    $events = $body['events'] ?? null;
    if (!is_array($events) || !array_is_list($events) || $events === []) {
        agent_json_response(['success' => false, 'message' => 'events must be a non-empty list.'], 422);
    }
    if (count($events) > ACTIVITY_MAX_BATCH) {
        agent_json_response(['success' => false, 'message' => 'Send at most ' . ACTIVITY_MAX_BATCH . ' events per request.'], 413);
    }

    $recent = $pdo->prepare(
        'SELECT COUNT(*) FROM file_activity_events
         WHERE device_id = :device_id AND received_at_utc >= UTC_TIMESTAMP(3) - INTERVAL 1 HOUR'
    );
    $recent->execute(['device_id' => $device['id']]);
    if ((int) $recent->fetchColumn() + count($events) > AGENT_MAX_ACTIVITY_EVENTS_PER_HOUR) {
        agent_json_response(['success' => false, 'message' => 'Too many file activity events from this device. Try again later.'], 429);
    }

    $receivedAt = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s.v');
    // ON DUPLICATE KEY keeps the first copy of a resent event; unlike INSERT IGNORE it does not hide other errors.
    $insert = $pdo->prepare(
        'INSERT INTO file_activity_events
            (device_id, event_uuid, event_type, source, is_directory, folder_label, old_path, old_name, old_extension,
             new_path, new_name, new_extension, file_size, user_account, event_time_utc, time_source,
             detected_at_utc, window_start_utc, received_at_utc, details)
         VALUES
            (:device_id, :event_uuid, :event_type, :source, :is_directory, :folder_label, :old_path, :old_name, :old_extension,
             :new_path, :new_name, :new_extension, :file_size, :user_account, :event_time_utc, :time_source,
             :detected_at_utc, :window_start_utc, :received_at_utc, :details)
         ON DUPLICATE KEY UPDATE id = id'
    );

    $accepted = [];
    $duplicates = [];
    $rejected = [];
    $pdo->beginTransaction();
    foreach ($events as $event) {
        $row = activity_validate_event($event);
        if (is_string($row)) {
            $eventId = is_array($event) && is_string($event['event_id'] ?? null) ? mb_substr($event['event_id'], 0, 64) : null;
            $rejected[] = ['event_id' => $eventId, 'reason' => $row];
            continue;
        }
        $insert->execute($row + ['device_id' => $device['id'], 'received_at_utc' => $receivedAt]);
        if ($insert->rowCount() === 1) {
            $accepted[] = $row['event_uuid'];
        } else {
            $duplicates[] = $row['event_uuid'];
        }
    }
    $pdo->commit();
} catch (Throwable $exception) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Agent file activity report failed: ' . $exception->getMessage());
    agent_json_response(['success' => false, 'message' => 'The server is temporarily unavailable.'], 500);
}

agent_json_response([
    'success' => true,
    'accepted' => $accepted,
    'duplicates' => $duplicates,
    'rejected' => $rejected,
    'received_at' => str_replace(' ', 'T', $receivedAt) . 'Z',
]);
