USE maldetect_db;

-- Phase 13: real-time file activity monitoring (created, modified, deleted, renamed, moved files).
-- Safe to run more than once.

CREATE TABLE IF NOT EXISTS file_activity_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id INT UNSIGNED NOT NULL,
    -- Made by the agent; with UNIQUE(device_id, event_uuid) a retried upload never creates a second row.
    event_uuid CHAR(36) NOT NULL,
    -- FILE_CREATED, FILE_MODIFIED, FILE_DELETED, FILE_RENAMED, FILE_MOVED and the FOLDER_* equivalents.
    event_type VARCHAR(20) NOT NULL,
    -- realtime: reported by Windows as it happened; reconciliation: found by comparing the folder with the
    -- agent's saved file list (for example after the agent was off), so the exact time may be unknown.
    source VARCHAR(20) NOT NULL DEFAULT 'realtime',
    is_directory TINYINT(1) NOT NULL DEFAULT 0,
    folder_label VARCHAR(50) NULL,
    old_path VARCHAR(1024) NULL,
    old_name VARCHAR(255) NULL,
    old_extension VARCHAR(32) NULL,
    new_path VARCHAR(1024) NULL,
    new_name VARCHAR(255) NULL,
    new_extension VARCHAR(32) NULL,
    file_size BIGINT UNSIGNED NULL,
    user_account VARCHAR(255) NULL,
    -- All times are UTC. event_time_utc is NULL when the real time is not known (reconciliation of deletes,
    -- renames and moves); the change then happened between window_start_utc and detected_at_utc.
    event_time_utc DATETIME(3) NULL,
    time_source VARCHAR(30) NULL,
    detected_at_utc DATETIME(3) NOT NULL,
    window_start_utc DATETIME(3) NULL,
    received_at_utc DATETIME(3) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'recorded',
    details VARCHAR(500) NULL,
    UNIQUE KEY file_activity_events_uuid_unique (device_id, event_uuid),
    INDEX file_activity_events_device_time_index (device_id, detected_at_utc),
    INDEX file_activity_events_type_time_index (event_type, detected_at_utc),
    INDEX file_activity_events_time_index (detected_at_utc),
    CONSTRAINT file_activity_events_device_foreign FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Extra folders chosen by an admin for one device (one path per line), sent to the agent in the heartbeat.
SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'devices' AND COLUMN_NAME = 'activity_folders') = 0,
    'ALTER TABLE devices ADD COLUMN activity_folders TEXT NULL', 'DO 0');
PREPARE phase13_stmt FROM @sql; EXECUTE phase13_stmt; DEALLOCATE PREPARE phase13_stmt;

-- The agent's last report of which folders it watches and any folder it cannot watch (JSON).
SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'devices' AND COLUMN_NAME = 'activity_status') = 0,
    'ALTER TABLE devices ADD COLUMN activity_status TEXT NULL', 'DO 0');
PREPARE phase13_stmt FROM @sql; EXECUTE phase13_stmt; DEALLOCATE PREPARE phase13_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'devices' AND COLUMN_NAME = 'activity_status_at') = 0,
    'ALTER TABLE devices ADD COLUMN activity_status_at TIMESTAMP NULL', 'DO 0');
PREPARE phase13_stmt FROM @sql; EXECUTE phase13_stmt; DEALLOCATE PREPARE phase13_stmt;
