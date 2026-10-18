USE maldetect_db;

-- Phase 10: "Scan now" commands for devices, and a shared VirusTotal rate limit.
-- Safe to run more than once.

-- Commands an admin sends to a device. The agent fetches them, runs them and reports back.
CREATE TABLE IF NOT EXISTS device_commands (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id INT UNSIGNED NOT NULL,
    command_type VARCHAR(30) NOT NULL,
    -- pending: waiting for the agent; sent: agent is running it; completed; failed; expired: agent never picked it up.
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    requested_by INT UNSIGNED NOT NULL,
    files_reported INT UNSIGNED NULL,
    result_message VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    picked_up_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    INDEX device_commands_device_status_index (device_id, status),
    CONSTRAINT device_commands_device_foreign FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    CONSTRAINT device_commands_requested_by_foreign FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row per VirusTotal request from the agent features, used to stay under the API limit.
CREATE TABLE IF NOT EXISTS virustotal_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX virustotal_requests_time_index (requested_at)
) ENGINE=InnoDB;

-- Whether a detection came from a normal download or from a "Scan now" command.
SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'device_detections' AND COLUMN_NAME = 'trigger_type') = 0,
    'ALTER TABLE device_detections ADD COLUMN trigger_type VARCHAR(20) NOT NULL DEFAULT ''download'' AFTER device_id', 'DO 0');
PREPARE phase10_stmt FROM @sql; EXECUTE phase10_stmt; DEALLOCATE PREPARE phase10_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'device_detections' AND COLUMN_NAME = 'command_id') = 0,
    'ALTER TABLE device_detections ADD COLUMN command_id BIGINT UNSIGNED NULL AFTER trigger_type', 'DO 0');
PREPARE phase10_stmt FROM @sql; EXECUTE phase10_stmt; DEALLOCATE PREPARE phase10_stmt;
