USE maldetect_db;

-- Phase 11: email alerts for threats found on devices.
-- Safe to run more than once.

-- When the admin alert email for a threat was sent (NULL = not sent). Prevents duplicate emails.
SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'device_detections' AND COLUMN_NAME = 'alert_sent_at') = 0,
    'ALTER TABLE device_detections ADD COLUMN alert_sent_at TIMESTAMP NULL AFTER checked_at', 'DO 0');
PREPARE phase11_stmt FROM @sql; EXECUTE phase11_stmt; DEALLOCATE PREPARE phase11_stmt;
