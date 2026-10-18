USE maldetect_db;

-- Phase 12: show a device as Offline as soon as its agent is stopped.
-- Safe to run more than once.

-- When the agent said it was stopping (Ctrl+C or closing its window). Cleared by its next request.
SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'devices' AND COLUMN_NAME = 'agent_stopped_at') = 0,
    'ALTER TABLE devices ADD COLUMN agent_stopped_at TIMESTAMP NULL AFTER last_ip', 'DO 0');
PREPARE phase12_stmt FROM @sql; EXECUTE phase12_stmt; DEALLOCATE PREPARE phase12_stmt;
