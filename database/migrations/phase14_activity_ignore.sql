USE maldetect_db;

-- Phase 14: files and folders an admin wants left out of file activity monitoring, per device.
-- Safe to run more than once.

-- One pattern per line: a name such as *.log or node_modules, or a full folder path such as D:\Data\Cache.
SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'devices' AND COLUMN_NAME = 'activity_ignore') = 0,
    'ALTER TABLE devices ADD COLUMN activity_ignore TEXT NULL', 'DO 0');
PREPARE phase14_stmt FROM @sql; EXECUTE phase14_stmt; DEALLOCATE PREPARE phase14_stmt;
