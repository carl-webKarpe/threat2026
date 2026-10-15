USE maldetect_db;

-- Brings an existing Phase 3 `scans` table up to the Phase 4 schema.
-- Safe to run more than once: each column and index is only added when it is missing.

ALTER TABLE scans MODIFY scan_status VARCHAR(50) NOT NULL DEFAULT 'queued';

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'analysis_id') = 0,
    'ALTER TABLE scans ADD COLUMN analysis_id VARCHAR(255) NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'threat_name') = 0,
    'ALTER TABLE scans ADD COLUMN threat_name VARCHAR(255) NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'safety_percentage') = 0,
    'ALTER TABLE scans ADD COLUMN safety_percentage DECIMAL(5,2) NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'risk_level') = 0,
    'ALTER TABLE scans ADD COLUMN risk_level VARCHAR(50) NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'detection_count') = 0,
    'ALTER TABLE scans ADD COLUMN detection_count INT UNSIGNED NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'malicious_count') = 0,
    'ALTER TABLE scans ADD COLUMN malicious_count INT UNSIGNED NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'suspicious_count') = 0,
    'ALTER TABLE scans ADD COLUMN suspicious_count INT UNSIGNED NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'harmless_count') = 0,
    'ALTER TABLE scans ADD COLUMN harmless_count INT UNSIGNED NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'undetected_count') = 0,
    'ALTER TABLE scans ADD COLUMN undetected_count INT UNSIGNED NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'total_engines') = 0,
    'ALTER TABLE scans ADD COLUMN total_engines INT UNSIGNED NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'scan_result') = 0,
    'ALTER TABLE scans ADD COLUMN scan_result VARCHAR(30) NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'scan_summary') = 0,
    'ALTER TABLE scans ADD COLUMN scan_summary TEXT NULL', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;

SET @sql := IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND INDEX_NAME = 'scans_analysis_id_index') = 0,
    'ALTER TABLE scans ADD INDEX scans_analysis_id_index (analysis_id)', 'DO 0');
PREPARE phase4_stmt FROM @sql; EXECUTE phase4_stmt; DEALLOCATE PREPARE phase4_stmt;
