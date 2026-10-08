USE maldetect_db;

ALTER TABLE scans
    MODIFY scan_status VARCHAR(50) NOT NULL DEFAULT 'queued',
    ADD COLUMN analysis_id VARCHAR(255) NULL AFTER scan_status,
    ADD COLUMN detection_count INT UNSIGNED NULL AFTER risk_level,
    ADD COLUMN malicious_count INT UNSIGNED NULL AFTER detection_count,
    ADD COLUMN suspicious_count INT UNSIGNED NULL AFTER malicious_count,
    ADD COLUMN harmless_count INT UNSIGNED NULL AFTER suspicious_count,
    ADD COLUMN undetected_count INT UNSIGNED NULL AFTER harmless_count,
    ADD COLUMN total_engines INT UNSIGNED NULL AFTER undetected_count,
    ADD COLUMN scan_result VARCHAR(30) NULL AFTER detection_count,
    ADD COLUMN scan_summary TEXT NULL AFTER scan_result,
    ADD INDEX scans_analysis_id_index (analysis_id);