USE maldetect_db;

CREATE TABLE IF NOT EXISTS scans (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_size BIGINT UNSIGNED NOT NULL,
    mime_type VARCHAR(150) NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    scan_status VARCHAR(50) NOT NULL DEFAULT 'queued',
    analysis_id VARCHAR(255) NULL,
    threat_name VARCHAR(255) NULL,
    safety_percentage DECIMAL(5,2) NULL,
    risk_level VARCHAR(50) NULL,
    detection_count INT UNSIGNED NULL,
    scan_result VARCHAR(30) NULL,
    scan_summary TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX scans_user_id_index (user_id),
    INDEX scans_sha256_hash_index (sha256_hash),
    INDEX scans_analysis_id_index (analysis_id),
    CONSTRAINT scans_user_id_foreign FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB;