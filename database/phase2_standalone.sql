CREATE DATABASE IF NOT EXISTS maldetect_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE maldetect_db;

CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('superadmin', 'admin', 'user') NOT NULL DEFAULT 'user',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Development-only accounts. Password for each account: ChangeMe123!
-- These are password_hash() bcrypt outputs. Do not use these credentials in production.
INSERT INTO users (name, username, email, password, role, is_active) VALUES
('System Superadmin', 'superadmin', 'superadmin@example.test', '$2y$10$Br.gD0np1DOLW8LOPpYMQ.VijN6B.DQTyRn0VDMdmyYYDgxq7CA.O', 'superadmin', 1),
('Operations Admin', 'admin', 'admin@example.test', '$2y$10$t3q.t.XP25XWds0wY9qhpOsR1WYJEY0sheuHWxjv8p1GBXTi8pWAC', 'admin', 1),
('Demo User', 'user', 'user@example.test', '$2y$10$Pq.y7IaPMvHA0uZck3XogOPbI.8WEpL7/zl/fwQ1NRn5JvjAbqhIW', 'user', 1);

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
    malicious_count INT UNSIGNED NULL,
    suspicious_count INT UNSIGNED NULL,
    harmless_count INT UNSIGNED NULL,
    undetected_count INT UNSIGNED NULL,
    total_engines INT UNSIGNED NULL,
    scan_result VARCHAR(30) NULL,
    scan_summary TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX scans_user_id_index (user_id),
    INDEX scans_sha256_hash_index (sha256_hash),
    INDEX scans_analysis_id_index (analysis_id),
    CONSTRAINT scans_user_id_foreign FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
