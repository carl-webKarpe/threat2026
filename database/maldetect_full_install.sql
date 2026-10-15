-- MalDetect full database install (fresh install).
-- In MySQL Workbench: File > Open SQL Script > this file, then Query > Execute All (Ctrl+Shift+Enter).
-- Creates maldetect_db with every table up to Phase 9. Safe to run again: existing tables and seed accounts are kept.
-- For a database that already exists from an older phase, you may instead run only the files in migrations/.


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
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Development-only accounts. Password for each account: ChangeMe123!
-- These are password_hash() bcrypt outputs. Do not use these credentials in production.
INSERT IGNORE INTO users (name, username, email, password, role, is_active) VALUES
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

-- Phase 7: audit log

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    actor_user_id INT UNSIGNED NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_user_id INT UNSIGNED NULL,
    details VARCHAR(1000) NULL,
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX audit_logs_created_at_index (created_at),
    INDEX audit_logs_actor_index (actor_user_id),
    INDEX audit_logs_target_index (target_user_id),
    CONSTRAINT audit_logs_actor_foreign FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT audit_logs_target_foreign FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Phase 8: login throttling and Superadmin OTP

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username_hash CHAR(64) NOT NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX login_attempts_window_index (ip_address, username_hash, attempted_at),
    INDEX login_attempts_time_index (attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS superadmin_otp_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX superadmin_otp_requests_user_window_index (user_id, requested_at),
    INDEX superadmin_otp_requests_ip_window_index (ip_address, requested_at),
    CONSTRAINT superadmin_otp_requests_user_foreign
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS superadmin_otps (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    used TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX superadmin_otps_user_index (user_id),
    INDEX superadmin_otps_lookup_index (user_id, used, expires_at),
    CONSTRAINT superadmin_otps_user_foreign FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Phase 9: endpoint agents (download detection on other PCs)

CREATE TABLE IF NOT EXISTS devices (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    hostname VARCHAR(255) NULL,
    os_info VARCHAR(255) NULL,
    agent_version VARCHAR(50) NULL,
    -- SHA-256 of the device token. The token itself is shown once and never stored.
    token_hash CHAR(64) NOT NULL,
    token_prefix CHAR(8) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_by INT UNSIGNED NOT NULL,
    last_seen_at TIMESTAMP NULL,
    last_ip VARCHAR(45) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY devices_token_hash_unique (token_hash),
    INDEX devices_last_seen_index (last_seen_at),
    CONSTRAINT devices_created_by_foreign FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS device_detections (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id INT UNSIGNED NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NULL,
    file_size BIGINT UNSIGNED NULL,
    sha256_hash CHAR(64) NOT NULL,
    source_url VARCHAR(2048) NULL,
    referrer_url VARCHAR(2048) NULL,
    downloaded_at DATETIME NULL,
    -- pending: hash lookup not done yet; not_found: VirusTotal does not know the file;
    -- analyzing: file uploaded and waiting for VirusTotal; completed; failed.
    scan_status VARCHAR(30) NOT NULL DEFAULT 'pending',
    analysis_id VARCHAR(255) NULL,
    scan_result VARCHAR(30) NULL,
    risk_level VARCHAR(50) NULL,
    threat_name VARCHAR(255) NULL,
    safety_percentage DECIMAL(5,2) NULL,
    detection_count INT UNSIGNED NULL,
    malicious_count INT UNSIGNED NULL,
    suspicious_count INT UNSIGNED NULL,
    harmless_count INT UNSIGNED NULL,
    undetected_count INT UNSIGNED NULL,
    total_engines INT UNSIGNED NULL,
    scan_summary TEXT NULL,
    lookup_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    checked_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX device_detections_device_index (device_id, created_at),
    INDEX device_detections_sha256_index (sha256_hash),
    INDEX device_detections_status_index (scan_status, checked_at),
    INDEX device_detections_result_index (scan_result, created_at),
    CONSTRAINT device_detections_device_foreign FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
