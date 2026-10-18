USE maldetect_db;

CREATE TABLE IF NOT EXISTS file_monitor_status (
    id TINYINT UNSIGNED PRIMARY KEY,
    initialized_at TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB;

INSERT IGNORE INTO file_monitor_status (id, initialized_at) VALUES (1, NULL);

CREATE TABLE IF NOT EXISTS file_monitor_state (
    file_path VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    file_size BIGINT UNSIGNED NOT NULL,
    INDEX file_monitor_state_hash_index (sha256_hash)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS file_monitor_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type ENUM('added', 'modified', 'deleted') NOT NULL,
    file_path VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    previous_sha256 CHAR(64) NULL,
    current_sha256 CHAR(64) NULL,
    file_size BIGINT UNSIGNED NOT NULL,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX file_monitor_events_detected_at_index (detected_at),
    INDEX file_monitor_events_type_index (event_type)
) ENGINE=InnoDB;
