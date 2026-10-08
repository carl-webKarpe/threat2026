USE maldetect_db;

-- Run the conditional statements once against an existing Phase 2 database.
SET @has_last_login := (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'last_login'
);
SET @sql := IF(@has_last_login = 0,
    'ALTER TABLE users ADD COLUMN last_login TIMESTAMP NULL AFTER is_active',
    'SELECT 1');
PREPARE phase7_stmt FROM @sql;
EXECUTE phase7_stmt;
DEALLOCATE PREPARE phase7_stmt;

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
