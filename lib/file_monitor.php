<?php

declare(strict_types=1);

/**
 * Compare the upload directory with the last saved inventory and persist changes.
 */
function file_monitor_capture(PDO $pdo, string $directory): void
{
    $root = realpath($directory);
    if ($root === false && (file_exists($directory) || is_link($directory))) {
        throw new RuntimeException('The upload storage directory is missing or unreadable.');
    }

    $inventory = [];
    if ($root !== false) {
        if (!is_dir($root) || !is_readable($root)) {
            throw new RuntimeException('The upload storage directory is unreadable.');
        }

        $rootPrefix = rtrim($root, "\\/") . DIRECTORY_SEPARATOR;
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY,
        );

        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->isLink()) {
                continue;
            }

            $path = $file->getRealPath();
            if ($path === false || strncasecmp($path, $rootPrefix, strlen($rootPrefix)) !== 0) {
                throw new RuntimeException('A file could not be safely resolved inside upload storage.');
            }

            $relativePath = str_replace('\\', '/', substr($path, strlen($rootPrefix)));
            if (strlen($relativePath) > 512 || !is_readable($path)) {
                throw new RuntimeException('A file path is too long or a stored file is unreadable.');
            }

            clearstatcache(true, $path);
            $size = filesize($path);
            $hash = hash_file('sha256', $path);
            if (!is_int($size) || !is_string($hash)) {
                throw new RuntimeException('A stored file could not be fingerprinted.');
            }

            $inventory[$relativePath] = [
                'sha256' => $hash,
                'file_size' => $size,
            ];
        }
    }

    $displayNames = file_monitor_display_names($pdo, array_keys($inventory));

    $pdo->beginTransaction();
    try {
        $baselineQuery = $pdo->query(
            'SELECT initialized_at FROM file_monitor_status WHERE id = 1 FOR UPDATE'
        );
        $initializedAt = $baselineQuery->fetchColumn();
        if ($initializedAt === false) {
            throw new RuntimeException('The file-monitoring status row is missing.');
        }

        $stateRows = $pdo->query(
            'SELECT file_path, display_name, sha256_hash, file_size FROM file_monitor_state'
        )->fetchAll();
        $previousState = [];
        foreach ($stateRows as $row) {
            $previousState[(string) $row['file_path']] = $row;
        }

        $isInitialBaseline = $initializedAt === null;
        $insertEvent = $pdo->prepare(
            'INSERT INTO file_monitor_events (event_type, file_path, display_name, previous_sha256, current_sha256, file_size)
             VALUES (:event_type, :file_path, :display_name, :previous_sha256, :current_sha256, :file_size)'
        );

        foreach ($previousState as $path => $previous) {
            if (isset($inventory[$path])) {
                continue;
            }

            if (!$isInitialBaseline) {
                $insertEvent->execute([
                    'event_type' => 'deleted',
                    'file_path' => $path,
                    'display_name' => $previous['display_name'],
                    'previous_sha256' => $previous['sha256_hash'],
                    'current_sha256' => null,
                    'file_size' => $previous['file_size'],
                ]);
            }

            $deleteState = $pdo->prepare('DELETE FROM file_monitor_state WHERE file_path = :file_path');
            $deleteState->execute(['file_path' => $path]);
        }

        $upsertState = $pdo->prepare(
            'INSERT INTO file_monitor_state (file_path, display_name, sha256_hash, file_size)
             VALUES (:file_path, :display_name, :sha256_hash, :file_size)
             ON DUPLICATE KEY UPDATE display_name = VALUES(display_name),
                 sha256_hash = VALUES(sha256_hash), file_size = VALUES(file_size)'
        );

        foreach ($inventory as $path => $current) {
            $previous = $previousState[$path] ?? null;
            $displayName = $displayNames[$path] ?? ($previous['display_name'] ?? basename($path));

            if (!$isInitialBaseline && $previous === null) {
                $insertEvent->execute([
                    'event_type' => 'added',
                    'file_path' => $path,
                    'display_name' => $displayName,
                    'previous_sha256' => null,
                    'current_sha256' => $current['sha256'],
                    'file_size' => $current['file_size'],
                ]);
            } elseif (
                !$isInitialBaseline
                && $previous !== null
                && !hash_equals((string) $previous['sha256_hash'], $current['sha256'])
            ) {
                $insertEvent->execute([
                    'event_type' => 'modified',
                    'file_path' => $path,
                    'display_name' => $displayName,
                    'previous_sha256' => $previous['sha256_hash'],
                    'current_sha256' => $current['sha256'],
                    'file_size' => $current['file_size'],
                ]);
            }

            $upsertState->execute([
                'file_path' => $path,
                'display_name' => $displayName,
                'sha256_hash' => $current['sha256'],
                'file_size' => $current['file_size'],
            ]);
        }

        if ($isInitialBaseline) {
            $pdo->exec('UPDATE file_monitor_status SET initialized_at = CURRENT_TIMESTAMP WHERE id = 1');
        }

        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $exception;
    }
}

/**
 * Resolve scanner-generated storage names to the original uploaded filenames.
 *
 * @param list<string> $paths
 * @return array<string, string>
 */
function file_monitor_display_names(PDO $pdo, array $paths): array
{
    $storedNames = array_values(array_unique(array_map(
        static fn (string $path): string => basename($path),
        $paths,
    )));
    $displayNames = [];

    foreach (array_chunk($storedNames, 500) as $chunk) {
        if ($chunk === []) {
            continue;
        }

        $placeholders = implode(', ', array_fill(0, count($chunk), '?'));
        $query = $pdo->prepare(
            "SELECT stored_filename, original_filename FROM scans WHERE stored_filename IN ({$placeholders}) ORDER BY id DESC"
        );
        $query->execute($chunk);
        foreach ($query->fetchAll() as $row) {
            $displayNames[(string) $row['stored_filename']] = (string) $row['original_filename'];
        }
    }

    $byPath = [];
    foreach ($paths as $path) {
        $storedName = basename($path);
        if (isset($displayNames[$storedName])) {
            $byPath[$path] = $displayNames[$storedName];
        }
    }

    return $byPath;
}
