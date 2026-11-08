<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_once __DIR__ . '/../config/agents.php';
require_role('admin');

$activityNotice = (string) ($_SESSION['activity_flash'] ?? '');
unset($_SESSION['activity_flash']);
$activityError = '';

// Saves the extra folders an admin wants monitored on one device, and the files and folders to ignore there;
// the agent receives both with its next heartbeat.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $deviceId = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $activityError = 'The request could not be verified. Please try again.';
    } elseif (($_POST['action'] ?? '') !== 'save_folders' || !is_int($deviceId)) {
        $activityError = 'Invalid request.';
    } else {
        $lines = preg_split('/\r\n|\r|\n/', (string) ($_POST['folders'] ?? '')) ?: [];
        $lines = array_values(array_filter(array_map('trim', $lines), static fn (string $line): bool => $line !== ''));
        $folders = agent_parse_extra_folders(implode("\n", $lines));
        try {
            $pdo = database_connection();
            $update = $pdo->prepare('UPDATE devices SET activity_folders = :folders WHERE id = :id');
            $update->execute(['folders' => $folders ? implode("\n", $folders) : null, 'id' => $deviceId]);
            $skipped = count($lines) - count($folders);
            $message = 'Saved ' . count($folders) . ' extra folder(s).'
                . ($skipped > 0 ? " {$skipped} line(s) were skipped: use full paths such as D:\\Lab\\Projects (at most " . AGENT_MAX_EXTRA_FOLDERS . ' folders).' : '');
            if (array_key_exists('ignore', $_POST)) {
                $ignoreLines = preg_split('/\r\n|\r|\n/', (string) $_POST['ignore']) ?: [];
                $ignoreLines = array_values(array_filter(array_map('trim', $ignoreLines), static fn (string $line): bool => $line !== ''));
                $patterns = agent_parse_ignore_patterns(implode("\n", $ignoreLines));
                $ignoreUpdate = $pdo->prepare('UPDATE devices SET activity_ignore = :patterns WHERE id = :id');
                $ignoreUpdate->execute(['patterns' => $patterns ? implode("\n", $patterns) : null, 'id' => $deviceId]);
                $ignoreSkipped = count($ignoreLines) - count($patterns);
                $message .= ' Ignoring ' . count($patterns) . ' pattern(s).'
                    . ($ignoreSkipped > 0 ? " {$ignoreSkipped} ignore line(s) were skipped: a folder must be a full path such as C:\\Users\\me\\Documents\\Cache (at most " . AGENT_MAX_IGNORE_PATTERNS . ' patterns).' : '');
            }
            $_SESSION['activity_flash'] = $message;
            header('Location: activity.php?device=' . $deviceId);
            exit;
        } catch (Throwable $exception) {
            error_log('Saving activity folders failed: ' . $exception->getMessage());
            $activityError = 'The settings could not be saved. Run database/migrations/phase13_file_activity.sql and phase14_activity_ignore.sql first.';
        }
    }
}

$activitySidebar = __DIR__ . '/../includes/admin_sidebar.php';
$activityCanEdit = true;
require __DIR__ . '/../includes/file_activity_view.php';
