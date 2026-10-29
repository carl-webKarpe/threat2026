<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_once __DIR__ . '/../config/agents.php';
require_role('admin');

$activityNotice = (string) ($_SESSION['activity_flash'] ?? '');
unset($_SESSION['activity_flash']);
$activityError = '';

// Saves the extra folders an admin wants monitored on one device; the agent receives them with its next heartbeat.
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
            $_SESSION['activity_flash'] = 'Saved ' . count($folders) . ' extra folder(s).'
                . ($skipped > 0 ? " {$skipped} line(s) were skipped: use full paths such as D:\\Lab\\Projects (at most " . AGENT_MAX_EXTRA_FOLDERS . ' folders).' : '');
            header('Location: activity.php?device=' . $deviceId);
            exit;
        } catch (Throwable $exception) {
            error_log('Saving activity folders failed: ' . $exception->getMessage());
            $activityError = 'The folders could not be saved. Run database/migrations/phase13_file_activity.sql first.';
        }
    }
}

$activitySidebar = __DIR__ . '/../includes/admin_sidebar.php';
$activityCanEdit = true;
require __DIR__ . '/../includes/file_activity_view.php';
