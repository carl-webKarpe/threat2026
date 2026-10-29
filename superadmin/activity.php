<?php

declare(strict_types=1);

// Read-only: the superadmin can review file activity but cannot change monitored folders or start scans.
require_once __DIR__ . '/../auth/superadmin.php';
require_superadmin_page();

$activitySidebar = __DIR__ . '/../includes/superadmin_sidebar.php';
$activityCanEdit = false;
require __DIR__ . '/../includes/file_activity_view.php';
