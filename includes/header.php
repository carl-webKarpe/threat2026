<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/auth_check.php';
$user = current_user();
$pageTitle = $pageTitle ?? 'Dashboard';
$basePath = $basePath ?? '..';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="MalDetect security workspace">
    <meta name="theme-color" content="#2563eb">
    <title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?> | MalDetect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { theme: { extend: { fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'] } } } };
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <?php require __DIR__ . '/theme_styles.php'; ?>
</head>
<body class="shell min-h-screen text-slate-800 antialiased">
