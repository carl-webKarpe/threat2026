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
    <meta name="description" content="JunMalware security workspace">
    <meta name="theme-color" content="#07070b">
    <title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?> | JunMalware</title>
    <?php require __DIR__ . '/theme_head.php'; ?>
</head>
<body class="shell min-h-screen text-neutral-200 antialiased">
