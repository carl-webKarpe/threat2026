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
    <title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?> | MalDetect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>body{font-family:Manrope,sans-serif}.mono{font-family:'DM Mono',monospace}.shell{background:radial-gradient(circle at 70% 0%,rgba(124,92,246,.15),transparent 30%),#080a13}@keyframes live-new{from{background:rgba(52,211,153,.18)}to{background:transparent}}.live-new{animation:live-new 4s ease-out}</style>
</head>
<body class="shell min-h-screen text-slate-100 antialiased">
