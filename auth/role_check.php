<?php

declare(strict_types=1);

require_once __DIR__ . '/auth_check.php';

function require_role(string $role): void
{
    require_login();

    if ($_SESSION['role'] !== $role) {
        header('Location: ../unauthorized.php');
        exit;
    }
}
