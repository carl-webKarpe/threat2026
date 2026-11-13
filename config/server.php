<?php

declare(strict_types=1);

/**
 * Address of this MalDetect server as the monitored PCs reach it. Shown on the Devices page in the agent
 * config and the install command. Change it here when the server's IP changes, or without touching the code:
 * set MALDETECT_SERVER_URL, or create config/server.local.php (see server.local.example.php).
 */
const MALDETECT_DEFAULT_SERVER_URL = 'http://192.168.0.63/threat2026';

function maldetect_server_url(): string
{
    $localConfigFile = __DIR__ . '/server.local.php';
    $local = is_file($localConfigFile) ? require $localConfigFile : [];
    $url = getenv('MALDETECT_SERVER_URL') ?: (is_array($local) ? (string) ($local['server_url'] ?? '') : '');
    $url = rtrim(trim($url), '/');

    return preg_match('#^https?://[^\s/]+(/\S*)?$#i', $url) ? $url : MALDETECT_DEFAULT_SERVER_URL;
}
