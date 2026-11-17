<?php

declare(strict_types=1);

// Checks the database connection exactly as the website makes it, and says what is wrong.
// Run on the server, in PowerShell:   C:\xampp\php\php.exe tools\check_database.php
// (use your XAMPP folder, for example C:\xampp1\php\php.exe). Command line only: it never runs from the browser.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$ok = static fn (string $text) => print("  [OK]    {$text}\n");
$bad = static fn (string $text) => print("  [ERROR] {$text}\n");
$hint = static fn (string $text) => print("          -> {$text}\n");

echo "MalDetect database check\n\n";

echo "1. PHP\n";
$ok('PHP ' . PHP_VERSION . ' (' . PHP_BINARY . ')');
if (!extension_loaded('pdo_mysql')) {
    $bad('The pdo_mysql extension is not loaded.');
    $hint('In php.ini (' . (php_ini_loaded_file() ?: 'not found') . ') remove the ; before extension=pdo_mysql, then restart Apache.');
    exit(1);
}
$ok('pdo_mysql is loaded');

echo "\n2. Settings the website uses\n";
$localFile = __DIR__ . '/../config/database.local.php';
$local = is_file($localFile) ? require $localFile : [];
$local = is_array($local) ? $local : [];
$settings = [
    'host' => getenv('MALDETECT_DB_HOST') ?: ($local['host'] ?? '127.0.0.1'),
    'port' => getenv('MALDETECT_DB_PORT') ?: (string) ($local['port'] ?? '3306'),
    'database' => getenv('MALDETECT_DB_NAME') ?: ($local['database'] ?? 'maldetect2026_db'),
    'username' => getenv('MALDETECT_DB_USER') ?: ($local['username'] ?? 'root'),
];
$password = getenv('MALDETECT_DB_PASSWORD') ?: (string) ($local['password'] ?? '');
echo '  config\database.local.php: ' . (is_file($localFile) ? 'present' : 'not present (defaults are used)') . "\n";
foreach ($settings as $name => $value) {
    echo "  {$name}: {$value}\n";
}
echo '  password: ' . ($password === '' ? '(empty)' : '(set, ' . strlen($password) . ' characters)') . "\n";

echo "\n3. Connection to the MySQL server\n";
try {
    $server = new PDO("mysql:host={$settings['host']};port={$settings['port']};charset=utf8mb4", $settings['username'], $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $ok('Connected: ' . $server->query('SELECT VERSION()')->fetchColumn());
} catch (PDOException $exception) {
    $bad($exception->getMessage());
    $message = $exception->getMessage();
    if (str_contains($message, 'Access denied')) {
        $hint('Wrong user or password. XAMPP\'s MySQL uses root with an empty password: rename config\database.local.php, or put the right password in it.');
    } elseif (str_contains($message, 'refused') || str_contains($message, 'No connection') || str_contains($message, '2002')) {
        $hint('MySQL is not running on ' . $settings['host'] . ':' . $settings['port'] . '. Start MySQL in the XAMPP Control Panel (or the MySQL80 service).');
    }
    exit(1);
}

echo "\n4. Database {$settings['database']}\n";
$databases = $server->query('SHOW DATABASES')->fetchAll(PDO::FETCH_COLUMN);
if (!in_array($settings['database'], $databases, true)) {
    $bad("The database {$settings['database']} does not exist on this MySQL server.");
    $hint('Databases found: ' . implode(', ', $databases));
    $hint('Run database\maldetect_full_install.sql (phpMyAdmin > Import, or MySQL Workbench), or fix the database name in config\database.local.php.');
    exit(1);
}
$ok('exists');

$expected = ['users', 'scans', 'audit_logs', 'login_attempts', 'superadmin_otp_requests', 'superadmin_otps', 'devices', 'device_detections', 'device_commands', 'virustotal_requests', 'file_activity_events'];
$problems = 0;
foreach ($expected as $table) {
    try {
        $rows = (int) $server->query("SELECT COUNT(*) FROM `{$settings['database']}`.`{$table}`")->fetchColumn();
        $ok(str_pad($table, 26) . " {$rows} row(s)");
    } catch (PDOException $exception) {
        $problems++;
        $bad(str_pad($table, 26) . ' ' . $exception->getMessage());
    }
}
if ($problems > 0) {
    $hint('Missing tables: run database\maldetect_full_install.sql. "doesn\'t exist in engine" or "in use": the table files are damaged; stop MySQL, delete the folder mysql\\data\\<database name> in XAMPP, start MySQL, create the database again and import maldetect_full_install.sql.');
    exit(1);
}

echo "\n5. Login accounts\n";
$accounts = $server->query("SELECT username, role, is_active FROM `{$settings['database']}`.users ORDER BY id")->fetchAll(PDO::FETCH_ASSOC);
foreach ($accounts as $account) {
    echo "  {$account['username']} ({$account['role']})" . ((int) $account['is_active'] === 1 ? '' : '  [disabled]') . "\n";
}
if (!$accounts) {
    $bad('No accounts. Run database\maldetect_full_install.sql to create superadmin, admin and user (password ChangeMe123!).');
    exit(1);
}

echo "\nEverything works. If the login page still says \"Unable to complete login\", restart Apache in the XAMPP Control Panel.\n";
