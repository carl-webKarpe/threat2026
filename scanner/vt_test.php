<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../config/virustotal.php';

require_role('admin');

$status = 0;
$apiCode = '';
$apiMessage = '';
$connectionState = 'FAILED';

try {
    virustotal_request('GET', '/users/me');
    $status = 200;
    $connectionState = 'SUCCESS';
} catch (VirusTotalApiException $exception) {
    $status = $exception->httpStatus;
    $apiMessage = 'Connection failed. Check the server log for details.';
    if ($exception->getMessage() === 'VirusTotal API key is not configured.') {
        $apiMessage = 'API key is not configured.';
    }
    error_log(sprintf(
        'VirusTotal connection test: HTTP %d; API code: %s; API message: %s; cURL error: %s',
        $status,
        $apiCode ?: 'none',
        $apiMessage,
        $exception->curlMessage ?: 'none',
    ));
} catch (Throwable $exception) {
    error_log($exception->getMessage());
    $apiMessage = 'Unexpected connection failure. Check the server log for details.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>VirusTotal Connection Test</title></head>
<body>
<h1>VirusTotal Connection: <?= htmlspecialchars($connectionState, ENT_QUOTES, 'UTF-8') ?></h1>
<p>API key configured: <?= virustotal_api_key() !== '' ? 'YES' : 'NO' ?></p>
<p>HTTP Status: <?= (int) $status ?></p>
<?php if ($apiCode !== '' || $apiMessage !== ''): ?><p>API Error: <?= htmlspecialchars(trim($apiCode . ($apiCode !== '' ? ': ' : '') . $apiMessage), ENT_QUOTES, 'UTF-8') ?></p><?php endif; ?>
<p>Delete or disable <code>scanner/vt_test.php</code> after testing.</p>
</body>
</html>