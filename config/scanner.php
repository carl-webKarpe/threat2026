<?php

declare(strict_types=1);

const MAX_UPLOAD_SIZE = 20 * 1024 * 1024;

const ALLOWED_FILE_TYPES = [
    'pdf' => ['application/pdf'],
    'txt' => ['text/plain'],
    'csv' => ['text/csv', 'text/plain'],
    'doc' => ['application/msword', 'application/octet-stream'],
    'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
    'xls' => ['application/vnd.ms-excel', 'application/octet-stream'],
    'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
    'ppt' => ['application/vnd.ms-powerpoint', 'application/octet-stream'],
    'pptx' => ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
    'jpg' => ['image/jpeg'],
    'jpeg' => ['image/jpeg'],
    'png' => ['image/png'],
    'gif' => ['image/gif'],
    'zip' => ['application/zip'],
];

function scanner_upload_directory(): string
{
    $configuredDirectory = trim((string) getenv('MALDETECT_UPLOAD_DIR'));
    if ($configuredDirectory !== '') {
        $documentRoot = realpath((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''));
        $configuredPath = rtrim($configuredDirectory, "\\/");
        if ($documentRoot !== false) {
            $documentRoot = rtrim($documentRoot, "\\/");
            $normalizedPath = str_replace('/', DIRECTORY_SEPARATOR, $configuredPath);
            $normalizedRoot = str_replace('/', DIRECTORY_SEPARATOR, $documentRoot);
            if (strncasecmp($normalizedPath, $normalizedRoot, strlen($normalizedRoot)) === 0) {
                throw new RuntimeException('Upload storage must be outside the web document root.');
            }
        }

        return $configuredPath;
    }

    return dirname(__DIR__, 3) . DIRECTORY_SEPARATOR . 'maldetect_uploads';
}

function scanner_allowed_extensions(): array
{
    return array_keys(ALLOWED_FILE_TYPES);
}

function scanner_format_size(int $bytes): string
{
    if ($bytes < 1024) {
        return $bytes . ' B';
    }

    $units = ['KB', 'MB', 'GB'];
    $size = $bytes;
    foreach ($units as $unit) {
        $size /= 1024;
        if ($size < 1024 || $unit === 'GB') {
            return number_format($size, $size < 10 ? 2 : 1) . ' ' . $unit;
        }
    }

    return $bytes . ' B';
}

/** @param array<string, mixed> $attributes
 *  @return array<string, mixed>
 */
function scanner_interpret_analysis(array $attributes): array
{
    $stats = is_array($attributes['stats'] ?? null)
        ? $attributes['stats']
        : (is_array($attributes['last_analysis_stats'] ?? null) ? $attributes['last_analysis_stats'] : []);
    $malicious = max(0, (int) ($stats['malicious'] ?? 0));
    $suspicious = max(0, (int) ($stats['suspicious'] ?? 0));
    $harmless = max(0, (int) ($stats['harmless'] ?? 0));
    $undetected = max(0, (int) ($stats['undetected'] ?? 0));
    $totalEngines = $malicious + $suspicious + $harmless + $undetected;
    $detectionCount = $malicious + $suspicious;
    $safetyPercentage = $totalEngines > 0
        ? round((($totalEngines - $malicious - $suspicious) / $totalEngines) * 100, 2)
        : null;
    $threatName = null;
    $engineResults = is_array($attributes['results'] ?? null)
        ? $attributes['results']
        : (is_array($attributes['last_analysis_results'] ?? null) ? $attributes['last_analysis_results'] : []);
    foreach ($engineResults as $engineResult) {
        if (!is_array($engineResult)) {
            continue;
        }
        $category = strtolower((string) ($engineResult['category'] ?? ''));
        $resultName = trim((string) ($engineResult['result'] ?? ''));
        if ($category === 'malicious' && $resultName !== '') {
            $threatName = $resultName;
            break;
        }
    }

    if ($malicious > 0) {
        $result = 'MALICIOUS';
        $riskLevel = 'Malicious';
    } elseif ($suspicious > 0) {
        $result = 'SUSPICIOUS';
        $riskLevel = 'Suspicious';
    } elseif ($totalEngines > 0) {
        $result = 'NO_THREAT_DETECTED';
        $riskLevel = 'No Threat Detected';
    } else {
        $result = 'UNKNOWN';
        $riskLevel = 'Unknown';
    }

    return [
        'scan_result' => $result,
        'risk_level' => $riskLevel,
        'threat_name' => $threatName,
        'safety_percentage' => $safetyPercentage,
        'detection_count' => $detectionCount,
        'malicious_count' => $malicious,
        'suspicious_count' => $suspicious,
        'harmless_count' => $harmless,
        'undetected_count' => $undetected,
        'total_engines' => $totalEngines,
        'scan_summary' => sprintf(
            'VirusTotal engines: %d malicious, %d suspicious, %d harmless, %d undetected.',
            $malicious,
            $suspicious,
            $harmless,
            $undetected,
        ),
    ];
}