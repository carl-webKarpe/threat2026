<?php

declare(strict_types=1);

const VIRUSTOTAL_API_BASE_URL = 'https://www.virustotal.com/api/v3';

final class VirusTotalApiException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $httpStatus = 0,
        public readonly string $apiCode = '',
        public readonly string $apiMessage = '',
        public readonly string $curlMessage = '',
    ) {
        parent::__construct($message);
    }
}

function virustotal_api_key(): string
{
    static $apiKey;
    if ($apiKey !== null) {
        return $apiKey;
    }

    $apiKey = trim((string) (getenv('VIRUSTOTAL_API_KEY') ?: getenv('MALDETECT_VT_API_KEY') ?: ''));
    $localConfig = __DIR__ . '/scanner.local.php';
    if ($apiKey === '' && is_file($localConfig)) {
        $configuration = require $localConfig;
        if (is_array($configuration)) {
            $apiKey = trim((string) ($configuration['virustotal_api_key'] ?? ''));
        }
    }

    if ($apiKey === 'YOUR_VIRUSTOTAL_API_KEY_HERE') {
        $apiKey = '';
    }

    return $apiKey;
}

/** @return array<string, mixed> */
function virustotal_request(string $method, string $path, ?string $filePath = null, string $filename = '', string $mimeType = ''): array
{
    $apiKey = virustotal_api_key();
    if ($apiKey === '') {
        throw new VirusTotalApiException('VirusTotal API key is not configured.');
    }

    $curl = curl_init(VIRUSTOTAL_API_BASE_URL . $path);
    if ($curl === false) {
        throw new VirusTotalApiException('Could not initialize the malware analysis client.');
    }

    $options = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 45,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'x-apikey: ' . $apiKey,
        ],
    ];

    if ($filePath !== null) {
        if (!is_readable($filePath)) {
            curl_close($curl);
            throw new VirusTotalApiException('The stored file is not readable.');
        }
        $options[CURLOPT_POSTFIELDS] = [
            'file' => new CURLFile($filePath, $mimeType ?: 'application/octet-stream', $filename ?: basename($filePath)),
        ];
    }

    curl_setopt_array($curl, $options);
    $body = curl_exec($curl);
    $curlError = curl_error($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($body === false) {
        throw new VirusTotalApiException('VirusTotal request failed.', 0, '', '', $curlError);
    }

    $payload = json_decode($body, true);
    if (!is_array($payload)) {
        throw new VirusTotalApiException('VirusTotal returned an invalid response.', $status);
    }
    if ($status < 200 || $status >= 300) {
        $apiError = is_array($payload['error'] ?? null) ? $payload['error'] : [];
        $apiCode = is_string($apiError['code'] ?? null) ? $apiError['code'] : '';
        $apiMessage = is_string($apiError['message'] ?? null) ? $apiError['message'] : 'The malware service rejected the request.';
        throw new VirusTotalApiException('VirusTotal request was rejected.', $status, $apiCode, $apiMessage);
    }

    return $payload;
}

/** @return array<string, mixed> */
function virustotal_upload(string $filePath, string $filename, string $mimeType): array
{
    return virustotal_request('POST', '/files', $filePath, $filename, $mimeType);
}

/** @return array<string, mixed> */
function virustotal_analysis(string $analysisId): array
{
    return virustotal_request('GET', '/analyses/' . rawurlencode($analysisId));
}

/** @return array<string, mixed> */
function virustotal_file_report(string $sha256): array
{
    return virustotal_request('GET', '/files/' . rawurlencode($sha256));
}