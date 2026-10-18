
<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Manila');

// Change this to the folder you want to monitor.
$folder = 'C:/Users/YOUR_USERNAME/Downloads';

// Store monitoring data outside your public website.
$stateDir = 'C:/maldetect-private';

if (!is_dir($folder)) {
    exit("Error: Monitored folder does not exist.\n");
}

if (!is_dir($stateDir)) {
    mkdir($stateDir, 0700, true);
}

$snapshotFile = $stateDir . '/snapshot.json';
$eventsFile = $stateDir . '/events.jsonl';

$current = [];

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(
        $folder,
        FilesystemIterator::SKIP_DOTS
    )
);

foreach ($iterator as $file) {
    if (!$file->isFile() || $file->isLink()) {
        continue;
    }

    $path = $file->getPathname();
    $hash = hash_file('sha256', $path);

    if ($hash !== false) {
        $current[substr($path, strlen($folder) + 1)] = [
            'hash' => $hash,
            'size' => $file->getSize()
        ];
    }
}

$previous = null;

if (is_file($snapshotFile)) {
    $data = json_decode(
        file_get_contents($snapshotFile),
        true
    );

    if (!is_array($data)) {
        exit("Error: Invalid previous snapshot.\n");
    }

    $previous = $data;
}

if ($previous === null) {
    file_put_contents(
        $snapshotFile,
        json_encode($current, JSON_PRETTY_PRINT),
        LOCK_EX
    );

    echo "Initial file baseline created.\n";
    exit;
}

$events = [];
$time = date(DATE_ATOM);

foreach ($current as $path => $details) {
    if (!isset($previous[$path])) {
        $events[] = [
            'time' => $time,
            'event' => 'NEW_FILE',
            'file' => $path
        ];
    } elseif (
        ($previous[$path]['hash'] ?? '') !== $details['hash']
    ) {
        $events[] = [
            'time' => $time,
            'event' => 'MODIFIED_FILE',
            'file' => $path
        ];
    }
}

foreach ($previous as $path => $details) {
    if (!isset($current[$path])) {
        $events[] = [
            'time' => $time,
            'event' => 'DELETED_FILE',
            'file' => $path
        ];
    }
}

if ($events !== []) {
    $handle = fopen($eventsFile, 'ab');

    if ($handle === false) {
        exit("Error: Cannot write event log.\n");
    }

    foreach ($events as $event) {
        fwrite(
            $handle,
            json_encode($event) . PHP_EOL
        );

        echo '[' . $event['event'] . '] '
            . $event['file'] . PHP_EOL;
    }

    fclose($handle);
} else {
    echo "No file changes detected.\n";
}

file_put_contents(
    $snapshotFile,
    json_encode($current, JSON_PRETTY_PRINT),
    LOCK_EX
);
