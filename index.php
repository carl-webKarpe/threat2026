<?php

declare(strict_types=1);

$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$normalizedPath = trim($requestPath, '/');

if (basename($normalizedPath) === 'login') {
    header('Location: loginform.php');
    exit;
}

$viewPath = __DIR__ . '/resources/views/landing.blade.php';
$layoutPath = __DIR__ . '/resources/views/layouts/app.blade.php';

if (!is_file($viewPath) || !is_file($layoutPath)) {
    http_response_code(500);
    exit('MalDetect landing page files are missing.');
}

$view = file_get_contents($viewPath);
$layout = file_get_contents($layoutPath);

preg_match("/@section\\('content'\\)(.*?)@endsection/s", $view, $contentMatch);
$content = trim($contentMatch[1] ?? '');

preg_match("/@push\\('head'\\)(.*?)@endpush/s", $view, $headMatch);
$headExtras = trim($headMatch[1] ?? '');

$layout = preg_replace(
    "/@yield\\('title',\\s*'([^']*)'\\)/",
    '$1',
    $layout
);
$layout = str_replace("{{ asset('css/app.css') }}", 'resources/css/app.css', $layout);
$layout = str_replace("{{ asset('js/app.js') }}", 'resources/js/app.js', $layout);
$layout = str_replace(" asset('css/app.css') }}", 'resources/css/app.css', $layout);
$layout = str_replace(" asset('js/app.js') }}", 'resources/js/app.js', $layout);
$layout = str_replace("@stack('head')", $headExtras, $layout);
$layout = str_replace("@stack('scripts')", '', $layout);
$layout = str_replace('@yield(\'content\')', $content, $layout);

// The standalone entry point reuses the Blade source until Laravel is installed.
echo $layout;
