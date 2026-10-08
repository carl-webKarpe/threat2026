<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="MalDetect is an intelligent malicious software detection system for clear, confident file security analysis.">
    <meta name="theme-color" content="#071016">
    <title>@yield('title', 'MalDetect | Intelligent Malicious Software Detection')</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Manrope', 'sans-serif'],
                        mono: ['DM Mono', 'monospace']
                    },
                    colors: {
                        ink: '#071016',
                        panel: '#0d1a20',
                        mint: '#8ef0c4',
                        signal: '#f4c95d',
                        fog: '#aabcc0'
                    }
                }
            }
        };
    </script>
    <link rel="stylesheet" href="{{ asset('css/app.css') }}">
    @stack('head')
</head>
<body class="bg-ink text-white antialiased">
    @yield('content')
    <script src="{{ asset('js/app.js') }}" defer></script>
    @stack('scripts')
</body>
</html>
