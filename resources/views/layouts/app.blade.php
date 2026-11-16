<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="JunMalware is an intelligent malicious software detection system: it checks every download on your monitored PCs with VirusTotal and records file activity in real time.">
    <meta name="theme-color" content="#07070b">
    <title>@yield('title', 'JunMalware | Intelligent Malicious Software Detection')</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Michroma&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], display: ['Michroma', 'Inter', 'sans-serif'] },
                    colors: { ink: '#07070b', panel: '#0f0f15', panel2: '#16161e', accent: { DEFAULT: '#2b3bff', light: '#8f98ff', dark: '#1f2be0' } }
                }
            }
        };
    </script>
    <link rel="stylesheet" href="{{ asset('css/app.css') }}">
    @stack('head')
</head>
<body class="bg-ink text-neutral-200 antialiased">
    @yield('content')
    <script src="{{ asset('js/app.js') }}" defer></script>
    @stack('scripts')
</body>
</html>
