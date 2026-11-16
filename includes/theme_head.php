<?php
// Shared <head> part of every JunMalware page: Tailwind with the theme colors and fonts, and the base styles.
// Dark "modern tech" theme: near-black background, dark panels, electric blue accent, wide display font.
?>
<script src="https://cdn.tailwindcss.com"></script>
<script>
    tailwind.config = { theme: { extend: {
        fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], display: ['Michroma', 'Inter', 'sans-serif'], mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'] },
        colors: { ink: '#07070b', panel: '#0f0f15', panel2: '#16161e', accent: { DEFAULT: '#2b3bff', light: '#8f98ff', dark: '#1f2be0' } },
    } } };
</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Michroma&display=swap" rel="stylesheet">
<?php require __DIR__ . '/theme_styles.php'; ?>
