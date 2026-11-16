<?php
// Shared look of every MalDetect page (light theme). Included in <head> after the Tailwind script.
?>
<style>
    :root { color-scheme: light; }
    body { font-family: Inter, system-ui, sans-serif; }
    .mono { font-family: 'JetBrains Mono', ui-monospace, monospace; }
    .shell { background: #f4f6fb; }
    /* New rows added by the live refresh get a short highlight. */
    @keyframes live-new { from { background: rgba(37, 99, 235, .12); } to { background: transparent; } }
    .live-new { animation: live-new 4s ease-out; }
    table thead { background: #f8fafc; }
    ::selection { background: #bfdbfe; color: #0f172a; }
    :focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; }
    input[type="search"], input[type="text"], input[type="email"], input[type="password"], input[type="date"], input[type="number"], select, textarea { color: #0f172a; }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; } }
</style>
