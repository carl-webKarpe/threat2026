<?php
// Base styles of every JunMalware page (dark "modern tech" theme). Included by includes/theme_head.php.
?>
<style>
    :root { color-scheme: dark; }
    body { font-family: Inter, system-ui, sans-serif; }
    .mono { font-family: 'JetBrains Mono', ui-monospace, monospace; }
    .font-display { font-family: Michroma, Inter, sans-serif; }
    /* Page background: near black with a faint blue glow and a fine grid, like a control room. */
    .shell { background: radial-gradient(circle at 85% -10%, rgba(43, 59, 255, .18), transparent 40%), linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px) 0 0 / 48px 48px, linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px) 0 0 / 48px 48px, #07070b; background-attachment: fixed; }
    /* New rows added by the live refresh get a short highlight. */
    @keyframes live-new { from { background: rgba(43, 59, 255, .22); } to { background: transparent; } }
    .live-new { animation: live-new 4s ease-out; }
    table thead { background: rgba(255, 255, 255, .03); }
    ::selection { background: #2b3bff; color: #fff; }
    :focus-visible { outline: 2px solid #8f98ff; outline-offset: 2px; }
    select option { background: #16161e; color: #f4f4f5; }
    input[type="date"] { color-scheme: dark; }
    ::-webkit-scrollbar { width: 10px; height: 10px; } ::-webkit-scrollbar-track { background: #0f0f15; } ::-webkit-scrollbar-thumb { background: #2a2a35; border-radius: 6px; }
    @media print { :root { color-scheme: light; } .shell { background: #fff !important; } }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; } }
</style>
