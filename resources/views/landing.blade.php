@extends('layouts.app')

@section('title', 'JunMalware | Intelligent Malicious Software Detection')

@section('content')
<header data-nav class="site-nav fixed inset-x-0 top-0 z-50 border-b border-transparent">
    <div class="mx-auto flex max-w-7xl items-center justify-between px-6 py-5 lg:px-10">
        <a href="#home" class="font-display text-sm uppercase tracking-[.3em] text-white" aria-label="JunMalware home">Jun<span class="text-accent-light">M</span>alware</a>
        <nav class="hidden items-center gap-10 text-[11px] uppercase tracking-[.3em] text-neutral-400 md:flex" aria-label="Primary navigation">
            <a class="transition hover:text-white" href="#home">Home</a><a class="transition hover:text-white" href="#features">Features</a><a class="transition hover:text-white" href="#process">Process</a><a class="transition hover:text-white" href="#about">About</a>
        </nav>
        <div class="flex items-center gap-3">
            <a href="loginform.php" class="hidden rounded border border-white/20 px-4 py-2 text-[11px] uppercase tracking-[.25em] text-white transition hover:border-accent hover:bg-accent md:inline-block">Sign in</a>
            <button data-menu-button aria-expanded="false" aria-controls="mobile-menu" class="grid h-10 w-10 place-items-center rounded border border-white/15 text-white md:hidden"><i class="fa-solid fa-bars"></i><span class="sr-only">Open menu</span></button>
        </div>
    </div>
    <nav id="mobile-menu" data-mobile-menu class="mx-6 mb-4 hidden rounded-lg border border-white/10 bg-panel/95 p-3 backdrop-blur md:hidden" aria-label="Mobile navigation">
        <a class="block px-3 py-2.5 text-xs uppercase tracking-[.25em] text-neutral-300" href="#features">Features</a><a class="block px-3 py-2.5 text-xs uppercase tracking-[.25em] text-neutral-300" href="#process">Process</a><a class="block px-3 py-2.5 text-xs uppercase tracking-[.25em] text-neutral-300" href="#about">About</a><a class="mt-2 block rounded bg-accent px-3 py-2.5 text-center text-xs uppercase tracking-[.25em] text-white" href="loginform.php">Sign in</a>
    </nav>
</header>

<main id="home">
    <section class="hero-bg relative overflow-hidden">
        <div class="hero-grid pointer-events-none absolute inset-0"></div>
        <ol class="absolute right-6 top-1/2 hidden -translate-y-1/2 space-y-5 text-[11px] text-neutral-500 lg:block" aria-hidden="true"><li class="text-white">01</li><li>02</li><li>03</li><li>04</li></ol>
        <div class="relative mx-auto grid min-h-screen max-w-7xl items-center gap-12 px-6 pb-20 pt-32 lg:grid-cols-[1.1fr_.9fr] lg:px-10">
            <div>
                <p class="text-xs uppercase tracking-[.45em] text-neutral-300">Here and now</p>
                <h1 class="relative isolate mt-6 font-display text-5xl uppercase leading-[1.05] tracking-[.1em] text-white sm:text-6xl xl:text-7xl"><span class="relative inline-block"><span class="absolute -inset-y-3 -left-4 right-[-.12em] -z-10 bg-accent" aria-hidden="true"></span>J</span>un<br>Malware</h1>
                <div class="mt-10 flex max-w-lg gap-5">
                    <span class="mt-1 h-20 w-px shrink-0 bg-white/25" aria-hidden="true"></span>
                    <p class="text-sm leading-7 text-neutral-400">Intelligent malicious software detection for your computer lab. Every download on your monitored PCs is checked with VirusTotal, file activity is recorded in real time, and administrators are alerted the moment a threat appears.</p>
                </div>
                <div class="mt-10 flex flex-wrap items-center gap-4"><a href="loginform.php" class="rounded bg-accent px-6 py-3 text-[11px] font-semibold uppercase tracking-[.3em] text-white shadow-lg shadow-accent/30 transition hover:bg-accent-dark">Let's go <i class="fa-solid fa-arrow-right ml-2"></i></a><a href="#features" class="px-2 py-3 text-[11px] uppercase tracking-[.3em] text-neutral-400 transition hover:text-white">Explore features</a></div>
            </div>
            <div class="reveal relative flex flex-col items-center gap-12 lg:items-end">
                <div class="scanner">
                    <span class="ring r1"></span><span class="ring r2"></span><span class="ring r3"></span>
                    <div class="core"><i class="fa-solid fa-shield-halved relative z-10 text-3xl text-white"></i></div>
                    <span class="absolute left-[-6%] top-[18%] hidden items-center gap-3 text-[10px] uppercase tracking-[.25em] text-neutral-400 sm:flex">Real-time monitoring <span class="h-px w-16 bg-white/30"></span></span>
                    <span class="absolute bottom-[20%] right-[-4%] hidden items-center gap-3 text-[10px] uppercase tracking-[.25em] text-neutral-400 sm:flex"><span class="h-px w-16 bg-white/30"></span> VirusTotal engines</span>
                </div>
                <div class="hidden w-full max-w-[440px] grid-cols-2 gap-8 border-t border-white/10 pt-5 lg:grid">
                    <div><p class="text-[11px] uppercase tracking-[.25em] text-white">Detection</p><p class="mt-2 text-xs leading-5 text-neutral-500">Malicious, suspicious or no threat detected, for every download.</p></div>
                    <div><p class="text-[11px] uppercase tracking-[.25em] text-white">Monitoring</p><p class="mt-2 text-xs leading-5 text-neutral-500">Created, renamed, moved and deleted files, as they happen.</p></div>
                </div>
            </div>
        </div>
    </section>

    <section id="features" class="mx-auto max-w-7xl px-6 py-28 lg:px-10">
        <div class="reveal flex flex-col justify-between gap-6 md:flex-row md:items-end"><div><p class="text-[11px] uppercase tracking-[.4em] text-accent-light">02 / Features</p><h2 class="mt-4 font-display text-2xl uppercase tracking-[.1em] text-white sm:text-3xl">Built to watch the lab</h2></div><p class="max-w-sm text-sm leading-7 text-neutral-400">A small agent runs on each monitored PC and reports to your JunMalware server. Administrators see everything in one place.</p></div>
        <div class="mt-14 grid gap-px overflow-hidden rounded-xl border border-white/10 bg-white/10 sm:grid-cols-2 lg:grid-cols-4">
            <div class="feature-card reveal bg-ink p-7"><i class="fa-solid fa-download text-xl text-accent-light"></i><h3 class="mt-8 text-[11px] uppercase tracking-[.25em] text-white">Download scanning</h3><p class="mt-3 text-sm leading-6 text-neutral-400">Every finished download is checked with VirusTotal: malicious, suspicious or no threat detected.</p></div>
            <div class="feature-card reveal bg-ink p-7"><i class="fa-solid fa-wave-square text-xl text-accent-light"></i><h3 class="mt-8 text-[11px] uppercase tracking-[.25em] text-white">File activity</h3><p class="mt-3 text-sm leading-6 text-neutral-400">Files created, modified, renamed, moved or deleted on the Desktop, Documents, Downloads and more.</p></div>
            <div class="feature-card reveal bg-ink p-7"><i class="fa-solid fa-bell text-xl text-accent-light"></i><h3 class="mt-8 text-[11px] uppercase tracking-[.25em] text-white">Threat alerts</h3><p class="mt-3 text-sm leading-6 text-neutral-400">Administrators get an email as soon as a malicious or suspicious file is found on any PC.</p></div>
            <div class="feature-card reveal bg-ink p-7"><i class="fa-solid fa-chart-column text-xl text-accent-light"></i><h3 class="mt-8 text-[11px] uppercase tracking-[.25em] text-white">Reports</h3><p class="mt-3 text-sm leading-6 text-neutral-400">Filter by date, device and result, then export a CSV or print a PDF report.</p></div>
        </div>
    </section>

    <section id="process" class="border-y border-white/10 bg-panel px-6 py-28 lg:px-10">
        <div class="mx-auto max-w-7xl">
            <div class="reveal"><p class="text-[11px] uppercase tracking-[.4em] text-accent-light">03 / Process</p><h2 class="mt-4 font-display text-2xl uppercase tracking-[.1em] text-white sm:text-3xl">Three steps</h2></div>
            <div class="mt-14 grid gap-10 md:grid-cols-3">
                <div class="reveal border-l border-white/15 pl-6"><p class="font-display text-4xl text-accent">01</p><h3 class="mt-6 text-[11px] uppercase tracking-[.25em] text-white">Register the PC</h3><p class="mt-3 text-sm leading-6 text-neutral-400">An administrator registers each PC on the Devices page and gets its token.</p></div>
                <div class="reveal border-l border-white/15 pl-6"><p class="font-display text-4xl text-accent">02</p><h3 class="mt-6 text-[11px] uppercase tracking-[.25em] text-white">Install the agent</h3><p class="mt-3 text-sm leading-6 text-neutral-400">One command installs the agent. It starts by itself, hidden, every time someone signs in.</p></div>
                <div class="reveal border-l border-white/15 pl-6"><p class="font-display text-4xl text-accent">03</p><h3 class="mt-6 text-[11px] uppercase tracking-[.25em] text-white">Review the results</h3><p class="mt-3 text-sm leading-6 text-neutral-400">Downloads, threats and file activity appear on the server within seconds, with live updates.</p></div>
            </div>
        </div>
    </section>

    <section id="about" class="mx-auto max-w-7xl px-6 py-28 lg:px-10">
        <div class="reveal grid gap-12 lg:grid-cols-2 lg:items-start">
            <div><p class="text-[11px] uppercase tracking-[.4em] text-accent-light">04 / About</p><h2 class="mt-4 font-display text-2xl uppercase leading-snug tracking-[.1em] text-white sm:text-3xl">Clear decisions, privacy in mind</h2></div>
            <div><p class="text-sm leading-7 text-neutral-400">Nothing is shown on the monitored PCs; results appear only on the JunMalware server. For file activity only names, paths, sizes and times are recorded, never file contents. Access is separated by role:</p>
                <ul class="mt-8 divide-y divide-white/10 border-y border-white/10 text-sm"><li class="flex justify-between py-4"><span class="text-[11px] uppercase tracking-[.25em] text-white">Superadmin</span><span class="text-neutral-400">Accounts and audit logs</span></li><li class="flex justify-between py-4"><span class="text-[11px] uppercase tracking-[.25em] text-white">Admin</span><span class="text-neutral-400">Devices, scans and reports</span></li><li class="flex justify-between py-4"><span class="text-[11px] uppercase tracking-[.25em] text-white">User</span><span class="text-neutral-400">Personal workspace</span></li></ul></div>
        </div>
    </section>

    <section class="relative overflow-hidden border-t border-white/10 px-6 py-24 lg:px-10">
        <div class="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(43,59,255,.18),transparent_60%)]"></div>
        <div class="relative mx-auto max-w-3xl text-center"><h2 class="font-display text-2xl uppercase tracking-[.12em] text-white sm:text-4xl">Ready to review your lab?</h2><p class="mx-auto mt-5 max-w-lg text-sm leading-7 text-neutral-400">Sign in with the account your administrator created for you.</p><a href="loginform.php" class="mt-9 inline-block rounded bg-accent px-7 py-3 text-[11px] font-semibold uppercase tracking-[.3em] text-white shadow-lg shadow-accent/30 transition hover:bg-accent-dark">Sign in <i class="fa-solid fa-arrow-right ml-2"></i></a></div>
    </section>
</main>

<footer class="border-t border-white/10 px-6 py-10 lg:px-10"><div class="mx-auto flex max-w-7xl flex-col gap-6 md:flex-row md:items-center md:justify-between"><a href="#home" class="font-display text-xs uppercase tracking-[.3em] text-white">Jun<span class="text-accent-light">M</span>alware</a><div class="flex flex-wrap gap-8 text-[11px] uppercase tracking-[.25em] text-neutral-500"><a class="hover:text-white" href="#features">Features</a><a class="hover:text-white" href="#process">Process</a><a class="hover:text-white" href="#about">About</a><a class="hover:text-white" href="loginform.php">Sign in</a></div><p class="text-xs text-neutral-600">© 2026 JunMalware</p></div></footer>
@endsection

@push('head')
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
@endpush
