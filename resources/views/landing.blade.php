@extends('layouts.app')

@section('title', 'MalDetect | Intelligent Malicious Software Detection')

@section('content')
<header data-nav class="site-nav fixed inset-x-0 top-0 z-50 border-b border-transparent">
    <div class="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-10">
        <a href="#home" class="flex items-center gap-3" aria-label="MalDetect home">
            <span class="grid h-9 w-9 place-items-center rounded-lg bg-blue-600 text-white shadow-sm shadow-blue-600/30"><i class="fa-solid fa-shield-halved text-sm"></i></span>
            <span class="text-lg font-bold tracking-tight text-slate-900">MalDetect</span>
        </a>
        <nav class="hidden items-center gap-8 text-sm font-medium text-slate-600 md:flex" aria-label="Primary navigation">
            <a class="transition hover:text-blue-700" href="#features">Features</a><a class="transition hover:text-blue-700" href="#process">How It Works</a><a class="transition hover:text-blue-700" href="#about">About</a>
            <a href="loginform.php" class="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white shadow-sm transition hover:bg-blue-700">Sign in</a>
        </nav>
        <button data-menu-button aria-expanded="false" aria-controls="mobile-menu" class="grid h-10 w-10 place-items-center rounded-lg border border-slate-200 bg-white text-slate-700 md:hidden"><i class="fa-solid fa-bars"></i><span class="sr-only">Open menu</span></button>
    </div>
    <nav id="mobile-menu" data-mobile-menu class="mx-6 mb-4 hidden rounded-xl border border-slate-200 bg-white p-3 shadow-lg md:hidden" aria-label="Mobile navigation">
        <a class="block rounded-lg px-3 py-2.5 text-sm text-slate-700 hover:bg-slate-50" href="#features">Features</a><a class="block rounded-lg px-3 py-2.5 text-sm text-slate-700 hover:bg-slate-50" href="#process">How It Works</a><a class="block rounded-lg px-3 py-2.5 text-sm text-slate-700 hover:bg-slate-50" href="#about">About</a><a class="mt-2 block rounded-lg bg-blue-600 px-3 py-2.5 text-center text-sm font-semibold text-white" href="loginform.php">Sign in</a>
    </nav>
</header>

<main id="home">
    <section class="hero-bg relative overflow-hidden">
        <div class="hero-grid pointer-events-none absolute inset-0"></div>
        <div class="relative mx-auto grid max-w-7xl items-center gap-14 px-6 pb-24 pt-36 lg:grid-cols-[1.05fr_.95fr] lg:px-10 lg:pt-40">
            <div>
                <span class="inline-flex items-center gap-2 rounded-full border border-blue-200 bg-white px-3 py-1.5 text-xs font-semibold text-blue-700 shadow-sm"><span class="h-2 w-2 rounded-full bg-emerald-500"></span> Endpoint monitoring for computer labs</span>
                <h1 class="mt-6 text-4xl font-extrabold leading-[1.08] tracking-tight text-slate-900 sm:text-5xl lg:text-6xl">Intelligent <span class="text-blue-600">malicious software</span> detection</h1>
                <p class="mt-6 max-w-xl text-lg leading-8 text-slate-600">MalDetect checks every file downloaded on your monitored PCs with VirusTotal, records file activity in real time, and alerts administrators when a threat is found. All results stay on your own server.</p>
                <div class="mt-9 flex flex-wrap items-center gap-3"><a href="loginform.php" class="rounded-lg bg-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700">Sign in to MalDetect <i class="fa-solid fa-arrow-right ml-2"></i></a><a href="#features" class="rounded-lg border border-slate-300 bg-white px-6 py-3 text-sm font-semibold text-slate-700 shadow-sm transition hover:border-blue-300 hover:text-blue-700">See the features</a></div>
                <dl class="mt-12 grid max-w-lg grid-cols-3 gap-6 border-t border-slate-200 pt-6 text-sm">
                    <div><dt class="text-slate-500">Scanning</dt><dd class="mt-1 font-semibold text-slate-900">VirusTotal</dd></div>
                    <div><dt class="text-slate-500">Monitoring</dt><dd class="mt-1 font-semibold text-slate-900">Real time</dd></div>
                    <div><dt class="text-slate-500">Access</dt><dd class="mt-1 font-semibold text-slate-900">Role-based</dd></div>
                </dl>
            </div>
            <div class="reveal">
                <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-xl shadow-slate-900/5">
                    <div class="flex items-center justify-between border-b border-slate-100 pb-4"><span class="text-sm font-semibold text-slate-900">Device Detections</span><span class="rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-600 ring-1 ring-emerald-200">● Live</span></div>
                    <ul class="mt-2 divide-y divide-slate-100 text-sm">
                        <li class="flex items-center justify-between gap-3 py-3"><span><span class="block font-medium text-slate-900">setup_installer.exe</span><span class="text-xs text-slate-500">Lab A - PC 01 · Downloads</span></span><span class="rounded-full bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-700 ring-1 ring-red-200">Malicious</span></li>
                        <li class="flex items-center justify-between gap-3 py-3"><span><span class="block font-medium text-slate-900">lecture_notes.pdf</span><span class="text-xs text-slate-500">Lab A - PC 02 · Downloads</span></span><span class="rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700 ring-1 ring-emerald-200">No Threat Detected</span></li>
                        <li class="flex items-center justify-between gap-3 py-3"><span><span class="block font-medium text-slate-900">report.docx → final_report.docx</span><span class="text-xs text-slate-500">Lab A - PC 01 · Documents</span></span><span class="rounded-full bg-sky-50 px-2.5 py-1 text-xs font-semibold text-sky-700 ring-1 ring-sky-200">FILE_RENAMED</span></li>
                    </ul>
                    <p class="mt-3 text-xs text-slate-400">Example view. Real results appear after signing in.</p>
                </div>
            </div>
        </div>
    </section>

    <section id="features" class="mx-auto max-w-7xl px-6 py-24 lg:px-10">
        <div class="reveal max-w-2xl"><p class="text-sm font-semibold uppercase tracking-wider text-blue-600">Features</p><h2 class="mt-2 text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl">Everything an administrator needs to watch the lab</h2><p class="mt-4 text-base leading-7 text-slate-600">A small agent runs on each monitored PC and reports to your MalDetect server. Administrators see everything in one place.</p></div>
        <div class="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            <div class="feature-card reveal rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><span class="grid h-11 w-11 place-items-center rounded-lg bg-blue-50 text-blue-600"><i class="fa-solid fa-download"></i></span><h3 class="mt-5 text-base font-semibold text-slate-900">Download scanning</h3><p class="mt-2 text-sm leading-6 text-slate-600">Every finished download is checked with VirusTotal: malicious, suspicious or no threat detected.</p></div>
            <div class="feature-card reveal rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><span class="grid h-11 w-11 place-items-center rounded-lg bg-violet-50 text-violet-600"><i class="fa-solid fa-wave-square"></i></span><h3 class="mt-5 text-base font-semibold text-slate-900">File activity</h3><p class="mt-2 text-sm leading-6 text-slate-600">Files created, modified, renamed, moved or deleted on the Desktop, Documents, Downloads and more, in real time.</p></div>
            <div class="feature-card reveal rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><span class="grid h-11 w-11 place-items-center rounded-lg bg-red-50 text-red-600"><i class="fa-solid fa-bell"></i></span><h3 class="mt-5 text-base font-semibold text-slate-900">Threat alerts</h3><p class="mt-2 text-sm leading-6 text-slate-600">Administrators get an email as soon as a malicious or suspicious file is found on any PC.</p></div>
            <div class="feature-card reveal rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><span class="grid h-11 w-11 place-items-center rounded-lg bg-emerald-50 text-emerald-600"><i class="fa-solid fa-chart-column"></i></span><h3 class="mt-5 text-base font-semibold text-slate-900">Reports</h3><p class="mt-2 text-sm leading-6 text-slate-600">Filter by date, device and result, then export a CSV or print a PDF report.</p></div>
        </div>
    </section>

    <section id="process" class="border-y border-slate-200 bg-slate-50 px-6 py-24 lg:px-10">
        <div class="mx-auto max-w-7xl">
            <div class="reveal mx-auto max-w-xl text-center"><p class="text-sm font-semibold uppercase tracking-wider text-blue-600">How it works</p><h2 class="mt-2 text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl">Three steps to a monitored lab</h2></div>
            <div class="mt-14 grid gap-6 md:grid-cols-3">
                <div class="reveal rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><span class="grid h-10 w-10 place-items-center rounded-full bg-blue-600 text-sm font-bold text-white">1</span><h3 class="mt-5 text-base font-semibold text-slate-900">Register the PC</h3><p class="mt-2 text-sm leading-6 text-slate-600">An administrator registers each PC on the Devices page and gets its token.</p></div>
                <div class="reveal rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><span class="grid h-10 w-10 place-items-center rounded-full bg-blue-600 text-sm font-bold text-white">2</span><h3 class="mt-5 text-base font-semibold text-slate-900">Install the agent</h3><p class="mt-2 text-sm leading-6 text-slate-600">One command installs the agent. It starts by itself, hidden, every time someone signs in.</p></div>
                <div class="reveal rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><span class="grid h-10 w-10 place-items-center rounded-full bg-blue-600 text-sm font-bold text-white">3</span><h3 class="mt-5 text-base font-semibold text-slate-900">Review the results</h3><p class="mt-2 text-sm leading-6 text-slate-600">Downloads, threats and file activity appear on the server within seconds, with live updates.</p></div>
            </div>
        </div>
    </section>

    <section id="about" class="mx-auto max-w-7xl px-6 py-24 lg:px-10">
        <div class="reveal grid gap-10 lg:grid-cols-2 lg:items-center">
            <div><p class="text-sm font-semibold uppercase tracking-wider text-blue-600">About MalDetect</p><h2 class="mt-2 text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl">Built for clear decisions, with privacy in mind</h2></div>
            <div><p class="text-base leading-7 text-slate-600">Nothing is shown on the monitored PCs; results appear only on the MalDetect server. For file activity only names, paths, sizes and times are recorded, never file contents. Access is separated by role:</p>
                <div class="mt-6 flex flex-wrap gap-2"><span class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700">Superadmin: accounts and audit logs</span><span class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700">Admin: devices, scans and reports</span><span class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700">User: personal workspace</span></div></div>
        </div>
    </section>

    <section class="bg-blue-600 px-6 py-20 text-center lg:px-10">
        <div class="mx-auto max-w-2xl"><h2 class="text-3xl font-bold tracking-tight text-white sm:text-4xl">Ready to review your lab?</h2><p class="mx-auto mt-4 max-w-lg text-base leading-7 text-blue-100">Sign in with the account your administrator created for you.</p><a href="loginform.php" class="mt-8 inline-block rounded-lg bg-white px-6 py-3 text-sm font-semibold text-blue-700 shadow-sm transition hover:bg-blue-50">Sign in <i class="fa-solid fa-arrow-right ml-2"></i></a></div>
    </section>
</main>

<footer class="border-t border-slate-200 px-6 py-10 lg:px-10"><div class="mx-auto flex max-w-7xl flex-col gap-6 md:flex-row md:items-center md:justify-between"><div><a href="#home" class="text-base font-bold text-slate-900">MalDetect</a><p class="mt-2 max-w-xs text-sm text-slate-500">Intelligent Malicious Software Detection System.</p></div><div class="flex flex-wrap gap-6 text-sm text-slate-600"><a class="hover:text-blue-700" href="#features">Features</a><a class="hover:text-blue-700" href="#process">How It Works</a><a class="hover:text-blue-700" href="#about">About</a><a class="hover:text-blue-700" href="loginform.php">Sign in</a></div><p class="text-sm text-slate-400">© 2026 MalDetect</p></div></footer>
@endsection

@push('head')
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
@endpush
