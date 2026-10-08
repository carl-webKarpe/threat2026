<?php

declare(strict_types=1);

require_once __DIR__ . '/../auth/role_check.php';
require_once __DIR__ . '/../auth/csrf.php';
require_once __DIR__ . '/../config/scanner.php';
require_role('admin');
$pageTitle = 'Scan File';
$currentPage = 'scan';
require_once __DIR__ . '/../includes/header.php';
?>
<div class="flex min-h-screen flex-col lg:flex-row">
	<div><?php require __DIR__ . '/../includes/admin_sidebar.php'; ?></div>
	<main class="min-w-0 flex-1 p-6 sm:p-10">
		<header class="border-b border-white/10 pb-8">
			<p class="mono text-xs tracking-[.2em] text-violet-300">SECURITY INTAKE</p>
			<h1 class="mt-3 text-3xl font-bold">Scan a File</h1>
			<p class="mt-2 max-w-2xl text-slate-400">Upload a file to prepare it for security analysis.</p>
		</header>

		<section class="mt-8 max-w-4xl" aria-labelledby="upload-heading">
			<h2 id="upload-heading" class="sr-only">File upload</h2>
			<form id="scanner-form" data-upload-url="../scanner/upload.php" data-csrf-token="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>" novalidate>
				<div id="drop-zone" class="rounded-2xl border border-dashed border-violet-300/35 bg-violet-300/[.04] p-8 text-center transition-colors sm:p-16" tabindex="0" role="button" aria-label="Choose a file to upload">
					<div class="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-violet-300/25 bg-violet-300/10 text-2xl text-violet-200" aria-hidden="true">↑</div>
					<p class="mt-6 text-lg font-semibold">Drag &amp; Drop your file here</p>
					<p class="mt-2 text-sm text-slate-500">or</p>
					<label class="mt-4 inline-flex cursor-pointer items-center rounded-xl bg-violet-300 px-5 py-3 text-sm font-bold text-slate-950 transition hover:bg-violet-200">
						Browse File
						<input id="file-input" class="sr-only" type="file" name="file" accept=".pdf,.txt,.csv,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.jpg,.jpeg,.png,.gif,.zip">
					</label>
					<p class="mt-5 text-xs text-slate-500">Maximum <?= htmlspecialchars(scanner_format_size(MAX_UPLOAD_SIZE), ENT_QUOTES, 'UTF-8') ?>. Supported documents, images, and ZIP archives.</p>
					<label class="mx-auto mt-6 flex max-w-xl items-start gap-3 text-left text-xs text-slate-400"><input id="privacy-acknowledged" class="mt-0.5" type="checkbox"><span>I understand that this file will be submitted to VirusTotal for analysis and may be shared according to VirusTotal policies.</span></label>
				</div>

				<p id="upload-error" class="mt-4 hidden rounded-xl border border-red-300/20 bg-red-400/10 px-4 py-3 text-sm text-red-200" role="alert"></p>
				<div id="file-preview" class="mt-6 hidden rounded-2xl border border-white/10 bg-white/[.04] p-5 sm:p-6">
					<div class="flex flex-col justify-between gap-5 sm:flex-row sm:items-center">
						<div class="min-w-0">
							<p class="mono text-[10px] tracking-[.18em] text-slate-500">SELECTED FILE</p>
							<p id="file-name" class="mt-2 truncate font-semibold"></p>
							<p id="file-meta" class="mt-1 text-sm text-slate-400"></p>
						</div>
						<button id="remove-file" type="button" class="shrink-0 rounded-xl border border-white/10 px-4 py-2 text-sm text-slate-300 hover:border-red-300/30 hover:text-red-200">Remove File</button>
					</div>
					<button id="upload-button" type="submit" class="mt-6 w-full rounded-xl bg-emerald-300 px-5 py-3 text-sm font-bold text-slate-950 transition hover:bg-emerald-200 disabled:cursor-not-allowed disabled:opacity-50">Upload &amp; Scan</button>
				</div>
			</form>
			<div id="scan-loading" class="mt-6 hidden rounded-2xl border border-violet-300/25 bg-violet-300/[.05] p-8 text-center sm:p-12" role="status" aria-live="polite">
				<div class="relative mx-auto grid h-20 w-20 place-items-center rounded-full border border-violet-300/30 text-3xl text-violet-200"><span class="absolute inset-0 animate-ping rounded-full border border-violet-300/20"></span><span aria-hidden="true">⌕</span></div>
				<p class="mono mt-7 text-xs tracking-[.2em] text-violet-300">SCANNING FILE...</p>
				<h2 class="mt-3 text-2xl font-bold">MalDetect is analyzing your file</h2>
				<p id="scan-file-name" class="mt-2 truncate text-sm text-violet-200"></p>
				<p id="scan-status-message" class="mt-3 text-sm text-slate-400">Preparing your file...</p>
				<div class="mx-auto mt-7 h-1 max-w-sm overflow-hidden rounded-full bg-white/10"><div class="scan-progress h-full w-1/2 rounded-full bg-violet-300"></div></div>
				<p class="mt-4 text-xs text-slate-500">This may take several minutes. Please keep this page open.</p>
			</div>
			<div id="upload-result" class="mt-6 hidden rounded-2xl border border-emerald-300/25 bg-emerald-300/[.06] p-6" role="status" aria-live="polite">
				<p class="mono text-xs tracking-[.18em] text-emerald-300">SCAN COMPLETE</p>
				<h2 id="result-headline" class="mt-3 text-2xl font-bold">Analysis complete</h2>
				<dl class="mt-5 grid gap-4 text-sm sm:grid-cols-2">
					<div><dt class="text-slate-500">File Name</dt><dd data-result="filename" class="mt-1 break-words font-semibold"></dd></div>
					<div><dt class="text-slate-500">File Size</dt><dd data-result="size" class="mt-1 font-semibold"></dd></div>
					<div><dt class="text-slate-500">File Type</dt><dd data-result="mime_type" class="mt-1 break-words font-semibold"></dd></div>
					<div><dt class="text-slate-500">Status</dt><dd data-result="status" class="mt-1 font-semibold text-emerald-200"></dd></div>
					<div><dt class="text-slate-500">Risk Level</dt><dd data-result="risk_level" class="mt-1 font-semibold"></dd></div>
					<div><dt class="text-slate-500">Safety Indicator</dt><dd data-result="safety_percentage" class="mt-1 font-semibold"></dd></div>
					<div><dt class="text-slate-500">Threat Information</dt><dd data-result="threat_name" class="mt-1 break-words font-semibold"></dd></div>
					<div><dt class="text-slate-500">Detection Count</dt><dd data-result="detection_count" class="mt-1 font-semibold"></dd></div>
					<div><dt class="text-slate-500">Total Engines</dt><dd data-result="total_engines" class="mt-1 font-semibold"></dd></div>
					<div><dt class="text-slate-500">Scanned At</dt><dd data-result="scanned_at" class="mt-1 font-semibold text-slate-400"></dd></div>
					<div class="sm:col-span-2"><dt class="text-slate-500">SHA-256</dt><dd data-result="sha256" class="mt-1 break-all font-mono text-xs text-violet-200"></dd></div>
					<div class="sm:col-span-2"><dt class="text-slate-500">Detection Results</dt><dd class="mt-1 grid grid-cols-2 gap-2 text-slate-300 sm:grid-cols-4"><span>Malicious: <strong data-result="malicious_count"></strong></span><span>Suspicious: <strong data-result="suspicious_count"></strong></span><span>Harmless: <strong data-result="harmless_count"></strong></span><span>Undetected: <strong data-result="undetected_count"></strong></span></dd></div>
					<div class="sm:col-span-2"><dt class="text-slate-500">Detection Information</dt><dd data-result="summary" class="mt-1 text-slate-300"></dd></div>
					<div class="sm:col-span-2"><dt class="text-slate-500">Scan Date</dt><dd data-result="scanned_at" class="mt-1 text-slate-300"></dd></div>
				</dl>
				<button id="new-scan" type="button" class="mt-7 rounded-xl border border-white/10 px-5 py-3 text-sm font-semibold text-slate-200 hover:border-violet-300/40 hover:text-white">Scan Another File</button>
			</div>
		</section>
	</main>
</div>
<script>
document.addEventListener('DOMContentLoaded', () => {
	const form = document.querySelector('#scanner-form');
	const input = document.querySelector('#file-input');
	const dropZone = document.querySelector('#drop-zone');
	const preview = document.querySelector('#file-preview');
	const error = document.querySelector('#upload-error');
	const loading = document.querySelector('#scan-loading');
	const loadingMessage = document.querySelector('#scan-status-message');
	const result = document.querySelector('#upload-result');
	const scanFileName = document.querySelector('#scan-file-name');
	const maxSize = <?= (int) MAX_UPLOAD_SIZE ?>;
	const allowedExtensions = <?= json_encode(scanner_allowed_extensions(), JSON_THROW_ON_ERROR) ?>;
	const privacyAcknowledged = document.querySelector('#privacy-acknowledged');
	const statusUrl = '../scanner/status.php';
	const activeScanStorageKey = 'maldetect_active_scan';
	let selectedFile = null;
	let pollTimer = null;
	let pollInFlight = false;
	let scanStartedAt = 0;

	const showError = (message) => { error.textContent = message; error.classList.toggle('hidden', !message); };
	const uploadErrorMessage = (payload, response) => {
		if (payload.http_status === 401) return 'VirusTotal authentication failed. Check the server-side API key.';
		if (payload.http_status === 403) return 'VirusTotal access was forbidden for this API key.';
		if (payload.http_status === 429) return 'VirusTotal rate limit reached. Please try again later.';
		if (payload.http_status >= 500) return 'VirusTotal is temporarily unavailable. Please try again later.';
		return payload.error_message || payload.message || `Upload failed (HTTP ${response.status}).`;
	};
	const resetSelection = () => { selectedFile = null; input.value = ''; preview.classList.add('hidden'); showError(''); };
	const setLoading = (message) => { loadingMessage.textContent = message; loading.classList.remove('hidden'); };
	const stopPolling = () => { if (pollTimer) window.clearTimeout(pollTimer); pollTimer = null; };
	const restoreUpload = () => { form.classList.remove('hidden'); const button = document.querySelector('#upload-button'); button.disabled = false; button.textContent = 'Upload & Scan'; };
	const showResult = (scan) => {
		stopPolling(); window.localStorage.removeItem(activeScanStorageKey); loading.classList.add('hidden'); result.classList.remove('hidden');
		result.querySelector('#result-headline').textContent = scan.result === 'MALICIOUS' ? 'Threat Detected' : scan.result === 'NO_THREAT_DETECTED' ? 'No Threat Detected' : 'Analysis Complete';
		Object.entries(scan).forEach(([key, value]) => { const target = result.querySelector(`[data-result="${key}"]`); if (target) target.textContent = value ?? 'Not provided'; });
		const safety = result.querySelector('[data-result="safety_percentage"]');
		if (safety && scan.safety_percentage !== null && scan.safety_percentage !== undefined) safety.textContent = `${Number(scan.safety_percentage).toFixed(2)}% (application-derived)`;
	};
	const pollStatus = async (scanId) => {
		if (pollInFlight) return;
		if (Date.now() - scanStartedAt > 300000) { stopPolling(); setLoading('VirusTotal is taking longer than expected. Your scan is still being processed.'); showError('The scan is still processing. Check Scan History for updates.'); return; }
		pollInFlight = true;
		try {
			const response = await fetch(`${statusUrl}?id=${encodeURIComponent(scanId)}`, { headers: { Accept: 'application/json' } });
			const payload = await response.json();
			if (response.status === 429) { stopPolling(); window.localStorage.removeItem(activeScanStorageKey); setLoading('VirusTotal request limit reached. Please try again later.'); showError('VirusTotal request limit reached. Please try again later.'); return; }
			if (!response.ok || !payload.success) throw new Error(payload.message || 'Unable to retrieve scan status.');
			const scan = payload.scan;
			if (scan.status === 'completed') { setLoading('Finalizing scan results...'); showResult(scan); return; }
			if (scan.status === 'failed') { stopPolling(); window.localStorage.removeItem(activeScanStorageKey); loading.classList.add('hidden'); restoreUpload(); showError(scan.summary || 'Unable to complete the malware analysis. Please try again.'); return; }
			loadingMessage.textContent = scan.status === 'queued' ? 'Uploading file for analysis...' : 'Checking security engines...';
			pollTimer = window.setTimeout(() => pollStatus(scanId), 2500);
		} catch (statusError) {
			loadingMessage.textContent = 'Connection interrupted. Checking scan status...';
			showError('Connection interrupted. Checking scan status...');
			pollTimer = window.setTimeout(() => pollStatus(scanId), 2500);
		} finally {
			pollInFlight = false;
		}
	};
	const inspectFile = (file) => {
		if (!file) { showError('Please select a file.'); return; }
		const extension = file.name.split('.').pop()?.toLowerCase() || '';
		if (file.size > maxSize) { resetSelection(); showError('File size exceeds the maximum allowed size.'); return; }
		if (!allowedExtensions.includes(extension)) { resetSelection(); showError('This file type is not supported.'); return; }
		selectedFile = file;
		document.querySelector('#file-name').textContent = file.name;
		document.querySelector('#file-meta').textContent = `${(file.size / 1024 / 1024).toFixed(2)} MB · .${extension} · ${file.type || 'Type detected on upload'}`;
		preview.classList.remove('hidden'); showError('');
	};
	input.addEventListener('change', () => inspectFile(input.files[0]));
	['dragenter', 'dragover'].forEach((eventName) => dropZone.addEventListener(eventName, (event) => { event.preventDefault(); dropZone.classList.add('border-violet-200', 'bg-violet-300/10'); }));
	['dragleave', 'drop'].forEach((eventName) => dropZone.addEventListener(eventName, (event) => { event.preventDefault(); dropZone.classList.remove('border-violet-200', 'bg-violet-300/10'); }));
	dropZone.addEventListener('drop', (event) => inspectFile(event.dataTransfer.files[0]));
	dropZone.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); } });
	document.querySelector('#remove-file').addEventListener('click', resetSelection);
	form.addEventListener('submit', async (event) => {
		event.preventDefault();
		if (!selectedFile) { showError('Please select a file.'); return; }
		if (!privacyAcknowledged.checked) { showError('Please acknowledge that this file will be submitted to VirusTotal.'); return; }
		const button = document.querySelector('#upload-button');
		button.disabled = true; button.textContent = 'Scanning...'; showError(''); scanFileName.textContent = selectedFile.name; setLoading('Preparing your file...');
		const body = new FormData(); body.append('file', selectedFile); body.append('privacy_acknowledged', '1');
		setLoading('Uploading file for analysis...');
		try {
			const response = await fetch(form.dataset.uploadUrl, { method: 'POST', headers: { 'X-CSRF-Token': form.dataset.csrfToken }, body });
			const payload = await response.json();
			if (!response.ok || !payload.success) {
				console.error('MalDetect upload diagnostic', { http_status: payload.http_status ?? response.status, error_code: payload.error_code ?? null, error_message: payload.error_message ?? payload.message ?? 'Unknown error' });
				throw new Error(uploadErrorMessage(payload, response));
			}
			resetSelection(); form.classList.add('hidden'); scanStartedAt = Date.now(); setLoading('MalDetect is analyzing your file...'); pollStatus(payload.scan.id);
			window.localStorage.setItem(activeScanStorageKey, JSON.stringify({ id: payload.scan.id, filename: payload.scan.filename, startedAt: scanStartedAt }));
		} catch (uploadError) { loading.classList.add('hidden'); showError(uploadError.message || 'The upload failed.'); button.disabled = false; button.textContent = 'Upload & Scan'; }
	});
	document.querySelector('#new-scan').addEventListener('click', () => { window.localStorage.removeItem(activeScanStorageKey); result.classList.add('hidden'); form.classList.remove('hidden'); document.querySelector('#upload-button').disabled = false; document.querySelector('#upload-button').textContent = 'Upload & Scan'; });
	try {
		const activeScan = JSON.parse(window.localStorage.getItem(activeScanStorageKey) || 'null');
		if (activeScan && Number.isInteger(Number(activeScan.id))) {
			form.classList.add('hidden'); scanFileName.textContent = activeScan.filename || 'Selected file'; scanStartedAt = Number(activeScan.startedAt) || Date.now(); setLoading('Checking security engines...'); pollStatus(Number(activeScan.id));
		}
	} catch (storageError) {
		window.localStorage.removeItem(activeScanStorageKey);
	}
});
</script>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
