<?php
// Live updates: every few seconds, re-fetches the current page and swaps in the new content of every
// element marked data-live-region="name". Rows with data-row-id that were not there before get a short
// highlight. Pauses while the tab is hidden; stops if the session expires.
// Usage: optionally set $liveRefreshSeconds, then require this file before the footer.
$liveRefreshSeconds = max(2, (int) ($liveRefreshSeconds ?? 5));
?>
<script>
(() => {
	const intervalMs = <?= $liveRefreshSeconds * 1000 ?>;
	const regions = () => document.querySelectorAll('[data-live-region]');
	if (!regions().length) return;
	const indicators = () => document.querySelectorAll('[data-live-indicator]');
	const setIndicator = (text, ok) => indicators().forEach((el) => {
		el.textContent = text;
		el.classList.toggle('text-emerald-300', ok);
		el.classList.toggle('text-amber-300', !ok);
	});
	// Last HTML received per region, so highlight classes added here do not count as changes.
	const lastHtml = new Map();
	let busy = false;
	let stopped = false;
	const refresh = async () => {
		if (busy || stopped || document.hidden) return;
		busy = true;
		try {
			const response = await fetch(window.location.href, { credentials: 'same-origin', cache: 'no-store', headers: { 'X-Requested-With': 'live-refresh' } });
			if (response.redirected || !response.ok) {
				// Usually a logout or expired session: the page redirected to the login form.
				stopped = response.redirected;
				setIndicator(stopped ? '● Live updates stopped (refresh the page)' : '● Live updates paused', false);
				return;
			}
			const page = new DOMParser().parseFromString(await response.text(), 'text/html');
			regions().forEach((region) => {
				const next = page.querySelector(`[data-live-region="${region.dataset.liveRegion}"]`);
				const name = region.dataset.liveRegion;
				if (!next || next.innerHTML === (lastHtml.get(name) ?? region.innerHTML)) return;
				lastHtml.set(name, next.innerHTML);
				const known = new Set([...region.querySelectorAll('[data-row-id]')].map((row) => row.dataset.rowId));
				region.innerHTML = next.innerHTML;
				region.querySelectorAll('[data-row-id]').forEach((row) => {
					if (!known.has(row.dataset.rowId)) row.classList.add('live-new');
				});
			});
			setIndicator('● Live · updated ' + new Date().toLocaleTimeString(), true);
		} catch (error) {
			setIndicator('● Live updates paused (connection problem)', false);
		} finally {
			busy = false;
		}
	};
	window.setInterval(refresh, intervalMs);
	document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
})();
</script>
