<?php
// Filters apply by themselves: every form marked data-auto-filter is sent as soon as a drop-down or date changes,
// and shortly after typing stops in a text field. The cursor goes back to that field after the page reloads.
// Without JavaScript the form keeps a normal Apply button (inside <noscript>).
// Usage: add data-auto-filter to the filter <form>, then require this file before the footer.
?>
<script>
(() => {
	const storageKey = 'maldetect-auto-filter-focus';
	const forms = document.querySelectorAll('form[data-auto-filter]');
	const send = (form, field) => {
		if (field && typeof field.selectionStart === 'number') {
			try { sessionStorage.setItem(storageKey, JSON.stringify({ name: field.name, position: field.selectionStart })); } catch (e) {}
		}
		// Only the filter values are sent (no empty fields), so the address stays short.
		const params = new URLSearchParams();
		new FormData(form).forEach((value, name) => { if (String(value).trim() !== '') params.append(name, value); });
		const query = params.toString();
		window.location.assign(window.location.pathname + (query ? '?' + query : ''));
	};
	forms.forEach((form) => {
		let timer = null;
		form.addEventListener('change', (event) => {
			if (event.target.matches('select, input[type="date"], input[type="checkbox"]')) send(form, null);
		});
		form.addEventListener('input', (event) => {
			if (!event.target.matches('input[type="search"], input[type="text"]')) return;
			clearTimeout(timer);
			timer = setTimeout(() => send(form, event.target), 700);
		});
		form.addEventListener('submit', (event) => { event.preventDefault(); clearTimeout(timer); send(form, document.activeElement); });
	});
	// Put the cursor back where it was when the page was reloaded by typing.
	try {
		const saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
		sessionStorage.removeItem(storageKey);
		const field = saved && document.querySelector(`form[data-auto-filter] [name="${CSS.escape(saved.name)}"]`);
		if (field) { field.focus(); const end = Math.min(saved.position ?? field.value.length, field.value.length); field.setSelectionRange(end, end); }
	} catch (e) {}
})();
</script>
