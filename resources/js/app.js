document.addEventListener('DOMContentLoaded', () => {
    const nav = document.querySelector('[data-nav]');
    const menuButton = document.querySelector('[data-menu-button]');
    const mobileMenu = document.querySelector('[data-mobile-menu]');

    const updateNav = () => nav?.classList.toggle('is-scrolled', window.scrollY > 24);
    updateNav();
    window.addEventListener('scroll', updateNav, { passive: true });

    menuButton?.addEventListener('click', () => {
        const isOpen = mobileMenu?.classList.toggle('hidden') === false;
        menuButton.setAttribute('aria-expanded', String(isOpen));
    });

    mobileMenu?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
        mobileMenu.classList.add('hidden');
        menuButton?.setAttribute('aria-expanded', 'false');
    }));

    document.querySelector('[data-password-toggle]')?.addEventListener('click', (event) => {
        const button = event.currentTarget;
        const input = document.querySelector('#password');
        const icon = button.querySelector('i');
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        button.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
        icon.classList.toggle('fa-eye', !isPassword);
        icon.classList.toggle('fa-eye-slash', isPassword);
    });

    document.querySelector('[data-login-form]')?.addEventListener('submit', () => {
        const submit = document.querySelector('[data-login-submit]');
        const label = document.querySelector('[data-login-label]');
        const icon = document.querySelector('[data-login-icon]');
        submit.disabled = true;
        label.textContent = 'Authenticating...';
        icon.className = 'fa-solid fa-spinner fa-spin';
    });

    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                revealObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.14 });
    document.querySelectorAll('.reveal').forEach((element) => revealObserver.observe(element));

    const counterObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            const element = entry.target;
            const target = Number(element.dataset.target);
            const suffix = element.dataset.suffix || '';
            const decimals = Number(element.dataset.decimals || 0);
            const duration = 1400;
            const start = performance.now();
            const tick = (now) => {
                const progress = Math.min((now - start) / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                element.textContent = `${(target * eased).toFixed(decimals)}${suffix}`;
                if (progress < 1) requestAnimationFrame(tick);
            };
            requestAnimationFrame(tick);
            observer.unobserve(element);
        });
    }, { threshold: 0.7 });
    document.querySelectorAll('[data-target]').forEach((element) => counterObserver.observe(element));
});
