/* Keep custom inputs limited to selected protocols; the server validates every write. */
(() => {
    function showCustom(container, action) {
        const custom = container.querySelector('[data-custom-secret]');
        if (!custom) return;
        custom.hidden = action !== 'custom';
        custom.querySelectorAll('input').forEach(input => { input.disabled = custom.hidden; });
    }
    function refresh() {
        const selected = [...document.querySelectorAll('[name="no_onboarding_pki_protocols"]:checked')]
            .reduce((bits, input) => bits | Number(input.value), 0);
        const onboarding = document.querySelector('[name="onboarding_protocol"]')?.value;
        const active = {
            cmp_shared_secret: onboarding !== undefined ? onboarding === '2' : Boolean(selected & 1),
            est_password: onboarding !== undefined ? ['4', '8'].includes(onboarding) : Boolean(selected & (4 | 32)),
            scep_challenge: onboarding === undefined && Boolean(selected & 64),
        };
        document.querySelectorAll('[data-device-secret]').forEach(container => {
            const field = container.dataset.deviceSecret;
            container.hidden = !active[field];
            container.querySelectorAll('input,select').forEach(input => { input.disabled = container.hidden; });
            if (!container.hidden) showCustom(container, container.querySelector('select')?.value);
        });
        document.querySelectorAll('[data-secret-replacement]').forEach(container => {
            showCustom(container, container.querySelector('[name="action"]')?.value);
        });
    }
    document.addEventListener('change', refresh);
    refresh();
})();
