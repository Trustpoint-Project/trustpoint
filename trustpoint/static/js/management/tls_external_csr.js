document.addEventListener('DOMContentLoaded', () => {
    const profileSelect = document.getElementById('id_cert_profile_select');
    profileSelect?.addEventListener('change', () => {
        const url = new URL(window.location.href);
        url.searchParams.set('cert_profile_pk', profileSelect.value);
        window.location.href = url.toString();
    });
    const button = document.getElementById('copy-csr-button');
    const textarea = document.getElementById('id_csr_pem');
    button?.addEventListener('click', async () => {
        textarea.select();
        try {
            await navigator.clipboard.writeText(textarea.value);
        } catch {
            document.execCommand('copy');
        }
    });
});