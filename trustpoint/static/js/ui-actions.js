/* Copyright (c) 2026 The Trustpoint Project Authors. SPDX-License-Identifier: MIT */
// Explicit actions keep user-controlled attribute values out of executable code.
document.addEventListener('click', (event) => {
    const element = event.target.closest('[data-tp-action]');
    if (!element) return;
    const value = element.dataset.tpValue;
    switch (element.dataset.tpAction) {
        case 'back': history.back(); break;
        case 'dashboard': window.location.href = '/home/dashboard/'; break;
        case 'query': updateQueryParam(event, element.dataset.tpParam, value); break;
        case 'filter-type': toggleFilterType(value); break;
        case 'filter-source': toggleFilterSource(value); break;
        case 'date-range': setDateRange(value); break;
        case 'revoke-devices': revokeSelectedDevices(); break;
        case 'delete-devices': deleteSelectedDevices(); break;
        case 'toggle-devices': toggleAllDevices(element); break;
        case 'suggest-pattern': {
            const input = document.getElementById('id_serial_number_pattern');
            input.value = document.getElementById('suggested-pattern').value;
            input.removeAttribute('readonly');
            break;
        }
    }
});
document.addEventListener('change', (event) => {
    const element = event.target.closest('[data-tp-change]');
    if (!element) return;
    switch (element.dataset.tpChange) {
        case 'submit': element.form.requestSubmit(); break;
        case 'domain': window.location.href = '?domain=' + encodeURIComponent(element.value); break;
        case 'revocation-command': updateRevocationCommand(); break;
    }
});
document.querySelectorAll('[data-tp-indent]').forEach((element) => {
    element.style.paddingLeft = element.dataset.tpIndent;
});
