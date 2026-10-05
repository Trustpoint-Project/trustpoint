// Client-side rendering of profile-driven certificate parameters on the help pages.
// Mirrors help_pages.cert_parameters.CertParameterTemplate.render().
(function () {
    'use strict';

    const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

    function formatValue(param, raw) {
        let value = raw.replace(CONTROL_CHARS, '');
        if (param.is_subject) {
            value = value.replace(/[\\/+]/g, '\\$&');
        }
        if (param.quoting === 'double') {
            return value.replace(/[\\"$`]/g, '\\$&').replace(/!/g, '"\'!\'"');
        }
        const escaped = value.replace(/'/g, "'\\''");
        return param.quoting === 'single' ? escaped : "'" + escaped + "'";
    }

    function render(data, values) {
        const key = data.optional_ids.map((id) => (values[id] ? '1' : '0')).join('');
        let command = data.variants[key];
        for (const param of data.parameters) {
            if (values[param.id]) {
                command = command.split(param.placeholder).join(formatValue(param, values[param.id]));
            } else if (param.required) {
                command = command.split(param.placeholder).join(param.missing_display);
            }
        }
        return command;
    }

    function setCommandText(codeElement, text) {
        codeElement.replaceChildren();
        text.split('\n').forEach((line, index) => {
            if (index > 0) {
                codeElement.appendChild(document.createElement('br'));
            }
            codeElement.appendChild(document.createTextNode(line));
        });
    }

    function profileElements(profileName) {
        return Array.from(document.querySelectorAll('[data-cert-params-profile]'))
            .filter((el) => el.dataset.certParamsProfile === profileName);
    }

    function update(profileName, data) {
        const inputs = profileElements(profileName).filter((el) => el.matches('.cert-param-input'));
        const values = {};
        let complete = true;
        for (const input of inputs) {
            const value = input.value.trim();
            const valid = input.checkValidity();
            input.classList.toggle('is-invalid', value !== '' && !valid);
            complete = complete && valid;
            values[input.dataset.certParamId] = value;
        }

        const commandRow = document.getElementById('cert-params-command-' + profileName);
        const codeElement = commandRow ? commandRow.querySelector('code.command-text') : null;
        if (codeElement) {
            setCommandText(codeElement, render(data, values));
        }

        for (const status of profileElements(profileName).filter((el) => el.hasAttribute('data-cert-params-status'))) {
            status.querySelector('[data-status="incomplete"]').hidden = complete;
            status.querySelector('[data-status="complete"]').hidden = !complete;
        }
    }

    function showProfile(profileName) {
        for (const el of document.querySelectorAll('[data-cert-params-profile]')) {
            const row = el.closest('li');
            if (row) {
                row.hidden = el.dataset.certParamsProfile !== profileName;
            }
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        for (const script of document.querySelectorAll('script[id^="cert-params-data-"]')) {
            const profileName = script.id.substring('cert-params-data-'.length);
            const data = JSON.parse(script.textContent);
            for (const input of profileElements(profileName).filter((el) => el.matches('.cert-param-input'))) {
                input.addEventListener('input', () => update(profileName, data));
            }
            update(profileName, data);
        }

        for (const select of document.querySelectorAll('.cert-profile-select')) {
            select.addEventListener('change', () => showProfile(select.value));
        }
    });
})();
