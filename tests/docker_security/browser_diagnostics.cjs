/* Copyright (c) 2026 The Trustpoint Project Authors. SPDX-License-Identifier: MIT */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function createSanitizer(secrets) {
    return value => {
        let text = String(value);
        for (const secret of secrets) {
            if (secret) text = text.split(secret).join('[redacted]');
        }
        text = text.replace(/https?:\/\/[^\s<>"']+/g, url => {
            try { const parsed = new URL(url); return parsed.origin + parsed.pathname; }
            catch { return '[url]'; }
        });
        text = text.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/gi, '$1 [redacted]');
        text = text.replace(/((?:password|secret|token|authorization|cookie|nonce|api[_-]?key|sessionid)[\w-]*["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1[redacted]');
        text = text.replace(/'nonce-[^']*'/g, "'nonce-[redacted]'");
        return text.slice(0, 2000);
    };
}

async function captureDiagnostics(context, directory, secrets) {
    const sanitize = createSanitizer(secrets);
    const data = { console: [], pageErrors: [], cspViolations: [], editor: [] };
    function record(kind, value) {
        if (data[kind].length < 200) data[kind].push(value);
    }
    await context.exposeBinding('captureCspViolation', (_source, event) => {
        record('cspViolations', {
            directive: event.directive, blocked: sanitize(event.blocked),
            source: sanitize(event.source), line: event.line,
        });
    });
    await context.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', event => {
            void window.captureCspViolation({
                directive: event.effectiveDirective, blocked: event.blockedURI,
                source: event.sourceFile, line: event.lineNumber,
            });
        });
    });
    context.on('page', page => {
        page.on('console', message => {
            if (['warning', 'error'].includes(message.type())) {
                record('console', { type: message.type(), message: sanitize(message.text()) });
            }
        });
        page.on('pageerror', error => record('pageErrors', sanitize(error.message)));
    });
    return {
        async rememberCookies() {
            // Read values only for redaction; never serialize cookies or headers.
            secrets.push(...(await context.cookies()).map(cookie => cookie.value));
        },
        async editorState(page, phase, expected) {
            record('editor', await page.evaluate(({ phase, expected }) => {
                const editor = document.querySelector('.cm-content');
                const textarea = window.document.querySelector('#id_yaml_text');
                return {
                    phase, platform: navigator.platform, focused: window.document.activeElement === editor,
                    documentLength: textarea?.value.length,
                    matchesExpected: textarea?.value === expected,
                    renderedName: editor?.textContent.includes('name: csp-test'),
                    renderedLines: editor?.querySelectorAll('.cm-line').length,
                };
            }, { phase, expected }));
        },
        clean(stage) {
            assert.deepEqual(data.pageErrors, [], `${stage}: JavaScript errors; see browser diagnostics`);
            assert.deepEqual(data.cspViolations, [], `${stage}: CSP violations; see browser diagnostics`);
        },
        save(error) {
            fs.mkdirSync(directory, { recursive: true });
            const output = JSON.parse(JSON.stringify(
                { ...data, failure: error ? error.message : null },
                (_key, value) => typeof value === 'string' ? sanitize(value) : value,
            ));
            fs.writeFileSync(path.join(directory, 'browser.json'), JSON.stringify(output, null, 2) + '\n');
            if (error) console.error('Browser diagnostics:', JSON.stringify(output));
        },
    };
}
module.exports = { captureDiagnostics, createSanitizer };
