/* Copyright (c) 2026 The Trustpoint Project Authors. SPDX-License-Identifier: MIT */
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createSanitizer } = require('./browser_diagnostics.cjs');

test('diagnostics redact credentials, cookies and URL parameters', () => {
    const secrets = ['synthetic-password'];
    const sanitize = createSanitizer(secrets);
    secrets.push('synthetic-session');
    const result = sanitize('synthetic-password synthetic-session password="hidden" token=hidden Authorization: Bearer sensitive-jwt Basic sensitive-basic== https://user:pass@example.test/path?token=hidden#secret');
    assert(!result.includes('synthetic-password'));
    assert(!result.includes('synthetic-session'));
    assert(!result.includes('hidden'));
    assert(!result.includes('sensitive-jwt'));
    assert(!result.includes('sensitive-basic'));
    assert(!result.includes('user:pass'));
    assert(!result.includes('?'));
    assert(!result.includes('#'));
    assert(result.includes('https://example.test/path'));
});

test('diagnostics preserve useful CSP errors and bound message size', () => {
    const sanitize = createSanitizer([]);
    assert.equal(sanitize("Refused inline script: script-src 'self'"), "Refused inline script: script-src 'self'");
    assert.equal(sanitize('x'.repeat(3000)).length, 2000);
});
