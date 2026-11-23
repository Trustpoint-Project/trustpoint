// Copyright (c) 2026 The Trustpoint Project Authors
// SPDX-License-Identifier: MIT

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = readFileSync(path.join(__dirname, '../../trustpoint/static/js/help_cert_params.js'), 'utf8');

function load() {
    const context = {
        document: {
            addEventListener() {},
            querySelectorAll: () => [],
        },
        console,
    };
    vm.runInNewContext(script, context);
    return context.tpHelpCertParams;
}

test('double-quoted values escape shell metacharacters and history expansion', () => {
    const { formatValue } = load();
    const param = { is_subject: false, quoting: 'double' };
    assert.equal(formatValue(param, 'a"b$c`d!e'), 'a\\"b\\$c\\`d"\'!\'"e');
});

test('subject values escape OpenSSL separators and keep single quotes', () => {
    const { formatValue } = load();
    const param = { is_subject: true, quoting: 'single' };
    assert.equal(formatValue(param, 'a/b+c\\d'), 'a\\/b\\+c\\\\d');
});

test('unquoted values are wrapped in single quotes and inner quotes are closed', () => {
    const { formatValue } = load();
    assert.equal(formatValue({ is_subject: false, quoting: 'none' }, 'abc'), "'abc'");
    assert.equal(formatValue({ is_subject: false, quoting: 'single' }, "it's"), "it'\\''s");
});

test('control characters are removed before quoting', () => {
    const { formatValue } = load();
    assert.equal(formatValue({ is_subject: false, quoting: 'none' }, 'a\u0000b\nc\u007f'), "'abc'");
});

test('render picks the variant for the present optional values', () => {
    const { render } = load();
    const data = {
        optional_ids: ['b'],
        variants: {
            '0': 'cmd <A>',
            '1': 'cmd <A> --b <B>',
        },
        parameters: [
            { id: 'a', placeholder: '<A>', required: true, missing_display: '<A>', is_subject: false, quoting: 'none' },
            { id: 'b', placeholder: '<B>', required: false, missing_display: '<B>', is_subject: false, quoting: 'none' },
        ],
    };
    assert.equal(render(data, { a: 'x' }), "cmd 'x'");
    assert.equal(render(data, { a: 'x', b: 'y' }), "cmd 'x' --b 'y'");
});

test('missing required values use the missing display', () => {
    const { render } = load();
    const data = {
        optional_ids: [],
        variants: { '': 'cmd <A>' },
        parameters: [
            { id: 'a', placeholder: '<A>', required: true, missing_display: '<A>', is_subject: false, quoting: 'none' },
        ],
    };
    assert.equal(render(data, {}), 'cmd <A>');
});
