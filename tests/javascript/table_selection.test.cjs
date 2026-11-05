// Copyright (c) 2026 The Trustpoint Project Authors
// SPDX-License-Identifier: MIT

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = readFileSync(path.join(__dirname, '../../trustpoint/static/js/trustpoint.js'), 'utf8');

function element(attributes = {}) {
    const listeners = new Map();
    return {
        checked: false,
        disabled: false,
        getAttribute: name => attributes[name] ?? null,
        addEventListener: (name, listener) => listeners.set(name, listener),
        dispatch(name, target = this) {
            listeners.get(name)?.({ currentTarget: this, target });
        },
    };
}

function table(values, { format = 'zip', numeric = false, url } = {}) {
    const master = element();
    const rows = values.map(value => Object.assign(element(), { value }));
    const button = element({
        'data-tp-url': url ?? (numeric ? 'download' : `download/${format}`),
        'data-tp-value-type': numeric ? null : 'log-filename',
    });
    const navigations = [];
    vm.runInNewContext(script, {
        document: {
            getElementById: () => null,
            querySelector: selector => selector === '#checkbox-column > input' ? master : null,
            querySelectorAll: selector => {
                if (selector === '.row_checkbox > input') return rows;
                if (selector === '.tp-table-select-btn') return [button];
                return [];
            },
        },
        window: {
            addEventListener() {},
            location: {
                href: numeric ? 'https://127.0.0.1/pki/certificates/' : 'https://127.0.0.1/management/logging/files/',
                assign: value => navigations.push(value),
            },
        },
        URL,
        console,
    });
    return { master, rows, button, navigations };
}

test('empty selections disable download and cannot navigate to the filename-less URL', () => {
    const page = table(['trustpoint.log']);
    assert.equal(page.button.disabled, true);
    page.button.dispatch('click');
    assert.deepEqual(page.navigations, []);
});

test('ZIP download appends the selected filename', () => {
    const page = table(['trustpoint.log', 'trustpoint.log.1']);
    page.rows[0].checked = true;
    page.rows[0].dispatch('change');
    assert.equal(page.button.disabled, false);
    page.button.dispatch('click');
    assert.deepEqual(page.navigations, ['/management/logging/files/download/zip/trustpoint.log/']);
});

test('TAR.GZ download includes only selected current and rotated logs', () => {
    const page = table(['trustpoint.log', 'trustpoint.log.1', 'trustpoint.log.12345'], { format: 'tar.gz' });
    page.rows[0].checked = page.rows[2].checked = true;
    page.button.dispatch('click');
    assert.deepEqual(page.navigations, ['/management/logging/files/download/tar.gz/trustpoint.log/trustpoint.log.12345/']);
});

test('select-all and clearing the last selection update the download button', () => {
    const page = table(['trustpoint.log', 'trustpoint.log.1']);
    page.master.checked = true;
    page.master.dispatch('change');
    assert.ok(page.rows.every(row => row.checked));
    assert.equal(page.button.disabled, false);
    page.master.checked = false;
    page.master.dispatch('change');
    assert.ok(page.rows.every(row => !row.checked));
    assert.equal(page.button.disabled, true);
});

test('invalid names and paths cannot be selected for log downloads', () => {
    const page = table(['../trustpoint.log', 'other.log', 'trustpoint.log.123456', 'trustpoint.log/1', '12']);
    page.master.checked = true;
    page.master.dispatch('change');
    assert.equal(page.button.disabled, true);
    page.button.dispatch('click');
    assert.deepEqual(page.navigations, []);
});

test('other tables continue to accept numeric IDs and reject filenames', () => {
    const page = table(['12', '34', 'trustpoint.log'], { numeric: true });
    page.master.checked = true;
    page.master.dispatch('change');
    page.button.dispatch('click');
    assert.deepEqual(page.navigations, ['/pki/certificates/download/12/34/']);
});

test('clicking a child inside the button uses the button URL and selection type', () => {
    const page = table(['trustpoint.log']);
    page.rows[0].checked = true;
    page.button.dispatch('click', element());
    assert.deepEqual(page.navigations, ['/management/logging/files/download/zip/trustpoint.log/']);
});

test('external download targets remain blocked', () => {
    const page = table(['trustpoint.log'], { url: '//example.invalid/download' });
    page.rows[0].checked = true;
    page.button.dispatch('click');
    assert.deepEqual(page.navigations, []);
});
