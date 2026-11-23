// Copyright (c) 2026 The Trustpoint Project Authors
// SPDX-License-Identifier: MIT

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = readFileSync(path.join(__dirname, '../../trustpoint/static/js/profile-builder.js'), 'utf8')
    + '\nglobalThis.CertificateProfileBuilder = CertificateProfileBuilder;';

function load() {
    const alerts = [];
    const context = {
        document: {
            addEventListener() {},
            getElementById: () => null,
        },
        alert: message => alerts.push(message),
        Event: class {
            constructor(type) {
                this.type = type;
            }
        },
        console,
    };
    vm.runInNewContext(script, context);
    const builder = Object.create(context.CertificateProfileBuilder.prototype);
    builder.editor = {
        value: '',
        dispatchEvent() {},
    };
    return { builder, alerts };
}

test('invalid JSON is reported and left untouched', () => {
    const { builder, alerts } = load();
    builder.editor.value = '{not json';
    builder.batchUpdateJson({ 'validity.days': 30 });
    assert.equal(builder.editor.value, '{not json');
    assert.deepEqual(alerts, ['Invalid JSON in editor. Cannot insert.']);
});

test('a valid update keeps unrelated profile keys', () => {
    const { builder } = load();
    builder.editor.value = '{"type":"cert_profile","credential_type":"domain"}';
    builder.batchUpdateJson({ 'validity.days': 30 });
    assert.deepEqual(JSON.parse(builder.editor.value), {
        type: 'cert_profile',
        credential_type: 'domain',
        validity: { days: 30 },
    });
});

test('nested child updates keep required and other existing flags', () => {
    const { builder } = load();
    const merged = (existing, value, isMutable) =>
        JSON.parse(JSON.stringify(builder.mergeChildUpdate(existing, value, isMutable)));
    assert.deepEqual(
        merged({ default: ['a'], required: true, mutable: true }, ['a', 'b'], true),
        { required: true, mutable: true, default: ['a', 'b'] },
    );
    assert.deepEqual(
        merged({ value: ['a'], required: true, mutable: true }, ['a', 'b'], false),
        { required: true, mutable: false, value: ['a', 'b'] },
    );
    assert.deepEqual(
        merged('old', 'new', false),
        { mutable: false, value: 'new' },
    );
});
