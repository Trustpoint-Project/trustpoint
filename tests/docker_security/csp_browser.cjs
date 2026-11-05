/* Copyright (c) 2026 The Trustpoint Project Authors. SPDX-License-Identifier: MIT */
// Run against a disposable operational deployment; requires Playwright via NODE_PATH.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { expect: playwrightExpect } = require('playwright/test');
const expect = playwrightExpect.configure({ timeout: 15_000 });
const { captureDiagnostics, createSanitizer } = require('./browser_diagnostics.cjs');

(async () => {
    const origin = process.env.TP_CSP_ORIGIN || 'https://localhost';
    assert(process.env.TP_CSP_USERNAME && process.env.TP_CSP_PASSWORD, 'Provide disposable test credentials');
    const browser = await chromium.launch({ headless: true });
    let diagnostics;
    let page;
    let failure;
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        diagnostics = await captureDiagnostics(
            context, process.env.TP_CSP_REPORT_DIR || 'reports/zap',
            [process.env.TP_CSP_PASSWORD, process.env.TP_CSP_USERNAME],
        );
        page = await context.newPage();
        async function clean(path) {
            // Page-specific readiness assertions below must finish first. There
            // is no fixed delay that could hide a slow or blocked dependency.
            diagnostics.clean(path);
            console.log(`${path}: browser CSP and JavaScript checks OK`);
        }
        async function visit(path) {
            const response = await page.goto(origin + path);
            assert.equal(response.status(), 200, path);
            assert.equal(new URL(page.url()).pathname, path, `Unexpected redirect from ${path}`);
        }
        await visit('/users/login/');
        const before = await page.locator('html').getAttribute('data-bs-theme');
        await page.locator('.theme-toggle').click();
        await expect(page.locator('html')).not.toHaveAttribute('data-bs-theme', before);
        await clean('/users/login/');
        await page.locator('[name=username]').fill(process.env.TP_CSP_USERNAME);
        await page.locator('[name=password]').fill(process.env.TP_CSP_PASSWORD);
        await Promise.all([
            page.waitForURL('**/home/dashboard/'),
            page.locator('button[type=submit]').click(),
        ]);
        await diagnostics.rememberCookies();
        const session = (await context.cookies()).find(cookie => cookie.name === 'sessionid');
        assert(session?.secure && session.httpOnly, 'Docker session cookie must be Secure and HttpOnly');
        await page.locator('#dashboard-refresh').click();
        await clean('/home/dashboard/');
        await visit('/management/notifications/');
        // These controls previously depended on inline handlers.
        await Promise.all([
            page.waitForURL(url => url.searchParams.has('notification_type')),
            page.locator('[data-tp-action="filter-type"]').first().click(),
        ]);
        await clean('/management/notifications/');
        await visit('/pki/cas/');
        await clean('/pki/cas/');
        await visit('/workflows2/definitions/new/');
        const editor = page.locator('.cm-content');
        const textarea = page.locator('#id_yaml_text');
        const initialYaml = await textarea.inputValue();
        assert(initialYaml.trim(), 'The workflow editor must load the initial YAML');
        await expect(editor).toBeVisible();
        await expect(editor.locator('.cm-line').first()).toHaveText(initialYaml.split('\n')[0]);
        await diagnostics.editorState(page, 'initialized', initialYaml);
        await page.locator('[data-node-id]').first().dispatchEvent('dblclick');
        const overlay = page.locator('.wf2-graph-floating-card').first();
        await expect(overlay).toBeVisible();
        await expect.poll(() => overlay.evaluate(el => el.style.left.endsWith('px') && el.style.top.endsWith('px'))).toBe(true);
        await page.keyboard.press('Escape');
        await editor.click();
        await expect(editor).toBeFocused();
        await page.keyboard.press('ControlOrMeta+A');
        const draft = 'version: 1\nname: csp-test\n';
        await page.keyboard.type(draft);
        await expect(textarea, 'Typing must update the submitted YAML').toHaveValue(draft);
        await expect(editor).toContainText('name: csp-test');
        await diagnostics.editorState(page, 'typed', draft);
        await page.keyboard.press('ControlOrMeta+z');
        await expect(textarea, 'Undo must change the document').not.toHaveValue(draft);
        await diagnostics.editorState(page, 'undone', draft);
        // CodeMirror uses Cmd+Shift+Z on macOS and Ctrl+Y on Linux/Windows.
        // A synthetic Shift+lowercase-z can instead match the undo binding.
        await page.keyboard.press(process.platform === 'darwin' ? 'Meta+Shift+Z' : 'Control+y');
        await expect(textarea, 'Redo must restore the complete document').toHaveValue(draft);
        await expect(editor).toContainText('name: csp-test');
        await diagnostics.editorState(page, 'redone', draft);
        await editor.evaluate(element => {
            const clipboardData = new DataTransfer();
            clipboardData.setData('text/plain', '# CSP paste');
            element.dispatchEvent(new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }));
        });
        await expect(textarea).toHaveValue(draft + '# CSP paste');
        await expect(editor).toContainText('# CSP paste');
        await diagnostics.editorState(page, 'pasted', draft + '# CSP paste');
        await page.locator('#wf2-open-guide').click();
        await expect(page.locator('body')).toHaveClass(/wf2-guide-open/);
        await clean('/workflows2/definitions/new/');
        await visit('/swagger/');
        await expect(page.locator('.swagger-ui .info')).toBeVisible();
        await clean('/swagger/');
        await visit('/redoc/');
        await expect(page.locator('#redoc-container h1').first()).toBeVisible();
        // Exercise the local search worker, whose blob permission is scoped to ReDoc.
        const search = page.locator('input[type=search], input[placeholder*="Search"]');
        await search.first().fill('certificate');
        await expect(search.first()).toHaveValue('certificate');
        await clean('/redoc/');
    } catch (error) {
        failure = error;
        if (page && diagnostics) {
            await diagnostics.editorState(page, 'failure', 'version: 1\nname: csp-test\n').catch(() => {});
        }
        throw error;
    } finally {
        if (diagnostics) diagnostics.save(failure);
        await browser.close();
    }
})().catch(error => {
    const sanitize = createSanitizer([process.env.TP_CSP_PASSWORD, process.env.TP_CSP_USERNAME]);
    console.error(sanitize(error.stack || error.message));
    process.exitCode = 1;
});
