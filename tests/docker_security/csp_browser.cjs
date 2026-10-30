/* Copyright (c) 2026 The Trustpoint Project Authors. SPDX-License-Identifier: MIT */
// Run against a disposable operational deployment; requires Playwright via NODE_PATH.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');

(async () => {
    const origin = process.env.TP_CSP_ORIGIN || 'https://localhost';
    assert(process.env.TP_CSP_USERNAME && process.env.TP_CSP_PASSWORD, 'Provide disposable test credentials');
    const browser = await chromium.launch({ headless: true });
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        await context.addInitScript(() => {
            window.cspViolations = [];
            document.addEventListener('securitypolicyviolation', event => {
                window.cspViolations.push(`${event.effectiveDirective}: ${event.blockedURI}`);
            });
        });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        async function clean(path) {
            await page.waitForTimeout(300); // Include asynchronous CSP violation events.
            assert.deepEqual(await page.evaluate(() => window.cspViolations), [], path);
            assert.deepEqual(errors, [], path);
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
        assert.notEqual(await page.locator('html').getAttribute('data-bs-theme'), before);
        await clean('/users/login/');
        await page.locator('[name=username]').fill(process.env.TP_CSP_USERNAME);
        await page.locator('[name=password]').fill(process.env.TP_CSP_PASSWORD);
        await Promise.all([
            page.waitForURL('**/home/dashboard/'),
            page.locator('button[type=submit]').click(),
        ]);
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
        await page.locator('.cm-content').waitFor();
        await page.locator('[data-node-id]').first().dispatchEvent('dblclick');
        const overlay = page.locator('.wf2-graph-floating-card').first();
        await overlay.waitFor();
        assert(await overlay.evaluate(el => el.style.left.endsWith('px') && el.style.top.endsWith('px')));
        await page.keyboard.press('Escape');
        await page.locator('.cm-content').click();
        await page.keyboard.press('ControlOrMeta+A');
        await page.keyboard.type('version: 1\nname: csp-test\n');
        const editor = page.locator('.cm-content');
        assert((await editor.innerText()).includes('name: csp-test'));
        await page.keyboard.press('ControlOrMeta+z');
        await page.keyboard.press('ControlOrMeta+Shift+z');
        assert((await editor.innerText()).includes('name: csp-test'));
        await editor.evaluate(element => {
            const clipboardData = new DataTransfer();
            clipboardData.setData('text/plain', '# CSP paste');
            element.dispatchEvent(new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }));
        });
        assert((await editor.innerText()).includes('# CSP paste'));
        await page.locator('#wf2-open-guide').click();
        assert(await page.locator('body').evaluate(el => el.classList.contains('wf2-guide-open')));
        await clean('/workflows2/definitions/new/');
        await visit('/swagger/');
        await page.locator('.swagger-ui .info').waitFor();
        await clean('/swagger/');
        await visit('/redoc/');
        await page.locator('#redoc-container h1').first().waitFor();
        // Exercise the local search worker, whose blob permission is scoped to ReDoc.
        const search = page.locator('input[type=search], input[placeholder*="Search"]');
        await search.first().fill('certificate');
        await clean('/redoc/');
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
