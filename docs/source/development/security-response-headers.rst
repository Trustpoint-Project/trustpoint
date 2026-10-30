Security response headers
=========================

Trustpoint 1.0.0 enforces Content Security Policy (CSP) in Django and at the
container's Nginx edge. The policy applies to login, bootstrap/setup, operational
pages, authentication redirects, CSRF rejections and production error responses.
It uses Django's built-in ``ContentSecurityPolicyMiddleware`` and CSP context
processor; no additional middleware package is required. See the
`Django CSP documentation <https://docs.djangoproject.com/en/6.0/howto/csp/>`_.

Policy and UI compatibility
---------------------------

The application denies resources by default. Scripts, styles, fonts and browser
connections are restricted to the same origin. Images additionally permit
``data:`` for bundled Bootstrap SVGs and generated images. Objects, base elements,
framing and inline event/style attributes are blocked; forms submit only to the
same origin. Trusted inline script/style elements carry a fresh request nonce.
Neither ``unsafe-inline`` nor ``unsafe-eval`` is permitted.

Inline event handlers were replaced with explicit actions in ``ui-actions.js``;
attribute values are never evaluated as JavaScript. Former inline layouts live
in ``ui-layout.css``. Dynamic hierarchy indentation and workflow overlay positions
use CSSOM property assignments. CodeMirror receives the request nonce through its
``EditorView.cspNonce`` extension. Ordinary text insertion uses CodeMirror transactions to prevent
Chromium copying syntax colors into native inline formatting during replacement;
composition and clipboard handling remain with CodeMirror. The fallback textarea
uses external CSS.

Swagger and ReDoc use distributions already installed with ``drf-yasg``, rather
than remote CDN scripts or fonts. ReDoc receives the nonce for generated styles.
Its view alone additionally authorizes ``worker-src 'self' blob:`` for its local
search worker. ``redoc-csp.min.js`` is reproduced from the installed ``drf-yasg``
asset with two reviewed substitutions: initialize Webpack's nonce before loading
embedded styles, and load its branding image from the installed local image.
The license notice is retained alongside the bundle. Search, mobile navigation
and branding remain available. Reproduce or verify it after dependency upgrades:

.. code-block:: bash

   uv run python tests/scripts/build_redoc_csp.py
   uv run python tests/scripts/build_redoc_csp.py --check


Deployment behavior
-------------------

* Django CSP middleware runs before security and authentication middleware so
  short-circuit responses retain CSP. It is also enabled in bootstrap settings.
* Nginx forwards Django's exact nonce policy as one CSP header. When no upstream
  policy exists, redirects, static files and edge errors receive a restrictive
  fallback policy. ``always`` covers error statuses. Nginx also supplies one copy
  of ``X-Frame-Options: DENY``, ``X-Content-Type-Options: nosniff`` and
  ``Referrer-Policy: same-origin`` and hides its version.
* HTTP enrollment locations inherit the complete sanitized proxy-header set.
  They no longer override individual headers, which would discard Nginx's
  server-level overrides of client-supplied TLS identity/protocol assertions.
* HTTP UI requests still redirect to HTTPS at Nginx. HTTP CRL, CMP and SCEP
  locations still reach Django. CSP does not add ``upgrade-insecure-requests``
  or enable Django-wide TLS redirects, which would break those protocol paths.
* Session and CSRF cookies are Secure in Docker. Direct native development keeps
  HTTP cookies usable. Session cookies remain HttpOnly; the CSRF cookie remains
  readable by the existing JavaScript CSRF-token helper.
* Only trusted reverse proxies should reach Gunicorn and set forwarded protocol
  headers. The shipped Nginx overwrites those headers. Deployments replacing
  Nginx must preserve CSP and equivalent headers on their own redirects, static
  files and errors. Do not add a second CSP that blocks application resources.
* Keep nonced HTML out of shared response caches. Never replace per-response
  nonces with a fixed value or inject nonces into arbitrary response HTML.
* HSTS remains a deployment decision: enable it at the outer TLS edge only after
  installing a trusted certificate and confirming HTTPS is permanent. Assess
  subdomains separately before enabling ``includeSubDomains`` or preload.
  Direct development, bootstrap certificates and HTTP enrollment remain supported.

Verification
------------

The ZAP workflow keeps its existing independent HTTP/HTTPS baselines and blocking
policy: scanner errors, missing evidence, medium/high findings and configured
scanner FAILs fail the job. No finding is suppressed. It additionally runs deployed
header/routing checks and an authenticated Chromium CSP smoke test using a
disposable administrator. The browser smoke test covers theme switching, login,
notifications, CA pages, workflow editing, Swagger and ReDoc search. This targeted
functional check does not replace authenticated security scanning of all APIs.

Run the focused regression checks from the repository root:

.. code-block:: bash

   uv run pytest trustpoint/trustpoint/tests/test_csp.py \
     trustpoint/trustpoint/tests/test_middleware.py tests/test_zap_reports.py
   python3 tests/docker_security/check_response_headers.py --insecure

Use ``--insecure`` only with a disposable deployment's self-signed certificate.
The header check covers HTTP redirects, HTTPS login/405, Nginx static success/404
and HTTP CRL/CMP/SCEP error paths without triggering enrollment.

To run the browser smoke test against a disposable operational instance:

.. code-block:: bash

   npm install --prefix /tmp/trustpoint-csp-browser --no-audit --no-fund playwright@1.64.1
   /tmp/trustpoint-csp-browser/node_modules/.bin/playwright install chromium --only-shell
   export TP_CSP_ORIGIN=https://localhost
   export TP_CSP_USERNAME=your-disposable-admin
   export TP_CSP_PASSWORD=your-disposable-password
   NODE_PATH=/tmp/trustpoint-csp-browser/node_modules node tests/docker_security/csp_browser.cjs

Release scan evidence and residual findings are recorded in
``RELEASE_READINESS_1.0.0.md``. Review the full JSON, Markdown and HTML reports,
including low/informational findings, before release.
