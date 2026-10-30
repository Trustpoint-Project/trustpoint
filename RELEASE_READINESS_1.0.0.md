# Trustpoint 1.0.0 Release Readiness Review

## Executive Summary

**Recommendation: NOT READY. Do not tag the reviewed commit as v1.0.0.**

Reviewed commit: `695df736b` (`Merge pull request #937 from Trustpoint-Project/v1_prep`). Review date: 28 October 2026, Europe/Berlin. The worktree was clean when the audit began. This report is the only intended repository change; no implementation fixes were made.

**Documentation follow-up:** the user subsequently authorized documentation fixes.
The Documentation Assessment below records that work and its verification.
Finding totals and original test results above/below describe the audit baseline;
they are not a claim that all findings remain untouched. H2's first-stable baseline decision is accepted, H5's documentation defects
are fixed, and H6's contributor instructions, controlled-DNS tests and CI test
selection are corrected. No security blocker was resolved by these documentation changes.

**Final-release framing:** at the user's direction, package, lockfile, documentation,
README, and changelog now identify final 1.0.0. The recommendations below are
adopted where they concern compatibility/documentation choices. Original security
findings and unexecuted checks remain recorded as evidence, rather than being
marked resolved by a version or wording change.

**Integration-credential fix:** H7 and the related B3 backup-page disclosure are
resolved in the current implementation changes. SMTP/SFTP secret fields now use
application-secret encryption from the initial 1.0.0 schema; forms never render saved/submitted secrets and support keep/replace/
explicit-clear behavior. Backup GET/POST access requires backup-management
permission. The original findings below remain for traceability, with resolution
notes; the table counts the original review, not currently open findings.


| Severity | Findings at original review |
| --- | ---: |
| P0 — Release Blocker | 6 |
| P1 — Should Fix Before 1.0 | 9 |
| P2 — Good 1.0 Cleanup | 4 |
| P3 — Post-1.0 Improvement | 2 |

The deployment and envelope-encryption work has substantial positive evidence: the current Dockerfile builds, isolated Compose setup/restart/recreation tests pass, secrets remain stable, concurrent PostgreSQL DEK initialization passes, and Behave passes with its required KEK configured. Ruff, mypy, Django system checks, migration drift checks, and shell checks pass. Dependency advisory scans found no known vulnerabilities in the scanned Python/runtime and JavaScript/production lock selections.

At the original reviewed commit, authorization and trust-boundary defects remained despite passing checks. They included issuance/download permission bypasses, backup-page credential disclosure, upstream CMP CA trust, SFTP host verification, and certificate-header trust on network-accessible Gunicorn. B3 is now fixed as described above; the other security findings have not been marked resolved by this integration-credential change.

Review breadth: inventory of 1,871 tracked files, including 1,069 Python files, 108 Markdown/reStructuredText files, 19 feature files, deployment scripts, hidden tooling, workflows, migrations, frontend manifests, bundled assets, and test credentials. Repository-wide mechanical searches and documentation builds were combined with manual tracing of critical flows. This is a broad release audit, **not a claim that every line, binary, historical commit, or possible protocol interaction was exhaustively verified**. Findings distinguish runtime probes, source tracing, and outstanding verification.

## Release Blockers

### B1 — RELEASE BLOCKER: management REST mutations bypass role permissions

- **Severity:** P0.
- **Affected files:** `trustpoint/rest_pki/api_views.py:165–243`, `trustpoint/request/enrollment.py:102–155`, `trustpoint/request/authorization/rest.py`, `trustpoint/pki/views/owner_credentials_api.py:97–231`, `trustpoint/trustpoint/settings.py:678`.
- **Problem:** `ApplicationCertificateEnrollView` requires only `IsAuthenticated`. It never checks `users.issue_certificates`. The management adapter binds the caller-selected device directly; downstream authorization checks device/domain/profile/protocol rules, not the management user's permission. In contrast, revocation explicitly checks `REVOKE_CERTIFICATES`. `DevOwnerIdViewSet` likewise uses only `IsAuthenticated` for creation and deletion of DevOwnerIDs.
- **Concrete consequence:** an authenticated service account with REST access but without issuance rights can request an application certificate for an existing eligible device using its own CSR. Device bootstrap credentials are unnecessary through this management adapter. An authenticated API caller can also mutate owner-credential configuration without a corresponding management permission.
- **Verification:** an isolated `APIRequestFactory` request, authenticated as a synthetic user whose `has_perm()` always returns false, reached `_run_enrollment_pipeline` and returned HTTP 200. Device lookup and issuance were mocked to avoid issuing a real certificate; this verifies the missing management authorization gate, not complete end-to-end issuance. Source tracing established the downstream checks.
- **Recommended fix:** enforce the relevant action permission before lookup or mutation, define the owner-credential management permission explicitly, and add deny/allow tests using real low-privilege users and service accounts. Preserve all existing device/profile policy checks.

### B2 — RELEASE BLOCKER: browser OTP creation bypasses private-key download permission

- **Severity:** P0.
- **Affected files:** `trustpoint/devices/views/browser_onboarding.py:42–101`, `trustpoint/devices/views/download.py:47–80,227–248`, `trustpoint/devices/urls.py:282`, `trustpoint/devices/models.py:368–409`.
- **Problem:** the manual download POST checks `DOWNLOAD_CREDENTIALS`, but the browser OTP view has no equivalent permission check. Its GET deletes an existing download record, creates a replacement, and returns the OTP for the supplied issued-credential ID.
- **Concrete consequence:** a logged-in user without download permission can visit `/devices/credential-download/browser/<id>/`, obtain an OTP, exchange it through the public browser login, and download a stored exportable device private key. The credential must have a stored downloadable key; CSR-only credentials do not provide one. GET also invalidates an existing operator's OTP.
- **Verification:** an isolated view request with every user permission false returned HTTP 200, created a synthetic OTP record, and included the OTP in the response. ORM access was mocked. The public token-to-credential export path was traced through the login form, token mixin, and base download view.
- **Recommended fix:** require `DOWNLOAD_CREDENTIALS` for OTP generation/cancellation, use POST with CSRF protection for these state changes, scope the selected credential as intended, and add a negative test spanning OTP creation through export.

### B3 — RELEASE BLOCKER (resolved): backup settings credential disclosure

- **Severity:** P0.
- **Resolution:** `BackupManageView` now checks `MANAGE_BACKUPS` for GET as well as POST. Stored/submitted secret values are never rendered, including invalid forms; blank edits preserve credentials, with explicit clearing controls. Actual low-privilege client GET returns 403; an authorized GET contains no saved password/key/passphrase. The original evidence below describes the audited baseline.
- **Affected files:** `trustpoint/management/views/backup.py:101–156`, `trustpoint/management/forms.py:595–625`, `trustpoint/templates/management/backups/manage_backups.html:312–344`, `trustpoint/management/urls.py:95`.
- **Problem:** `BackupManageView` checks `MANAGE_BACKUPS` only on POST. GET constructs a model form from the saved singleton. Password and key-passphrase widgets use `render_value=True`, and the private key is rendered in a textarea. The template includes these fields without a permission gate.
- **Concrete consequence:** any logged-in web user can retrieve the configured backup password, SSH private key, and passphrase from the HTML, even if the navigation hides the page. This can expose the external backup account and its accessible backup history.
- **Verification:** an isolated GET with `has_perm()` always false returned HTTP 200 and included all three synthetic credential values. The singleton lookup and response renderer were mocked; the actual model form generated the fields.
- **Recommended fix:** protect the entire view with backup-management permission. Make secret fields replacement-only, never render existing credentials, and preserve existing values when an authorized administrator leaves them blank. Add low-privilege GET tests and response-body secret absence assertions.

### B4 — RELEASE BLOCKER: upstream CMP CA enrollment accepts unauthenticated certificate material

- **Severity:** P0.
- **Affected files:** `trustpoint/request/clients/cmp_client.py:173–208,481–574`, `trustpoint/pki/services/ca_enrollment.py:124–197,269–410`, `trustpoint/pki/views/ca_api.py:317–319`, `trustpoint/pki/views/issuing_cas.py:1153`.
- **Problem:** `send_pki_message()` disables HTTPS certificate verification. `_parse_response()` decodes the message but does not verify CMP protection, transaction ID, or nonce binding. `CmpCaEnrollmentService` then saves the returned CA certificate/chain without validating its key against the pending managed key or its chain against the configured truststore. The configured truststore is used to derive the recipient name; that does not authenticate a response. The stronger device RA validator in `request/security_hardening.py:801` does not cover this CA-enrollment service.
- **Concrete consequence:** with an active network interception position during an administrator's CMP CA enrollment, an attacker can replace the reply and introduce untrusted CA/chain material or bind the pending key to an unrelated certificate, breaking subsequent issuance and CA trust relationships. This does not imply disclosure of the original managed private key.
- **Verification:** source trace through both browser/API callers to persistence. A local probe confirmed `_parse_response()` accepts a DER-encoded CMP confirmation with no protection. A full interception/forged-CP integration test was not performed.
- **Recommended fix:** authenticate upstream responses using the configured TLS trust and/or verified CMP protection, bind replies to the request, verify the returned CA certificate's public key, CA constraints, validity, and chain, then persist all related state atomically. Reject malformed/unprotected/untrusted/mismatched responses in negative integration tests.

### B5 — RELEASE BLOCKER: SFTP backups do not verify the SSH server host key

- **Severity:** P0.
- **Affected files:** `trustpoint/util/sftp.py:98–142`, `trustpoint/management/models/backup.py`, `trustpoint/management/views/backup.py` (SFTP upload actions).
- **Problem:** `_connect_sftp()` constructs `paramiko.Transport` and calls `connect(username=..., password=...)` or `connect(..., pkey=...)` without `hostkey`. No known-hosts lookup or fingerprint comparison occurs. Installed Paramiko's signature defaults `hostkey=None`; its docstring explicitly identifies this as disabling host-key verification.
- **Concrete consequence:** an attacker intercepting the configured backup destination can impersonate it, receive database backups, and, for password authentication, receive the SFTP password. Private-key authentication does not send the private key, but still sends the backup to an unauthenticated destination.
- **Verification:** application path and installed Paramiko API inspected. No live external backup server was contacted.
- **Recommended fix:** provision an expected host key/fingerprint or managed known-hosts file, verify it before authenticating, fail closed on mismatch, and test both authentication modes against a wrong-host-key server.

### B6 — RELEASE BLOCKER: network-accessible Gunicorn permits certificate-header impersonation

- **Severity:** P0, conditional on direct backend reachability.
- **Affected files:** `docker/trustpoint/runtime_config.py:329–343`, `trustpoint/agents/api_views.py:32–99`, `trustpoint/request/authentication/base.py` (`ClientCertificateAuthentication`), `trustpoint/pki/util/x509.py:454–493`, `docker/trustpoint/nginx/trustpoint-nginx-https.conf`.
- **Problem:** production/bootstrap Gunicorn binds `0.0.0.0` on ports 8001/8000. Agent certificate authentication parses `SSL-Client-Cert` and resolves a registered valid credential without checking that the connection came from the TLS proxy. The shared certificate extractor also reads the header directly. Nginx correctly overwrites these headers on the normal ingress path, but direct backend traffic bypasses nginx.
- **Concrete consequence:** a process able to reach the application container's backend port can submit another device's public certificate in a header and impersonate that agent without its private key. Sibling containers on the Compose network can reach the backend; Linux host access to container addresses is also relevant. This is **not** an allegation that external port 443 accepts a spoofed header: that ingress is overwritten correctly.
- **Verification:** bind configuration and authentication source paths traced; no cross-container impersonation exploit was run. Prerequisites are backend network access and possession of the victim's registered public certificate.
- **Recommended fix:** bind Gunicorn to loopback or a protected Unix socket and centralize trusted-proxy/TLS-proof checks for every certificate-authenticated endpoint. Add a regression where a sibling container's direct header request is refused while genuine mTLS through nginx succeeds.

## P1 — Should Fix Before 1.0

### H1 — EST CA enrollment selects certificates by position and omits CA-result validation

- **Severity:** P1.
- **Affected files:** `trustpoint/request/clients/est_client.py:120–147`, `trustpoint/pki/services/ca_enrollment.py:41–121,269–410`.
- **Problem:** EST response parsing selects the first non-CA certificate, otherwise `certificates[0]`. For CA enrollment, every certificate in a valid returned CA chain can be a CA, and PKCS#7 order is not a reliable leaf indicator. The service assigns the chosen certificate without matching its public key, verifying CA semantics/trust, or atomically updating primary-certificate relationships. CMP hierarchy helpers additionally identify existing CAs by subject/issuer names rather than fingerprint and link parents by names.
- **Consequence:** a legitimate unordered chain, or renewed CA certificates with the same distinguished names, can attach the wrong certificate/parent or leave inconsistent credential relationships. EST's verified TLS does not guarantee that its returned application data matches the requested key.
- **Fix:** select by requested public key, validate the complete CA result and signatures, identify certificates by DER fingerprint, preserve primary-certificate invariants, and commit the complete update atomically. Add shuffled-chain and same-DN rollover tests.

### H2 — Compatibility baseline accepted: 1.0.0 is the first stable version

- **Original severity:** P1; **1.0 API/UX DECISION — resolved by the user's baseline decision**.
- **Decision:** 1.0.0 is the first stable version. Documentation describes its current schema, device types, and encryption format without development-era migration history.
- **Affected files:** `README.md`, `CHANGELOG.md`, `docs/source/features/management/upgrading.rst`, `docs/source/development/architecture/device_lifecycle.md`.
- **Future requirement:** preserve stable migration history and verify explicitly supported updates between subsequent stable releases, including key and data continuity.

### H3 — Backup/restore CI still launches containers without required secrets

- **Severity:** P1.
- **Affected files:** `.github/workflows/backup-restore.yml` (both `docker run` steps and trigger), `trustpoint/trustpoint/secret_key.py`.
- **Problem:** the backup/restore workflow's application containers receive database settings but no Django signing-key mount or software-KEK mount. The production signing-key loader requires the mounted key. The isolated Docker smoke test independently confirmed that production settings fail when it is absent.
- **Consequence:** this workflow cannot validate successful runtime backup/restore as written; it either fails earlier or tests a container that cannot start. Its host-side setup also needs a stable KEK shared with the container for encrypted data to remain readable. It is `workflow_call`-only, and no caller was found in the tracked workflows, so normal main/PR CI does not run it at all.
- **Fix:** provision synthetic installation-specific signing/KEK secrets once, mount them consistently into initial and restored containers, preserve all required crypto state, and verify decrypted credentials after restore. Run the repaired reusable workflow before release. This workflow was inspected, not executed locally.

### H4 — Migration compatibility CI tests the wrong upgrade direction

- **Severity:** P1.
- **Affected files:** `.github/workflows/test-migrations-compatibility.yml`, `.github/actions/setup-uv-action/action.yml`, `docs/source/development/release-checklist.rst`.
- **Problem:** the job migrates the proposed branch first, checks out the base branch, then runs `check` and `showmigrations`. That does not migrate an existing base schema/data set forward, and Django's system checks do not prove that old model queries work against the new schema. The path filter also excludes model-only edits that forget migrations.
- **Consequence:** a green compatibility check cannot establish data preservation, encryption continuity, or forward upgrades. The separately provided Compose regression is valuable but not invoked by this workflow and normally recreates the same image unless an upgrade image is explicitly supplied.
- **Fix:** add a PostgreSQL base-release database with representative encrypted data, apply the release forward, and exercise issuance/decryption/revocation. Run `makemigrations --check --dry-run` on model changes as well. Keep backward-code compatibility as a separate assertion when required.

### H5 — Resolved: documentation sources, references, and strict CI build

- **Original severity:** P1.
- **Follow-up status:** duplicate docnames and missing includes/diagrams are resolved. A clean strict HTML build passes with zero warnings. The existing Read the Docs configuration now enables `sphinx.fail_on_warning`, and `docs/source/conf.py` enables nitpicky references for hosted and local builds. No duplicate GitHub documentation workflow is needed. Rendered-page inspection also identified and repaired two test-plan links that incorrectly pointed to filenames instead of internal targets. Original evidence below is retained as the audit baseline.
- **Verification:** clean `sphinx-build -E -a -b html -n -W --keep-going` passes with zero warnings. Local links, anchors and image targets resolve across all 84 generated HTML pages; workflow, deployment, backup and testing content is present. Remote URLs and browser layout were not exhaustively tested.
- **Affected files:** `docs/source/features/workflows/index.md` and `index.rst`; `docs/source/development/architecture/backup_restore.md` and `backup_restore.rst`; `docs/source/development/testing/ci_cd.rst`; `docs/source/development/testing/test_plan.rst`; `docs/source/development/architecture/index.md:129`.
- **Problem:** the HTML build with nitpicky references produced **63 warnings**, including duplicate document names, a nonexistent architecture overview, missing PlantUML diagrams, and missing source includes whose paths point under `docs/.github` or `docs/trustpoint` instead of the repository root. One include still names `r_013_feature_test.yml`, which is absent.
- **Consequence:** rendered docs can omit intended workflow/backup instructions and testing evidence while the build still succeeds. Which duplicate source is selected must not determine release documentation accidentally.
- **Fix:** consolidate duplicate docnames, repair actual includes/references, inspect rendered deployment/workflow/backup pages, and gate a Sphinx build with warnings treated as failures. The lightweight local Markdown-link scan found no missing filesystem targets; it does not validate anchors, RST roles, or remote URLs.

### H6 — Resolved: complete test selection and controlled DNS in unit tests

- **Original severity:** P1.
- **Follow-up status:** resolved. Contributor/developer commands select `trustpoint/ tests/` and the explicit Behave feature path, with SQLite/PostgreSQL selection and test-KEK prerequisites explained. Both `.github/workflows/pytest.yml` and `codecov-upload.yml` now include root utility tests. Root webhook tests replace only DNS resolution, retain the production validation path, and cover public results, blocked results and resolution errors.
- **Verification:** 30 root/application validation tests pass. All nine root tests pass with external DNS explicitly disabled. The combined documented pytest selection collects 6,193 tests without errors; this collection check is not a full-suite execution. Ruff and workflow YAML/selection checks pass. Original problem and consequence below describe the audit baseline.
- **Affected files:** `CONTRIBUTING.md` (Making Changes/Testing), `docs/source/development/index.rst:75–81,295–305`, `tests/test_validation.py:58–70`, `.github/workflows/pytest.yml`.
- **Problem:** contributing instructions run `pytest tests/`, while the main application tests live under `trustpoint/` and CI selects that directory. The root test's purported valid webhook hostnames require real DNS; `api.example.com` failed resolution locally. Developer docs also describe PostgreSQL with an automatic SQLite fallback, while settings explicitly select SQLite for normal local development and do not implement that described fallback. Running `manage.py behave` from the repository root did not locate the feature directory; an explicit `trustpoint/features/` path worked.
- **Consequence:** contributors can run only six tests and believe the application is validated; a documented test selection also fails depending on external DNS. Test setup must explain the KEK required for encrypted fields.
- **Fix:** document one complete test command and its database/secret prerequisites, include root utility tests in CI, replace live DNS in unit tests with controlled resolver results, and correct database/cwd instructions.

### H7 — Resolved: SMTP and backup credentials encrypted at rest

- **Original severity:** P1; fixed in the current changes.
- **Affected files:** `trustpoint/management/models/backup.py`, `trustpoint/management/models/email.py`, `trustpoint/management/forms.py`, `trustpoint/management/migrations/0001_initial.py`, backup/SMTP templates, and integration-credential tests.
- **Implementation:** SFTP password/private key/key passphrase and SMTP password use `EncryptedTextField` through the established application-secret service. Text columns safely fit ciphertext for maximum-length Unicode passwords. Existing input length limits remain validated.
- **Baseline:** 1.0.0 is a fresh-install-only first stable release. Encrypted fields are defined directly in `0001_initial`; `0002_initial` adds cross-app relations. There is no legacy conversion, squash replacement, or development-database upgrade path. Empty schema creation does not initialize encryption keys.
- **Forms/API:** existing and submitted secrets are never echoed. Blank fields retain stored values; replacements and explicit clear controls work for saves and unsaved connection/mail tests. Changing SFTP authentication removes obsolete credentials. The backup API serializer exposes only its existing nonsecret fields. B3's whole-view permission check is also fixed.
- **Verification:** credential tests cover raw SQL ciphertext, recovery with the original KEK, wrong-key rejection, blank values, Unicode maximum lengths, multiline keys, secret non-disclosure, explicit clearing, authentication switching, and access denial. Fresh-schema tests verify encrypted migration fields and no encryption-key initialization. Historical migration tests have been replaced with first-stable baseline tests.
- **Operational requirement:** start with a fresh database for 1.0.0 and retain its matching original key material for recovery. Development-era database states are unsupported.


### H9 — Attribution tooling and notices added; provenance review remains

- **Original severity:** P1. Missing frontend notices and distribution tooling are fixed; remaining provenance/source-obligation review stays open.
- **Implementation:** the workflow editor retains legal comments and generates full notices for 18 direct/transitive packages from actual esbuild inputs. Missing license files fail the build. Full upstream license texts now accompany Bootstrap/Popper, Bootstrap Icons (including fonts and SVG sprite), Chart.js/@kurkle/color, adapted Django theme, and the pinned uv binary. Existing Quicksand OFL and PlantUML MIT notices are inventoried; the JAR's own runtime acknowledgements are retained.
- **Distribution:** Docker copies `THIRD_PARTY_LICENSES` and ships generated editor notices beside the JavaScript. Collected Python package notices remain as static license texts; there is no container exporter, hash manifest, or supplemental-version enforcement.
- **Regression prevention:** one frontend CI check compares rebuilt JavaScript and generated notices against committed files. Existing Python license checks remain. The release checklist points to the notice inventory and remaining review requirements.
- **Verification:** local frontend rebuild/check passes. Bootstrap's vendored bundle matches its tagged upstream artifact after removing comments/whitespace. The earlier container-reporting machinery has been removed in favor of copying the notice files directly.
- **Binary package review:** the existing arm64 image has 223 installed Debian packages, all with readable copyright files. Primary terms of all 17 directly installed apt packages and CPython/uv notice locations are documented in `THIRD_PARTY_LICENSES/README.md`. Two upstream common-license references use incorrect filenames, although the corresponding texts are present. Exact corresponding-source availability for GPL/LGPL components and the static uv dependency notice inventory remain unverified; no source archive was published. This is a version-specific image snapshot, not a guarantee for later apt resolutions.
- **Remaining evidence:** The unused ministry logo was removed at the maintainer's direction. Externally supplied branding and third-party diagram/screenshot content still need provenance confirmation. The PlantUML runtime credits identify embedded components that still require a complete upstream-source license review. The actual release image still needs matching-source distribution and static binary dependency attribution review. These gaps are recorded in `THIRD_PARTY_LICENSES/README.md`; successful automated checks do not establish these rights.

## P2 — Good 1.0 Cleanup

### C1 — Resolved: shared tool environment and changed-file formatting policy

- **Original severity:** P2.
- **Files:** `.pre-commit-config.yaml`, `pyproject.toml`, `.github/workflows/ruff.yml`, `.github/workflows/mypy.yml`, contributor/developer and CI documentation.
- **Implementation:** local Ruff/mypy hooks use `language: system` and `uv run --frozen`, sharing the project pins and lockfile, runtime dependencies and Django typing support with CI. Both lint and mypy check the complete project rather than an incomplete filename subset. No separate hook tool versions remain.
- **Formatting decision:** pre-commit checks staged Python files; Ruff CI checks added/modified/renamed Python files in pull requests, respecting project exclusions. Deleted files and empty change sets are skipped. Existing untouched formatting debt is explicitly deferred; repository-wide formatting remains a diagnostic, not a passing release requirement. No mechanical repository reformat was performed.
- **Verification:** the pre-commit configuration validates, and actual local lint/mypy/formatter hooks pass. Repository-wide lint and mypy pass (609 sources). The CI file-selection command was exercised with added/modified/renamed/deleted/untouched files, filenames containing spaces, and an empty change set. Original evidence: the audit's full formatter check reported 558 files requiring formatting; that historical backlog is not represented as fixed.

### C2 — Committed editor bundle is not reproduced by the documented build

- **Severity:** P2.
- **Files:** `trustpoint/workflows2/frontend/package-lock.json`, `build.mjs`, `trustpoint/static/js/workflows2/editor_bundle.js`, `.github/workflows/`, `docker/trustpoint/Dockerfile`.
- **Problem/consequence:** `npm ci` and `npm run build` succeed in a temporary copy, but `cmp` reports the output differs from the committed bundle at character 68. Docker ships the committed bundle; no corresponding frontend rebuild/check was found in the inspected CI. A byte difference alone does not establish a functional regression; minifier/toolchain differences may contribute.
- **Fix:** establish a reproducible Node/toolchain baseline, regenerate/review the bundle, and check source-to-artifact consistency in CI. Keep all rebuilds outside the audit worktree until a fix is requested.

### C3 — An obsolete publishing pipeline references a nonexistent root Dockerfile

- **Severity:** P2.
- **Files:** `.github/workflows/main-ci-cd.yml` (build job), `docker/trustpoint/Dockerfile`, `.github/workflows/docker-manual.yml`, `.github/workflows/publish-ghcr.yml`.
- **Problem/consequence:** the message-gated main pipeline uses `docker build ... --file Dockerfile`, but the tracked application Dockerfile is under `docker/trustpoint/`. A matching `build:` commit therefore activates a broken job. Other publishing workflows use the correct path, leaving multiple inconsistent release routes.
- **Fix:** remove or repair the obsolete job, choose the supported registry/release path, require tests before release publishing, and assert tag/metadata agreement.
- **Version follow-up:** GHCR and manual publishers now guard project/lockfile/Git-tag agreement, emit stable version aliases only on matching Git-tag refs, and explicitly label images with the package version. Branch builds still publish moving/commit tags. The obsolete main job and broader release test gating remain separate unresolved C3 work.

### C4 — Scan evidence now fails closed; authenticated release coverage remains explicit

- **Original severity:** P2.
- **Files:** `.github/workflows/zap.yml`, `.github/check_zap_reports.py`, `tests/test_zap_reports.py`, `.github/workflows/codecov-upload.yml`, CI documentation and release checklist.
- **Implementation:** ZAP builds this checkout with disposable automatic setup and requires the completed-setup database record, administrator and operational login endpoint before scanning. Independent HTTP/HTTPS scans retain exit status, logs and all three report formats. The final checker rejects missing/empty/malformed reports, absent target sites and scanner errors/timeouts; reporting steps do not infer success from absent evidence. Artifacts are retained on failure and missing artifacts fail upload.
- **Finding policy:** medium/high alerts or a scanner FAIL result fail the job. Informational/low findings are explicitly reported without failing the baseline. Infrastructure/evidence errors and blocking findings have separate checker exit codes. No medium/high exception list is configured.
- **Coverage decision:** removed the unsupported >85% checklist claim. Coverage/test XML artifacts are retained, including on fork PRs where authenticated Codecov uploads are skipped. Coverage percentages/regressions require review; no numeric minimum is enforced.
- **Operational/authentication boundary:** this is an unauthenticated baseline against an operational deployment, not an authenticated spider. The release checklist separately requires recorded authenticated-session, role and protected-path coverage, including confirmation that the scanner stays logged in. That release acceptance work remains unexecuted.
- **Verification scope:** 27 new report-policy cases and nine existing root tests pass (36 total). Cases cover missing/empty artifacts and statuses, malformed JSON/schema/targets, scanner errors/timeouts, accepted low findings and blocking medium/high/configured FAIL results. The real command entry point fails on absent evidence; a simulated scanner verifies HTTPS still runs after an HTTP failure and both exact statuses are retained. Workflow shell steps pass ShellCheck; lint, formatter, checker typing and strict documentation build pass. Full ZAP/Compose and hosted CI execution are not implied by these local tests.

## P3 — Post-1.0 Improvements

### F1 — Plan supported database KEK/DEK rotation

**P3.** `trustpoint/appsecrets/service.py`, `docs/source/features/management/docker_deployment.rst` (Rotation/Recovery). Missing/wrong keys fail closed, which is appropriate. Software KEK/DEK rotation is explicitly unimplemented. Design and test a recoverable rotation procedure after the immediate defects are fixed; do not rotate keys during ordinary updates.

### F2 — Replace a remaining placeholder GDS unit test

**P3.** `trustpoint/request/tests/test_gds_push_service.py:288–303`, `trustpoint/request/tests/integration/test_gds_push_workflow.py`. `test_build_ca_chain` patches the very method it purports to test and finishes with `assert True` without invoking it. Replace it with a real chain assertion; maintain a separate real-server GDS interoperability test. This does not negate the other GDS tests in the suite.

## Security Findings

| Finding | Boundary/asset | Required action |
| --- | --- | --- |
| B1 | Management API role authorization | Deny mutations without action permission |
| B2 | Exportable device private keys | Authorize OTP creation and cancellation |
| B3 (resolved) | External backup credentials | Whole-view permission check and replacement-only forms implemented |
| B4 | Upstream CMP CA trust | Authenticate and bind replies before persistence |
| B5 | External backup destination | Pin/verify SSH host identity |
| B6 | mTLS proxy boundary | Restrict backend reachability and trust proxy proof |
| H1 | Upstream CA/key integrity | Match keys, validate chains, commit atomically |
| H7 (resolved) | External-service credentials at rest | Encryption, atomic data conversion, and original-key recovery verified |
| H8 — resolved | Operator security assurance | Removed placeholder health/vulnerability checks; aggregate failures raise `CommandError` |
| H9/C4 | Distribution/release assurance | Notices/tooling added; verify remaining provenance, source obligations and scan completion |

No real deployment secrets were printed or copied into this report. The tracked-file secret-marker search found test keys/fixtures and synthetic examples, not a confirmed live API/cloud credential. Many PEM/private-key/PKCS#12 fixtures are intentionally tracked under `tests/data`; never reuse these identities in production. Local `.env`, credential files, databases, logs, and `secrets/` exist but are ignored rather than tracked. This was not a full-history entropy/credential scan, and a clean marker search is not a guarantee that no historical secret exists.

Positive source observations: production signing keys are loaded from supplied files and are not generated into the image; nginx overwrites client-cert headers; operational Django has DEBUG disabled; PostgreSQL's published port is loopback-bound; protocol handlers verify CSRs/proof-of-possession in the reviewed enrollment paths; revocation uses transactions/row locks and resolves the verified issuing CA for rollover; YAML uses a safe loader. Disabled certificate validation in the discovery scanner is intentional certificate collection, not authentication. Webhooks and remote-CA destinations are administrator-configured integrations; no generic SSRF claim is made solely because they make outbound requests.

Advisory results: `pip-audit` reported no known vulnerabilities for 102 exported locked runtime dependencies. `npm audit --omit=dev --package-lock-only` reported zero findings. These are point-in-time advisory checks, not proof that the application, vendored JavaScript, development packages, or container OS has no vulnerabilities. No arbitrary dependency upgrades were performed.

## Upgrade and Migration Assessment

- **Clean installation:** the current source image built successfully; the repository's isolated `compose_smoke.py` passed auto-setup with PostgreSQL, web, and worker, synthetic secrets, and no published ports. Interactive wizard completion was not manually exercised in a browser.
- **Fresh schema:** pytest and Behave create test schemas; the Compose regression applies the production PostgreSQL schema. `makemigrations --check --dry-run` reports no changes. This establishes current model/schema agreement, not historical upgrade compatibility.
- **Stable baseline:** 1.0.0 is the first stable version (H2). Initial installation uses its current schema and installation-specific keys. Supported cross-version update validation applies to subsequent stable releases.
- **Persistent signing key:** `docker/init_secret.py` creates the host file atomically, validates existing files, preserves exact contents, refuses conflicting imports/symlinks, and requires root ownership/group 33/mode 0440. Runtime production loading fails closed when unavailable. Image rebuild does not replace the key.
- **Software KEK/DEK:** the independent KEK is a supplied host secret; the wrapped DEK resides in the database. Web/worker must use the same secret and database. Recreating containers with the same Compose project/volumes preserves them. Wrong/missing keys are recovery failures, not instructions to regenerate.
- **Observed rebuild/restart behavior:** the isolated smoke test verified signing-key/DEK stability across restart and recreation and verified operational data retention. It also verified read-only secret mounts even for container root and concurrent PostgreSQL initialization selecting one shared DEK. The test used the same release image for recreation; it was not a historical cross-version image upgrade.
- **HSM:** preserve provider/PIN files, token objects, HSM KEK, bootstrap handoff, media, and appropriate volumes. The standalone envelope regressions passed for software and an actual synthetic SoftHSM token inside network-isolated release containers, including recovery, fail-closed behavior, and encrypted-field round trips. That does not establish real hardware-HSM behavior or the complete optional SoftHSM Compose stack.
- **Routine commands:** `docker compose up -d` and `up -d --build` are structurally safe for a compatible existing 1.0 schema when the same project/configuration/secrets/volumes are retained. `down -v`, volume pruning, changing project names, replacing secrets, and reinitializing HSM state are destructive changes, not routine updates.
- **Rollback:** restore a matched database, original secrets, and matching token/runtime state. Rolling back only the image after a forward schema change is not proven safe. Repair and execute the backup/restore workflow before release (H3).

Architecture assessment: keep the current separation between root deployment configuration, web-owned application state, bootstrap handoff, managed signing keys, and app-secret envelopes. The concrete weaknesses are inconsistent security enforcement across adapters (management API versus protocol authorization; device RA validation versus CA enrollment), and implicit trust in network/proxy boundaries. Consolidating those checks is justified; a broad architectural rewrite is not required. Startup still couples versioning, migrations, security synchronization, TLS restoration, and scheduled initialization, so failures must leave recoverable state and surface clearly.

## Test Assessment

Discovered pytest application tests, root validation tests, Behave capability suites, Docker setup integration features, deployment/security smoke scripts, OpenSSL protocol endpoint scripts, and real-server GDS/HSM tests. Local Python is 3.13.0; the Docker image uses Python 3.14. Native test success alone therefore does not prove identical behavior on the production interpreter.

| Check actually executed | Result / interpretation |
| --- | --- |
| `.venv/bin/pytest trustpoint/ -q -o md_report=false --basetemp=/tmp/trustpoint-release-pytest` with SQLite selection | 6,128 passed, 12 failed, 17 skipped, 48 subtests passed in 615.16 seconds; all 12 failures subsequently passed in targeted runs with corrected execution conditions, as detailed below |
| Targeted unrestricted rerun of failing network tests, CMP workflow module, and secret-initializer module | 20 passed, 7 failed; all five original network failures passed; the seven remaining failures were temporary-directory group ownership, not key-content validation |
| Secret-initializer module rerun using the native user temporary directory | 22 passed; all seven remaining application-suite failures resolved under the correct directory ownership |
| `.venv/bin/pytest tests/ -q -o md_report=false` | 5 passed, 1 failed: `test_valid_webhook_urls`, DNS resolution of `api.example.com`; test/environment dependency, not demonstrated production validator failure |
| `manage.py behave trustpoint/features/ --no-capture --format pretty` with temporary SQLite DB and synthetic KEK | 18 features, 70 scenarios, 365 steps passed |
| `ruff check . --output-format concise` | Passed |
| `ruff format --check .` | Failed: 558 files would be reformatted, 575 already formatted; formatting/configuration issue (C1) |
| `mypy .` | Passed: 611 source files |
| `manage.py check` | Passed, no issues |
| `manage.py makemigrations --check --dry-run` | Passed, no changes detected |
| `shellcheck --severity=warning` on all tracked shell scripts | Passed |
| `sphinx-build -b html -n docs/source /tmp/trustpoint-release-docs` | Build succeeded with 63 warnings; documentation defects (H5) |
| Relative filesystem-target scan across tracked Markdown | No missing local targets; anchors/remote targets not checked |
| `docker build -t trustpoint-release-audit:695df736b -f docker/trustpoint/Dockerfile .` | Passed |
| `TRUSTPOINT_TEST_IMAGE=trustpoint-release-audit:695df736b python tests/docker_security/compose_smoke.py` | Passed: initial secret failures, fresh install, web/worker key sharing, read-only secrets, restart/recreation/data retention, PostgreSQL concurrent initialization |
| `docker run --rm --network=none --user 33:33 ... /tests/envelope_smoke.py software` and `pkcs11` against the release image, mounting only the test script | Both passed: wrapping, recovery, fail-closed behavior, and field round trips; PKCS#11 uses a fresh synthetic SoftHSM token without deployment volumes |
| `uv export --frozen --no-dev --no-emit-project --no-hashes` then `pip-audit --no-deps --disable-pip` | No known vulnerabilities, 102 dependencies |
| `npm audit --omit=dev --package-lock-only` | Zero vulnerabilities reported |
| `npm ci` + `npm run build` in a temporary frontend copy, then byte comparison | Build passed; committed bundle differs (C2) |
| Isolated authorization probes | B1, B2, B3 reproduced at the view/adapter boundary with mocked persistence; no real credential issuance/export performed |
| Unprotected CMP parser probe | An unprotected CMP confirmation was accepted (B4); no network interception performed |

Execution caveats and failure triage:

- Initial Docker socket access was blocked by the sandbox; the approved isolated Docker commands subsequently succeeded. Existing user deployments were not stopped or reset.
- The first Behave invocation from the repository root omitted the feature path and failed to discover steps (invocation/cwd issue). An explicit path then hit the sandbox's local-port restriction (environment). An unrestricted run without a supplied KEK produced 56 passed scenarios, 1 failed, 13 errors, including missing `/run/secrets/trustpoint_software_kek` (configuration). Supplying a synthetic temporary KEK resolved these failures; the final complete Behave run passed.
- At the audit baseline, the root validation failure depended on live DNS for an example host. H6 now replaces the resolver in unit tests while preserving production hostname validation; the root suite passes with external DNS disabled.
- Five main-suite failures were local-port sandbox restrictions: the CMP webhook receiver, three CMP mock-server cases, and encrypted OPC UA discovery. They passed when rerun with local sockets permitted. Seven initializer cases created preexisting files under `/tmp` with inherited group 0, while the fixture expected process group 20; permission validation correctly ran before malformed-content validation. They still failed outside the sandbox with that directory, and all 22 initializer tests passed under the native user temporary root (group 20). Do not weaken production permission checks to accommodate this fixture/environment mismatch.
- The application suite therefore has no unresolved implementation failure demonstrated by this run, but the full suite was not rerun as one unrestricted invocation. The original root DNS failure has since been resolved under H6. The 17 application skips include unavailable configured PKCS#11 providers, opt-in real-server GDS networking, and PostgreSQL row-lock behavior unavailable on SQLite; they are not recorded as passes.
- Formatting and documentation warnings are recorded as failures/gaps rather than silently ignored. Successful lint/type/system checks do not establish authorization correctness.

Important missing/remaining coverage: low-privilege mutation and secret-readback tests; OTP-to-export permission tests; direct backend versus nginx mTLS tests; malformed/untrusted/mismatched upstream CA replies; shuffled EST CA chains; same-subject CA rollover; wrong SSH host keys; actual cross-version PostgreSQL upgrades with encrypted records; restore with retained keys; real hardware HSM and OPC UA server interoperability; external OpenSSL EST/CMP/SCEP endpoint interoperability. SQLite skips genuine row-lock behavior, so database concurrency must be tested on PostgreSQL.

Not executed here: remote GitHub Actions/CodeQL/ZAP, full authenticated browser UX, hardware HSM tests, the complete SoftHSM Compose variant, complete backup/restore CI, historical upgrade, remote documentation-link crawl, full-history secrets scan, container OS vulnerability scan, frontend browser tests, or a fresh package-index installation across every declared Python/platform combination. These require external services, dedicated credentials/hardware, separate deployment scenarios, or additional isolated infrastructure; no result is implied. Run the remaining documented SoftHSM-stack commands in `docs/source/development/release-checklist.rst`, the repaired backup workflow, and `tests/scripts/test_protocol_endpoints.sh` in their configured environments before tagging.

Local evidence logs are under `/tmp/trustpoint-release-*` (pytest, Ruff, format, mypy, docs, shellcheck, Docker build, Compose, Behave, dependency scans, frontend build). They are temporary local evidence, not committed release artifacts.

## CI Assessment

The repository has substantial CI breadth: pytest, Behave capability matrices, mypy, Ruff, shellcheck, CodeQL, Docker Compose/auto-setup, OpenSSL enrollment endpoints, backup/restore, migration compatibility, copyright/license checks, SBOM generation, attestations, and ZAP. This audit inspected definitions; it did not fetch the current hosted run status or branch-protection settings.

Address H3/H4 before relying on recovery/upgrade evidence. Address C3 and execute C4's operational/authenticated release acceptance checks; the written checklist now distinguishes enforced baseline evidence from manual coverage review. The pytest and coverage workflow selections now include root utility tests (H6). Formatting is gated on changed Python files under C1; the existing Read the Docs build treats warnings as failures under H5. Run the secret-persistence and PostgreSQL concurrency regressions in CI rather than relying only on their documented manual commands. Actions largely use version tags, not immutable commit SHAs; consider reviewed SHA pinning, but no unsupported assertion is made that a particular action tag is obsolete or compromised. The optional comprehensive report workflow still targets `master`/a special report branch, unlike normal `main` CI.

## Documentation Assessment

**CRA mapping review (2026-10-30):** corrected `CRA_COMPLIANCE.md` to distinguish
verified 1.0.0 metadata and source artefacts from unverified publication, hosted
runs, support duration and formal assessment. Recovery timings are unmeasured
targets; configured provenance steps are distinguished from verified release
attestations. Removed the misattributed Article 15 update-trigger reference.
The risk register's summary conflicts with its individual entries
(six Low/three Medium); the mapping records that inconsistency without changing
risk ratings or declaring acceptance. Source inventory confirms 26 threats,
nine risks and 25 controls, not control effectiveness. Completing this document
review does not establish legal conformity, close security findings, or approve
the release.

- **README — fixed:** documented 1.0.0 as the first stable baseline; documented retention of the Django signing key, independent software KEK, runtime volumes, and HSM recovery material. Replaced the v0.6.0-centered highlights with final 1.0.0 information and links to release notes and capability limits.
- **Installation/operations — clarified:** retained the existing Compose/key/backup instructions and added explicit manual acceptance scenarios for interactive setup, custom ports/hostnames, IPv6, original-key restore, cross-version updates, and real client/provider combinations in `docs/source/development/release-checklist.rst`. These checks are still pending for the final release; documentation edits do not constitute deployment verification.
- **User documentation — fixed and rendered:** kept `features/workflows/index.md` and `development/architecture/backup_restore.rst` as canonical pages, removing their duplicate sources. Corrected backup manifest/recovery wording, management API documentation URLs, SCEP's implemented certificate-authenticated PKCSReq behavior, CMP trigger limitations, and the unregistered remote-rollover stub. Added `features/capabilities.md` to distinguish implementation, unavailable functionality, and interoperability evidence.
- **Developer documentation — instructions fixed:** `CONTRIBUTING.md` and the development guide now select both application/root pytest tests and the explicit Behave directory; explain a synthetic KEK, database selection, native temporary-file ownership, matching Python/tool versions, and skipped integration requirements. Documented the current device types without development-era migration references. The documented native SQLite setup sequence was executed successfully against a separate temporary database. The root DNS-dependent test and both pytest/coverage CI selections are now fixed under H6; the root suite passes without external DNS.
- **Markdown/Sphinx consistency — fixed:** repaired include paths, absent references, empty CRA links, glossary/usage-guide labels, invalid RST headings, a PlantUML class diagram, and empty root-URL rendering in generated docs/the generator. A clean HTML build with `-E -a -n -W --keep-going` passed with no warnings/errors when Java execution was permitted. Local Markdown targets passed across the 109 source files inventoried after these edits. Remote URLs, screenshots, translations, and every prose claim were not exhaustively validated; they remain separate acceptance checks.
- **Release documentation — finalized:** `CHANGELOG.md`, README, package metadata, lockfile, and Sphinx release version identify final 1.0.0 as directed. Release notes cover the stable baseline, recovery material, implemented capabilities, and actual limitations. Development acceptance procedures stay in the release checklist; unexecuted checks and unresolved audit findings are not represented as completed.

## 1.0 API / UX Decisions

The following recommendations are adopted for 1.0.0; they are not open requests
for another maintainer decision. Implementing outstanding security fixes and
recording actual test results remain separate work.

1. **Compatibility baseline — adopted:** 1.0.0 is the first stable version. Preserve its migration history and key/data continuity in subsequent supported stable updates.
2. **Authorization contract — adopted:** use explicit action permissions consistently for management operations, credential export/delegation, and service accounts. Authentication alone is not permission to mutate resources or export keys. B1–B3 remain implementation defects against this contract, not behavior accepted by this decision.
3. **Public API naming — retained:** keep `/api/` for management and `/rest/` for device enrollment; retain `/api/rest-pki/`, `workflows2`, and existing DevOwnerID/owner-credential identifiers. Clarify their meanings in documentation instead of introducing breaking renames for 1.0.
4. **Capability scope — documented:** publish implemented operations and their limits in `docs/source/features/capabilities.md`. Do not advertise SCEP polling, PKCS#11 ML-DSA signing, or remote-CA rollover as available. Retain AOKI's proof-of-concept designation and distinguish software/SoftHSM evidence from real hardware interoperability.
5. **Secret lifecycle — retained:** keep the Django signing key, software KEK, database-held wrapped DEK, and HSM recovery material distinct. Preserve existing keys on restart/update; missing keys fail closed. Document recovery requirements and the absence of software KEK/DEK rotation.
6. **Workflow integration contract — documented:** retain the existing YAML/trigger/approval/lease interfaces and design integrations to tolerate retried external calls. Require idempotent receivers or integration-specific deduplication; do not promise exactly-once external effects. References: `workflows2/services/dispatch.py`, `runtime.py`, `worker.py`, and the workflow guide.
7. **Deployment route — retained:** source-built Linux Docker Compose is the primary documented deployment. Published images are optional and must match the intended release/platform. Do not infer a multi-architecture guarantee from QEMU setup alone.

## Repository Hygiene

The initial tracked worktree was clean. `.gitignore` and `.dockerignore` exclude local `.env`, `secrets/`, database/credential files, media, logs, common caches, and IDE state. The local checkout contains ignored databases, logs, keys, reports, and editor files; their presence is not evidence they were committed. Do not delete them as audit cleanup. The Docker build excludes the sensitive local paths and copies selected public test chains for demo truststores rather than all test private keys.

Tracked private-key/PKCS#12 files are predominantly explicit test fixtures and should remain visibly non-production. Five nonempty non-migration Python files lacked an SPDX header in their first 600 characters: `tests/docker_integration/features/environment.py`, `tests/docker_integration/features/steps/__init__.py`, `tests/docker_integration/features/steps/r_200_steps.py`, `tests/scripts/est_csr.py`, and `tests/test_validation.py`; review them against project policy without mechanically changing historical copyright dates. `docs/unused/` and internal architecture implementation plans contain historical TODO/design material; label their status rather than presenting it as current user guidance. The remaining remote-CA rollover stub is not automatically a broken user feature: registration/reachability must be checked before advertising it.

Dependency organization: the committed `uv.lock` provides a production version selection; broad declaration ranges are not by themselves a defect in the frozen Docker build. `pyproject.toml` puts documentation/analysis/stub packages such as furo, pydeps, and Django typing dependencies in runtime dependencies. `requests` is directly imported by production EST/CMP/webhook code but declared directly only in the dev group; the current production closure nevertheless includes it through Sphinx/furo. Declare runtime imports directly before pruning tooling dependencies. No installed dependency was conclusively proven unused across every supported workflow, and no arbitrary upgrades are recommended.

## Version / Release Changes Required

**Version identity review (2026-10-30; source `2953fb01e`):**

| Surface | Observed / configured value | Evidence limit |
| --- | --- | --- |
| Package and runtime | Declared and installed package, lockfile entry and `APP_VERSION`: `1.0.0` | Verified in this local environment |
| UI | Registered context processor renders the actual footer fragment as `v1.0.0`, linking to release tag `v1.0.0` | Browser/deployed-image verification remains separate |
| Database | Read-only local SQLite query: `AppVersion` row 1 is `1.0.0`; operational startup synchronizes from runtime metadata | Does not establish a production/PostgreSQL instance's state |
| OpenAPI | Generated schema `info.version` is `1.0.0` | Generation also reports existing custom-authentication/serializer schema warnings; this is a version check, not a clean-schema assertion |
| Container labels | Both publishers explicitly set `org.opencontainers.image.version` from the checked package version (`1.0.0`) | Source configuration verified; newly published image labels not yet inspected |
| Registry / Git tags | Canonical release tag is `v1.0.0`; both workflows reject mismatched tag refs, and branches publish moving/commit tags rather than stable version aliases | No matching remote Git tag was returned; GHCR and Docker Hub `v1.0.0` manifest reads returned not found |

Both workflow version guards were exercised for matching/mismatched refs and
lockfile drift; YAML/shell checks pass. The 36 existing initialization/startup
command tests pass. No Git tag, registry artefact or database record was created
or rewritten to force agreement. Agent, protocol, dependency and fixture versions
retain their own meanings.

- [x] Set `pyproject.toml` project version to final `1.0.0`.
- [x] Align `uv.lock` project metadata with `1.0.0`; `uv lock --check --offline` passes without dependency upgrades.
- [x] Set the Sphinx release version in `docs/source/conf.py` to `1.0.0`.
- [x] Update README v0.6.0 highlights with accurate release information and the initial stable installation.
- [x] Finalize the `CHANGELOG.md` 1.0.0 entry and include it in the Sphinx release notes.
- [x] Apply the user's instruction to present final 1.0.0 release notes; no further documentation approval is pending.
- [x] Document 1.0.0 as the first stable compatibility baseline (H2).
- [x] Review `docs/source/cra/CRA_COMPLIANCE.md` claims/version table against actual release evidence; keep legal conformity, maintainer risk acceptance and unverified release artefacts explicitly outside the review result.
- [x] Confirm declared/installed package version, runtime `APP_VERSION`, rendered UI version, local database `AppVersion` and generated OpenAPI version agree on `1.0.0` (display/release links use `v1.0.0`).
- [x] Make publishing version identity explicit: reject project/lockfile or Git-tag mismatches before publishing, set OCI version labels to the raw package version, and emit stable version tags only from matching Git-tag refs.
- [ ] Confirm the final published `v1.0.0` Git tag, registry tags, image digests and OCI labels agree with the running release. On 2026-10-30, the remote Git lookup returned no `v1.0.0` tag and public GHCR/Docker Hub manifest lookups returned “not found”; this final-artifact check cannot yet be marked complete.
- [ ] Verify `.github/workflows/docker-manual.yml` and `publish-ghcr.yml` tag generation, registry destinations, test gating, and release image digests. Avoid silently overwriting a final version-derived tag during unrelated main pushes.
- [x] Retain source-built Linux Compose as the primary deployment and avoid an unverified multi-architecture claim. Published-image/platform validation remains part of release testing.
- [ ] Produce reviewed SBOM, notices, provenance, and security/test artifacts for the exact release image, including its OS packages and shipped frontend.
- [ ] Run the full supported test/deployment matrix against the final versioned commit before creating `v1.0.0`.

## Final 1.0 Checklist

- [x] Resolve B3 and H7 with encryption in the initial schema, replacement-only forms, and negative disclosure/access tests.
- [ ] Resolve the remaining B1, B2, B4–B6 findings and add their authorization/trust-boundary regressions.
- [ ] Resolve selected P1 findings and explicitly accept/document any deferred ones.
- [x] Record the full application pytest result and triage all failures/skips; affected cases pass with corrected execution conditions.
- [ ] Obtain a single green full application/root test invocation in the supported release environment, retaining the separate HSM/PostgreSQL/interoperability requirements.
- [x] Fix the root utility test's live-DNS dependency and include it in pytest and coverage CI.
- [x] Behave passes with the documented required secret configuration.
- [x] Ruff lint, mypy, Django system checks, migration drift check, and shellcheck pass locally.
- [x] Reconcile formatter/tool environments, adopt changed-file formatting, and rerun the chosen checks.
- [x] Current Dockerfile builds.
- [x] Isolated software-backed Compose clean-install, restart, recreation, and PostgreSQL concurrent DEK tests pass.
- [x] Persistent signing key/DEK and read-only secret mounts survive recreation in the isolated release stack.
- [ ] For subsequent stable releases, test supported previous-stable-image → new-image updates with encrypted data; this is not an acceptance prerequisite for the first stable baseline.
- [x] Accept 1.0.0 as the first stable version; describe current behavior without development-era migration history.
- [ ] Verify recovery from matched database/KEK/HSM backups; repair/run backup-restore CI.
- [x] Run software and real SoftHSM/PKCS#11 envelope regressions inside the release image.
- [ ] Validate the complete optional SoftHSM stack and required hardware-HSM behavior.
- [ ] Run real EST/CMP/SCEP/OpenSSL and OPC UA interoperability checks for advertised capabilities.
- [ ] Verify production configuration, external hostnames, custom ports, IPv6, proxy boundaries, and interactive wizard in a fresh browser session.
- [x] Resolve Sphinx warnings/duplicate pages and verify a clean strict build and rendered workflow/backup/release/development pages.
- [ ] Complete production README installation and manual deployment acceptance checks on the final release.
- [ ] Verify remote documentation links and important screenshots/examples.
- [x] Locked Python runtime and npm production advisory scans completed without known findings.
- [ ] Review container OS scan, CodeQL/ZAP results, historical secrets scan, notices, and release SBOM.
- [ ] Rebuild/review the shipped frontend bundle using a fixed toolchain.
- [ ] Set version consistently to 1.0.0 and prepare accurate release notes.
- [ ] Confirm required hosted CI checks and branch/release protections for the exact final commit.
- [ ] Create the release tag only after the blockers are fixed and the release evidence is complete.

**Would you tag the current commit as Trustpoint v1.0.0? No.** The verified permission/credential-disclosure paths and the traced upstream/SSH/proxy trust failures are unacceptable in a public PKI release, even though deployment persistence and many automated checks pass. Fix those boundaries, establish the upgrade contract, and rerun the final release matrix before tagging.

## CSP and ZAP release hardening — 2026-10-30

The patched working tree based on `c0ba27657cd1be80ebbc6929bb2fafc60a1af71c`
was built and tested in disposable Docker Desktop arm64 containers with synthetic
credentials, isolated networks and volumes. The application image was
`sha256:e09b44e54db75ca7946ee0a768e8d0860ae47aef68606a7f43c3999a933f04d6`.
These results supplement the earlier audit limitations above.

Changes:

- Enforced Django CSP covers login, bootstrap/setup, operational pages, redirects,
  CSRF failures and production errors. Trusted inline scripts/styles use fresh
  request nonces. Inline handlers/layouts were moved to explicit actions and CSS;
  neither `unsafe-inline` nor `unsafe-eval` is allowed.
- CodeMirror receives its style nonce; graph overlays use CSSOM. Ordinary typing
  uses editor transactions to avoid Chromium copying syntax colors into native
  inline formatting. Undo/redo and paste were exercised.
- Swagger/ReDoc use self-hosted assets. The reproducible ReDoc bundle initializes
  its nonce before style loading and uses a local branding image; its license is
  retained. Only ReDoc permits a local blob search worker.
- Nginx preserves the exact Django CSP once and supplies restrictive CSP/security
  headers on its own redirects, static files and errors. HTTP enrollment locations
  inherit all sanitized proxy assertions; partial overrides previously discarded
  server-level TLS identity/protocol header sanitization.
- Docker session/CSRF cookies are Secure. Native HTTP development and HTTP CRL,
  CMP and SCEP routing remain supported. No global HTTPS redirect, HSTS policy,
  CSP resource wildcard, scanner suppression or threshold relaxation was added.
- CI adds deployed header/routing and authenticated Chromium checks. Pytest CI
  checks the reproducibility of the bundled ReDoc asset against installed dependencies.

Final independent ZAP results (`ghcr.io/zaproxy/zaproxy:stable`, ZAP 2.17.0,
image digest `sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238`):

| Target | Medium | High | Low | Informational | Scanner exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| HTTP | 0 | 0 | 4 | 9 | 2 |
| HTTPS | 0 | 0 | 5 | 12 | 2 |

Both scans used the workflow's unchanged `zap-baseline.py -t <origin> -a -T 5`
commands and JSON/Markdown/HTML outputs. Docker Desktop required
`--network container:trustpoint-zap-release-app` in place of Linux runner host
networking; both scanners still targeted `http://localhost` / `https://localhost`.
Exit 2 represents warnings; `.github/check_zap_reports.py` accepted both complete
reports and found no medium/high or configured FAIL results. Rules 10038 (missing
CSP) and 10055 (CSP weaknesses) are absent. No rules were excluded or downgraded.

Residual alerts remain visible for release review:

| Rule | Disposition |
| --- | --- |
| 10010: cookie without HttpOnly | The evidence is `csrftoken`, read by existing JavaScript CSRF helpers. Session cookies remain HttpOnly. |
| 10035: missing HSTS (HTTPS only) | Deployment-specific: enable at a permanent, trusted TLS edge after reviewing host/subdomain scope. Self-signed bootstrap and direct HTTP development remain supported. |
| 10063: Permissions-Policy missing | Low-priority browser capability restriction remains unset; no threshold change or suppression. |
| 90004: COEP/CORP missing | Additional cross-origin isolation headers remain unset. COOP remains Django's `same-origin`. |
| 10027: suspicious comments | Informational matches in ordinary static JavaScript comments, including references to Django admin and user-controlled attributes; no secret disclosure was identified in those instances. |
| 10031: user-controllable HTML attribute | Informational login-form reflection. Django escaping remains active; a regression test verifies injected markup stays escaped. |
| 10049, 10094, 10109, 10111, 10112, 90005 | Informational cache behavior, nonce/token Base64, modern application/authentication/session detection and missing scanner request Fetch Metadata headers. Full instances remain in the reports. |

Validation: 246 tests and 11 subtests passed across security/middleware/settings,
ZAP evidence policy, Nginx inheritance, users and Docker setup tests. The final
focused suite, including cookie defaults and escaped login reflection, passed 90 tests.
Authenticated Chromium checks passed for theme switching, login, dashboard,
notification filtering, CA pages, workflow overlays/editing/undo/redo/paste,
Swagger and ReDoc search, with zero CSP violations or JavaScript errors.
A separate bootstrap container passed authenticated setup chooser, fresh-install
admin, connect-existing database and restore database page checks. Deployed
HTTP/HTTPS headers, HTTP enrollment error paths and `nginx -t` passed.
The strict Sphinx build, focused Ruff/mypy checks and frontend bundle checks passed.

Local raw evidence is retained under the ignored
`var/release-security-1.0.0/` directory: `zap/` contains both complete report sets,
logs and exit codes; accompanying logs record browser, bootstrap, header, test,
typing, documentation and image-build checks. `evidence.json` records scan scope
and `source-sha256.json` records the reviewed working-tree files.

Hosted GitHub Actions was not dispatched: the available GitHub authentication was
invalid and these changes are unpublished. Local execution of the workflow's scan
commands is verified; a green hosted run of the patched revision remains a release
check. The browser smoke test is targeted functional coverage, not an authenticated
ZAP scan of every role/API. Enrollment issuance, hardware HSM, external TLS edges
and every deployment variant were not rerun by this hardening task.
See `docs/source/development/security-response-headers.rst` for policy details,
asset regeneration and deployment-specific settings.
