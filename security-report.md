# Trustpoint security audit report

Date: **8 November 2026**  
Reviewed commit: `25d2e27edf58c6d70083b77d2f7af9c9d6375105`  
Status: **Remediations tested — independent audit confirmation incomplete**

## Remediation pass — 9 November 2026

L-01 through L-21 have received source-level fixes or conditional defensive hardening, with focused regression coverage. No severity rating or independent vulnerability-confirmation claim is added. L-18's distinct security impact, L-19's deployed ingress boundary and L-20's real-data reader policy remain conditional. Focused runtime regressions ran in an isolated offline Docker container; results and limits are recorded below. The original audit evidence and coverage limitations below remain historical records.

## Remediation validation — 9 November 2026

- The affected-module run finished with **595 passed, 2 skipped and one compatibility failure**: the initial token endpoint returned 401 instead of its established 403 for a user without REST entitlement. The shared policy now raises the existing permission-denied response, retaining entitlement checks for login, refresh and bearer requests.
- After that correction, the final rerun of both user-authentication modules plus workflow and extended device-view callers finished with **120 passed, 2 skipped**. There are no remaining observed failures. These counts overlap and must not be added together.
- The two skips require PostgreSQL/nonblocking row locks; the isolated tests used SQLite. The disposable toolchain omitted the optional Markdown-report pytest plugin, causing two unknown-report-option warnings only.
- Ruff passed for all changed production Python files, AST parsing passed for all 42 changed Python files, `bash -n` passed for the installer, and `git diff --check` passed.

The following two validation invocations ran inside local image `trustpoint-setup-wizard-regression:local`, using its existing Python 3.14/application dependencies and already-installed pure-Python development packages copied read-only from the local virtual environment. Nothing was downloaded or installed. The first invocation covered 20 affected modules. The second reran the two user modules after the status-code correction and checked the workflow/device callers.

```sh
python -B -m pytest -p pytest_django.plugin \
  --basetemp=/scratch/pytest -o cache_dir=/scratch/cache -q \
  trustpoint/trustpoint/tests/test_security_lead_permissions.py \
  trustpoint/setup_wizard/tests/test_pkcs11_snapshot.py \
  trustpoint/users/tests/test_security_regressions.py \
  trustpoint/users/tests/test_service_accounts.py \
  trustpoint/pki/tests/test_issued_credential.py \
  trustpoint/pki/tests/test_owner_credential_enrollment_service.py \
  trustpoint/pki/tests/test_security_hardening.py \
  trustpoint/pki/tests/test_owner_credential_views.py \
  trustpoint/request/tests/test_authorization.py \
  trustpoint/request/tests/test_authentication_branches.py \
  trustpoint/request/tests/test_authentication_extended.py \
  trustpoint/help_pages/tests/test_scep_config_download.py \
  trustpoint/agents/tests/test_views.py \
  trustpoint/devices/tests/test_views/test_browser_onboarding.py \
  trustpoint/devices/tests/test_views/test_device_views.py \
  trustpoint/pki/tests/test_crl_cycle_views.py \
  trustpoint/pki/tests/test_crl.py \
  trustpoint/pki/tests/test_views_issuing_ca_core.py \
  trustpoint/est/tests/test_est_interface.py \
  trustpoint/rest_pki/tests/test_views.py
```

```sh
python -B -m pytest -p pytest_django.plugin \
  --basetemp=/scratch/pytest -o cache_dir=/scratch/cache -q \
  trustpoint/users/tests/test_security_regressions.py \
  trustpoint/users/tests/test_service_accounts.py \
  trustpoint/workflows2/tests/test_views_http.py \
  trustpoint/devices/tests/test_views/test_device_views_extended.py
```

Sandbox controls: `--network none`, read-only container root and disposable source/toolchain mount, user `65534:65534`, all capabilities dropped, `no-new-privileges`, one CPU, 2 GiB memory with no additional swap, 64 processes, 256 file descriptors, 64 MiB maximum file size, 768 MiB scratch tmpfs, and a parent-enforced 300-second timeout followed by forced container cleanup. Source-copy media and development-state links pointed only into `/scratch`; no host databases, credentials, sockets or services were mounted.

The target started through `env -i` with only these allowlisted values: `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=/scratch/home`, `TMPDIR=/scratch/tmp`, `XDG_CACHE_HOME=/scratch/cache`, `PYTHONDONTWRITEBYTECODE=1`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONPATH=/audit/tools:/audit/source/trustpoint`, `DJANGO_SETTINGS_MODULE=trustpoint.settings`, `TRUSTPOINT_PHASE=operational`, `TRUSTPOINT_OPERATIONAL_DATABASE=sqlite`, `TRUSTPOINT_OPERATIONAL_SQLITE_PATH=/scratch/operational.sqlite3`, and `DJANGO_SECRET_KEY_FILE=/scratch/django-key`. That file contained only `dummy-isolated-test-signing-key-for-security-regressions-only`. All principals, passwords, certificates and uploaded-file inputs came from local dummy fixtures.

The disposable workspace was removed after verification. The full repository suite, PostgreSQL concurrency behavior, deployed proxy isolation and root-privileged installer integration were not checked. These regressions validate the changes; they do not constitute independent confirmation of every original vulnerability claim.

## Review follow-up — 9 November 2026

The three ponytail-review findings were corrected:

1. Certificate deletion now acquires a row lock on a freshly loaded certificate inside `transaction.atomic()` before checking truststore membership and deleting. A real-record denial test preserves both certificate and membership. A PostgreSQL test verifies from a separate connection that the row is already locked when membership authorization runs.
2. CMP issuer-chain construction no longer stops merely because subject and issuer names match. A rollover regression verifies that a same-name certificate signed by the old CA key retains that issuer.
3. The remaining CRL help-page caller now renders a POST form with a CSRF token and preserves its `next` destination. An integration test submits that form with CSRF enforcement, generates a CRL and returns to the help page.

**Validation: 133 passed, no skips**, using disposable PostgreSQL 18.6 and the existing local Python/application image. Ruff, AST syntax checks and `git diff --check` also passed. The optional Markdown pytest report plugin was omitted, producing two unknown-report-option warnings only.

The regression command was:

```sh
python -B -m pytest -p pytest_django.plugin \
  --basetemp=/scratch/pytest -o cache_dir=/scratch/cache -q \
  trustpoint/pki/tests/test_certificate_delete_permissions.py \
  trustpoint/pki/tests/test_security_hardening.py \
  trustpoint/pki/tests/test_crl_cycle_views.py \
  trustpoint/help_pages/tests/test_pki_help_views.py \
  trustpoint/trustpoint/tests/test_security_lead_permissions.py \
  trustpoint/pki/tests/test_views_issuing_ca_core.py \
  trustpoint/pki/tests/test_audit_regressions.py
```

Both containers used read-only roots, no capabilities, no new privileges, one CPU each, 64-process and 256-file-descriptor limits, and 64 MiB file-size limits. The database had 512 MiB memory and a 256 MiB scratch tmpfs; the test process had 2 GiB memory and a 512 MiB scratch tmpfs. There was no additional swap. PostgreSQL ran in a `--network none` namespace; the test container joined only that isolated namespace and connected over loopback. No host ports, credentials, databases or sockets were exposed. Startup was bounded to 45 seconds and tests to 240 seconds, with forced container cleanup. Only a disposable read-only source/toolchain copy was mounted; it was removed after verification.

The test process started through `env -i` with `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=/scratch/home`, `TMPDIR=/scratch/tmp`, `XDG_CACHE_HOME=/scratch/cache`, `PYTHONDONTWRITEBYTECODE=1`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONPATH=/audit/tools:/audit/source/trustpoint`, `DJANGO_SETTINGS_MODULE=trustpoint.settings`, `DJANGO_SECRET_KEY_FILE=/scratch/django-key`, `TRUSTPOINT_PHASE=operational`, `TRUSTPOINT_OPERATIONAL_DATABASE=postgresql`, `TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND=1`, `DATABASE_HOST=127.0.0.1`, `DATABASE_PORT=5432`, `POSTGRES_DB=postgres`, `DATABASE_USER=review`, and `DATABASE_PASSWORD=dummy-review-db-password`. The signing-key file contained only `dummy-review-fix-signing-key-for-local-tests-only`. The database started through `env -i` with `PATH=/usr/lib/postgresql/18/bin:/usr/local/bin:/usr/bin:/bin`, `HOME=/scratch`, `TMPDIR=/scratch`, and `LANG=C.UTF-8`; `initdb --auth=trust --username=review` initialized only scratch-local dummy data. No packages were installed or downloaded.

The full suite, deployed ingress and root-privileged installer integration remain outside this validation. This run exercises PostgreSQL row locking but does not claim production-load stress coverage or independent closure of all original audit leads.

## CMP provenance follow-up — 9 November 2026

The second review found that a signature-linked path alone did not authenticate the supplied issuer certificates. An attacker could place the legitimate issuer's public key in a replacement certificate signed by an unapproved root, and both certificates passed the old filter.

CMP CA enrollment now loads trust anchors only from its explicitly configured `no_onboarding_config.trust_store`. The existing `CertificateVerifier.verify_ca_cert` builds a path to those anchors; only that path's issuers may become CA inventory or parent relationships. The previous per-issuer CA-extension checks remain. Missing issuer trust, an empty truststore or an untrusted result fails before certificate, credential or CA persistence.

Service-level regressions exercise a replacement issuer with the real public key and an attacker signature. A legitimate result uses the configured root and discards both forged extras; an untrusted result preserves the existing credential and creates no certificate or CA records. Missing configuration/truststore cases, same-name replacement CAs and rollover paths are also covered.

**Validation: 88 passed**, followed by **2 passed** after refining the forged-certificate fixtures to carry matching authority-key identifiers and explicitly verifying their signatures. Counts overlap. Ruff, AST syntax checks for the three changed Python files, and `git diff --check` passed. The optional Markdown pytest report plugin was omitted, producing two unknown-report-option warnings only.

```sh
python -B -m pytest -p pytest_django.plugin \
  --basetemp=/scratch/pytest -o cache_dir=/scratch/cache -q \
  trustpoint/pki/tests/test_security_hardening.py \
  trustpoint/pki/tests/test_audit_regressions.py \
  trustpoint/pki/tests/test_util_x509.py \
  trustpoint/pki/tests/test_ca_crl_api.py
```

The final focused invocation used the same command options with only `trustpoint/pki/tests/test_audit_regressions.py::test_cmp_enrollment_never_imports_attacker_cross_signed_extras`.

These checks used the existing local Python/application image and copied, already-installed pure-Python test dependencies; no packages were installed or downloaded. The container had no network, read-only root/source/toolchain, user `65534:65534`, all capabilities dropped, no new privileges, one CPU, 2 GiB memory with no extra swap, 64 processes, 256 file descriptors, 64 MiB file-size limits, a 512 MiB scratch tmpfs and a parent-enforced 180-second timeout with forced cleanup. The disposable source/toolchain was removed afterward. No host credentials, databases, sockets or services were exposed.

The target started through `env -i` with only `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=/scratch/home`, `TMPDIR=/scratch/tmp`, `XDG_CACHE_HOME=/scratch/cache`, `PYTHONDONTWRITEBYTECODE=1`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONPATH=/audit/tools:/audit/source/trustpoint`, `DJANGO_SETTINGS_MODULE=trustpoint.settings`, `DJANGO_SECRET_KEY_FILE=/scratch/django-key`, `TRUSTPOINT_PHASE=operational`, `TRUSTPOINT_OPERATIONAL_DATABASE=sqlite`, and `TRUSTPOINT_OPERATIONAL_SQLITE_PATH=/scratch/test.sqlite3`. The signing-key file contained only `dummy-cmp-trust-fix-signing-key-for-local-tests-only`; all certificates, keys and accounts were dummy fixtures.

The full suite and a live upstream enrollment were not checked. Existing CMP configurations must contain trusted issuer material that can validate the requested CA certificate; a transport-only truststore from a different PKI will now fail closed.

## CA chain search without a fixed cap — 9 November 2026

The fixed signature-check budget was replaced at the owner's request. The shared CA path builder now uses an iterative, cycle-aware traversal. Certificates are deduplicated and grouped by issuer subject; each reachable certificate is queued once, with a predecessor recorded for path reconstruction. Candidate signatures still have to verify and the path still has to reach an explicitly configured trust anchor.

This removes permutation-based backtracking and Python recursion without imposing a signature-count or chain-length cap. Search work is proportional to certificates and candidate issuer links (at worst quadratic in the number of distinct certificates), rather than factorial in cyclic inputs. State belongs only to the current validation call.

Regressions verify rejection of a six-certificate cycle after **seven signature checks**, discovery of a valid issuer alongside that cyclic branch, and acceptance of a **1,101-certificate trusted chain**. An ordinary direct chain also continues to validate after a rejected input.

**Validation: 187 passed, no skips.** Ruff, AST parsing of both changed Python files and `git diff --check` passed. Two warnings concerned only the omitted optional Markdown pytest report plugin.

```sh
python -B -m pytest -p pytest_django.plugin \
  --basetemp=/scratch/pytest -o cache_dir=/scratch/cache -q \
  trustpoint/pki/tests/test_util_x509.py \
  trustpoint/pki/tests/test_security_hardening.py \
  trustpoint/pki/tests/test_audit_regressions.py \
  trustpoint/pki/tests/test_security_policy.py \
  trustpoint/pki/tests/test_ca_crl_api.py \
  trustpoint/pki/tests/test_forms_truststores.py \
  trustpoint/pki/tests/test_forms_issuing_cas_extended.py
```

The test used the existing local application image and already-installed pure-Python test packages; no packages were installed or downloaded. It ran with no network, read-only container root/source/toolchain, user `65534:65534`, all capabilities dropped, no new privileges, one CPU, 2 GiB memory with no additional swap, 64 processes, 256 file descriptors, 64 MiB file-size limits, a 512 MiB scratch tmpfs and a parent-enforced 180-second timeout with forced cleanup. Only scratch-local dummy fixtures and databases were writable, and the disposable source/toolchain was removed afterward.

The process started through `env -i` with only `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=/scratch/home`, `TMPDIR=/scratch/tmp`, `XDG_CACHE_HOME=/scratch/cache`, `PYTHONDONTWRITEBYTECODE=1`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONPATH=/audit/tools:/audit/source/trustpoint`, `DJANGO_SETTINGS_MODULE=trustpoint.settings`, `DJANGO_SECRET_KEY_FILE=/scratch/django-key`, `TRUSTPOINT_PHASE=operational`, `TRUSTPOINT_OPERATIONAL_DATABASE=sqlite`, and `TRUSTPOINT_OPERATIONAL_SQLITE_PATH=/scratch/test.sqlite3`. The signing-key file contained only `dummy-chain-traversal-signing-key-for-local-tests-only`. No host credentials, sockets, databases or shared services were mounted.

The full repository suite and a live upstream enrollment were not checked.

## Executive summary

The review identified **21 unverified source-level security leads**. The recurring concern is inconsistent operation authorization between browser routes, APIs and shared processing. Other leads concern certificate revocation, credential lifetime, generated command escaping, and privileged file handling.

**No vulnerability has completed independent source verification and bounded runtime confirmation.** No severity ratings are assigned. The empty `findings.json` records that evidence state; it does not establish that the application is free of vulnerabilities.

Candidate validation and independent final-record verification have not run. A clean final coverage pass is also outstanding. The recorded stopping point followed a reported chat display restriction; runtime checks were separately unavailable because the audit's required execution sandbox had not been established.

Original vulnerability claims below retain status **Unverified**; dated remediation updates describe the subsequent source changes separately. They describe possible effects and the invariants to validate, without asserting successful exploitation. Exact candidate fingerprints and their linked coverage units are retained here for audit continuity:

<details>
<summary>Unverified candidate fingerprints and coverage-unit references</summary>

**L-01 — Manual browser issuance authorization**  
Fingerprint: `trustpoint/devices/views/credential_issuance.py:AbstractIssueCredentialView:missing-issue-certificates-permission`

- Coverage unit: `trustpoint%2Fdevices%2Furls.py%23manual%20generated-key%20and%20external-CSR%20issuance%20routes::trustpoint%2Frequest%2Fauthorization%2Fmanual.py%23ManualAuthorization::trustpoint%2Fdevices::ATTACK-CLASSES.md%23Access%20control`

**L-02 — REST management issuance authorization**  
Fingerprint: `rest_pki/api_views.ApplicationCertificateEnrollView.missing-issue-permission`

- Coverage unit: `trustpoint%2Fest%2Furls.py::trustpoint%2Frequest%2Fauthentication%2Fbase.py::trustpoint%2Frequest::ATTACK-CLASSES.md%23Access%20control`

**L-03 — Browser signing authorization**  
Fingerprint: `signer/views.py:SignHashView:missing-signer-authorization`

- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23browser::trustpoint%2Fusers%2Fmiddleware.py::trustpoint%2Ftemplates::ATTACK-CLASSES.md%23Access%20control`

**L-04 — Owner and zero-touch browser mutations**  
Fingerprint: `trustpoint/browser-owner-credentials/missing-operation-authorization`

- Coverage unit: `trustpoint%2Fdevices%2Furls.py%23zero-touch%20and%20trustpoint%2Fpki%2Furls.py%23owner-credential%20browser%20lifecycle%20routes::trustpoint%2Fdevices%2Fviews%2Fowner_credentials.py%23browser%20mutation%20to%20owner%20credential%20and%20onboarding%20trust%20state::trustpoint%2Fdevices::ATTACK-CLASSES.md%23Access%20control`

**L-05 — GDS truststore association and upload**  
Fingerprint: `devices/OpcUaGdsPushTruststoreAssociationView/missing-mutation-permissions`

- Coverage unit: `trustpoint%2Fdevices%2Furls.py%23OPC%20UA%20discovery%20and%20truststore-association%20routes::trustpoint%2Fdevices%2Fviews%2Fcredential_issuance.py%23OpcUaGdsPushTruststoreAssociationView::trustpoint%2Fdevices::ATTACK-CLASSES.md%23Access%20control`

**L-06 — Presented-certificate revocation binding**  
Fingerprint: `pki/models/credential.py:historical-certificate-auth-checks-current-primary`

- Coverage unit: `trustpoint%2Fcmp%2Furls.py::trustpoint%2Fpki%2Fmodels%2Fcredential.py%23is_valid_issued_credential::trustpoint%2Frequest::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use`
- Coverage unit: `trustpoint%2Fest%2Furls.py::trustpoint%2Fpki%2Fmodels%2Fcredential.py%23is_valid_issued_credential::trustpoint%2Frequest::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use`
- Coverage unit: `trustpoint%2Frest_pki%2Furls.py::trustpoint%2Fpki%2Fmodels%2Fcredential.py%23is_valid_issued_credential::trustpoint%2Frequest::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use`
- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23api::trustpoint%2Fusers%2Fpermissions.py::trustpoint%2Fagents::ATTACK-CLASSES.md%23Business%20logic`
- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23api::trustpoint%2Fusers%2Fpermissions.py::trustpoint%2Fagents::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use`

**L-07 — SCEP command argument escaping**  
Fingerprint: `help_pages/NoOnboardingScepStrategy/renewal-subject-shell-injection`

- Coverage unit: `trustpoint%2Fdevices%2Furls.py%23device%20enrollment%20help%20and%20agent%20setup-profile%20downloads::trustpoint%2Fhelp_pages%2Fdevices_help_views.py%23BaseHelpView%20and%20AgentSetupProfileDownloadView::trustpoint%2Fhelp_pages::ATTACK-CLASSES.md%23Feature%20abuse%20and%20data%20leakage`

**L-08 — Device protocol-disable policy**  
Fingerprint: `request/authorization.http-enrollment.missing-device-protocol-policy`

- Coverage unit: `trustpoint%2Fest%2Furls.py::trustpoint%2Frequest%2Fauthentication%2Fbase.py::trustpoint%2Frequest::ATTACK-CLASSES.md%23Access%20control`
- Coverage unit: `trustpoint%2Fest%2Furls.py::trustpoint%2Frequest%2Fauthentication%2Fbase.py::trustpoint%2Frequest::ATTACK-CLASSES.md%23Business%20logic`

**L-09 — Certificate deletion and truststore membership**  
Fingerprint: `pki/views/certificates.py:destroy-cascades-truststore-without-permission`

- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23api::trustpoint%2Fusers%2Fpermissions.py::trustpoint%2Fagents::ATTACK-CLASSES.md%23Access%20control`

**L-10 — Workflow runtime controls**  
Fingerprint: `workflows2/views.runtime-controls.missing-management-permission`

- Coverage unit: `trustpoint%2Fworkflows2%2Furls.py::trustpoint%2Fworkflows2%2Fapi_views.py::trustpoint%2Fworkflows2::ATTACK-CLASSES.md%23Access%20control`
- Coverage unit: `trustpoint%2Fworkflows2%2Furls.py::trustpoint%2Fworkflows2%2Fapi_views.py::trustpoint%2Fworkflows2::ATTACK-CLASSES.md%23Business%20logic`

**L-11 — GDS renewal configuration**  
Fingerprint: `devices/views/gds_push.py:cert-renewal-settings.missing-device-permission`

- Coverage unit: `trustpoint%2Fworkflows2%2Furls.py::trustpoint%2Fworkflows2%2Fapi_views.py::trustpoint%2Fworkflows2::ATTACK-CLASSES.md%23Access%20control`
- Coverage unit: `trustpoint%2Fworkflows2%2Furls.py::trustpoint%2Fworkflows2%2Fapi_views.py::trustpoint%2Fworkflows2::ATTACK-CLASSES.md%23Business%20logic`

**L-12 — Browser CRL generation**  
Fingerprint: `pki/issuing-cas/browser-crl-generation-missing-manage-cas`

- Coverage unit: `trustpoint%2Fpki%2Furls.py%23CRL%20import%20and%20public%20CRL%20distribution::trustpoint%2Fpki%2Fmodels%2Fcrl.py%23CrlModel.create_from_pem::trustpoint%2Fpki::ATTACK-CLASSES.md%23Business%20logic`

**L-13 — REST entitlement withdrawal**  
Fingerprint: `users/oauth2_views.py:api_user_authentication_rule:rest-api-entitlement-refresh`

- Coverage unit: `trustpoint%2Fusers%2Furls.py::trustpoint%2Fusers%2Fauthentication.py::trustpoint%2Fusers::ATTACK-CLASSES.md%23Access%20control`
- Coverage unit: `trustpoint%2Fusers%2Furls.py::trustpoint%2Fusers%2Fauthentication.py::trustpoint%2Fusers::WEB-PROTOCOL-AND-AUTH.md%23JWT%20verification%20and%20claim%20binding`
- Coverage unit: `trustpoint%2Fusers%2Furls.py::trustpoint%2Fusers%2Fauthentication.py::trustpoint%2Fusers::WEB-PROTOCOL-AND-AUTH.md%23Session%20fixation%20and%20invalidation`

**L-14 — Global API credential maximum age**  
Fingerprint: `users/models.py:ServiceAccountCredential.is_valid:global-max-age-unenforced`

- Coverage unit: `trustpoint%2Fusers%2Furls.py::trustpoint%2Fusers%2Fauthentication.py::trustpoint%2Fusers::WEB-PROTOCOL-AND-AUTH.md%23API-key%20scope%20and%20resource%20binding`

**L-15 — CMP authentication side-effect ordering**  
Fingerprint: `trustpoint/request/authentication/cmp.py:idevid-auto-create-before-protection`

- Coverage unit: `trustpoint%2Fcmp%2Furls.py::trustpoint%2Frequest%2Fauthentication%2Fcmp.py::trustpoint%2Fcmp::ATTACK-CLASSES.md%23Access%20control`
- Coverage unit: `trustpoint%2Fcmp%2Furls.py::trustpoint%2Frequest%2Fauthentication%2Fcmp.py::trustpoint%2Fcmp::ATTACK-CLASSES.md%23Business%20logic`
- Coverage unit: `trustpoint%2Fcmp%2Furls.py::trustpoint%2Frequest%2Fauthentication%2Fcmp.py::trustpoint%2Fcmp::ATTACK-CLASSES.md%23Cryptography%20and%20secrets`
- Coverage unit: `trustpoint%2Fcmp%2Furls.py::trustpoint%2Frequest%2Fauthentication%2Fcmp.py::trustpoint%2Fcmp::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Pre-authentication%20work%20imbalance`

**L-16 — Privileged PKCS#11 staging race**  
Fingerprint: `docker/trustpoint/wizard/internal/install_pkcs11_assets.sh:staged-path-race-root-read`

- Coverage unit: `docker-compose.yml::docker%2Ftrustpoint%2Fnginx%2Ftrustpoint-nginx-https.conf::docker::ATTACK-CLASSES.md%23Access%20control`
- Coverage unit: `docker-compose.yml::docker%2Ftrustpoint%2Fnginx%2Ftrustpoint-nginx-https.conf::docker::CLOUD-AND-DEPLOYMENT.md%23Host%20or%20control-plane%20capability%20exposure`

**L-17 — CMP extra certificate provenance**  
Fingerprint: `request/cmp-extraCerts-to-ca-inventory`

- Coverage unit: `trustpoint%2Fpki%2Furls.py%23upstream%20EST%20and%20CMP%20certificate%20acquisition::trustpoint%2Frequest%2Fclients%23upstream%20response%20to%20persisted%20credential::trustpoint%2Frequest%2Fclients::ATTACK-CLASSES.md%23Cryptography%20and%20secrets`

**L-18 — Owner EST result binding**  
Fingerprint: `pki/owner-est-result-unbound-to-pending-key`

- Coverage unit: `trustpoint%2Fpki%2Furls.py%23upstream%20EST%20and%20CMP%20certificate%20acquisition::trustpoint%2Frequest%2Fclients%23upstream%20response%20to%20persisted%20credential::trustpoint%2Frequest%2Fclients::ATTACK-CLASSES.md%23Cryptography%20and%20secrets`

**L-19 — Agent proxy-header provenance**  
Fingerprint: `agents/api_views.py:certificate-header-without-trusted-peer-binding`

- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23api::trustpoint%2Fusers%2Fpermissions.py::trustpoint%2Fagents::ATTACK-CLASSES.md%23Feature%20abuse%20and%20data%20leakage`
- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23api::trustpoint%2Fusers%2Fpermissions.py::trustpoint%2Fagents::WEB-PROTOCOL-AND-AUTH.md%23mTLS%20peer%20and%20application-identity%20confusion`

**L-20 — Secret-bearing agent profile reads**  
Fingerprint: `agents/web_views.py:profile-config-unrestricted-secret-read`

- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23browser::trustpoint%2Fusers%2Fmiddleware.py::trustpoint%2Ftemplates::ATTACK-CLASSES.md%23Access%20control`

**L-21 — Credential-download cancellation on GET**  
Fingerprint: `devices/views/browser_onboarding.py:cancel-on-get`

- Coverage unit: `trustpoint%2Ftrustpoint%2Furls.py%23browser::trustpoint%2Fusers%2Fmiddleware.py::trustpoint%2Ftemplates::WEB-PROTOCOL-AND-AUTH.md%23Ordinary%20CSRF`

</details>

## Scope and evidence

| Item | Recorded state |
|---|---|
| Profile | Standard; incomplete source-review pass |
| Scope | First-party source and checked-in deployment/release configuration |
| Recorded source paths | 292 |
| Coverage units with owned source evidence | 63 |
| Deferred coverage units | 1 |
| Unverified leads | 21 |
| Independently confirmed vulnerabilities | 0 |
| Target-code executions or live probes | 0 |
| Application source changes | None |

The worktree was clean at the reviewed revision. No compatible earlier audit ledger was found when this run began. The later analysis resumed the same source revision; no prior confirmations were carried forward. No strict agent budget was set. The recorded work comprises 4 reconnaissance assignments, 16 hunter assignments, 5 coverage-critic passes and one administrative completion acknowledgement.

Source evidence means a recorded review of specific paths and controls. It is not a successful runtime reproduction or a guarantee of exhaustive coverage.

## Lead index

| ID | Unverified lead |
|---|---|
| L-01 | Manual browser issuance authorization |
| L-02 | REST management issuance authorization |
| L-03 | Browser signing authorization |
| L-04 | Owner and zero-touch browser mutations |
| L-05 | GDS truststore association and upload |
| L-06 | Presented-certificate revocation binding |
| L-07 | SCEP command argument escaping |
| L-08 | Device protocol-disable policy |
| L-09 | Certificate deletion and truststore membership |
| L-10 | Workflow runtime controls |
| L-11 | GDS renewal configuration |
| L-12 | Browser CRL generation |
| L-13 | REST entitlement withdrawal |
| L-14 | Global API credential maximum age |
| L-15 | CMP authentication side-effect ordering |
| L-16 | Privileged PKCS#11 staging race |
| L-17 | CMP extra certificate provenance |
| L-18 | Owner EST result binding |
| L-19 | Agent proxy-header provenance |
| L-20 | Secret-bearing agent profile reads |
| L-21 | Credential-download cancellation on GET |

## Detailed observations

### L-01 — Manual browser issuance authorization

**Remediation update (2026-11-08):** Source review supports the missing permission check: browser middleware requires authentication, while `ManualAuthorization` checks device/domain/profile/protocol/security policy without checking the human actor's issuance permission. `AbstractIssueCredentialView` now uses the existing `UserPermissionRequiredMixin` with `AppPermissions.ISSUE_CERTIFICATES`, covering generated-key, external-CSR and OPC UA domain-credential issuance before form processing. Regression cases were added for GET/POST denial, unchanged issued-credential records, and successful issuance after granting the same non-superuser the permission. The later isolated regression pass exercised denial and authorized issuance for all three paths; independent verification remains outstanding, so this lead is not marked independently confirmed or closed.

**Potential effect:** A human without issue_certificates may reach generated-key or external-CSR issuance, including the OPC UA domain-credential subclass. Device/domain/profile validation does not establish the human actor's authority.

**Conditions and limits:** Generated private-key downloads have a separate permission check; key disclosure is not established.

**Validation requirement:** Require the issuance permission before form processing, key generation or signing. Validate denial with unchanged credential records and an authorized-user control.

**Initial source references:**

- [trustpoint/devices/urls.py:130](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/urls.py:130)
- [trustpoint/devices/views/credential_issuance.py:851](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/views/credential_issuance.py:851)
- [trustpoint/request/operation_processor/issue_cert.py:381](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/operation_processor/issue_cert.py:381)

### L-02 — REST management issuance authorization

**Remediation update (2026-11-09):** REST management enrollment now requires `ISSUE_CERTIFICATES` before serializer processing; device/domain/profile/workflow checks remain in the existing pipeline. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** A service account with general REST access may select a no-onboarding device and reach application certificate issuance without issue_certificates or that device's enrollment credentials.

**Conditions and limits:** Domain/profile restrictions, cryptographic policy and configured workflows still apply.

**Validation requirement:** Verify that an account lacking issue_certificates is denied before issuance, while allowed device/profile policy and an authorized account still behave correctly.

**Initial source references:**

- [trustpoint/rest_pki/api_views.py:168](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/rest_pki/api_views.py:168)
- [trustpoint/request/enrollment.py:152](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/enrollment.py:152)
- [trustpoint/request/operation_processor/issue_cert.py:381](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/operation_processor/issue_cert.py:381)

### L-03 — Browser signing authorization

**Remediation update (2026-11-09):** The browser signing form now requires `MANAGE_SIGNER` at dispatch, before form validation, key use or signed-message creation. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** The browser hash-signing form appears to use an active configured signer without manage_signer, although the equivalent API enforces that capability.

**Conditions and limits:** This is a possible unauthorized signing operation; private-key extraction and CA issuance are not established.

**Validation requirement:** Verify that a human lacking manage_signer cannot obtain a signature or create a signed-message record. Include a permitted account as a control.

**Initial source references:**

- [trustpoint/signer/urls.py:48](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/signer/urls.py:48)
- [trustpoint/signer/views.py:278](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/signer/views.py:278)
- [trustpoint/signer/views.py:295](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/signer/views.py:295)

### L-04 — Owner and zero-touch browser mutations

**Remediation update (2026-11-09):** Owner imports, configuration, association and deletion now require `MANAGE_DEVICES`; certificate preparation and acquisition require `ISSUE_CERTIFICATES`. Preparation checks run before dispatch-time pending-key mutations. Truststore import and combined onboarding setup additionally require `MANAGE_TRUSTSTORES`. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** Owner-credential browser handlers appear to omit the operation permissions enforced by REST siblings. The smallest proposed effect is replacing an existing owner configuration's TLS truststore.

**Conditions and limits:** Import, setup, association, deletion and acquisition are related paths; no successful remote issuance has been observed.

**Validation requirement:** Check management and issuance permissions before validation-time persistence, pending-key changes or deletion. Denied requests must leave owner, registration, truststore and credential records unchanged.

**Initial source references:**

- [trustpoint/devices/urls.py:407](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/urls.py:407)
- [trustpoint/pki/forms/owner_credential.py:354](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/forms/owner_credential.py:354)
- [trustpoint/pki/forms/owner_credential.py:366](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/forms/owner_credential.py:366)

### L-05 — GDS truststore association and upload

**Remediation update (2026-11-09):** GDS truststore association now requires `MANAGE_DEVICES`; its upload branch additionally checks `MANAGE_TRUSTSTORES` before persistence-producing form validation. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** A logged-in human without the relevant management capabilities may change a GDS device's server-validation truststore or create a global truststore through the upload branch.

**Conditions and limits:** The claim stops at trust-configuration mutation; server impersonation or remote-device compromise is not established.

**Validation requirement:** Verify device-management authority before association and the intended import authority before the persistence-producing upload validation. Denial must precede database writes.

**Initial source references:**

- [trustpoint/devices/urls.py:214](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/urls.py:214)
- [trustpoint/devices/views/credential_issuance.py:643](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/views/credential_issuance.py:643)
- [trustpoint/devices/forms.py:1386](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/forms.py:1386)

### L-06 — Presented-certificate revocation binding

**Remediation update (2026-11-09):** Shared certificate lookup now rejects an inactive exact presented certificate, including a revoked historical certificate, before its credential can be used by agent, HTTP, CMP or SCEP authentication. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** Certificate lookup includes retained historical certificates, while credential validity checks the current primary. A revoked older certificate may therefore inherit the validity of its replacement.

**Conditions and limits:** Agent authentication is the original trace. Follow-up source checks also identify EST, REST and CMP variants; TLS-layer revocation may prevent some HTTP paths.

**Validation requirement:** Bind authentication validity to the exact presented certificate. Validate rejection of a revoked historical certificate with a valid replacement as the positive control.

**Initial source references:**

- [trustpoint/agents/api_urls.py:13](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/agents/api_urls.py:13)
- [trustpoint/pki/models/issued_credential.py:125](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/models/issued_credential.py:125)
- [trustpoint/agents/api_views.py:277](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/agents/api_views.py:277)

### L-07 — SCEP command argument escaping

**Remediation update (2026-11-09):** The SCEP renewal subject now uses the existing double-quoted shell-argument escaping helper; regression inputs cover quotes, backslashes, dollar expansion and command substitutions. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** A stored device name is interpolated into a generated SCEP renewal shell command without the escaping used by neighboring command builders. A different operator may later copy and execute that instruction.

**Conditions and limits:** Requires another operator to execute the copied command. No server-side or automatic browser execution is established.

**Validation requirement:** Verify that every permitted device-name character remains literal within one subject argument in the supported generated command. Reuse the existing shell-escaping convention if the issue is confirmed.

**Initial source references:**

- [trustpoint/devices/urls.py:48](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/urls.py:48)
- [trustpoint/util/field.py:38](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/util/field.py:38)
- [trustpoint/static/js/copy_clipboard.js:8](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/static/js/copy_clipboard.js:8)

### L-08 — Device protocol-disable policy

**Remediation update (2026-11-09):** Shared HTTP enrollment authorization now checks the selected device's EST or REST protocol bit for both onboarding and no-onboarding configurations, including management REST enrollment. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** EST and REST authorization appear not to consult the authenticated device's enabled-protocol bitmask before application issuance, despite the model describing cleared flags as disabling issuance.

**Conditions and limits:** Existing domain, profile, key and workflow policy still constrains the requested certificate.

**Validation requirement:** Verify that disabling the device's relevant protocol prevents issuance without requiring revocation of its otherwise valid domain credential.

**Initial source references:**

- [trustpoint/rest_pki/views.py:27](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/rest_pki/views.py:27)
- [trustpoint/request/authentication/base.py:90](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/authentication/base.py:90)
- [trustpoint/request/operation_processor/issue_cert.py:381](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/operation_processor/issue_cert.py:381)

### L-09 — Certificate deletion and truststore membership

**Remediation update (2026-11-09):** Certificate deletion now requires `MANAGE_CAS` and, when the certificate has truststore memberships, `MANAGE_TRUSTSTORES`. The membership check and deletion run under a certificate row lock in one transaction. The repository has no separate certificate-inventory management capability. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** The authentication-only certificate deletion API may remove an imported certificate and cascade deletion of its truststore membership, bypassing the direct truststore-management permission.

**Conditions and limits:** Requires a deletable certificate without protecting credential or CA references. Arbitrary CA-key deletion is not established.

**Validation requirement:** Verify operation authority for deletion and every affected truststore relation. A denied request must preserve both the certificate and membership.

**Initial source references:**

- [trustpoint/pki/api_urls.py:18](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/api_urls.py:18)
- [trustpoint/util/db.py:57](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/util/db.py:57)
- [trustpoint/pki/models/truststore.py:130](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/models/truststore.py:130)

### L-10 — Workflow runtime controls

**Remediation update (2026-11-09):** Run cancellation, inline execution, idempotency release and instance cancellation/stop/resume/inline execution now reuse the existing workflow-management permission mixin. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** Runtime cancellation, stop/resume and related control routes appear to rely on login without the management capability used by workflow administration.

**Conditions and limits:** The minimum proposed effect is cancellation of a queued dummy run; approval bypass or arbitrary issuance is not established.

**Validation requirement:** Verify that a user lacking workflow-management authority cannot change another operator-created run, instance, job or idempotency state.

**Initial source references:**

- [trustpoint/workflows2/urls.py:57](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/workflows2/urls.py:57)
- [trustpoint/workflows2/views/runs.py:354](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/workflows2/views/runs.py:354)
- [trustpoint/workflows2/views/runs.py:370](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/workflows2/views/runs.py:370)

### L-11 — GDS renewal configuration

**Remediation update (2026-11-09):** The GDS server-certificate/trustlist renewal-settings view now requires `MANAGE_DEVICES` before loading and modifying device configuration. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** The server-certificate/trustlist renewal-settings view appears to persist enabled state and intervals for a selected device without manage_devices.

**Conditions and limits:** No remote-device action, failed renewal or outage has been observed.

**Validation requirement:** Verify rejection before changing renewal configuration for an unauthorized human, with a permitted account as a control and external scheduling disabled in the fixture.

**Initial source references:**

- [trustpoint/devices/urls.py:313](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/urls.py:313)
- [trustpoint/devices/views/gds_push.py:188](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/views/gds_push.py:188)
- [trustpoint/devices/views/gds_push.py:203](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/views/gds_push.py:203)

### L-12 — Browser CRL generation

**Remediation update (2026-11-09):** Browser CRL generation now requires `MANAGE_CAS` and POST. All three UI callers, including the CRL help page, submit CSRF-protected forms; existing generation tests use POST. Authorized GET is rejected without generating or publishing a CRL. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** A GET-only browser view appears to reach CA signing and active CRL publication without manage_cas. The REST equivalent and neighboring management operations enforce that permission.

**Conditions and limits:** Generated content still uses stored revocation records; revocation suppression, key disclosure and service outage are not established.

**Validation requirement:** Verify permission enforcement before signing and publication, and require that a GET request leaves CRL state unchanged.

**Initial source references:**

- [trustpoint/pki/urls.py:278](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/urls.py:278)
- [trustpoint/pki/util/crl.py:146](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/util/crl.py:146)
- [trustpoint/pki/views/issuing_cas.py:1439](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/views/issuing_cas.py:1439)

### L-13 — REST entitlement withdrawal

**Remediation update (2026-11-09):** Refresh authentication now rechecks `use_rest_api`; the configured bearer authenticator also applies current entitlement and human password-rotation policy on every request, after the existing JWT checks. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** Initial token issuance checks use_rest_api, while the refresh rule and configured bearer authenticator appear not to recheck that entitlement after a role change.

**Conditions and limits:** The scenario requires a previously issued token for an otherwise active account.

**Validation requirement:** Verify that withdrawal of REST access prevents refresh and subsequent protected API access, while keeping active-account and password-rotation checks intact.

**Initial source references:**

- [trustpoint/trustpoint/urls.py:105](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/trustpoint/urls.py:105)
- [trustpoint/users/oauth2_views.py:33](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/users/oauth2_views.py:33)
- [trustpoint/pki/views/certificates.py:478](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/views/certificates.py:478)

### L-14 — Global API credential maximum age

**Remediation update (2026-11-09):** Service credential expiration now applies the current global maximum age from `created_at`, as well as explicit `expires_at`, including credentials created before the policy changed. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** The configured global credential maximum age appears to be stored but omitted from normal service-credential creation and validation, which checks explicit expires_at only.

**Conditions and limits:** An explicitly expired or disabled credential has a separate existing rejection path.

**Validation requirement:** Verify that a positive global lifetime rejects an older otherwise valid service credential, including existing credentials after the policy changes.

**Initial source references:**

- [trustpoint/users/api_auth.py:74](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/users/api_auth.py:74)
- [trustpoint/users/authentication.py:219](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/users/authentication.py:219)
- [trustpoint/users/models.py:637](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/users/models.py:637)

### L-15 — CMP authentication side-effect ordering

**Remediation update (2026-11-09):** CMP initialization verifies the protection signature before IDevID authentication can create device/configuration records. The IDevID-capable poll path also verifies proof before authentication fallback. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** CMP IDevID initialization can reach automatic device/configuration creation before protection-signature verification. A rejected request may therefore leave onboarding state behind.

**Conditions and limits:** Requires a registration-matching trusted public IDevID. Certificate issuance or account takeover is not established.

**Validation requirement:** Verify that a failed proof-of-possession request creates no persistent device or onboarding configuration. Keep a valid-signature control.

**Initial source references:**

- [trustpoint/cmp/views.py:89](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/cmp/views.py:89)
- [trustpoint/request/authentication/cmp.py:444](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/authentication/cmp.py:444)
- [trustpoint/pki/util/idevid.py:158](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/util/idevid.py:158)

### L-16 — Privileged PKCS#11 staging race

**Remediation update (2026-11-09):** The privileged installer now snapshots staged regular files through no-follow directory/file descriptors into a private root-owned directory, then installs only those snapshots. Hard links and non-regular files are rejected, copies are bounded to the existing 32 MiB upload limit, and descriptor-relative cleanup happens only after successful installation. Root-privilege integration validation is still required. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** The restricted root installer checks a mutable staged pathname and later reopens it. A local application process may be able to change that entry before the privileged copy.

**Conditions and limits:** Requires local application-process access and a race; no unauthenticated HTTP exploit, root code execution or host escape is established.

**Validation requirement:** In an isolated privilege fixture, verify that mutable staging cannot cause the helper to read outside the approved staged regular file. Use only a root-owned dummy file.

**Initial source references:**

- [docker/trustpoint/wizard/sudoers:17](/Users/florianhandke/PycharmProjects/trustpoint/docker/trustpoint/wizard/sudoers:17)
- [docker/trustpoint/wizard/internal/install_pkcs11_assets.sh:62](/Users/florianhandke/PycharmProjects/trustpoint/docker/trustpoint/wizard/internal/install_pkcs11_assets.sh:62)
- [docker/trustpoint/wizard/internal/install_pkcs11_assets.sh:140](/Users/florianhandke/PycharmProjects/trustpoint/docker/trustpoint/wizard/internal/install_pkcs11_assets.sh:140)

### L-17 — CMP extra certificate provenance

**Remediation update (2026-11-09):** CMP CA enrollment validates the issued certificate to explicitly configured trust anchors and retains only that verified issuer path before inventory persistence, preventing unprotected extras from supplying their own root. Parent relationships follow that ordered chain; unrelated or same-name wrong-key certificates are excluded. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** The upstream CMP client authenticates header/body with PBM while accepting extra certificates outside that protection. The CA enrollment service appears to persist unrelated extras as keyless CA inventory.

**Conditions and limits:** Requires interference with a legitimate upstream enrollment. A new inventory record is not automatically a trusted anchor or signing authority.

**Validation requirement:** Verify that an unrelated extra certificate cannot create a global CA record unless its provenance and permitted relationship to the requested result are established.

**Initial source references:**

- [trustpoint/request/clients/cmp_client.py:735](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/clients/cmp_client.py:735)
- [trustpoint/request/clients/cmp_client.py:612](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/request/clients/cmp_client.py:612)
- [trustpoint/pki/models/ca.py:518](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/models/ca.py:518)

### L-18 — Owner EST result binding

**Remediation update (2026-11-09):** Defensive result binding now rejects a returned certificate whose public key or CA role differs from the pending key/signed CSR before persistence. DevOwnerID profiles may legitimately request CA certificates. A distinct unauthorized impact from a malicious authenticated upstream remains unconfirmed; this is not a full certificate-path/profile validation change. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** Owner EST enrollment appears to attach the returned certificate to the pending private key without the key/purpose checks used by sibling CA and RA paths.

**Conditions and limits:** The configured upstream HTTPS peer is authenticated. A distinct unauthorized outcome remains part of the candidate-validation gate.

**Validation requirement:** Verify key and intended-role correspondence before credential attachment. Independently assess whether a bad result creates security impact beyond the trusted upstream simply refusing service.

**Initial source references:**

- [trustpoint/devices/views/owner_credentials.py:875](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/views/owner_credentials.py:875)
- [trustpoint/pki/services/owner_credential.py:144](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/services/owner_credential.py:144)
- [trustpoint/pki/services/owner_credential.py:146](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/pki/services/owner_credential.py:146)

### L-19 — Agent proxy-header provenance

**Remediation update (2026-11-09):** Agent certificate headers now pass through the existing trusted TCP-peer check before parsing. Source hardening is complete; actual ingress isolation and header replacement remain deployment-dependent and were not inspected. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** Agent authentication reads a certificate header without the shared application-side trusted-peer check. A caller-controlled assertion could matter on an alternate or direct backend path.

**Conditions and limits:** The supplied nginx configuration overwrites the header correctly; direct or alternate backend exposure is unknown.

**Validation requirement:** Verify rejection of assertions from an untrusted peer and privately inspect actual ingress isolation and header replacement.

**Initial source references:**

- [trustpoint/agents/api_urls.py:13](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/agents/api_urls.py:13)
- [trustpoint/agents/api_views.py:58](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/agents/api_views.py:58)
- [trustpoint/agents/api_views.py:277](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/agents/api_views.py:277)

### L-20 — Secret-bearing agent profile reads

**Remediation update (2026-11-09):** The full agent profile editor now requires `MANAGE_DEVICES` for reads and writes, matching its existing write permission and protecting any stored secrets in editor JSON. Real secret-bearing profiles and organizational reader policy were not inspected. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** The agent profile editor returns complete stored JSON on GET under login/protocol gating. If supported fill steps contain real device passwords, a non-managing user may receive them.

**Conditions and limits:** Meaningful disclosure depends on actual secret-bearing profiles and reader policy; public templates have no such effect.

**Validation requirement:** Verify the intended reader policy and response to an unprivileged user with a dummy secret-bearing profile. Deny access or redact confidential fields as the policy requires.

**Initial source references:**

- [trustpoint/agents/urls.py:23](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/agents/urls.py:23)
- [trustpoint/agents/web_views.py:69](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/agents/web_views.py:69)
- [trustpoint/templates/agents/profiles/config.html:157](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/templates/agents/profiles/config.html:157)

### L-21 — Credential-download cancellation on GET

**Remediation update (2026-11-09):** Browser download cancellation now accepts POST only, and its UI sends a CSRF-protected form. Regression coverage preserves grants on GET and on POST without a CSRF token. Runtime validation is tracked in the remediation validation section above; this update does not independently confirm or close the original vulnerability claim.

**Potential effect:** A GET cancellation handler deletes a transient browser-download record. Cross-site top-level navigation may trigger that mutation with the victim's session.

**Conditions and limits:** Impact is limited to cancellation of a pending download flow; certificate/key deletion or disclosure is not established.

**Validation requirement:** Verify that GET leaves pending download state unchanged and that cancellation requires request-intent protection under actual browser cookie behavior.

**Initial source references:**

- [trustpoint/devices/urls.py:318](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/urls.py:318)
- [trustpoint/devices/views/browser_onboarding.py:133](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/views/browser_onboarding.py:133)
- [trustpoint/devices/views/browser_onboarding.py:138](/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/devices/views/browser_onboarding.py:138)

## Positive source observations

The inspected source includes domain/profile binding, CSR proof-of-possession checks, bounded CMP/SCEP handling, confirmation and challenge lifecycle controls, authenticated field encryption, managed-key export restrictions, pinned SFTP host keys, backup/log capability checks, and audit redaction. The supplied nginx configuration replaces certificate identity headers on the intended ingress path.

Focused rollover review found permission checks, locked state transitions, stale-task rejection and an atomic signing-authority handoff. CRL import validates issuer/signature. RA response handling has separate certificate-path, requested-key and profile checks. These observations constrain the associated hypotheses; they are not runtime assurance.

Permission checks located in `form_valid` or `post` were considered. A missing permission mixin alone was not treated as a vulnerability. Hypothetical resource exhaustion or broad script execution was not claimed without a concrete boundary result.

## Open coverage item

**External-CSR browser CA certificate upload remains deferred.** The last coverage critic requested a focused review of caller authority and completion/replacement state in `IssuingCaExternalCsrView`, including its form and final credential attachment. No hunter assignment or independent validation closed that item. It is a coverage gap, not a twenty-second finding.

No clean final coverage review has completed. The ledger records 64 units: 33 with source checks and no retained candidate, 30 with candidate-bearing source evidence, and 1 deferred.

## Limitations

- Fresh independent candidate verification and final-record review remain outstanding for all 21 leads.
- The required OS-enforced execution controls were not established together: network denial, an empty allowlisted environment, read-only source/toolchain, scratch-only writes, and CPU/memory/process/file-size/disk/wall-clock limits. No target tests, builds, services or fixtures were run.
- Live deployment topology, actual backend reachability, external revocation enforcement, provider/HSM policy, storage ACLs and retention were not inspected.
- Actual secret-bearing agent profiles and their intended reader policy are unknown. Host credentials and user audit-export contents were not inspected.
- Current third-party advisory inventory and historical revisions were outside the observed review. No claim is made about them.

## Recommended next steps

1. Close the deferred external-CSR coverage item and obtain a clean independent coverage review.
2. Have a fresh reviewer challenge each candidate's source trace, intended authority and preventing controls; reject unsupported claims.
3. Establish the required isolated offline environment, then run the smallest dummy-data permission, lifecycle and regression checks. Keep conditional owner inspections separate from runtime tests.
4. Independently verify the resulting records before assigning severity or issuing a final vulnerability report.

## Supporting artifacts

- [Detailed initial source traces and validation plans](NEEDS-VALIDATION.md)
- [Machine-readable candidate proposals](candidates.json)
- [Coverage ledger](coverage-ledger.json)
- [Run metadata](run-metadata.json)
- [Architecture and trust boundaries](architecture.md)
- [Final-disposition file — currently empty](findings.json)

The supporting candidate proposals are initial review output, not accepted vulnerability verdicts. This document consolidates their evidence and limits; it does not promote their validation status.
