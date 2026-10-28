# Capabilities and limitations

This page describes paths implemented in the 1.0 development candidate. Availability
depends on the active security preset, certificate profiles, backend capabilities,
and device/domain configuration. An implemented path does not establish production
security approval or interoperability with every client. See the
[release notes](../release_notes.md) for compatibility and remaining release checks.

## Enrollment and lifecycle interfaces

| Interface | Implemented paths | Limits and operator responsibilities |
| --- | --- | --- |
| [EST](apis/est.md) | Enrollment/re-enrollment and CA certificate retrieval with configured authentication. | Requires TLS and matching device/domain/profile policy. Validate the intended client, trust chain, and upstream-RA scenario. |
| [CMP](apis/cmp.md) | Configured initialization/certification, revocation, certificate confirmation, and workflow-related polling paths. | Check the operation and protection algorithms supported by the specific endpoint; upstream CA/RA behavior needs separate validation. |
| [SCEP](apis/scep.md) | `GetCACaps`, `GetCACert`, initial enrollment, certificate-authenticated renewal, and transaction retries. | No `GetNextCACert`, `GetCert`, `GetCRL`, `CertPoll`, or asynchronous `PENDING`; no workflow approval/polling integration. |
| [REST enrollment](apis/rest.md) | Trustpoint-specific device enrollment/re-enrollment under `/rest/`. | Distinct from resource administration under `/api/`; not a standardized substitute for EST/CMP/SCEP. |
| [Management API](apis/rest_api.rst) | Resource/configuration endpoints under `/api/`; schema at `/schema/`, UI at `/swagger/` or `/redoc/`. | Check the individual action's authentication/permission contract and the outstanding release-readiness findings. |
| [Manual/browser delivery](devices/index.md) | Operator-driven issuance and delivery of stored credentials in supported export formats. | Export needs stored, exportable key material. A CSR-only request does not give Trustpoint the device's private key. |
| [AOKI](aoki/index.md) | Experimental zero-touch onboarding path. | Proof of concept; do not describe it as generally validated production onboarding. |
| [OPC UA GDS Push](../development/architecture/device_lifecycle.md) and [agents](devices/agents.md) | GDS Push certificate/trust-list operations and agent workflows. | GDS Push and agents are separate integrations. Validate real target-server security, credentials, algorithms, and certificate deployment/reconnection. |

## CAs, backends, and recovery

| Area | Current behavior | Limits |
| --- | --- | --- |
| [Local CA and rollover](pki/rollover.md) | Imported replacement material or generated managed keys followed by EST/CMP certificate acquisition. | Rollover applies to locally managed signing CAs. Device trust distribution is a separate provisioning responsibility. The separate remote-CA rollover strategy is not registered/available. |
| [CA/RA configuration](pki/cas_ras.md) | Local CA signing, upstream CA requests, and EST/CMP RA forwarding use different paths. | Test upstream response validation, trust configuration, and supported operations for the chosen mode; these modes are not interchangeable. |
| [Software encryption](security/db_encryption.rst) | The database stores a wrapped DEK; the independent software KEK comes from the deployment's secret file. | Retain the original KEK with database recovery material. Software KEK/DEK rotation is not implemented. |
| [PKCS#11](security/pkcs11.rst) | Configured provider/token-backed operations according to reported capabilities. | Real provider mechanisms vary. SoftHSM is for development/testing; its test success does not certify a hardware HSM. PKCS#11 ML-DSA generation/signing is not implemented. |
| [ML-DSA](../development/architecture/cryptography.md) | Supported through the software backend. | Do not infer HSM support from the software algorithm catalog. Protocol/client tooling must support the chosen algorithm. |
| [Backup and restore](management/backups.md) | PostgreSQL payload plus manifest; original external keys and runtime/HSM state retained separately. | 1.0.0 is the first stable compatibility baseline. A payload digest is not backup-source authentication. |

## Workflow availability

The [workflow engine guide](workflows/index.md) lists the registered triggers,
approval behavior, YAML syntax, and worker/inline execution modes. A trigger or
strategy mentioned in design source is not available merely because its class or
enum exists. SCEP has no built-in workflow enrollment trigger in the current
handler. External webhook side effects and retries need an integration-specific
idempotency plan; do not assume exactly-once delivery.

## Release deployment validation

Use the [release checklist](../development/release-checklist.rst) to record actual
results for the final candidate. Software Compose restart/recreation tests,
standalone SoftHSM envelope tests, supported cross-version update tests, and hardware-HSM
interoperability are different checks. Complete interactive setup, custom
ports/hostnames/IPv6, original-key restore, and intended real client/server tests
before describing a deployment combination as validated. Documentation edits
alone do not complete those checks.
