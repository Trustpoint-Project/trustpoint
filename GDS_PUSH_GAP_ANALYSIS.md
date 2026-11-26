# OPC UA GDS Push — Gap Analysis and Implementation Backlog

**Status:** working document, basis for implementation
**Date:** 2026-11-26
**Standard:** OPC UA Part 12, v1.05.07
**Implementation baseline:** `trustpoint/request/gds_push/gds_push_service.py` (1322 lines), `trustpoint/devices/tasks.py`, `trustpoint/devices/models.py`, `trustpoint/devices/views/gds_push.py`, `trustpoint/pki/default_certificate_profiles/opc_ua*.json`

> Line numbers refer to the baseline above and will drift as the code changes.
> Re-check the referenced method before editing.

## 1. Scope and positioning

The linked standard section (Part 12 §6) defines the **Global Discovery Server**:
application directory, registration methods and discovery. Certificate
distribution via PushManagement is defined in **§7.4, §7.7 and §7.10**, with
trust lists in **§7.8** and certificate requirements in **Part 6 §6.2.2**.

Trustpoint currently implements only the **CertificateManager client** half of
PushManagement. It has no OPC UA server and therefore cannot act as a GDS.

Two deployment interpretations are possible, and the answer changes the backlog:

- **A. Trustpoint replaces the GDS** (direct CertificateManager → server push).
  §6 registration/discovery is out of scope; §7.7/§7.10 conformance is the goal.
- **B. Trustpoint integrates with an existing GDS.** Then §6 registration,
  `ApplicationId` persistence, directory browsing and GDS-side discovery are
  required as well.

The backlog below marks §6 items as **conditional** on decision B.

### Legend

| Status | Meaning |
|---|---|
| Implemented | Meets the requirement for the supported happy path |
| Partial | Works in some paths or for some servers, not consistently |
| Missing | Not implemented |
| Non-conformant | Violates an explicit `shall` in the standard |
| N/A | Server-side or otherwise not applicable to a CertificateManager |

Priority and completion:

| Priority | Meaning |
|---|---|
| P0 | Correctness, security or explicit non-conformance; fix first |
| P1 | Required workflow or interoperability gap; blocks real servers |
| P2 | Important capability or robustness gap |
| P3 | Optional, hardening or low-risk improvement |
| — | Already implemented; no action |

`Done` is `[ ]` while open and `[x]` when implemented or verified. Update it as work lands.

## 2. Summary

Trustpoint correctly implements the core single-certificate sequence:

```
CreateSigningRequest -> sign CSR -> UpdateCertificate -> ApplyChanges (if required)
```

and the trust-list write sequence:

```
Open(Write|EraseExisting) -> Write chunks -> CloseAndUpdate -> ApplyChanges (if required)
```

It works with servers that:

- accept `Basic256Sha256` + `SignAndEncrypt`,
- generate their own private key without a nonce,
- expose a single application certificate group with `ApplicationCertificateType`,
- already trust Trustpoint's issuing CA.

Findings by priority: **P0 = 5**, **P1 = 9**, **P2 = 17**, **P3 = 7**, **already implemented = 6**.

The main gaps are:

1. one explicit method-level violation (`CreateSigningRequest` nonce),
2. certificate group/certificate type selection based on names instead of the
   information model, causing wrong or failed updates,
3. incomplete workflow ordering (standalone certificate update skips the trust list),
4. no server capability negotiation (security policy, private-key formats,
   trust-list size limits),
5. no trust bootstrap / dead discovery-to-truststore path,
6. optional §7.10 features missing (key upload, rejected list, certificate
   inventory, transaction diagnostics, managed applications).

## 3. Findings

### 3.1 §6 — GDS role, registration and discovery

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| GDS-01 | P2 | GDS is an OPC UA server exposing `Directory`, registration and discovery (§6.1–§6.5) | Missing | No OPC UA server exists in Trustpoint; `gds_push_service.py` only creates `asyncua.Client` instances. | Conditional on decision B. Either document "Trustpoint is a CertificateManager, not a GDS", or implement a §6 server (large, separate project). | [ ] |
| GDS-02 | P2 | Application registration: `FindApplications`, `RegisterApplication`, `UpdateApplication`, `UnregisterApplication`, `GetApplication` (§6.4, §6.5.4–6.5.9) | Missing | No calls to these methods anywhere. No `ApplicationId` is persisted. | Conditional on decision B. Add GDS client service and persist `ApplicationId` per device/application. | [ ] |
| GDS-03 | P2 | Persist `ApplicationRecordDataType`: `ApplicationUri`, `ProductUri`, `DiscoveryUrls`, `ServerCapabilities`, `ApplicationNames` (§6.5.5) | Missing | `OpcUaGdsPushConfig` has only IP, port, OPC user/password, truststore and renewal settings (`devices/models.py:203`). | Conditional on decision B. Add fields; use discovery to populate them. | [ ] |
| GDS-04 | P3 | Browse `Directory/CertificateGroups` and persist selected `CertificateGroupIds` (§6.4) | Missing | Trustpoint browses the server's own `ServerConfiguration/CertificateGroups` directly (`gds_push_service.py:886`). | Conditional on decision B. Otherwise keep direct browsing (current behavior is valid for interpretation A). | [ ] |
| GDS-05 | — | Minimise connection time; disconnect after each sequence (§6.3) | Implemented | New client/session per operation in `devices/tasks.py`. | Keep. | [x] |
| GDS-06 | P2 | Credentials must have the server's `SecurityAdmin` role (§6.2, §7.2) | Partial | Documented in `docs/source/features/devices/opc_ua_gds.md`; Trustpoint cannot verify the role and surfaces all failures generically. | Improve error classification (see METH-08); map `Bad_UserAccessDenied` / `Bad_SecurityModeInsufficient` to actionable messages. | [ ] |

### 3.2 §7.4 / §7.7 — PushManagement workflows

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| WF-01 | P1 | Update the TrustList before updating a certificate (§7.4, §7.7.2) | Partial | Periodic task does trust list first (`devices/tasks.py:61–77`); the standalone "update server certificate" task does not (`devices/tasks.py:109–127`). | Make "update certificate" always run or offer the required trust-list step first, or combine both in one workflow entry point. | [ ] |
| WF-02 | P2 | For each CertificateType, determine whether an update is required (§7.7.2) | Missing | Fixed interval only (`opc_gds_push_renewal_interval`); no expiry, CRL or policy check. Every cycle replaces the certificate. | Add a decision step: compare server certificate expiry, configured renewal threshold and pending CRL changes. Skip when nothing is due. | [ ] |
| WF-03 | P0 | Only `ApplicationCertificateType` groups are considered (§7.7.2); use `CertificateTypes`/`Purpose` (§7.8.3.1) | Non-conformant | Certificate update skips names containing `UserToken` (`gds_push_service.py:1017`); trust-list update targets every group (`:905`). `Purpose` and `CertificateTypes` are never read. | Read `Purpose` and `CertificateTypes`; select only application-purpose groups and a permitted certificate type (see METH-02). Do not overwrite HTTPS/UserToken trust lists by default. | [ ] |
| WF-04 | P1 | `ApplyChanges` completes the workflow; handle forced renegotiation (§7.7.2, §7.10.9) | Partial | Called when required, but per group/per operation (`:969`, `:1147`). No reconnect or verification after the server forces channel renegotiation. | Collect `ApplyChangesRequired` across the workflow and apply once per transaction scope. Reconnect and verify the new certificate/trust list afterwards. | [ ] |
| WF-05 | P3 | Use `CreateSelfSignedCertificate` when no usable certificate exists (§7.7.4) | Missing | Method never called. | Optional. Implement only if servers without an existing certificate must be supported. | [ ] |
| WF-06 | P2 | CertificateManager generates the private key when the server cannot (§7.7.4) | Missing | Always `RegeneratePrivateKey=True`; no fallback path. | Read `SupportedPrivateKeyFormats`; on `Bad_NotSupported`, generate key + CSR locally, sign, and upload key via `UpdateCertificate`. | [ ] |
| WF-07 | P3 | Create Endpoint / Update Configuration workflows (§7.7.5/§7.7.6) | Missing | No `ConfigurationFile`, `UpdateTargets`, `ConfirmUpdate` usage. | Optional; separate feature. Not required for certificate replacement. | [ ] |
| WF-08 | P2 | CertificateManager needs a `DiscoveryUrl`; NAT/hostnames supported (§7.7.2) | Missing | URL is built as `opc.tcp://{ip_address}:{port}` (`gds_push_service.py:101`). | Add an optional discovery URL / endpoint URL field, with hostname support and fallback to IP:port. | [ ] |
| WF-09 | P0 | Workflow consistency | Partial / bug | `update_trustlist` returns success if at least one group succeeded (`:876`); `update_server_certificate` does the same (`:1040`). The periodic task then logs success and continues. | Return a structured per-group result; define whether partial success is allowed. Do not mark the cycle successful or onboarding complete on partial failure. | [ ] |

### 3.3 §7.10 — method-level conformance

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| METH-01 | P0 | `CreateSigningRequest`: Nonce shall be at least 32 bytes when `RegeneratePrivateKey=TRUE` (§7.10.10) | **Non-conformant** | Passes `None` (`gds_push_service.py:1117–1124`). | Generate at least 32 cryptographically random bytes and pass them. Add a stricter test server that rejects a missing/short nonce. | [ ] |
| METH-02 | P0 | `CertificateTypeId` must be one permitted by the group's `CertificateTypes` (§7.10.5, §7.8.3.1) | Missing | Always `ApplicationCertificateType` (i=12557) (`:1108`), even when the group permits only `RsaSha256ApplicationCertificateType`, ECC types or HTTPS types. | Read `CertificateGroupType.CertificateTypes`; select a permitted application type (prefer the server's current type or strongest supported). Fail clearly if none is usable. | [ ] |
| METH-03 | — | `UpdateCertificate` arguments: group, type, DER cert, issuer list, key format/key (§7.10.5) | Implemented | Correct for the server-generated-key case (`:1135–1143`). `IssuerCertificates` is redundant for application certificates per the standard and is ignored by the server. | Keep; extend for METH-04. | [x] |
| METH-04 | P2 | Upload an externally generated private key (PKCS#8/PKCS#12) (§7.7.4, §7.10.5) | Missing | `PrivateKeyFormat=''`, `PrivateKey=b''` always. | Add CM-side key generation and key upload, gated by `SupportedPrivateKeyFormats`. | [ ] |
| METH-05 | — | TrustList write sequence: `Open(Write\|EraseExisting)`, `Write`, `CloseAndUpdate`, `ApplyChanges` (§7.7.3, §7.8.2.2) | Implemented | Correct modes and order (`:944–979`). | Keep. | [x] |
| METH-06 | P3 | Write block size must not exceed `MaxByteStringLength` (§7.7.3) | Partial | Fixed 1024 bytes (`:929`); property not read. | Read the property and clamp the chunk size; keep 1024 as a safe default. | [ ] |
| METH-07 | P1 | Read `ServerConfiguration` capabilities: `MaxTrustListSize`, `SupportedPrivateKeyFormats`, `SupportsTransactions`, `InApplicationSetup`, `ServerCapabilities` (§7.10.3) | Missing | No read of any of these properties. | Add a capability probe after connect; use it to size writes, choose key handling, decide transaction/reconnect behavior and detect application setup mode. | [ ] |
| METH-08 | P2 | Use `GetCertificates`, `GetRejectedList`, `TrustList.Read`, `TransactionDiagnostics` (§7.10.8, §7.10.12, §7.8.2.4, §7.10.17) | Missing | No calls. Server errors are only visible as generic exceptions. | Add diagnostics: current certificates, rejected client certificates for trust bootstrap, transaction error details. `GetCertificates` also supplies the current certificate type. | [ ] |
| METH-09 | P2 | Transaction model: `CancelChanges`, transaction scope, `Bad_TransactionPending` (§7.10.2, §7.10.11) | Partial | No explicit cancel (session close implicitly cancels); no `SupportsTransactions` handling; no `Bad_TransactionPending` retry/backoff. | Detect transaction support; use `CancelChanges` on failure; add bounded retry for `Bad_TransactionPending`. | [ ] |
| METH-10 | P3 | `ManagedApplications` / `ApplicationConfigurationType` (§7.10.14–16) | Missing | Only `ServerConfiguration` is addressed. | Optional feature. Implement only if proxy management of clients/non-UA applications is required. | [ ] |
| METH-11 | P2 | Audit events `CertificateUpdateRequested` / `CertificateUpdated` (§7.10.26/27) | N/A (server-side) | The server raises them. Trustpoint records no per-operation audit trail and does not attribute the operation to the triggering user. | Add Trustpoint-side audit records for push operations (who, device, groups, result). Not an OPC UA client requirement, but an enterprise control. | [ ] |

### 3.4 §7.8 — TrustList content and semantics

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| TL-01 | — | `SpecifiedLists` mask and four lists (§7.8.2.8) | Implemented | `All` with all four lists populated (`:278–283`). | Keep. | [x] |
| TL-02 | P1 | List semantics: trusted anchors vs issuers (§7.8.2.8) | Partial | The full CA chain is written to both `TrustedCertificates` and `IssuerCertificates`, and CRLs to both. Works on many servers; makes every intermediate a trust anchor and may be rejected by strict servers. | Write roots as trusted certificates, intermediates as issuer certificates, with matching CRL lists. Verify against at least one strict server. | [ ] |
| TL-03 | — | Provide all issuers/CRLs needed for the new certificate (§7.7.2) | Implemented | Domain CA chain + CRLs. | Keep; include the server's new issuer after selection. | [x] |
| TL-04 | P0 | Do not destroy unrelated trust entries | Partial / risk | `Open(Write\|EraseExisting)` replaces the entire trust list by design; Trustpoint never reads the current list and targets all groups. Unrelated admin/HTTPS/user-token anchors are removed. | Restrict to the relevant application group(s). Document that the trust list is authoritative for those groups. Optionally read and display the current list before replacing it. | [ ] |
| TL-05 | P2 | CRLs | Partial (stricter than spec) | A CRL is mandatory for **every** CA (`:253–256`), including roots that commonly have none. Expiry is checked. | Allow trust-list updates when a CA legitimately has no CRL (configurable policy), or document the restriction as a product requirement. | [ ] |
| TL-06 | P2 | Respect `MaxTrustListSize` (§7.10.3) | Missing | No size pre-check; oversize lists fail at the server. | Compare the serialized size against `MaxTrustListSize` (0 = unlimited) and fail with a clear message before writing. | [ ] |

### 3.5 Security and certificate interoperability

| ID | Priority | Aspect | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| SEC-01 | P1 | Security policy negotiation | Partial | Hard-coded `Basic256Sha256` + `SignAndEncrypt` (`:565–573`). Servers that only offer AES/ECC policies cannot be managed. | Select from `GetEndpoints`; support at least `Basic256Sha256`, `Aes128Sha256RsaOaep`, `Aes256Sha256RsaPss`; add ECC only if in scope. Keep `SignAndEncrypt`. | [ ] |
| SEC-02 | P2 | Server authentication and rotation | Partial | Pins the leaf certificate at truststore order 0 (`:483–527`); no chain validation against a CA truststore, no automatic rotation. Fail-closed is good. | Keep pinning as an option; add CA-based validation and a controlled update path when the server certificate changes. | [ ] |
| SEC-03 | P1 | Trust bootstrap / TOFU (Annex G.2) | Missing | `discover_server` returns endpoints only, not the certificate (`:785–809`). The view reads `server_info['server_certificate_available']`, but this key is never set; `request.session['opc_ua_server_info']` is never used. The UI hint is dead. | Capture the server certificate during discovery, expose it for truststore creation/import, and set the flag. Or document manual bootstrap explicitly and remove the dead UI path. | [ ] |
| SEC-04 | P3 | Client certificate profile (Part 6 §6.2.2) | Implemented | `opc_ua_domain_credential.json` has RSA key usages and `clientAuth`. Runtime validation (`:403`) omits `nonRepudiation`, but the profile includes it. | Optional hardening: align the runtime check with the profile. | [ ] |
| SEC-05 | P2 | Trustpoint RBAC for push operations | Partial | `MANAGE_DEVICES` can replace a server trust list; `ISSUE_CERTIFICATES` can replace its server certificate and revoke the old one. No four-eyes/approval, no user attribution on the queued task. | Split permissions if needed; record the initiating user; consider an approval step for certificate replacement. | [ ] |
| SEC-06 | P2 | Domain credential renewal | Partial / risk | Old credential is revoked immediately. If a server trusts only the old client certificate rather than the CA, renewal locks Trustpoint out. | Document the CA-trust requirement; verify connectivity with the new credential before revoking the old one where possible. | [ ] |
| SEC-07 | — | Secrets at rest | Implemented | `EncryptedCharField` for the OPC password. | Keep. | [x] |

### 3.6 Testing and operational robustness

| ID | Priority | Aspect | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| OPS-01 | P1 | Unit tests cover real protocol strictness | Partial | Tests mock `asyncua` and assert current call shapes, including the missing nonce. | Add tests for nonce length, type selection, group filtering, partial results and capability handling. | [ ] |
| OPS-02 | P1 | Integration server behaves like a strict server | Partial | `trustpoint/request/gds_push/asyncua-gds-push-test/server.py` ignores the nonce (`:162`) and uses a simplified address space. | Make the test server enforce the nonce, permitted certificate types and separate group purposes; add negative tests. | [ ] |
| OPS-03 | P1 | Real-stack conformance | Missing | No test against open62541, a commercial GDS, or an AES/ECC-only server. | Add one real-stack interoperability test before claiming conformance. | [ ] |
| OPS-04 | P2 | Timeouts, retries, concurrency | Partial | No configurable secure-channel/session timeout (`_create_secure_client`), no retry/backoff, no lock preventing a manual push from overlapping the scheduled push. | Add configurable timeouts, bounded retries and a per-device operation lock. | [ ] |
| OPS-05 | P3 | Discovery documentation matches behavior | Partial | Docs claim discovery shows "certificate management capabilities"; it only lists endpoints (`docs/source/features/devices/opc_ua_gds.md`). | Either extend discovery (groups, `ServerConfiguration` capabilities) or correct the documentation. | [ ] |

## 4. Implementation plan

### Milestone 1 — Conformance and correctness (must do)

- [ ] **METH-01** Pass a ≥ 32-byte nonce to `CreateSigningRequest`.
- [ ] **WF-03 / METH-02** Select certificate groups by `Purpose`/`CertificateTypes`; select a permitted certificate type instead of the hard-coded base type.
- [ ] **WF-03 / TL-04** Restrict trust-list updates to the relevant application group(s); stop writing the application trust list into HTTPS/UserToken groups.
- [ ] **WF-01** Ensure every certificate update is preceded by the required trust-list update (or combine them in one workflow).
- [ ] **WF-09** Return structured per-group results; do not report partial success as success.
- [ ] **OPS-01 / OPS-02** Extend the test server and unit tests to catch these regressions.

**Exit criteria:** the workflow succeeds against a strict test server that enforces a nonce, permits only `RsaSha256ApplicationCertificateType`, and exposes separate HTTPS/UserToken groups; a partial group failure is reported as failure.

### Milestone 2 — Interoperability and server capabilities

- [ ] **SEC-01** Negotiate the security policy from the server's endpoints (AES + Basic256Sha256).
- [ ] **METH-07** Read `MaxTrustListSize`, `SupportedPrivateKeyFormats`, `SupportsTransactions`, `InApplicationSetup`, `ServerCapabilities`.
- [ ] **TL-06 / METH-06** Enforce trust-list size and chunk-size limits.
- [ ] **WF-06 / METH-04** Add the CM-generated-key fallback and private-key upload.
- [ ] **WF-04 / METH-09** Apply changes once per workflow scope; reconnect and verify; handle `Bad_TransactionPending` and `CancelChanges`.
- [ ] **TL-02** Correct trusted-vs-issuer list content.

**Exit criteria:** certificate replacement works on a server that does not generate keys and on a server that only offers `Aes256Sha256RsaPss`.

### Milestone 3 — Trust bootstrap, diagnostics and operations

- [ ] **SEC-03** Capture the server certificate during discovery and offer it for truststore creation/import; fix or remove the dead `server_certificate_available` path.
- [ ] **METH-08** Add `GetCertificates`, `GetRejectedList` and `TransactionDiagnostics`-based error reporting.
- [ ] **WF-02** Add an expiry/CRL-based "update required" decision instead of blind interval renewal.
- [ ] **METH-11 / SEC-05** Add per-operation audit records and user attribution.
- [ ] **OPS-04** Add timeouts, retries and a per-device operation lock.
- [ ] **OPS-03** Run one real-stack interoperability test.

**Exit criteria:** a fresh server can be onboarded from discovery without manual certificate export; failures show the server's transaction diagnosis and the rejected-certificate list.

### Milestone 4 — Optional standard features (only if required)

- [ ] **WF-05** `CreateSelfSignedCertificate` when no certificate exists.
- [ ] **METH-10** `ManagedApplications` / `ApplicationConfigurationType`.
- [ ] **WF-07** Create Endpoint / Update Configuration workflows.
- [ ] **TL-05** Configurable CRL requirement (allow missing root CRL).
- [ ] **WF-08** Configurable discovery/endpoint URL and hostname support.
- [ ] **GDS-01 … GDS-04** §6 GDS role and registration (only for interpretation B).

## 5. Decisions needed

1. **GDS or CertificateManager?** Does Trustpoint replace the GDS (interpretation A) or integrate with one (B)? This decides whether §6 is in scope.
2. **Trust-list authority.** Is Trustpoint the sole authority for a server's application trust list, or must it merge with existing entries? The protocol forces a full replacement per group; the scope decision matters.
3. **Target servers.** Which security policies, key types and certificate types must be supported?
4. **Renewal policy.** Is interval-based renewal a product requirement, or should renewal be driven by certificate expiry/CRL state?
5. **Managed applications.** Must Trustpoint manage client/non-UA applications behind a proxy?
6. **Audit and approval.** Is four-eyes approval or a full audit trail required for certificate/trust-list replacement?

## 6. Verification checklist

Before closing the core conformance work, verify each item against a strict server:

- [ ] `CreateSigningRequest` rejects a missing nonce (proves Trustpoint sends one).
- [ ] Group with only `RsaSha256ApplicationCertificateType` is updated successfully.
- [ ] HTTPS and UserToken groups are untouched by application trust-list updates.
- [ ] Certificate update fails cleanly if the trust list was not updated first and the issuer is unknown.
- [ ] Partial group failure is surfaced as a failure, not success.
- [ ] AES-only server is manageable.
- [ ] Server without key generation is manageable via uploaded private key.
- [ ] Oversize trust list is rejected before writing, with a clear message.
- [ ] New certificate is usable after `ApplyChanges` (reconnect check).
- [ ] Discovery shows the server certificate and it can be imported into the truststore.

## 7. File and line map (baseline 2026-11-26)

| Topic | Location |
|---|---|
| Device connection settings, renewal settings | `trustpoint/devices/models.py:203` |
| Scheduled renewal, trust list then certificate | `trustpoint/devices/tasks.py:23` |
| Standalone trust-list push | `trustpoint/devices/tasks.py:92` |
| Standalone certificate push | `trustpoint/devices/tasks.py:109` |
| Trust-list construction (CA chain + CRLs) | `trustpoint/request/gds_push/gds_push_service.py:222` |
| Secure client, hard-coded policy | `trustpoint/request/gds_push/gds_push_service.py:529` |
| Server certificate pinning | `trustpoint/request/gds_push/gds_push_service.py:483` |
| Endpoint discovery | `trustpoint/request/gds_push/gds_push_service.py:680` |
| Certificate group discovery | `trustpoint/request/gds_push/gds_push_service.py:1053` |
| Trust-list group discovery (all groups) | `trustpoint/request/gds_push/gds_push_service.py:886` |
| Trust-list write sequence | `trustpoint/request/gds_push/gds_push_service.py:928` |
| Certificate update (CSR, nonce, type) | `trustpoint/request/gds_push/gds_push_service.py:1091` |
| CSR signing / certificate issuance | `trustpoint/request/gds_push/gds_push_service.py:1161` |
| Local truststore replacement | `trustpoint/request/gds_push/gds_push_service.py:1268` |
| Discovery view (dead certificate flag) | `trustpoint/devices/views/credential_issuance.py:587–589` |
| Client certificate profile | `trustpoint/pki/default_certificate_profiles/opc_ua_domain_credential.json` |
| Server certificate profile | `trustpoint/pki/default_certificate_profiles/opc_ua.json` |
| Test server | `trustpoint/request/gds_push/asyncua-gds-push-test/server.py` |
| User documentation | `docs/source/features/devices/opc_ua_gds.md` |
