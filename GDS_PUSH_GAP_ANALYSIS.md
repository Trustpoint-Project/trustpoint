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

Findings by priority: **P0 = 5 (all done)**, **P1 = 13**, **P2 = 19**, **P3 = 7**, **already implemented = 6** — 13 of 50 items are done.

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
| GDS-02 | P2 | Application registration: `FindApplications`, `RegisterApplication`, `UpdateApplication`, `UnregisterApplication`, `GetApplication` (§6.4, §6.5.4–6.5.9); `ApplicationAdmin` grants (v1.05.07, §7.2) | Missing | No calls to these methods anywhere. No `ApplicationId` is persisted and no per-user application grants exist. | Conditional on decision B. Add a GDS client service, persist `ApplicationId` per device/application, and map `ApplicationAdmin` to a configured subset of applications. | [ ] |
| GDS-03 | P2 | Persist `ApplicationRecordDataType`: `ApplicationUri`, `ProductUri`, `DiscoveryUrls`, `ServerCapabilities`, `ApplicationNames` (§6.5.5) | Missing | `OpcUaGdsPushConfig` has only IP, port, OPC user/password, truststore and renewal settings (`devices/models.py:203`). | Conditional on decision B. Add fields; use discovery to populate them. | [ ] |
| GDS-04 | P3 | Browse `Directory/CertificateGroups` and persist selected `CertificateGroupIds` (§6.4) | Missing | Trustpoint browses the server's own `ServerConfiguration/CertificateGroups` directly (`gds_push_service.py:1004`). | Conditional on decision B. Otherwise keep direct browsing (current behavior is valid for interpretation A). | [ ] |
| GDS-05 | — | Minimise connection time; disconnect after each sequence (§6.3) | Implemented | New client/session per operation in `devices/tasks.py`. | Keep. | [x] |
| GDS-06 | P2 | Credentials must have the server's `SecurityAdmin` role (§6.2, §7.2) | Partial | Documented in `docs/source/features/devices/opc_ua_gds.md`; Trustpoint cannot verify the role and surfaces all failures generically. | Improve error classification (see METH-08); map `Bad_UserAccessDenied` / `Bad_SecurityModeInsufficient` to actionable messages. | [ ] |
| GDS-07 | P2 | LDS/GDS discovery and autopopulation: `FindServersOnNetwork`/`FindServers` scan, admin approval, GDS self-registration with an LDS, mDNS (§4, §6.1, Annex C) | Missing | Devices are added manually by IP and port. No LDS scan, `FindServers`, or approval staging. The .NET GDS sample implements a scan → stage → `DiscoveryAdmin` approval → `RegisterApplication` flow. | Conditional on interpretation A/B. Add a scan-and-stage flow only if automatic discovery is in scope; never auto-register without an approval gate. | [ ] |

### 3.2 §7.4 / §7.7 — PushManagement workflows

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| WF-01 | P1 | Update the TrustList before updating a certificate (§7.4, §7.7.2) | Partial | Periodic task does trust list first (`devices/tasks.py:61–77`); the standalone "update server certificate" task does not (`devices/tasks.py:109–127`). .NET issue #2552 confirms that strict revocation checking fails with `BadCertificateRevocationUnknown` when the CRL is not in the trust list before `UpdateCertificate`. | Make "update certificate" always run or offer the required trust-list step first, or combine both in one workflow entry point. | [ ] |
| WF-02 | P2 | For each CertificateType, determine whether an update is required (§7.7.2) | Missing | Fixed interval only (`opc_gds_push_renewal_interval`); no expiry, CRL or policy check. Every cycle replaces the certificate. | Add a decision step: compare server certificate expiry, configured renewal threshold and pending CRL changes. Skip when nothing is due. | [ ] |
| WF-03 | P0 | Only `ApplicationCertificateType` groups are considered (§7.7.2); use `CertificateTypes`/`Purpose` (§7.8.3.1) | Implemented | `_discover_certificate_groups` reads `Purpose`/`CertificateTypes`, skips HTTPS/UserToken/unknown non-application groups, and selects a permitted type. Name fallback only when both properties are unavailable. | Done; covered by discovery tests. | [x] |
| WF-04 | P1 | `ApplyChanges` completes the workflow; handle forced renegotiation (§7.7.2, §7.10.9) | Partial | Called when required, but per group/per operation (`:969`, `:1147`). The trust-list and certificate changes are not staged in one transaction, and the session is reused after apply. No reconnect or verification. The .NET reference stages trust list + certificate, applies once, disconnects, reconnects with the new certificate and inspects it. open62541 #8093 shows a heap-use-after-free when two `ApplyChanges` calls are sent in one `CallRequest`; repeated apply is an interop risk. | Stage per workflow, apply once, handle `BadServerHalted` (WF-10), disconnect/reconnect with the new certificate, and verify. | [ ] |
| WF-05 | P3 | Use `CreateSelfSignedCertificate` when no usable certificate exists (§7.7.4) | Missing | Method never called. | Optional. Implement only if servers without an existing certificate must be supported. | [ ] |
| WF-06 | P2 | CertificateManager generates the private key when the server cannot (§7.7.4) | Missing | Always `RegeneratePrivateKey=True`; no fallback path. | Read `SupportedPrivateKeyFormats`; on `Bad_NotSupported`, generate key + CSR locally, sign, and upload key via `UpdateCertificate`. | [ ] |
| WF-07 | P3 | Create Endpoint / Update Configuration workflows (§7.7.5/§7.7.6) | Missing | No `ConfigurationFile`, `UpdateTargets`, `ConfirmUpdate` usage. | Optional; separate feature. Not required for certificate replacement. | [ ] |
| WF-08 | P2 | CertificateManager needs a `DiscoveryUrl`; NAT/hostnames supported (§7.7.2) | Missing | URL is built as `opc.tcp://{ip_address}:{port}` (`gds_push_service.py:101`). | Add an optional discovery URL / endpoint URL field, with hostname support and fallback to IP:port. | [ ] |
| WF-09 | P0 | Workflow consistency | Implemented | `update_trustlist` and `update_server_certificate` now require every targeted group to succeed; partial updates return `False` with a per-group message and do not replace the local truststore. | Done; partial-success tests added. | [x] |
| WF-10 | P1 | `ApplyChanges` completion and session teardown (§7.10.9, §7.7.2) | Partial | `BadServerHalted` is now treated as success and the async client tears the session down; no automatic reconnect or verification after apply yet. | Remaining: reconnect with the new truststore/certificate and report the verification result separately. | [ ] |

### 3.3 §7.10 — method-level conformance

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| METH-01 | P0 | `CreateSigningRequest`: Nonce shall be at least 32 bytes when `RegeneratePrivateKey=TRUE` (§7.10.10) | Implemented | Passes `os.urandom(32)`; unit test asserts the nonce. | Done. Still recommended: make the test server reject a missing/short nonce (OPS-02). | [x] |
| METH-02 | P0 | `CertificateTypeId` must be one permitted by the group's `CertificateTypes` (§7.10.5, §7.8.3.1) | Implemented | `_select_application_certificate_type` reads `CertificateTypes` and prefers RsaSha256, then RsaMin, then named ECC types; groups with no application type are skipped. | Done; covered by discovery tests. Follow-up: prefer the currently assigned slot type discovered via `GetCertificates` (METH-08). | [x] |
| METH-03 | — | `UpdateCertificate` arguments: group, type, DER cert, issuer list, key format/key (§7.10.5) | Implemented | Correct for the server-generated-key case (`:1135–1143`). `IssuerCertificates` is redundant for application certificates per the standard and is ignored by the server. | Keep; extend for METH-04. | [x] |
| METH-04 | P2 | Upload an externally generated private key (PKCS#8/PKCS#12) (§7.7.4, §7.10.5) | Missing | `PrivateKeyFormat=''`, `PrivateKey=b''` always. | Add CM-side key generation and key upload, gated by `SupportedPrivateKeyFormats`. | [ ] |
| METH-05 | — | TrustList write sequence: `Open(Write\|EraseExisting)`, `Write`, `CloseAndUpdate`, `ApplyChanges` (§7.7.3, §7.8.2.2) | Implemented | Correct modes and order (`:944–979`). | Keep. Verify the expected `CloseAndUpdate` status codes against Mantis 9851 (possible incorrect status code in the specification/stack). | [x] |
| METH-06 | P3 | Write block size must not exceed `MaxByteStringLength` (§7.7.3) | Partial | Fixed 1024 bytes (`:929`); property not read. | Read the property and clamp the chunk size; keep 1024 as a safe default. | [ ] |
| METH-07 | P1 | Read `ServerConfiguration` capabilities: `MaxTrustListSize`, `SupportedPrivateKeyFormats`, `SupportsTransactions`, `InApplicationSetup`, `HasSecureElement`, `ServerCapabilities` (§7.10.3) | Missing | No read of any of these properties. `SupportsTransactions` has no well-known singleton-instance NodeId and must be resolved by browse path; the .NET reference does exactly that. | Add a capability probe after connect; use it to size writes, choose key handling, decide transaction/reconnect behavior, detect application setup mode and secure-element key handling. | [ ] |
| METH-08 | P2 | Use `GetCertificates`, `GetRejectedList`, `TrustList.Read`, `TransactionDiagnostics`, and the staged `DeleteCertificate`/`CreateSelfSignedCertificate` (§7.10.7/8/12/17, §7.8.2.4) | Missing | No calls. Server errors are only visible as generic exceptions. Note: `GetCertificates` is the one §7.10 method that does **not** treat a null group as `DefaultApplicationGroup`; the group must be named. It returns one row per `CertificateType`, which also identifies the slot to renew. | Add diagnostics: current certificates per type, rejected client certificates for trust bootstrap, transaction status/errors. Use explicit group IDs for `GetCertificates`. `TransactionDiagnostics` reports `Bad_OutOfService` before the first transaction, `Bad_InvalidState` while open, `Good` after completion. | [ ] |
| METH-09 | P2 | Transaction model: `CancelChanges`, single active transaction, `Bad_TransactionPending` (§7.10.2, §7.10.11) | Partial | No explicit cancel (session close implicitly cancels); no `SupportsTransactions` handling; no `Bad_TransactionPending` retry/backoff; no staged preview/cancel. Mantis 9852/9853 report File-API deadlock and concurrent-read issues; open62541 #8093 reports a double-apply crash. | Detect transaction support; keep one transaction per workflow; use `CancelChanges` on failure; add bounded retry/backoff for `Bad_TransactionPending` and File-API contention; expose apply/cancel as a separate step (see WF-04/WF-10). | [ ] |
| METH-10 | P3 | `ManagedApplications` / `ApplicationConfigurationType` (§7.10.14–16) | Missing | Only `ServerConfiguration` is addressed. | Optional feature. Implement only if proxy management of clients/non-UA applications is required. | [ ] |
| METH-11 | P2 | Audit events `CertificateUpdateRequested` / `CertificateUpdated` (§7.10.26/27) | N/A (server-side) | The server raises them. Trustpoint records no per-operation audit trail and does not attribute the operation to the triggering user. | Add Trustpoint-side audit records for push operations (who, device, groups, result). Not an OPC UA client requirement, but an enterprise control. | [ ] |
| METH-12 | P1 | Reuse the server's existing private key (`RegeneratePrivateKey=FALSE`) (§7.10.10, §7.7.4) | Implemented | New `opc_gds_push_regenerate_server_key` setting defaults to false; `CreateSigningRequest` now sends `False` with an empty nonce unless rollover is enabled, and the nonce is sent only when a new key is requested. UI checkbox added to the renewal settings. | Done; covered by service/config tests. | [x] |

### 3.4 §7.8 — TrustList content and semantics

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| TL-01 | — | `SpecifiedLists` mask and four lists (§7.8.2.8) | Implemented | `All` with all four lists populated (`:278–283`). | Keep. | [x] |
| TL-02 | P1 | List semantics: trusted anchors vs issuers (§7.8.2.8) | Partial | The full CA chain is written to both `TrustedCertificates` and `IssuerCertificates`, and CRLs to both. Works on many servers; makes every intermediate a trust anchor and may be rejected by strict servers. Duplicates can also consume two slots against device trust-list limits (see TL-08). | Write roots as trusted certificates, intermediates as issuer certificates, with matching CRL lists. Verify against at least one strict server. | [ ] |
| TL-03 | — | Provide all issuers/CRLs needed for the new certificate (§7.7.2) | Implemented | Domain CA chain + CRLs. | Keep; include the server's new issuer after selection. | [x] |
| TL-04 | P0 | Do not destroy unrelated trust entries | Implemented | Trust-list discovery now targets only application-purpose groups, so HTTPS/UserToken trust lists are no longer overwritten with the application CA chain. Full replacement within a targeted group remains the protocol-defined `Open(Write\|EraseExisting)` behaviour. | Done; document that the trust list is authoritative for the targeted application groups. Optional: read and display the current list before replacing it. | [x] |
| TL-05 | P2 | CRLs | Partial (stricter than spec) | A CRL is mandatory for **every** CA (`:253–256`), including roots that commonly have none. Expiry is checked. .NET issue #2552 shows strict revocation checking failing after a certificate update when the CRL is missing. | Allow trust-list updates when a CA legitimately has no CRL (configurable policy), or document the restriction as a product requirement. | [ ] |
| TL-06 | P2 | Respect `MaxTrustListSize` (§7.10.3) | Missing | No size pre-check; oversize lists fail at the server. Device limits can be much smaller: Siemens S7-1500 documents 62 trust-list entries (CRLs consume entries) and 4,096 bytes per element; certificates shared between services count once. | Compare the serialized size against `MaxTrustListSize` (0 = unlimited) and preflight per-device entry/element limits (TL-08). | [ ] |
| TL-07 | P1 | Read the current TrustList and rejected list before pushing (§7.8.2.4, §7.10.12, §7.7.3) | Implemented | `_read_trustlist` reads the current list; `_merge_trustlists` merges certificates and replaces CRLs per issuer, preserving other trust entries. `GetRejectedList` is read and the count logged. Merge is the default; there is no UI replace/merge choice yet. | Done for read/merge; optional UI follow-up for explicit replace and displaying rejected certificates. Watch Mantis 9852/9853 (File-API deadlock/concurrent reads) when retrying reads. | [x] |
| TL-08 | P1 | Device trust-list capacity and element-size preflight | Missing | No count/element-size check. Siemens S7-1500 (firmware-specific, verify) limits the trust list to 62 entries including CRLs, 4,096 bytes per element, and counts a certificate shared between services only once. Merging preserves entries and can silently exceed such limits; duplicated CA entries in trusted+issuer lists make it worse. | Add configurable per-device limits, count certificates + CRLs across lists, check each DER element size and the aggregate, and offer prune/replace behavior. Keep vendor limits configurable, not hard-coded in the generic layer. | [ ] |

### 3.5 Security and certificate interoperability

| ID | Priority | Aspect | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| SEC-01 | P1 | Security policy negotiation | Partial | Hard-coded `Basic256Sha256` + `SignAndEncrypt` (`:565–573`). Servers that only offer AES/ECC policies cannot be managed. | Select from `GetEndpoints`; support at least `Basic256Sha256`, `Aes128Sha256RsaOaep`, `Aes256Sha256RsaPss`; add ECC only if in scope. Keep `SignAndEncrypt`. | [ ] |
| SEC-02 | P2 | Server authentication and rotation | Partial | Pins the leaf certificate at truststore order 0 (`:483–527`); no chain validation against a CA truststore, no automatic rotation. Fail-closed is good. | Keep pinning as an option; add CA-based validation and a controlled update path when the server certificate changes. | [ ] |
| SEC-03 | P1 | Trust bootstrap / TOFU (Annex G.2) | Missing | `discover_server` returns endpoints only, not the certificate (`:785–809`). The view reads `server_info['server_certificate_available']`, but this key is never set; `request.session['opc_ua_server_info']` is never used. The .NET client seeds a push application's certificate from the connected endpoint's `ServerCertificate` and uses `GetRejectedList`/the rejected store to trust client certificates. | Capture the endpoint certificate during discovery, expose it for truststore creation/import, and surface rejected client certificates via `GetRejectedList`. Or document manual bootstrap explicitly and remove the dead UI path. | [ ] |
| SEC-04 | P3 | Client certificate profile (Part 6 §6.2.2) | Implemented | `opc_ua_domain_credential.json` has RSA key usages and `clientAuth`. Runtime validation (`:403`) omits `nonRepudiation`, but the profile includes it. | Optional hardening: align the runtime check with the profile. | [ ] |
| SEC-05 | P2 | Trustpoint RBAC for push operations | Partial | `MANAGE_DEVICES` can replace a server trust list; `ISSUE_CERTIFICATES` can replace its server certificate and revoke the old one. No four-eyes/approval, no user attribution on the queued task. If Trustpoint ever acts as a GDS, the v1.05.07 `ApplicationAdmin` privilege (subset of registered applications) has no equivalent. | Split permissions if needed; record the initiating user; consider an approval step for certificate replacement; map `ApplicationAdmin` grants if the GDS role is implemented. | [ ] |
| SEC-06 | P2 | Domain credential renewal | Partial / risk | Old credential is revoked immediately. If a server trusts only the old client certificate rather than the CA, renewal locks Trustpoint out. | Document the CA-trust requirement; verify connectivity with the new credential before revoking the old one where possible. | [ ] |
| SEC-07 | — | Secrets at rest | Implemented | `EncryptedCharField` for the OPC password. | Keep. | [x] |
| SEC-08 | P2 | Issued certificate must satisfy the server's configured validation policy | Missing | The server validates the pushed certificate against its own `SecurityConfiguration` (minimum key size, SHA-1 rejection, unknown revocation). .NET issue #3931 shows a server rejecting a valid push because the validation path ignored its configured policy. Trustpoint cannot read that policy over OPC UA; the `opc_ua` profile defaults may not match the device. | Make key size/signature algorithm and revocation expectations configurable per device/profile; surface `BadCertificatePolicyCheckFailed` and related status codes with actionable messages; document that the device policy must be aligned out of band. | [ ] |

### 3.6 Testing and operational robustness

| ID | Priority | Aspect | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| OPS-01 | P1 | Unit tests cover real protocol strictness | Partial | Tests mock `asyncua` and assert current call shapes, including the missing nonce. | Add tests for nonce length, type selection, group filtering, partial results and capability handling. | [ ] |
| OPS-02 | P1 | Integration server behaves like a strict server | Partial | `trustpoint/request/gds_push/asyncua-gds-push-test/server.py` ignores the nonce (`:162`) and uses a simplified address space. | Make the test server enforce the nonce, permitted certificate types and separate group purposes; add negative tests. | [ ] |
| OPS-03 | P1 | Real-stack conformance | Missing | No test against open62541, a commercial GDS, or an AES/ECC-only server. | Add one real-stack interoperability test before claiming conformance. | [ ] |
| OPS-04 | P2 | Timeouts, retries, concurrency | Partial | No configurable secure-channel/session timeout (`_create_secure_client`), no retry/backoff, no lock preventing a manual push from overlapping the scheduled push. | Add configurable timeouts, bounded retries and a per-device operation lock. | [ ] |
| OPS-05 | P3 | Discovery documentation matches behavior | Partial | Docs claim discovery shows "certificate management capabilities"; it only lists endpoints (`docs/source/features/devices/opc_ua_gds.md`). | Either extend discovery (groups, `ServerConfiguration` capabilities) or correct the documentation. | [ ] |

### 3.7 Reference implementation cross-check (.NET GDS samples)

Source: [OPCFoundation/UA-.NETStandard-Samples — Samples/GDS](https://github.com/OPCFoundation/UA-.NETStandard-Samples/blob/master/Samples/GDS/README.md),
especially [`Client/Model/TrustListModel.cs`](https://github.com/OPCFoundation/UA-.NETStandard-Samples/blob/master/Samples/GDS/Client/Model/TrustListModel.cs)
and [`Client/Model/CertificateModel.cs`](https://github.com/OPCFoundation/UA-.NETStandard-Samples/blob/master/Samples/GDS/Client/Model/CertificateModel.cs).

The sample implements v1.05.07 and exposes behavior that is easy to miss from the specification text alone. The following are now captured above:

- **Everything is staged until `ApplyChanges`.** `UpdateCertificate`, `DeleteCertificate`, `CreateSelfSignedCertificate` and trust-list writes change nothing until the transaction is committed; `CancelChanges` discards it. The client shows Server Status, Apply and Cancel as separate steps, then **disconnects and reconnects with the new certificate to verify**. See WF-04/WF-10/METH-09.
- **`BadServerHalted` is expected.** Applying changes may restart the server; it answers `BadServerHalted` and drops the connection. The reference treats that as success and closes the session. See WF-10.
- **Trust list is read, merged and pushed.** The reference reads the current trust list (with masks) plus `GetRejectedList`, merges the GDS CA/list, and pushes the result. It does not blindly replace it. See TL-07/TL-04.
- **Reuse the existing private key by default.** The push client calls `CreateSigningRequest` with `RegeneratePrivateKey=false` and an empty nonce; it only rolls the key when intended. This matters for secure elements and non-exportable keys. See METH-12.
- **Per-slot certificate management.** `GetCertificates` returns one row per CertificateType and identifies the current slot; `DeleteCertificate` and `CreateSelfSignedCertificate` are staged operations. `GetCertificates` is the one method that does **not** accept a null group as the default. See METH-08/METH-02.
- **Optional `ServerConfiguration` surface.** `SupportsTransactions` has no well-known singleton NodeId (browse path), and `HasSecureElement`, `InApplicationSetup` and `TransactionDiagnostics` statuses drive the UI. See METH-07/METH-08.
- **Trust bootstrap uses the endpoint certificate.** For push, the reference seeds the application certificate from the connected endpoint's `ServerCertificate`; rejected client certificates are recovered through `GetRejectedList`/the rejected store. See SEC-03.
- **GDS-side features not applicable to a pure CertificateManager:** `ManagedApplications` (METH-10), `ApplicationAdmin` grant mapping (GDS-02/SEC-05), LDS scan/autopopulation (GDS-07), Part 17 AliasNames merging and Part 21 onboarding tickets. The last two are outside certificate push and are not gaps for Trustpoint.

## 4. Implementation plan

### Milestone 1 — Conformance and correctness (must do)

- [x] **METH-01** Pass a ≥ 32-byte nonce to `CreateSigningRequest`.
- [x] **WF-03 / METH-02** Select certificate groups by `Purpose`/`CertificateTypes`; select a permitted certificate type instead of the hard-coded base type.
- [x] **WF-03 / TL-04** Restrict trust-list updates to the relevant application group(s); stop writing the application trust list into HTTPS/UserToken groups.
- [ ] **WF-01** Ensure every certificate update is preceded by the required trust-list update (or combine them in one workflow).
- [x] **WF-09** Return structured per-group results; do not report partial success as success.
- [ ] **OPS-01 / OPS-02** Extend the test server and unit tests to catch these regressions. (Unit tests added; test server nonce/type enforcement still open.)

**Exit criteria:** the workflow succeeds against a strict test server that enforces a nonce, permits only `RsaSha256ApplicationCertificateType`, and exposes separate HTTPS/UserToken groups; a partial group failure is reported as failure.

### Milestone 2 — Interoperability and server capabilities

- [ ] **SEC-01** Negotiate the security policy from the server's endpoints (AES + Basic256Sha256).
- [ ] **METH-07** Read `MaxTrustListSize`, `SupportedPrivateKeyFormats`, `SupportsTransactions` (browse path), `InApplicationSetup`, `HasSecureElement`, `ServerCapabilities`.
- [ ] **TL-06 / METH-06** Enforce trust-list size and chunk-size limits.
- [x] **METH-12** Reuse the existing server key by default; make rollover opt-in.
- [ ] **WF-06 / METH-04** Add the CM-generated-key fallback and private-key upload.
- [ ] **WF-04 / WF-10 / METH-09** Stage per workflow, apply once, reconnect/verify with the new certificate, and support `CancelChanges`/`Bad_TransactionPending`. (`BadServerHalted` handling is done; reconnect/verification remains.)
- [x] **TL-07** Read the current trust list and rejected list; merge before pushing.
- [ ] **TL-02** Correct trusted-vs-issuer list content.
- [ ] **TL-08** Add configurable per-device trust-list capacity and element-size preflight.
- [ ] **SEC-08** Align issued certificates with the device's configured validation policy (key size, signature, revocation).

**Exit criteria:** certificate replacement works on a server that does not generate keys and on a server that only offers `Aes256Sha256RsaPss`; an existing server key can be kept; apply/restart is treated as success and the new certificate is verified after reconnect; a trust-list push preserves or explicitly replaces the existing list.

### Milestone 3 — Trust bootstrap, diagnostics and operations

- [ ] **SEC-03** Capture the server certificate during discovery and offer it for truststore creation/import; fix or remove the dead `server_certificate_available` path.
- [ ] **METH-08** Add `GetCertificates` (explicit group, one row per type), `GetRejectedList`, `DeleteCertificate`, `CreateSelfSignedCertificate` and `TransactionDiagnostics`-based error reporting.
- [ ] **WF-02** Add an expiry/CRL-based "update required" decision instead of blind interval renewal.
- [ ] **METH-11 / SEC-05** Add per-operation audit records and user attribution.
- [ ] **OPS-04** Add timeouts, retries and a per-device operation lock.
- [ ] **OPS-03** Run one real-stack interoperability test.
- [ ] **GDS-07** Add LDS/GDS scan-and-stage discovery with `DiscoveryAdmin` approval (conditional).

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
- [x] `BadServerHalted` from `ApplyChanges` is treated as success and the session is closed.
- [x] An existing server key can be reused (`RegeneratePrivateKey=false`); a secure-element server is not forced to roll its key.
- [x] The current trust list is read and merged; rejected certificates are read and logged.
- [ ] `GetCertificates` is called with an explicit group and returns the current type per slot.
- [ ] Discovery shows the server certificate and it can be imported into the truststore.
- [ ] Trust-list entry count, per-element DER size and aggregate size are checked against the device limits before writing (e.g., S7-1500: 62 entries / 4,096 bytes).
- [ ] No CA certificate is duplicated between trusted and issuer lists when the device counts entries across lists.
- [ ] Only one `ApplyChanges` is sent per transaction; repeated apply is tested against open62541.
- [ ] `UpdateCertificate` succeeds with strict revocation checking when the trust list with CRLs was applied first.
- [ ] The issued certificate's key size/signature is accepted by the device's configured validation policy.

## 7. File and line map (current code, 2026-11-26)

| Topic | Location |
|---|---|
| Device connection settings, renewal settings | `trustpoint/devices/models.py:203` |
| Scheduled renewal, trust list then certificate | `trustpoint/devices/tasks.py:23` |
| Standalone trust-list push | `trustpoint/devices/tasks.py:92` |
| Standalone certificate push | `trustpoint/devices/tasks.py:109` |
| Trust-list construction (CA chain + CRLs) | `trustpoint/request/gds_push/gds_push_service.py:256` |
| Secure client, hard-coded policy | `trustpoint/request/gds_push/gds_push_service.py:563` |
| Server certificate pinning | `trustpoint/request/gds_push/gds_push_service.py:517` |
| Endpoint discovery | `trustpoint/request/gds_push/gds_push_service.py:714` |
| Certificate group discovery | `trustpoint/request/gds_push/gds_push_service.py:1256` |
| Trust-list group discovery (application groups only) | `trustpoint/request/gds_push/gds_push_service.py:1004` |
| Trust-list write sequence | `trustpoint/request/gds_push/gds_push_service.py:1115` |
| TrustList read | `trustpoint/request/gds_push/gds_push_service.py:1073` |
| TrustList merge (certs/CRLs) | `trustpoint/request/gds_push/gds_push_service.py:1055` |
| Rejected list read | `trustpoint/request/gds_push/gds_push_service.py:1101` |
| Certificate update (CSR, nonce, type) | `trustpoint/request/gds_push/gds_push_service.py:1305` |
| CSR signing / certificate issuance | `trustpoint/request/gds_push/gds_push_service.py:1385` |
| Local truststore replacement | `trustpoint/request/gds_push/gds_push_service.py:1492` |
| Discovery view (dead certificate flag) | `trustpoint/devices/views/credential_issuance.py:587–589` |
| Client certificate profile | `trustpoint/pki/default_certificate_profiles/opc_ua_domain_credential.json` |
| Server certificate profile | `trustpoint/pki/default_certificate_profiles/opc_ua.json` |
| Test server | `trustpoint/request/gds_push/asyncua-gds-push-test/server.py` |
| User documentation | `docs/source/features/devices/opc_ua_gds.md` |

## 8. Sources and research entry points

These sources are **implementation aids, not normative requirements**. Part 12 remains authoritative. Verify every issue, forum note and vendor statement against the current specification revision and the target device firmware before relying on it. Keep vendor-specific limits and workarounds in configuration; do not hard-code them into the generic GDS protocol layer.

### 8.1 Source priority

| Priority | Source | Purpose |
|---|---|---|
| P0 | OPC UA Part 12 v1.05.07 | Normative requirements |
| P0 | OPC Foundation Mantis | Ambiguities and specification corrections |
| P0 | .NET GDS reference implementation | Practical client/server behavior |
| P0 | .NET GDS issues, PRs and regression tests | Known edge cases and fixes |
| P1 | open62541 implementation and tests | Independent implementation |
| P1 | OPC Foundation CTT | Conformance expectations and negative cases (access required) |
| P1 | Vendor documentation (Siemens, Unified Automation, Prosys, Softing, …) | Device limits and interoperability |
| P2 | Working-group minutes and release candidates | Design rationale and future changes |
| P2 | IOP workshop results | Real-world cross-vendor failures (confidential) |

### 8.2 OPC Foundation Mantis

Base: <https://mantis.opcfoundation.org/>

| Issue | Subject | Relevance to Trustpoint |
|---|---|---|
| [9850](https://mantis.opcfoundation.org/view.php?id=9850) | Inconsistency in the Push Management transaction diagram | Interpret the intended transaction sequence against WF-04/METH-09; confirm which methods share one transaction. |
| [9851](https://mantis.opcfoundation.org/view.php?id=9851) | Incorrect status code for `CloseAndUpdate()` | Verify the expected success/failure codes in the trust-list write path (METH-05/WF-10). |
| [9852](https://mantis.opcfoundation.org/view.php?id=9852) | Potential deadlock when manipulating TrustLists via the File API | Add retry/backoff and avoid overlapping read/write sessions (METH-09/OPS-04). Trustpoint now reads and writes the trust list on the same connection (TL-07). |
| [9853](https://mantis.opcfoundation.org/view.php?id=9853) | Concurrent read access to TrustLists | Serialize trust-list reads/writes per device and handle contention (TL-07/OPS-04). |
| [9854](https://mantis.opcfoundation.org/view.php?id=9854) | Missing TrustList validation for `RemoveCertificate()` | Not used by Trustpoint; relevant only if `RemoveCertificate` is added. |

These were raised by an implementer in September 2024. **Resolution status was not independently verified**; check the current specification and the target stack before coding around them.

### 8.3 OPC Foundation developer forum

Base: <https://forum.opcfoundation.org/>

Thread: **“Issues found in the GDS Push Management”** (Marcel Patzlaff / Randy Armstrong). Read for the rationale behind transaction handling and the proposal of batch update operations. Useful for interpreting ambiguous requirements, but treat conclusions as discussion input, not normative text.

### 8.4 GitHub issues, pull requests and regression tests

Issue states below were checked via the GitHub API on **2026-11-26**. “Closed” does not guarantee a fix in the version you target; check the fix commit and release notes.

| Item | State | Relevance |
|---|---|---|
| [UA-.NETStandard #2552](https://github.com/OPCFoundation/UA-.NETStandard/issues/2552) — IOP: `BadCertificateRevocationUnknown` when calling `ApplyChanges` after a certificate update | Closed | Strict revocation checking fails when the updated certificate's CRL is not in the trust list. Reinforces WF-01/TL-05: apply the trust list with CRLs before `UpdateCertificate`. |
| [UA-.NETStandard #3795](https://github.com/OPCFoundation/UA-.NETStandard/pull/3795) — GDS Part 12 Full Compliance | Closed PR | A concrete checklist of 57 gaps across authorization, audit, push/pull, `CreateSelfSignedCertificate`, audit redaction, `ApplicationAdmin` and LDS. Use as a review checklist for METH-08, METH-10 and GDS-02. |
| [UA-.NETStandard #3931](https://github.com/OPCFoundation/UA-.NETStandard/issues/3931) — GDS Push validation needs to honor security configuration | Closed | The server's certificate validation policy (minimum key size, SHA-1, unknown revocation) is not necessarily the default. Trustpoint cannot read it over OPC UA; see SEC-08. |
| [open62541 #8093](https://github.com/open62541/open62541/issues/8093) — GDS PushManagement double-`ApplyChanges` use-after-free | Closed | Two `ApplyChanges` calls in one `CallRequest` crash the server. Reinforces “apply once per transaction” (WF-04/METH-09) and avoiding repeated apply loops. |

Additional research entry points:

- .NET Standard GDS Push issues: <https://github.com/OPCFoundation/UA-.NETStandard/issues?q=gds+push>
- .NET Standard GDS Pull requests: <https://github.com/OPCFoundation/UA-.NETStandard/pulls?q=gds+push>
- .NET Samples GDS issues: <https://github.com/OPCFoundation/UA-.NETStandard-Samples/issues?q=gds>
- open62541 GDS issues: <https://github.com/open62541/open62541/issues?q=gds+push>
- python-asyncua GDS issues: <https://github.com/FreeOpcUa/opcua-asyncio/issues?q=gds>

### 8.5 Vendor-specific limits and behavior

Vendor documentation describes limits the specification does not define. Treat these as **per-device configuration**, not protocol constants.

- **Siemens S7-1500 GDS Push configuration limits** (verify against the firmware/STEP 7 documentation for the exact model): a maximum of **62 trust-list entries**, including resources consumed by certificate-based services; a maximum **element size of 4,096 bytes**; CRLs also consume entries; a certificate shared between services counts only once.
  - Impact: check the number of certificates **and CRLs** per list, each DER element size, and the aggregate before pushing (TL-08). Merging existing entries (TL-07) makes overflow more likely; duplicated CA entries in trusted+issuer lists (TL-02) can consume extra slots.
- **Other vendors:** Unified Automation, Prosys, Softing and others publish support notes, firmware release notes and SDK changelogs. Use them for capacity limits, supported security policies, certificate-type support and known regressions. Keep the generic layer vendor-neutral.

### 8.6 Internal / membership-only sources

These were **not accessed** and must not be presented as evidence in this document. If Trustpoint has OPC Foundation membership access, they are worth reviewing:

- UA working-group minutes and technical decisions.
- Release candidates and pre-publication changes.
- CTT test scripts and negative test cases.
- Interoperability workshop test database and results (confidential).
- Certification laboratory findings.

The most valuable next step for Trustpoint would be to participate in an IOP workshop as a certificate-management client, and to run the CTT against a real GDS Push target. Both expose interoperability defects that the specification text and unit tests do not.

### 8.7 How these sources map to the backlog

| Source | Backlog items |
|---|---|
| #2552 (strict revocation / missing CRL) | WF-01, TL-05 |
| #3795 (full Part 12 compliance) | METH-08, METH-10, GDS-02; audit and `CreateSelfSignedCertificate` |
| #3931 (server validation policy) | SEC-08 |
| open62541 #8093 (double apply) | WF-04, METH-09 |
| Mantis 9852/9853 (File-API deadlock/concurrency) | METH-09, TL-07, OPS-04 |
| Mantis 9850/9851 (transaction/status codes) | WF-04, METH-05, METH-09 |
| Siemens S7-1500 limits | TL-02, TL-06, TL-08 |
| Forum thread on GDS Push issues | WF-04, METH-09 (transaction interpretation) |
