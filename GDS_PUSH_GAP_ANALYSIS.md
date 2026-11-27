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

Findings by priority: **P0 = 6 (all done)**, **P1 = 13**, **P2 = 21**, **P3 = 7**, **already implemented = 6** — 35 of 53 items are done.

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
| GDS-04 | P3 | Browse `Directory/CertificateGroups` and persist selected `CertificateGroupIds` (§6.4) | Missing | Trustpoint browses the server's own `ServerConfiguration/CertificateGroups` directly (`gds_push_service.py:1686`). | Conditional on decision B. Otherwise keep direct browsing (current behavior is valid for interpretation A). | [ ] |
| GDS-05 | — | Minimise connection time; disconnect after each sequence (§6.3) | Implemented | New client/session per operation in `devices/tasks.py`. | Keep. | [x] |
| GDS-06 | P2 | Credentials must have the server's `SecurityAdmin` role (§6.2, §7.2) | Partial | Documented in `docs/source/features/devices/opc_ua_gds.md`; Trustpoint cannot verify the role and surfaces all failures generically. | Improve error classification (see METH-08); map `Bad_UserAccessDenied` / `Bad_SecurityModeInsufficient` to actionable messages. | [ ] |
| GDS-07 | P2 | LDS/GDS discovery and autopopulation: `FindServersOnNetwork`/`FindServers` scan, admin approval, GDS self-registration with an LDS, mDNS (§4, §6.1, Annex C) | Missing | Devices are added manually by IP and port. No LDS scan, `FindServers`, or approval staging. The .NET GDS sample implements a scan → stage → `DiscoveryAdmin` approval → `RegisterApplication` flow. | Conditional on interpretation A/B. Add a scan-and-stage flow only if automatic discovery is in scope; never auto-register without an approval gate. | [ ] |

### 3.2 §7.4 / §7.7 — PushManagement workflows

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| WF-01 | P1 | Update the TrustList before updating a certificate (§7.4, §7.7.2) | Implemented | Both the periodic task and the standalone certificate update now apply the trust list first; the standalone task continues to the certificate if the trust-list update fails. .NET issue #2552 confirms that strict revocation checking needs the CRL in the trust list before `UpdateCertificate`. | Done; task-order test added. | [x] |
| WF-02 | P2 | For each CertificateType, determine whether an update is required (§7.7.2) | Partial | The periodic task refreshes the trust list every cycle but replaces the certificate only when the pinned server certificate expires within `opc_gds_push_renewal_threshold_days` (default 30). CRL-change detection and independent schedules are not implemented. | Remaining: detect pending CRL changes and allow independent certificate/trust-list cadences. | [ ] |
| WF-03 | P0 | Only `ApplicationCertificateType` groups are considered (§7.7.2); use `CertificateTypes`/`Purpose` (§7.8.3.1) | Implemented | `_discover_certificate_groups` reads `Purpose`/`CertificateTypes`, skips HTTPS/UserToken/unknown non-application groups, and selects a permitted type. Name fallback only when both properties are unavailable. | Done; covered by discovery tests. | [x] |
| WF-04 | P1 | `ApplyChanges` completes the workflow; handle forced renegotiation (§7.7.2, §7.10.9) | Implemented | New `update_trustlist_and_certificate` stages the trust list and certificate in one session, applies once after all groups succeed, updates the local truststore, and verifies the reconnect. The periodic and manual certificate-renewal tasks use it. | Done; combined-workflow and task tests added. Standalone methods remain for targeted operations. | [x] |
| WF-05 | P3 | Use `CreateSelfSignedCertificate` when no usable certificate exists (§7.7.4) | Missing | Method never called. | Optional. Implement only if servers without an existing certificate must be supported. | [ ] |
| WF-06 | P2 | CertificateManager generates the private key when the server cannot (§7.7.4) | Implemented | On `Bad_NotSupported`/`Bad_InvalidState` from `CreateSigningRequest`, Trustpoint generates an RSA or supported EC key, builds a CSR from the current subject/SANs, signs it, and uploads the key. If a server ignores a requested rollover, a new key is generated and uploaded. | Done; tests cover missing key generation and ignored rollover. | [x] |
| WF-07 | P3 | Create Endpoint / Update Configuration workflows (§7.7.5/§7.7.6) | Missing | No `ConfigurationFile`, `UpdateTargets`, `ConfirmUpdate` usage. | Optional; separate feature. Not required for certificate replacement. | [ ] |
| WF-08 | P2 | CertificateManager needs a `DiscoveryUrl`; NAT/hostnames supported (§7.7.2) | Implemented | `opc_server_url` is an optional full endpoint URL (including resource path) that overrides IP/port; discovery returns advertised endpoint URLs unchanged. node-opcua's Erlangen IOP findings drove the separation of connection address and advertised URL. | Done; service/model/form tests added. | [x] |
| WF-09 | P0 | Workflow consistency | Implemented | `update_trustlist` and `update_server_certificate` now require every targeted group to succeed; partial updates return `False` with a per-group message and do not replace the local truststore. | Done; partial-success tests added. | [x] |
| WF-10 | P1 | `ApplyChanges` completion and session teardown (§7.10.9, §7.7.2) | Implemented | `BadServerHalted` is treated as success; after a trust-list or certificate update Trustpoint reconnects with the current truststore and reports `reconnect verified` or the verification error without failing the applied update. | Done; verification success/failure tests added. | [x] |

### 3.3 §7.10 — method-level conformance

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| METH-01 | P0 | `CreateSigningRequest`: Nonce shall be at least 32 bytes when `RegeneratePrivateKey=TRUE` (§7.10.10) | Implemented | Passes `os.urandom(32)` when rollover is requested; unit test asserts the nonce and the test server rejects a missing/short nonce. | Done. | [x] |
| METH-02 | P0 | `CertificateTypeId` must be one permitted by the group's `CertificateTypes` (§7.10.5, §7.8.3.1) | Implemented | `_select_application_certificate_type` reads `CertificateTypes` and prefers RsaSha256, then RsaMin, then named ECC types; groups with no application type are skipped. | Done; covered by discovery tests. Follow-up: prefer the currently assigned slot type discovered via `GetCertificates` (METH-08). | [x] |
| METH-03 | — | `UpdateCertificate` arguments: group, type, DER cert, issuer list, key format/key (§7.10.5) | Implemented | Correct for the server-generated-key case (`:1135–1143`). `IssuerCertificates` is redundant for application certificates per the standard and is ignored by the server. | Keep; extend for METH-04. | [x] |
| METH-04 | P2 | Upload an externally generated private key (PKCS#8/PKCS#12) (§7.7.4, §7.10.5) | Implemented | Generated keys are uploaded in a server-advertised format: PFX (PKCS#12), PEM (PKCS#8), or base64 PKCS#8 DER. RSA 2048 and supported NIST/Brainpool EC keys are generated; Curve25519/448 is rejected. | Done. | [x] |
| METH-05 | — | TrustList write sequence: `Open(Write\|EraseExisting)`, `Write`, `CloseAndUpdate`, `ApplyChanges` (§7.7.3, §7.8.2.2) | Implemented | Correct modes and order (`:944–979`). | Keep. Verify the expected `CloseAndUpdate` status codes against Mantis 9851 (possible incorrect status code in the specification/stack). node-opcua's Part 12 fixes (#1776/#1779) cover `AddCertificate`/`RemoveCertificate` status codes, chain completeness and CRL cleanup; relevant if those methods are added. | [x] |
| METH-06 | P3 | Write block size must not exceed `MaxByteStringLength` (§7.7.3) | Implemented | `_read_server_capabilities` reads `MaxByteStringLength`; `_effective_chunk_size` clamps the write block to it (0 = no limit, 1024 default). | Done; clamping test added. | [x] |
| METH-07 | P1 | Read `ServerConfiguration` capabilities: `MaxTrustListSize`, `SupportedPrivateKeyFormats`, `SupportsTransactions`, `InApplicationSetup`, `HasSecureElement`, `ServerCapabilities` (§7.10.3) | Implemented | `_read_server_capabilities` probes all six properties after connect (browse path for `SupportsTransactions`) and stores them on the service. `MaxTrustListSize` is enforced during preflight. | Done; tests cover property reads and max-size rejection. Use the remaining values for key handling/transactions in follow-ups. | [x] |
| METH-08 | P2 | Use `GetCertificates`, `GetRejectedList`, `TrustList.Read`, `TransactionDiagnostics`, and the staged `DeleteCertificate`/`CreateSelfSignedCertificate` (§7.10.7/8/12/17, §7.8.2.4) | Partial | `GetCertificates` is used with an explicit group ID to read the currently assigned certificates and prefer the existing certificate type; `GetRejectedList` is read/logged; `TrustList.Read` is implemented. `DeleteCertificate`, `CreateSelfSignedCertificate` and `TransactionDiagnostics` remain unused. | Remaining: staged delete/self-signed and transaction diagnostics/inventory UI. | [ ] |
| METH-09 | P2 | Transaction model: `CancelChanges`, single active transaction, `Bad_TransactionPending` (§7.10.2, §7.10.11) | Partial | One transaction per combined workflow; failures call `CancelChanges`; the task retries once after `Bad_TransactionPending`. No `SupportsTransactions` branch, File-API backoff, or staged apply/cancel UI. | Remaining: transaction-support detection, File-API retry/backoff, and apply/cancel UI. | [ ] |
| METH-10 | P3 | `ManagedApplications` / `ApplicationConfigurationType` (§7.10.14–16) | Missing | Only `ServerConfiguration` is addressed. | Optional feature. Implement only if proxy management of clients/non-UA applications is required. | [ ] |
| METH-11 | P2 | Audit events `CertificateUpdateRequested` / `CertificateUpdated` (§7.10.26/27) | Implemented | Manual push operations create a `GDS_PUSH_UPDATE` audit entry with actor, device, result and message; periodic operations are recorded with a system actor. The server-side OPC UA audit events remain the server's responsibility. | Done; task audit test added. | [x] |
| METH-12 | P1 | Reuse the server's existing private key (`RegeneratePrivateKey=FALSE`) (§7.10.10, §7.7.4) | Implemented | New `opc_gds_push_regenerate_server_key` setting defaults to false; `CreateSigningRequest` now sends `False` with an empty nonce unless rollover is enabled, and the nonce is sent only when a new key is requested. UI checkbox added to the renewal settings. | Done; covered by service/config tests. | [x] |
| METH-13 | P2 | Verify that key rollover actually happened | Implemented | When `regenerate_private_key` is true, `_validate_csr_identity` compares the CSR public key with the current certificate and rejects a reused key. Traeger-style servers that ignore the flag now fail with a clear error instead of silently reusing the key. | Done; tests cover reused and new keys. | [x] |

### 3.4 §7.8 — TrustList content and semantics

| ID | Priority | Requirement | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| TL-01 | — | `SpecifiedLists` mask and four lists (§7.8.2.8) | Implemented | `All` with all four lists populated (`:278–283`). | Keep. | [x] |
| TL-02 | P1 | List semantics: trusted anchors vs issuers (§7.8.2.8) | Implemented | The root CA and its CRL go to `TrustedCertificates`/`TrustedCrls`; issuing and intermediate CAs and their CRLs go to `IssuerCertificates`/`IssuerCrls`. Merge also removes a trusted certificate from the issuer list. | Done; tests assert root-only trust anchors and cross-list de-duplication. Verify against a strict server with a multi-level chain. | [x] |
| TL-03 | — | Provide all issuers/CRLs needed for the new certificate (§7.7.2) | Implemented | Domain CA chain + CRLs. | Keep; include the server's new issuer after selection. | [x] |
| TL-04 | P0 | Do not destroy unrelated trust entries | Implemented | Trust-list discovery now targets only application-purpose groups, so HTTPS/UserToken trust lists are no longer overwritten with the application CA chain. Full replacement within a targeted group remains the protocol-defined `Open(Write\|EraseExisting)` behaviour. | Done; document that the trust list is authoritative for the targeted application groups. Optional: read and display the current list before replacing it. | [x] |
| TL-05 | P2 | CRLs | Implemented | A CRL is required by default for every CA; `opc_gds_push_require_crls` (default true) can be disabled per device to continue without a CRL. Expired CRLs are still rejected. .NET issue #2552 remains the reason the default is strict. | Done; config/UI/tests added. | [x] |
| TL-06 | P2 | Respect `MaxTrustListSize` (§7.10.3) | Implemented | `_read_server_capabilities` reads `MaxTrustListSize`; `_validate_trustlist_limits` rejects a serialized trust list above it before writing. Device entry/element limits are separate (TL-08). | Done. | [x] |
| TL-07 | P1 | Read the current TrustList and rejected list before pushing (§7.8.2.4, §7.10.12, §7.7.3) | Implemented | `_read_trustlist` reads the current list; `_merge_trustlists` merges certificates and replaces CRLs per issuer, preserving other trust entries. `GetRejectedList` is read and the count logged. Merge is the default; there is no UI replace/merge choice yet. | Done for read/merge; optional UI follow-up for explicit replace and displaying rejected certificates. Watch Mantis 9852/9853 (File-API deadlock/concurrent reads) when retrying reads. | [x] |
| TL-08 | P1 | Device trust-list capacity and element-size preflight | Implemented | Configurable `opc_gds_push_max_trustlist_entries` and `opc_gds_push_max_trustlist_element_size` (0 = no limit) preflight the merged list, counting unique DER objects across all four lists (shared certificates count once) and checking each element size. UI fields and migration 0004_tp_v1_0_2 added. | Done; tests cover shared entries, excess count and oversized elements. Aggregate size remains in TL-06. | [x] |

### 3.5 Security and certificate interoperability

| ID | Priority | Aspect | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| SEC-01 | P1 | Security policy negotiation | Implemented | `_select_security_policy` discovers the server endpoints and selects the strongest SignAndEncrypt policy: Aes256Sha256RsaPss, Aes128Sha256RsaOaep, Basic256Sha256, then legacy Basic256/Basic128Rsa15. Falls back to Basic256Sha256 if discovery fails. | Done; selection test covers AES preference and None endpoint exclusion. ECC policies remain out of scope. | [x] |
| SEC-02 | P2 | Server authentication and rotation | Partial | Pins the leaf certificate at truststore order 0 (`:483–527`); no chain validation against a CA truststore, no automatic rotation. Fail-closed is good. node-opcua #1770 found clients that sign the whole received chain; verifiers must try the leaf and then the chain, and both leaf-only and chained layouts need tests. | Keep pinning as an option; add CA-based validation and a controlled update path when the server certificate changes. Test leaf-only and chained certificate representations. | [ ] |
| SEC-03 | P1 | Trust bootstrap / TOFU (Annex G.2) | Implemented | Discovery captures the endpoint certificate (base64 in `server_info`), sets `server_certificate_available`, and exposes a download on the truststore-association page for import via the existing truststore modal. `GetRejectedList` is read/logged. Capabilities include `InApplicationSetup` with a warning. | Done; manual import is intentional. Vendor-specific provisioning modes are documented in §8.8. | [x] |
| SEC-04 | P3 | Client certificate profile (Part 6 §6.2.2) | Implemented | The domain credential profile has RSA key usages and `clientAuth`; runtime validation now also requires `content_commitment` (nonRepudiation), matching the profile. | Done; test certificate updated. | [x] |
| SEC-05 | P2 | Trustpoint RBAC for push operations | Partial | Audit entries now attribute manual operations to the initiating user. `MANAGE_DEVICES` can still replace a trust list and `ISSUE_CERTIFICATES` can replace a certificate; no four-eyes/approval or permission split. `ApplicationAdmin` grant mapping has no equivalent. | Remaining: approval workflow and finer permission split. | [ ] |
| SEC-06 | P2 | Domain credential renewal | Partial / risk | Old credential is revoked immediately. If a server trusts only the old client certificate rather than the CA, renewal locks Trustpoint out. | Document the CA-trust requirement; verify connectivity with the new credential before revoking the old one where possible. | [ ] |
| SEC-07 | — | Secrets at rest | Implemented | `EncryptedCharField` for the OPC password. | Keep. | [x] |
| SEC-08 | P2 | Issued certificate must satisfy the server's configured validation policy | Missing | The server validates the pushed certificate against its own `SecurityConfiguration` (minimum key size, SHA-1 rejection, unknown revocation). .NET issue #3931 shows a server rejecting a valid push because the validation path ignored its configured policy. Trustpoint cannot read that policy over OPC UA; the `opc_ua` profile defaults may not match the device. | Make key size/signature algorithm and revocation expectations configurable per device/profile; surface `BadCertificatePolicyCheckFailed` and related status codes with actionable messages; document that the device policy must be aligned out of band. | [ ] |
| SEC-09 | P0 | Validate and preserve the CSR/issued certificate identity (SAN, ApplicationUri, CN) | Implemented | `_validate_csr_identity` requires exactly one ApplicationUri SAN, at least one DNS/IP SAN, and a CN; it compares URI, CN and all current DNS/IP SANs with the server's current certificate before signing. Missing/changed identity values are rejected with actionable errors. | Done; tests cover valid identity, missing URI, changed CN and missing DNS SAN. Verify against real vendor CSRs. | [x] |

### 3.6 Testing and operational robustness

| ID | Priority | Aspect | Status | Evidence / current behavior | Required change | Done |
|---|---|---|---|---|---|---|
| OPS-01 | P1 | Unit tests cover real protocol strictness | Implemented | Tests now cover nonce length, group/type filtering, partial results, trust-list limits, SAN/CN identity, policy selection, apply-once and status-code hints. Stack interactions are still mocked; OPS-03 covers real-stack interop. | Done for unit-level strictness. | [x] |
| OPS-02 | P1 | Integration server behaves like a strict server | Implemented | The test server now rejects a missing/short nonce when key rollover is requested and rejects non-application certificate types. Group filtering is covered by discovery tests. | Done; negative tests added. | [x] |
| OPS-03 | P1 | Real-stack conformance | Missing | No test against open62541, a commercial GDS, or an AES/ECC-only server. | Add one real-stack interoperability test before claiming conformance. | [ ] |
| OPS-04 | P2 | Timeouts, retries, concurrency | Partial | Secure client uses fixed 10 s channel / 20 s session timeouts; periodic/manual tasks share a per-device cache lock; the combined workflow retries once on `Bad_TransactionPending`. Timeouts are not configurable and other transient failures are not retried. | Remaining: configurable timeouts and broader bounded retry/backoff. | [ ] |
| OPS-05 | P3 | Discovery documentation matches behavior | Implemented | Discovery now captures the endpoint certificate and exposes it for truststore import; the user guide documents policy negotiation, identity validation, trust-list merge and reconnect verification. | Done. | [x] |
| OPS-06 | P2 | Preserve OPC UA status codes and distinguish auth/trust/config failures | Implemented | `_status_error` keeps the symbolic name and hex code and adds actionable hints for access denied, insufficient security, untrusted/invalid/revocation-unknown certificates, hostname mismatch, signature failure, security-check failure and pending transactions. | Done; status-code test added. | [x] |

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
- [x] **WF-01** Ensure every certificate update is preceded by the required trust-list update (or combine them in one workflow).
- [x] **WF-09** Return structured per-group results; do not report partial success as success.
- [x] **SEC-09** Validate and preserve CSR/issued-certificate SANs, ApplicationUri and CN before deployment.
- [x] **OPS-01 / OPS-02** Extend the test server and unit tests to catch these regressions.

**Exit criteria:** the workflow succeeds against a strict test server that enforces a nonce, permits only `RsaSha256ApplicationCertificateType`, and exposes separate HTTPS/UserToken groups; a partial group failure is reported as failure.

### Milestone 2 — Interoperability and server capabilities

- [x] **SEC-01** Negotiate the security policy from the server's endpoints (AES + Basic256Sha256).
- [x] **METH-07** Read `MaxTrustListSize`, `SupportedPrivateKeyFormats`, `SupportsTransactions` (browse path), `InApplicationSetup`, `HasSecureElement`, `ServerCapabilities`.
- [x] **TL-06** Enforce the server `MaxTrustListSize`.
- [x] **METH-06** Read `MaxByteStringLength` and clamp the write chunk size.
- [x] **METH-12** Reuse the existing server key by default; make rollover opt-in.
- [x] **WF-06 / METH-04** Add the CM-generated-key fallback and private-key upload.
- [x] **WF-04** Stage trust list + certificate per workflow and apply once.
- [ ] **METH-09** Support `CancelChanges`/retry for `Bad_TransactionPending`.
- [x] **WF-10** Reconnect and verify after `ApplyChanges`; handle `BadServerHalted`.
- [x] **TL-07** Read the current trust list and rejected list; merge before pushing.
- [x] **TL-02** Correct trusted-vs-issuer list content.
- [x] **TL-08** Add configurable per-device trust-list capacity and element-size preflight.
- [ ] **SEC-08** Align issued certificates with the device's configured validation policy (key size, signature, revocation).

**Exit criteria:** certificate replacement works on a server that does not generate keys and on a server that only offers `Aes256Sha256RsaPss`; an existing server key can be kept; apply/restart is treated as success and the new certificate is verified after reconnect; a trust-list push preserves or explicitly replaces the existing list.

### Milestone 3 — Trust bootstrap, diagnostics and operations

- [x] **SEC-03** Capture the server certificate during discovery and offer it for truststore creation/import; fix or remove the dead `server_certificate_available` path.
- [ ] **METH-08** Add `GetCertificates` (explicit group, one row per type), `GetRejectedList`, `DeleteCertificate`, `CreateSelfSignedCertificate` and `TransactionDiagnostics`-based error reporting.
- [ ] **WF-02** Add an expiry/CRL-based "update required" decision. (Certificate expiry done; CRL-change detection remains.)
- [x] **METH-11** Add per-operation audit records and user attribution.
- [ ] **SEC-05** Add approval/finer permission split for certificate replacement.
- [x] **METH-13** Verify that key rollover actually changed the public key (or fail/warn).
- [x] **OPS-06** Preserve OPC UA status codes and separate auth/trust/configuration failures.
- [ ] **OPS-04** Add timeouts, retries and a per-device operation lock.
- [ ] **OPS-03** Run one real-stack interoperability test against a third independent stack (node-opcua).
- [ ] **GDS-07** Add LDS/GDS scan-and-stage discovery with `DiscoveryAdmin` approval (conditional).

**Exit criteria:** a fresh server can be onboarded from discovery without manual certificate export; failures show the server's transaction diagnosis and the rejected-certificate list.

### Milestone 4 — Optional standard features (only if required)

- [ ] **WF-05** `CreateSelfSignedCertificate` when no certificate exists.
- [ ] **METH-10** `ManagedApplications` / `ApplicationConfigurationType`.
- [ ] **WF-07** Create Endpoint / Update Configuration workflows.
- [x] **TL-05** Configurable CRL requirement (allow missing root CRL).
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
- [x] Server without key generation is manageable via uploaded private key.
- [ ] Oversize trust list is rejected before writing, with a clear message.
- [x] New certificate is usable after `ApplyChanges` (reconnect check).
- [x] `BadServerHalted` from `ApplyChanges` is treated as success and the session is closed.
- [x] An existing server key can be reused (`RegeneratePrivateKey=false`); a secure-element server is not forced to roll its key.
- [x] The current trust list is read and merged; rejected certificates are read and logged.
- [ ] `GetCertificates` is called with an explicit group and returns the current type per slot.
- [x] Discovery shows the server certificate and it can be imported into the truststore.
- [x] Trust-list entry count and per-element DER size are checked against the configured device limits before writing.
- [x] Aggregate serialized size is checked against `MaxTrustListSize` before writing.
- [x] No CA certificate is duplicated between trusted and issuer lists.
- [ ] Only one `ApplyChanges` is sent per transaction; repeated apply is tested against open62541.
- [x] The standalone certificate update applies the trust list first.
- [ ] `UpdateCertificate` succeeds with strict revocation checking when the trust list with CRLs was applied first.
- [ ] The issued certificate's key size/signature is accepted by the device's configured validation policy.
- [x] The issued server certificate has the ApplicationUri and DNS/IP SANs required by clients; the CN matches the vendor's rule.
- [x] A requested key rollover is verified by comparing public keys; an ignored rollover is detected.
- [x] Failure messages preserve the original OPC UA StatusCode and distinguish auth, trust, hostname and configuration errors.
- [x] Advertised endpoint URLs preserve host and resource path, and the connection address is configurable separately.
- [ ] Certificate inventory is read from the device (`GetCertificates`) rather than inferred from the last deployment.

## 7. File and line map (current code, 2026-11-27)

| Topic | Location |
|---|---|
| Device connection settings, renewal settings | `trustpoint/devices/models.py:203` |
| Scheduled renewal, trust list then certificate | `trustpoint/devices/tasks.py:23` |
| Standalone trust-list push | `trustpoint/devices/tasks.py:92` |
| Standalone certificate push | `trustpoint/devices/tasks.py:109` |
| Trust-list construction (CA chain + CRLs) | `trustpoint/request/gds_push/gds_push_service.py:263` |
| Secure client, hard-coded policy | `trustpoint/request/gds_push/gds_push_service.py:716` |
| Server certificate pinning | `trustpoint/request/gds_push/gds_push_service.py:629` |
| Endpoint discovery | `trustpoint/request/gds_push/gds_push_service.py:870` |
| Certificate group discovery | `trustpoint/request/gds_push/gds_push_service.py:1686` |
| Trust-list group discovery (application groups only) | `trustpoint/request/gds_push/gds_push_service.py:1176` |
| Trust-list write sequence | `trustpoint/request/gds_push/gds_push_service.py:1447` |
| TrustList read | `trustpoint/request/gds_push/gds_push_service.py:1313` |
| Trust-list limits preflight | `trustpoint/request/gds_push/gds_push_service.py:1272` |
| TrustList merge (certs/CRLs) | `trustpoint/request/gds_push/gds_push_service.py:1250` |
| Server capability read | `trustpoint/request/gds_push/gds_push_service.py:1372` |
| Status-code error rendering | `trustpoint/request/gds_push/gds_push_service.py:1210` |
| Reconnect verification | `trustpoint/request/gds_push/gds_push_service.py:1362` |
| Write chunk clamp | `trustpoint/request/gds_push/gds_push_service.py:1440` |
| Rejected list read | `trustpoint/request/gds_push/gds_push_service.py:1414` |
| Combined trust-list + certificate workflow | `trustpoint/request/gds_push/gds_push_service.py:1612` |
| Certificate renewal threshold | `trustpoint/request/gds_push/gds_push_service.py:1341` |
| Certificate update (CSR, nonce, type) | `trustpoint/request/gds_push/gds_push_service.py:1735` |
| CSR signing / certificate issuance | `trustpoint/request/gds_push/gds_push_service.py:1820` |
| Local truststore replacement | `trustpoint/request/gds_push/gds_push_service.py:1932` |
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

### 8.8 Additional sources from the second research pass

These sources were added after the first backlog review. Items marked **verified** were checked against the linked page on 2026-11-26; the others are leads and must be checked against the target firmware/version.

#### Traeger OPC UA SDK — GDS Push limitations (verified)

Source: <https://www.traeger.de/en/docs/development/opcua/security/gds-push> · [version history](https://www.traeger.de/en/docs/development/opcua/version-history)

Check the SDK version history before relying on a limitation: some of these were fixed in later releases, and the target firmware determines the actual behavior.

| Traeger behavior | Implication for Trustpoint |
|---|---|
| `CreateSigningRequest` always uses the existing key and **ignores `regeneratePrivateKey` and `nonce`**. | If rollover is requested, verify the resulting public key changed; otherwise the flag was silently ignored (METH-13). Keep the default “reuse existing key” behavior. |
| The new certificate's **CN must match the previous CN** (case-insensitive); other subject parts may differ. | Validate/preserve the CN during renewal; do not silently change it (SEC-09). |
| Only **PEM and PFX** private-key formats are accepted. | Use `SupportedPrivateKeyFormats` instead of assuming PKCS#8 (METH-04/METH-07). |
| With a single certificate type in a group, the certificate type may be omitted. | Passing an explicit type is safe; test servers that ignore/refuse optional arguments (METH-02). |
| `ApplyChanges` **disconnects all sessions** and switches to the new certificate. | Treat the disconnect as expected; reconnect and verify with the new identity (WF-10). |
| Do not pass issuer certificates with a **self-signed** certificate. | Build issuer lists according to the certificate being installed; relevant if `CreateSelfSignedCertificate` is added (WF-05). |
| GDS Push requires a `SecurityAdmin` ACL entry, `SignAndEncrypt`, and a non-anonymous session. | Keep the current secure-channel requirements; map `BadUserAccessDenied` to a clear permissions/ACL diagnostic (SEC-03/OPS-06). |

#### node-opcua — Erlangen IOP findings (verified)

Source: [node-opcua v2.187.3 release notes](https://github.com/node-opcua/node-opcua/releases/tag/v2.187.3)

| IOP finding | What Trustpoint should test / change |
|---|---|
| A push-renewed certificate came back from a real GDS **without any SAN**; hostname-verifying clients rejected it. | Require/preserve ApplicationUri and DNS/IP SANs when signing the server CSR (SEC-09). |
| A **CA-issued certificate chain** broke `ActivateSession` for a client that signed the whole chain. | Verify leaf-first and chain signatures; test leaf-only and chained certificate layouts (SEC-02). |
| A containerized server advertised an **unreachable container hostname**; `FindServers` returned the configured host instead of the client-used host. | Separate the connection address from advertised URLs; preserve the URL the client used (WF-08). |
| An advertised endpoint **lost its resource path** and URLs differing only by path were deduplicated. | Preserve the complete endpoint URL including path (WF-08). |
| Connection failures reached the application as “disconnected by third party” instead of the original StatusCode. | Preserve protocol status codes and symbolic names (OPS-06). |
| Certificate rotation disrupted existing sessions. | Reconnect and verify after `ApplyChanges`; handle `BadServerHalted`/normal disconnects (WF-10). |
| Part 12 TrustList deviations: `AddCertificate`/`RemoveCertificate` status codes, issuer-removal checks, chain completeness, CRL cleanup, `GetRejectedList` scope, and two self-signed certificates with the same key misread as issuers. | Add negative tests if Add/Remove are implemented; for Read/Write, check chain completeness and CRL cleanup; treat `GetRejectedList` as the default-group shortcut (METH-05/METH-08). |
| A server in `NoConfiguration` auto-trusted every client and never left setup state. | Detect `InApplicationSetup`; require an explicit exit from setup/TOFU state (SEC-03). |
| `ServerProfileArray` did not advertise the GlobalCertificateManagement profile after installing push management. | Use `ServerCapabilities`/profile data to verify push support during discovery (METH-07). |
| HSM/KMS-held keys and rotation without immediate session termination are supported. | Keep key reuse as default; do not assume the key is exportable (METH-12/METH-04). |

Related PRs worth reading: [#1756](https://github.com/node-opcua/node-opcua/pull/1756), [#1770](https://github.com/node-opcua/node-opcua/pull/1770), [#1771](https://github.com/node-opcua/node-opcua/pull/1771), [#1772](https://github.com/node-opcua/node-opcua/pull/1772), [#1775](https://github.com/node-opcua/node-opcua/pull/1775), [#1776](https://github.com/node-opcua/node-opcua/pull/1776), [#1779](https://github.com/node-opcua/node-opcua/pull/1779), [#1761](https://github.com/node-opcua/node-opcua/pull/1761), [#1762](https://github.com/node-opcua/node-opcua/pull/1762), [#1767](https://github.com/node-opcua/node-opcua/pull/1767).

#### Unified Automation — UaGDS troubleshooting

Source: <https://documentation.unified-automation.com/uagds/1.2.0/html/ts_push_error_sec.html>

- Initial push fails when the UaGDS is not yet trusted by the OPC UA server.
- The guide separates authentication/role problems from certificate-trust problems and points at the GDS status/configuration.
- Unified Automation's SDK documentation states there is no special provisioning mode: the server must explicitly trust the GDS before Push management is possible.
- Use this to improve onboarding diagnostics and the auth-vs-trust distinction (SEC-03/OPS-06).

#### Cloud Initiative Reference Solution — embedded push

Source: <https://github.com/OPCFoundation/Cloud-Initiative-Reference-Solution>

- Implements GDS Push embedded in a larger publisher application, with on-demand push and a `PushCertsBeforePublishing` toggle.
- Replaces the server certificate with one issued by the publisher's CA; requires a role allowed to update certificates (typically `SecurityAdmin`).
- Falls back to manual certificate exchange when push is unsupported or admin credentials are rejected.
- Useful as an architectural reference for Trustpoint: certificate management is a workflow inside a larger product, not a standalone GDS.
- Inspect its trust-list inspection/management UI and failure handling.

#### Fraunhofer IOSB — independent GDS

Source: <https://www.iosb.fraunhofer.de/en/projects-and-products/global-discovery-server-for-opc-ua.html>

- open62541-based GDS with Push and Pull management, automatic application registration and PKI integration.
- An open-source release is planned; the complete source was **not verified as publicly available**.
- Fraunhofer announced commercialization with o6 Automation in November 2026 and reports IOP interoperability testing.
- Use as a third independent implementation target when it becomes available; do not treat marketing/IOP claims as verified behavior.

#### Siemens — GDS Push and TIA Portal certificates

Sources:

- [Dynamic certificate management with SIMATIC S7-1500: OPC UA GDS Push](https://support.industry.siemens.com/cs/attachments/109799888/109799888_OPCUA_GDSPush_DOC_V1_1_en.pdf)
- [Using certificates with TIA Portal](https://support.industry.siemens.com/cs/attachments/109769068/109769068_UsingCertificatesWithTIAPortal_DOC_V2_1_en.pdf)

- S7-1500 uses a provisioning state and initial trust-list/certificate load before regular GDS Push updates.
- TIA Portal V19+/FW 3.1 can download certificates at runtime via hardware configuration; certificates must keep the same certificate ID.
- Siemens errata (as reported) note that certificates downloaded through hardware configuration may not be registered while runtime-managed certificates are still present. Treat the device's actual certificate inventory, not the last successful deployment, as authoritative (METH-08).
- Trust-list limits from TL-08 remain vendor/firmware-specific.

#### Research publications (not reviewed)

Fraunhofer IOSB's secure OPC UA research references:

| Year | Publication | Relevance |
|---|---|---|
| 2022 | Secure Provisioning of OPC UA Applications Using the Asset Administration Shell | Automated commissioning |
| 2021 | On the Security of IIoT Deployments: An Investigation of Secure Provisioning Solutions for OPC UA | Security weaknesses, initial trust |
| 2020 | Portable Trust Anchor for OPC UA Using Auto-Configuration | Trust anchors, automated configuration |
| 2022 | IUNO2PAKT — Tools for securing automation and communication technologies | Practical industrial security |

These inform onboarding architecture, not individual method conformance. They were not downloaded or reviewed for this document.

#### Consolidated repositories for local analysis

| Repository | Language | Purpose |
|---|---|---|
| [UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard) | C# | Primary stack reference |
| [UA-.NETStandard-Samples](https://github.com/OPCFoundation/UA-.NETStandard-Samples) | C# | GDS client workflows |
| [UA-Nodeset](https://github.com/OPCFoundation/UA-Nodeset) | XML | Information model and identifiers |
| [open62541](https://github.com/open62541/open62541) | C | Independent Push receiver |
| [node-opcua](https://github.com/node-opcua/node-opcua) | TypeScript | Independent implementation and IOP findings |
| [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) | Python | Python stack behavior/limitations |
| [Cloud-Initiative-Reference-Solution](https://github.com/OPCFoundation/Cloud-Initiative-Reference-Solution) | C# | Embedded certificate-management workflows |

When reviewing these, inspect the **git history, closed issues, pull requests and regression tests**, not only the current source. The regression tests show which edge cases the maintainers had to fix in the field.

### 8.9 Proposed engineering backlog from the sources

The following is the consolidated backlog suggested by the vendor/IOP sources. It is an investigation list, not a claim that every item is a confirmed Trustpoint defect. Status refers to this document.

| Priority | Topic | Mapped items | Status |
|---|---|---|---|
| P0 | Secure initial trust establishment | SEC-03, GDS-07 | Open |
| P0 | CSR and issued-certificate validation | SEC-09 | Open |
| P0 | ApplicationUri and SAN preservation | SEC-09 | Open |
| P0 | Transaction lifecycle and failure recovery | WF-04, WF-10, METH-09 | Partial |
| P0 | Certificate-chain construction and validation | TL-02 (done), SEC-02 | Partial |
| P0 | TrustList merging and preservation | TL-07, TL-04 | Done |
| P0 | Certificate activation verification after `ApplyChanges` | WF-10 | Partial |
| P1 | Dynamic certificate-group/type discovery | WF-03, METH-02 | Done |
| P1 | Independent certificate/trust-list/CRL scheduling | WF-02 | Open |
| P1 | Idempotent operations and retry handling | OPS-04, METH-09 | Open |
| P1 | Server-side vs externally generated keys | METH-04, WF-06, METH-12 | Done |
| P1 | Concurrent certificate-management operations | OPS-04 | Open |
| P1 | Vendor-specific resource limitations | TL-08, TL-06 | Done |
| P1 | Support for older Part 12 implementations | — | Not yet specified; add if older servers are in scope |
| P2 | `CertificateExpirationAlarm` integration | WF-02 | Open |
| P2 | `TransactionDiagnostics` integration | METH-08 | Open |
| P2 | `ApplicationConfiguration` proxy support | METH-10 | Open |
| P2 | Part 21 automated provisioning | — | Out of scope for certificate push |

**Reading rule:** sources explain failures and vendor behavior; they do not override the normative specification. Keep vendor limits and workarounds in configuration, not in the generic GDS protocol layer.
