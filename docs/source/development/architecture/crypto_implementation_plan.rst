====================================
Crypto Redesign Implementation Plan
====================================

Overview
--------

This document defines the phased implementation plan for the crypto backend redesign described in
:doc:`./crypto_redesign`.

The redesign should be executed as a controlled replacement, not as a series of incremental patches to the current
crypto layer.


Implementation Principles
-------------------------

- Do not spread new PKCS#11 calls across the existing codebase.
- Introduce the new ``trustpoint.crypto`` package first.
- Migrate one full vertical slice at a time.
- Keep the old and new crypto paths side-by-side only for as long as necessary.
- Delete old code aggressively once a vertical slice is proven.
- Treat documentation, contract tests, and observability as part of the implementation, not follow-up work.


Scope Decisions for This Plan
-----------------------------

- Trustpoint ingress TLS remains out of scope for this redesign.
- Persistent Trustpoint-managed keys move to PKCS#11-backed custody.
- One-time downloadable credential bundles remain supported through the backend.
- The current DB-stored private key model is a transition artifact, not a target.


Milestone Summary
-----------------

.. list-table::
   :header-rows: 1
   :widths: 15 40 45

   * - Phase
     - Goal
     - Exit Criteria
   * - 0
     - Freeze target design and choose replacement boundaries
     - Docs approved; old implementation marked legacy
   * - 1
     - Create new crypto package and contracts
     - Stable ``CryptoBackend`` API and domain model
   * - 2
     - Build PKCS#11 backend core
     - Capability probe, session pool, key lookup, sign
   * - 3
     - Prove first vertical slice
     - One local issuing CA key in PKCS#11 can issue one certificate
   * - 4
     - Migrate persistent server-held signing flows
     - signer, CRL, CMP/EST, CA issuance use new backend
   * - 5
     - Migrate one-time export/download flows
     - export bundles work through backend without generic stored private keys
   * - 6
     - Replace secret protection
     - encrypted-field dependency on ``PKCS11Token`` removed
   * - 7
     - Remove legacy crypto implementation
     - old PKCS#11 utility/model paths deleted
   * - 8
     - Hardening and rollout
     - restore/bootstrap validated; docs and tests complete


Phase 0: Freeze the Target
--------------------------

Deliverables:

- architecture document approved
- implementation plan approved
- explicit statement that the current crypto layer is legacy
- decision on initial provider-profile model
- decision on managed-key vs export-bundle boundaries

Required repo cleanup at this stage:

- add documentation links to the redesign docs
- mark current crypto modules as legacy in code comments or internal notes if needed

Exit criteria:

- no open design ambiguity around:

  - single backend boundary
  - provider profile configuration
  - persistent managed key custody
  - export bundle lifecycle
  - restore expectations


Phase 1: Create the New Package Skeleton
----------------------------------------

Create the new package structure:

.. code-block:: text

   trustpoint/crypto/
     domain/
     application/
     adapters/pkcs11/
     django/

Work items:

- define domain types such as:

  - ``ManagedKeyRef``
  - ``CredentialRef``
  - ``ExportBundleRef``
  - ``KeySpec``
  - ``KeyPolicy``
  - ``CertificateSpec``
  - ``SignRequest``
  - normalized error classes

- define the application-facing ``CryptoBackend`` interface
- define repository interfaces for managed keys, credentials, bundles, and provider profiles

Exit criteria:

- codebase has a stable contract to build against
- no application code depends on PKCS#11 types to use the new package


Phase 2: Build the PKCS#11 Core
-------------------------------

Implement the new PKCS#11 adapter core inside ``trustpoint.crypto.adapters.pkcs11``.

Work items:

- provider profile loader
- PKCS#11 library loader
- capability probe
- session pool
- object locator using stable object identity
- mechanism selection policy
- centralized error mapping

Supported first operations:

- provider verification
- managed key generation
- managed key lookup
- public key retrieval
- signing

Do not migrate application code yet.

Exit criteria:

- backend contract tests pass against SoftHSM
- session reuse works
- provider errors are normalized
- no code from ``management.pkcs11_util`` is reused directly


Phase 3: First Vertical Slice
-----------------------------

Implement the smallest useful end-to-end path:

- create or bind a local issuing CA key as a managed PKCS#11 key
- issue one end-entity certificate
- persist the certificate and managed key reference
- verify the certificate can be used by downstream application flow

Recommended first migration target:

- local issuing CA certificate issuance

Reason:

- it exercises key lookup, signing, certificate issuance, and credential persistence
- it avoids the download/export complexity of device bundles
- it proves the architecture with real application value

Legacy modules to bypass during this phase:

- ``devices.issuer`` signing internals
- direct ``CredentialModel.get_private_key_serializer().as_crypto()`` calls

Exit criteria:

- one production-relevant business path runs solely through the new backend
- the old PKCS#11 utility layer is not used for that path


Phase 4: Migrate Persistent Server-Held Flows
---------------------------------------------

Move the following flows to the new backend:

- local CA issuance
- signer operations
- CRL generation
- CMP response protection signing
- EST CSR signing where Trustpoint signs with persistent server-held keys

Main files expected to be rewritten or heavily simplified:

- ``trustpoint/devices/issuer.py``
- ``trustpoint/request/operation_processor/issue_cert.py``
- ``trustpoint/request/operation_processor/sign.py``
- ``trustpoint/request/operation_processor/csr_sign.py``
- ``trustpoint/pki/util/crl.py``
- ``trustpoint/request/message_builder/cmp.py``
- ``trustpoint/request/message_responder/cmp.py``

Exit criteria:

- no persistent server-held signing flow depends on raw key object branching in business code
- application code calls backend operations instead of crypto primitives directly


Phase 5: Migrate Export / Download Flows
----------------------------------------

Replace the generic stored-credential export model with explicit export-bundle flows.

Work items:

- define export bundle request and response types
- add bundle metadata persistence
- add TTL / one-time-use / audit handling
- rewrite device download endpoints to use bundle generation instead of reconstructing private keys from stored credentials

Primary file to replace conceptually:

- ``trustpoint/devices/views/download.py``

Supporting cleanup:

- stop treating generic credential records as always-exportable
- stop creating key-only credentials via direct model creation in:

  - ``devices.views.owner_credentials``
  - ``pki.views.owner_credentials_api``

Exit criteria:

- device download flows work through backend-owned bundle generation
- exported private material is not stored as a reusable managed server key


Phase 6: Replace Secret Protection
----------------------------------

Remove the encrypted-field dependency on the current PKCS#11 token singleton.

Work items:

- introduce ``SecretProtectionService`` behind ``CryptoBackend``
- replace ``EncryptedCharField`` and ``EncryptedTextField`` runtime dependency on ``PKCS11Token.objects.first()``
- remove DEK cache/state handling from startup logic

Primary files to replace:

- ``trustpoint/util/encrypted_fields.py``
- large parts of ``trustpoint/management/models/pkcs11.py``
- HSM-dependent startup/restore branches in:

  - ``trustpoint/management/util/startup_context.py``
  - ``trustpoint/management/util/startup_strategies.py``
  - ``trustpoint/setup_wizard/views.py``

Exit criteria:

- secret protection no longer depends on crypto state hidden in Django model fields
- startup no longer revolves around DEK-cache recovery


Phase 7: Remove Legacy Crypto Implementation
--------------------------------------------

Delete the old implementation once all migrated paths are green.

Delete or replace:

- ``trustpoint/management/pkcs11_util.py``
- ``trustpoint/management/models/pkcs11.py``
- PKCS#11 branches in ``trustpoint/pki/models/credential.py``
- duplicated storage-policy helpers in:

  - ``trustpoint/pki/forms/issuing_cas.py``
  - ``trustpoint/signer/forms.py``
  - ``trustpoint/pki/management/commands/add_domains_and_devices.py``

- direct long-lived private key storage in ``CredentialModel.private_key`` for managed credentials

Refactor targets:

- replace ``CredentialModel`` with slimmer credential/certificate records
- replace global storage toggles with provider profile + key policy

Exit criteria:

- no runtime code imports the old PKCS#11 modules
- no business flow depends on ``CredentialModel`` as a crypto engine


Phase 8: Hardening, Restore, and Rollout
----------------------------------------

Work items:

- provider profile administration
- bootstrap workflow
- restore verification workflow
- degraded-mode behavior if provider unavailable
- observability and metrics
- final documentation updates

Required scenarios:

- SoftHSM dev bootstrap from empty environment
- restore into a system with the same PKCS#11 token state
- restore into a system where managed keys are missing
- provider library path change
- token replacement / mismatch detection

Exit criteria:

- restore can detect and report missing or mismatched managed keys
- provider health is visible
- rollout guidance exists for dev, demo, and production environments


Testing Strategy
----------------

Test categories:

- unit tests for domain and application services
- backend contract tests
- SoftHSM integration tests
- vertical-slice integration tests through actual Trustpoint flows
- restore/bootstrap tests
- export bundle tests

Recommended contract-test matrix:

- key generation
- key lookup
- public key retrieval
- signing
- certificate issuance
- CRL issuance
- export bundle generation
- provider unavailability
- session exhaustion / relogin


Recommended Order of File-Level Migration
-----------------------------------------

1. Introduce new ``trustpoint.crypto`` package
2. Migrate one CA issuance path
3. Migrate signer and CRL flows
4. Migrate CMP/EST signing flows
5. Migrate export/download flows
6. Migrate secret protection
7. Delete legacy PKCS#11 implementation


De-Risking Guidelines
---------------------

- Keep old and new paths in parallel only during active migration of a specific vertical slice.
- Do not attempt to rewrite every flow at once.
- Prefer replacing duplicated signing logic with backend calls before removing legacy persistence models.
- Use SoftHSM for CI and reproducible local testing from the first PKCS#11 backend milestone onward.
- Add metrics and logging before rollout so provider issues are visible immediately.


Definition of Done
------------------

The crypto redesign is complete when:

- Trustpoint business code uses exactly one crypto backend boundary
- persistent Trustpoint-managed private keys are no longer stored in the DB
- PKCS#11 calls are isolated to the crypto adapter layer
- one-time downloadable credential bundles still work
- restore and bootstrap are explicit, tested workflows
- the legacy PKCS#11 and credential crypto implementation has been removed

