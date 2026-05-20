===========================
Crypto Backend Redesign
===========================

Overview
--------

This document defines the **target architecture** for the Trustpoint cryptography redesign.

It is intentionally opinionated and does **not** preserve the current credential-centric crypto design.
The goal is to replace the current mixed software/PKCS#11 implementation with a maintainable architecture
that gives Trustpoint **one application-facing crypto backend** while keeping PKCS#11 concerns fully contained.

This document is the target-state design for future work. It does **not** describe the current implementation.
For the current credential architecture, see :doc:`./credentials`.


Status
------

This is a design-and-implementation blueprint for the planned redesign.


Goals
-----

- Trustpoint application code uses **one** crypto backend interface.
- PKCS#11 is the custody and provider model for persistent server-held keys.
- Trustpoint business code does not know whether the provider is SoftHSM, a simulator, or a hardware HSM.
- Low-level PKCS#11 concerns stay in one adapter layer.
- Long-lived private keys are not stored in the Trustpoint database.
- One-time downloadable credentials remain supported through backend-controlled export flows.
- Vendor-specific PKCS#11 library differences are handled centrally.
- Bootstrap, restore, concurrency, error mapping, and observability are part of the design rather than bolt-ons.


Non-Goals
---------

- Redesigning Trustpoint ingress TLS termination.

  That remains out of scope for this crypto redesign.

- Preserving the current ``CredentialModel`` crypto abstraction.
- Preserving the current KEK/DEK/backup-password design around ``PKCS11Token``.
- Allowing PKCS#11 concepts to appear in forms, views, request processors, or business services.


Repository Findings That Drive This Design
------------------------------------------

The redesign is grounded in the current repository structure and pain points:

- ``pki.models.credential.CredentialModel`` currently mixes certificate persistence, software key storage,
  PKCS#11 key references, HSM import/generation, and runtime key reconstruction.
- ``management.pkcs11_util`` makes PKCS#11 keys imitate ``cryptography`` private key interfaces, which leaks
  provider and mechanism details into the rest of the application.
- ``management.models.pkcs11.PKCS11Token`` currently mixes token metadata, PIN retrieval, session handling,
  KEK/DEK management, backup-password recovery, and runtime crypto state.
- Request and business flows sign directly with raw key objects in modules such as:

  - ``devices.issuer``
  - ``request.operation_processor.issue_cert``
  - ``request.operation_processor.sign``
  - ``request.operation_processor.csr_sign``
  - ``pki.util.crl``
  - ``request.message_builder.cmp``
  - ``request.message_responder.cmp``

- Export/download flows in ``devices.views.download`` assume a generic stored credential can always be turned
  back into PKCS#12 or PEM.
- Global storage toggles in ``management.models.key_storage.KeyStorageConfig`` force application code to think
  in terms of software-vs-HSM storage instead of use-case policy.


Core Design Decision
--------------------

Trustpoint will expose **one application-facing backend**:

- ``CryptoBackend`` is the only crypto boundary used by application code.
- Trustpoint does not branch on software vs HSM vs SoftHSM.
- The implementation family behind that backend is PKCS#11-based.
- Development and demo profiles use SoftHSM or an HSM simulator through the same backend contract.

The application sees **one backend**.
Provider differences are handled by **backend configuration and capability probing**, not by application branching.


Use-Case Model
--------------

The design separates crypto use cases by lifecycle, not by provider type.

Managed Keys
^^^^^^^^^^^^

Managed keys are long-lived keys that Trustpoint keeps using after creation.

Examples:

- local root CA keys
- local issuing CA keys
- signer keys
- CMP/EST response signing keys
- other persistent server-held private keys

Properties:

- stored and used through PKCS#11
- referenced by stable backend identifiers
- non-exportable by default
- restored by rebinding to the provider and verifying that the key still exists


Export Bundles
^^^^^^^^^^^^^^

Export bundles are one-time delivery artifacts produced for downstream devices.

Examples:

- downloadable PKCS#12 packages
- password-protected PEM ZIP/TAR bundles
- temporary server-generated credentials that are shipped once and then used outside Trustpoint

Properties:

- created through the same ``CryptoBackend``
- not treated as Trustpoint-managed long-lived keys
- may use provider-native exportable flows or backend-owned transient generation, depending on provider capabilities
- persisted only as metadata and audit information, not as reusable long-lived private keys in the DB

This separation is critical. It avoids forcing one-time delivery credentials into the same lifecycle as
persistent CA and signer keys.


Top-Level Architecture
----------------------

.. uml::

   @startuml
   !theme plain
   skinparam componentStyle rectangle

   package "Trustpoint Application" {
     [Devices / PKI / Request Flows] as App
     [CryptoBackend] as Backend
   }

   package "Crypto Application Layer" {
     [Key Manager]
     [Certificate Service]
     [Signing Service]
     [Bundle Export Service]
     [Secret Protection Service]
   }

   package "Provider Layer" {
     [Pkcs11Backend]
     [Provider Profile]
     [Capability Probe]
   }

   package "PKCS#11 Adapter Layer" {
     [Session Pool]
     [Object Locator]
     [Mechanism Policy]
     [Error Mapper]
   }

   package "Persistence" {
     [Managed Key Records]
     [Credential Records]
     [Export Bundle Records]
     [Provider Profile Records]
   }

   App --> Backend
   Backend --> [Key Manager]
   Backend --> [Certificate Service]
   Backend --> [Signing Service]
   Backend --> [Bundle Export Service]
   Backend --> [Secret Protection Service]

   [Key Manager] --> [Pkcs11Backend]
   [Certificate Service] --> [Pkcs11Backend]
   [Signing Service] --> [Pkcs11Backend]
   [Bundle Export Service] --> [Pkcs11Backend]
   [Secret Protection Service] --> [Pkcs11Backend]

   [Pkcs11Backend] --> [Provider Profile]
   [Pkcs11Backend] --> [Capability Probe]
   [Pkcs11Backend] --> [Session Pool]
   [Pkcs11Backend] --> [Object Locator]
   [Pkcs11Backend] --> [Mechanism Policy]
   [Pkcs11Backend] --> [Error Mapper]

   [Key Manager] --> [Managed Key Records]
   [Certificate Service] --> [Credential Records]
   [Bundle Export Service] --> [Export Bundle Records]
   [Pkcs11Backend] --> [Provider Profile Records]
   @enduml


Layer Responsibilities
----------------------

Application / Business Layer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Application code may:

- request a key by alias or role
- ask for signing, certificate issuance, verification, or export bundle generation
- receive stable domain-level objects such as ``ManagedKeyRef`` or ``ExportBundleRef``

Application code may **not**:

- import ``pkcs11``
- open sessions
- choose mechanisms
- track object handles
- load PINs
- branch on provider type


Crypto Application Layer
^^^^^^^^^^^^^^^^^^^^^^^^

This layer exposes the stable backend contract and orchestrates use cases:

- ``KeyManager``: generate, import, lookup, public-key retrieval, existence checks
- ``CertificateService``: certificate issuance, CSR creation, CRL issuance
- ``SigningService``: sign, verify, hash, MAC
- ``BundleExportService``: one-time exportable credential bundles
- ``SecretProtectionService``: application secret protection for values such as onboarding secrets


Provider Layer
^^^^^^^^^^^^^^

The provider layer contains the implementation family used by Trustpoint:

- ``Pkcs11Backend``
- provider profile loading
- capability probing
- vendor-specific overrides

Trustpoint may support multiple PKCS#11 provider profiles over time, but the application-facing contract remains one.


PKCS#11 Adapter Layer
^^^^^^^^^^^^^^^^^^^^^

This is the only place that knows about:

- library loading
- slot/token selection
- login and relogin
- session pooling
- object lookup by ``CKA_ID`` and label
- mechanism selection
- provider-specific quirks
- error normalization


Target Package Structure
------------------------

The target Python package structure should look roughly like this:

.. code-block:: text

   trustpoint/crypto/
     domain/
       algorithms.py
       errors.py
       policies.py
       refs.py
       specs.py
     application/
       backend.py
       keys.py
       certificates.py
       signing.py
       bundles.py
       secrets.py
     adapters/
       pkcs11/
         backend.py
         config.py
         capability_probe.py
         session_pool.py
         locator.py
         mechanisms.py
         error_map.py
         vendor_overrides.py
     django/
       models.py
       repositories.py


Backend Contract
----------------

The application-facing backend should be small and operation-oriented.

.. code-block:: python

   class CryptoBackend(Protocol):
       def ensure_managed_key(self, alias: str, spec: KeySpec, policy: KeyPolicy) -> ManagedKeyRef: ...
       def import_managed_key(self, alias: str, pkcs8_pem: bytes, policy: KeyPolicy) -> ManagedKeyRef: ...
       def get_managed_key(self, alias: str) -> ManagedKeyRef: ...
       def public_key(self, key: ManagedKeyRef) -> PublicKey: ...
       def sign(self, key: ManagedKeyRef, data: bytes, request: SignRequest) -> bytes: ...
       def issue_certificate(self, issuer: CredentialRef, subject: PublicKey | ManagedKeyRef, spec: CertificateSpec) -> IssuedCertificate: ...
       def create_csr(self, key: ManagedKeyRef, spec: CsrSpec) -> CertificateSigningRequest: ...
       def issue_crl(self, issuer: CredentialRef, spec: CrlSpec) -> CertificateRevocationList: ...
       def create_export_bundle(self, request: ExportBundleRequest) -> ExportBundleRef: ...
       def read_export_bundle(self, bundle: ExportBundleRef) -> ExportBundlePayload: ...
       def protect_secret(self, plaintext: bytes, purpose: SecretPurpose) -> ProtectedSecret: ...
       def unprotect_secret(self, protected: ProtectedSecret) -> bytes: ...


Key Referencing Strategy
------------------------

The redesign must stop relying on label-only PKCS#11 references.

Managed keys should be referenced by:

- internal Trustpoint UUID
- stable application alias
- provider profile id
- PKCS#11 object identity based primarily on ``CKA_ID``
- optional human-readable label
- stored public-key fingerprint
- algorithm and capability metadata

Object handles are **never** persisted.
They are session-local runtime details inside the PKCS#11 adapter.


Provider Profiles
-----------------

The current ``KeyStorageConfig`` and ``PKCS11Token`` models should be replaced by an explicit provider profile model.

Provider profile fields should include:

- profile name
- PKCS#11 module library path
- token selector:

  - serial number preferred
  - label optional
  - slot index only as fallback

- authentication source:

  - environment variable
  - file path / secret file
  - external secret provider hook

- optional mechanism overrides
- optional vendor name / driver family
- active flag
- last capability probe result

This makes different HSM vendor libraries a configuration problem instead of an architectural fork.


Capability Probing
------------------

At startup and whenever a provider profile changes, the backend should probe and cache capabilities such as:

- supported key generation mechanisms
- supported sign mechanisms
- supported curves
- supported RSA sizes
- wrap/unwrap support
- object copy/import constraints
- login/session quirks

The rest of the backend uses a mechanism policy that selects from supported options instead of hardcoding SoftHSM assumptions.


Managed Key Flow
----------------

.. uml::

   @startuml
   !theme plain

   actor "Application Flow" as App
   participant "CryptoBackend" as Backend
   participant "Key Manager" as Keys
   participant "Pkcs11Backend" as P11
   participant "Session Pool" as Pool
   participant "Object Locator" as Locator
   database "Managed Key Records" as Repo

   App -> Backend : ensure_managed_key(alias, spec, policy)
   Backend -> Keys : ensure_managed_key(...)
   Keys -> Repo : lookup(alias)
   Repo --> Keys : missing
   Keys -> P11 : generate_key(alias, spec, policy)
   P11 -> Pool : borrow session
   P11 -> Locator : resolve/create objects
   Locator --> P11 : key id + metadata
   P11 --> Keys : provider key metadata
   Keys -> Repo : save managed key record
   Repo --> Keys : ManagedKeyRef
   Keys --> Backend : ManagedKeyRef
   Backend --> App : ManagedKeyRef
   @enduml


Export Bundle Flow
------------------

Export bundles are intentionally separate from managed keys.

.. uml::

   @startuml
   !theme plain

   actor "Application Flow" as App
   participant "CryptoBackend" as Backend
   participant "Bundle Export Service" as Bundles
   participant "Pkcs11Backend" as P11
   database "Export Bundle Records" as Repo

   App -> Backend : create_export_bundle(request)
   Backend -> Bundles : create_export_bundle(request)
   Bundles -> P11 : generate delivery artifact
   P11 --> Bundles : PKCS#12/PEM payload + metadata
   Bundles -> Repo : save metadata only
   Repo --> Bundles : ExportBundleRef
   Bundles --> Backend : ExportBundleRef
   Backend --> App : ExportBundleRef
   @enduml

The backend may implement this using:

- exportable PKCS#11 objects where the provider supports it, or
- backend-owned transient key generation for delivery-only credentials

The application does not care which path was used.


Sessions, Login, and Concurrency
--------------------------------

PKCS#11 session management must be centralized.

Rules:

- load each PKCS#11 library once per process
- keep one provider object per active profile
- use a bounded session pool per provider profile
- login when a session is created or borrowed, depending on provider behavior
- never share raw session objects with business code
- always reacquire object handles per session
- treat handles as ephemeral

Expected session-pool behavior:

- borrow/release for each operation
- retry once on invalid-session or provider-reset errors
- surface clear degraded-mode errors if the provider is unavailable


Certificates and Credential Records
-----------------------------------

Certificates and chains remain database records.
Private key custody does not.

The future replacement for the current credential records should store:

- leaf certificate id
- chain certificate ids
- managed key reference for persistent keys, if applicable
- export bundle reference for delivery-only credentials, if applicable
- role / usage classification
- certificate status metadata

The DB stores certificate-related state and key references.
It does not store reusable private key material for managed keys.


Secrets Protection
------------------

The current encrypted-field design should be replaced by a dedicated secret protection service.

It must not:

- call ``PKCS11Token.objects.first()`` from a model field
- depend on application startup cache state
- mix field serialization with provider login/session logic

It should:

- use the same ``CryptoBackend`` boundary
- have a dedicated purpose model
- rotate or rebind cleanly during restore
- keep secret protection independent from credential issuance flows


Bootstrap and Restore
---------------------

Bootstrap and restore must be explicit backend workflows.

Bootstrap responsibilities:

- configure active provider profile
- validate module path and token selection
- authenticate successfully
- probe capabilities
- persist provider profile metadata
- create managed keys lazily or explicitly, depending on feature policy

Restore responsibilities:

- restore DB state
- rebind to the configured provider profile
- verify that referenced managed keys still exist
- verify that stored public-key fingerprints still match
- mark missing keys as degraded state instead of failing silently

.. uml::

   @startuml
   !theme plain

   actor Operator
   participant "Restore Workflow" as Restore
   participant "CryptoBackend" as Backend
   participant "Pkcs11Backend" as P11
   database "Managed Key Records" as Repo

   Operator -> Restore : restore DB + provider profile
   Restore -> Backend : verify_provider()
   Backend -> P11 : load profile and probe
   P11 --> Backend : provider OK
   Restore -> Repo : list managed key refs
   loop for each managed key
     Restore -> Backend : verify_key(ref)
     Backend -> P11 : locate by provider id
     P11 --> Backend : public key
     Backend --> Restore : matches / missing / mismatch
   end
   Restore --> Operator : restore report
   @enduml


Error Handling
--------------

The backend must expose a small, domain-oriented error model.

Recommended error categories:

- ``ProviderUnavailableError``
- ``ProviderAuthError``
- ``ManagedKeyNotFoundError``
- ``MechanismUnsupportedError``
- ``KeyPolicyViolationError``
- ``ExportNotAllowedError``
- ``BundleExpiredError``
- ``SecretProtectionError``
- ``TransientProviderError``

All low-level PKCS#11 exceptions are mapped centrally.


Observability
-------------

Every backend operation should emit:

- operation name
- provider profile id
- algorithm
- mechanism chosen
- latency
- success/failure
- normalized error type

Logs must never contain:

- PIN values
- plaintext secrets
- private key material
- full sensitive payloads


What Should Be Removed
----------------------

The redesign explicitly replaces the following current architectural elements:

- ``pki.models.credential.CredentialModel`` as the main crypto abstraction
- ``management.models.pkcs11.PKCS11Token``
- ``management.models.key_storage.KeyStorageConfig`` as a global software-vs-HSM switch
- ``management.pkcs11_util`` as a public crypto layer
- PKCS#11 usage in forms, views, request processors, and Django models
- DB storage of long-lived managed private keys


Out-of-Scope but Related
------------------------

- ingress TLS termination integration with Nginx/OpenSSL
- UI redesign for crypto/provider administration
- multi-tenant HSM partitioning


Summary
-------

The target architecture is:

- one application-facing crypto backend
- PKCS#11-backed persistent key custody
- SoftHSM/simulator for dev and demo
- explicit provider profiles for vendor library support
- managed keys separated from one-time export bundles
- no PKCS#11 leakage into Trustpoint business code
- no DB-stored long-lived private keys

