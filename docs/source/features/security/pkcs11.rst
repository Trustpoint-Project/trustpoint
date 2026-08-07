HSM Integration in Trustpoint
=============================

Overview
--------

Trustpoint integrates with Hardware Security Modules (HSMs) through the PKCS#11 standard to provide secure key storage and cryptographic operations. 

Supported HSM Types
-------------------

SoftHSM
~~~~~~~

**Primary Support**: SoftHSM2 is the default.

- **Library Path**: ``/usr/lib/libsofthsm2.so`` in the Trustpoint container, which points to the packaged SoftHSM module.
- **Use Case**: Development and CI validation. Use a production-grade HSM for production deployments.

The local ``tp_wizard.sh`` SoftHSM setup mounts the SoftHSM token directory into the Trustpoint container and uses the SoftHSM PKCS#11 module directly. This is intentional: the direct module exposes the AES key-wrap and AES-CBC mechanisms required for HSM-backed application-secret protection.

Physical HSM
~~~~~~~~~~~~

**Standards-Based Support**: Physical HSM devices are supported through their PKCS#11 module when they expose the mechanisms Trustpoint requires.

- **Status**: Provider-specific configuration files are treated as opaque input and passed to the uploaded module through an operator-provided environment variable.
- **Use Case**: High-security production deployments

Supported Cryptographic Operations
-----------------------------------

RSA Key Operations
~~~~~~~~~~~~~~~~~~

**Key Generation**:
- RSA key pair generation within HSM
- Supported key sizes: 2048, 3072, 4096 bits
- Keys marked as non-extractable for security

**Signing Operations**:
- PKCS#1 v1.5 padding support
- Supported hash algorithms: SHA-256, SHA-384, SHA-512, SHA-224
- Pre-hashed data signing capability

**Public Key Handling**:
- Public key extraction for certificate generation and key verification

EC (Elliptic Curve) Key Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Key Generation**:
- EC key pair generation within HSM
- Supported curves: P-256, P-384, P-521
- Curve parameter validation

**Signing Operations**:
- ECDSA signature generation
- Supported hash algorithms: SHA-256, SHA-384, SHA-512
- Data is hashed before signing (pre-hashed data not supported)
- ASN.1 DER encoded signatures
- Mechanism mapping: ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512

**Key Management**:
- Named curve support via OID mapping
- Public key point extraction
- Keys marked as non-extractable (EXTRACTABLE=False)
- EC is used for signing, not encryption/decryption

AES Key Operations
~~~~~~~~~~~~~~~~~~

**Symmetric Key Generation**:
- AES key generation in HSM
- Supported key lengths: 128, 192, 256 bits
- Primary use for KEK storage

**Application Secret Protection**:
- HSM-backed application-secret protection is the default for PKCS#11 fresh installs.
- Trustpoint stores database secrets encrypted with an application-secret DEK.
- When PKCS#11 app-secret protection is enabled, that DEK is protected by a non-exportable AES KEK on the token.

**Encryption/Decryption Operations**:
- DEK protection with standard PKCS#11 AES key wrap/unwrap mechanisms when available
- Fallback DEK protection with AES-CBC-PAD or AES-CBC C_Encrypt/C_Decrypt

General HSM Operations
~~~~~~~~~~~~~~~~~~~~~~

**Token Management**:
- Token initialization and configuration
- Slot enumeration and selection
- Token authentication with PIN

**Session Management**:
- Session creation and termination
- User authentication
- Session state management

**Object Management**:
- Key object creation and destruction
- Object attribute management
- Label-based key retrieval

**Random Number Generation**:
- Uses OS-level randomness (``os.urandom()``) for DEK generation
- SoftHSM provides cryptographically secure random generation
- Used for nonce/IV generation in encryption operations

**Digest Operations**:
- Hardware-accelerated hashing via HSM
- Supported algorithms: SHA-224, SHA-256, SHA-384, SHA-512
- Mechanism mapping: SHA224, SHA256, SHA384, SHA512

Architecture
------------

.. uml::

   @startuml
   !theme plain
   
   package "Docker Environment" {
       package "Trustpoint Container" {
           [Django Application] as App
           [PKCS#11 Utilities] as Utils
           [SoftHSM] as HSM
           [Cache] as Cache
       }
       
       package "PostgreSQL Container" {
           [Database] as DB
       }
       
       package "Docker Secrets" {
           [HSM PIN] as PIN
           [SO PIN] as SOPIN
       }
       
       package "Docker Volumes" {
           [SoftHSM Tokens] as Tokens
       }
   }
   
   App --> Utils
   Utils --> HSM : PKCS#11 API
   Utils --> DB : Store wrapped DEK
   Utils --> Cache : Cache DEK
   Utils --> PIN : Authentication
   Utils --> SOPIN : Token initialization
   HSM --> Tokens : Token storage
   
   @enduml

Key Components
~~~~~~~~~~~~~~

**Trustpoint Container**:
- Django application with HSM integration
- SoftHSM with token storage
- DEK caching for database encryption

**Docker Infrastructure**:
- Secure PIN management via Docker secrets
- Persistent token storage via Docker volumes
- Separate database container with encrypted fields

**Key Management**:
- KEK stored in HSM, marked as non-extractable (SENSITIVE=True, EXTRACTABLE=False)
- DEK protected by the KEK using PKCS#11 AES key wrap or AES encryption and cached in-process
- Database fields encrypted with AES-256-GCM

Fresh-install wizard behavior
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Selecting the PKCS#11 crypto backend in the setup wizard configures managed
signing keys on the PKCS#11 token. By default, Trustpoint also requires the
token to protect the application-secret DEK. Setup is refused when the token can
authenticate and generate signing keys but cannot protect and recover the DEK
with supported PKCS#11 AES flows.

Operators can disable this policy in the wizard when the token should only
manage signing keys. In that mode, application secrets use Trustpoint's software
app-secret backend for compatibility with signing-only tokens.

When PKCS#11 application-secret protection is enabled, the DEK is recovered
through the HSM-backed KEK at startup and then cached in-process. Per-field
encryption still uses local AES-256-GCM.

Protected imported keys
~~~~~~~~~~~~~~~~~~~~~~~

Trustpoint normally generates signing authority keys through the configured
crypto backend. Existing private-key credentials can be imported only when the
operator explicitly enables **Allow imported private keys** under
**Management > Settings > Security**.

Protected imported keys require both the PKCS#11 crypto backend and PKCS#11
application-secret protection. The imported private key is encrypted with the
application-secret DEK and stored in the Trustpoint database as a managed-key
binding. It is not imported into the HSM token. Trustpoint accesses it only
through the crypto backend service API, so PKI code uses the same managed-key
interface for generated and protected imported keys.

Docker Integration
------------------

Setup Instructions
~~~~~~~~~~~~~~~~~~~

To set up SoftHSM with Docker, you need to create the required secret files in the root directory of the project:

1. Create the database user file:

   .. code-block:: bash

      echo "<DB_USER>" > db_user.txt

2. Create the database password file:

   .. code-block:: bash

      echo "<DB_PASSWORD>" > db_password.txt

3. Create the HSM PIN file:

   .. code-block:: bash

      echo "<HSM_PIN>" > hsm_pin.txt

4. Create the HSM SO PIN file:

   .. code-block:: bash

      echo "<HSM_SO_PIN>" > hsm_so_pin.txt

Set appropriate permissions on the secret files:

.. code-block:: bash

   chmod 600 db_user.txt db_password.txt hsm_pin.txt hsm_so_pin.txt

To start the Trustpoint application with SoftHSM support, run the following command:

.. code-block:: bash

   docker compose -f docker-compose.softhsm.yml up --build

This will build and start the containers for Trustpoint, PostgreSQL, and SoftHSM.

Container Configuration
~~~~~~~~~~~~~~~~~~~~~~~

The Trustpoint container includes pre-configured SoftHSM support with token directory and configuration file setup. HSM PINs are managed through Docker secrets for secure credential handling.

**Docker Compose Secrets**:

.. code-block:: yaml

   secrets:
     db_user:
       file: db_user.txt
     db_password:
       file: db_password.txt
     hsm_pin:
       file: hsm_pin.txt
     hsm_so_pin:
       file: hsm_so_pin.txt

   environment:
     DATABASE_USER_FILE: /run/secrets/db_user
     DATABASE_PASSWORD_FILE: /run/secrets/db_password
     HSM_PIN_FILE: /run/secrets/hsm_pin
     HSM_SO_PIN_FILE: /run/secrets/hsm_so_pin
