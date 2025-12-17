HSM Integration in Trustpoint
=============================

Overview
--------

Trustpoint integrates with Hardware Security Modules (HSMs) through the PKCS#11 standard to provide secure key storage and cryptographic operations. 

Supported HSM Types
-------------------

SoftHSM
~~~~~~~

**Primary Support**: SoftHSM2 is the default and fully supported HSM implementation.

- **Library Path**: ``/usr/lib/softhsm/libsofthsm2.so``
- **Use Case**: Development, testing, and small-scale production deployments

Physical HSM
~~~~~~~~~~~~

**Future Support**: Physical HSM devices are planned for production environments.

- **Status**: Interface defined but not fully implemented
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
- RSA-PSS padding support
- PKCS#1 v1.5 padding support
- Supported hash algorithms: SHA-256, SHA-384, SHA-512, SHA-224
- Pre-hashed data signing capability

**Encryption/Decryption Operations**:
- RSA-OAEP padding support for encryption/decryption
- PKCS#1 v1.5 padding support
- Public key extraction for certificate generation

**Key Import**:
- Import existing RSA private keys from cryptography library to HSM
- Keys stored as non-extractable in HSM

EC (Elliptic Curve) Key Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Key Generation**:
- EC key pair generation within HSM
- Supported curves: P-256, P-384, P-521, secp256k1
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
- Key import from cryptography library to HSM
- Keys marked as non-extractable (EXTRACTABLE=False)
- Encryption/decryption not supported (EC is for signing only)

AES Key Operations
~~~~~~~~~~~~~~~~~~

**Symmetric Key Generation**:
- AES key generation in HSM
- Supported key lengths: 128, 192, 256 bits
- Primary use for KEK storage

**Encryption/Decryption Operations**:
- AES-ECB encryption for DEK wrapping
- DEK wrapping and unwrapping operations
- Note: AES Key Wrap (RFC 3394) not supported by SoftHSM2
- 8-byte random IV prepended to encrypted data for format consistency

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
- DEK wrapped by KEK using AES-ECB, cached at startup
- Database fields encrypted with AES-256-GCM
- Token-specific cache keys: ``trustpoint-dek-chache-{token_label}``

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
     POSTGRES_USER_FILE: /run/secrets/db_user
     POSTGRES_PASSWORD_FILE: /run/secrets/db_password
     HSM_PIN_FILE: /run/secrets/hsm_pin
     HSM_SO_PIN_FILE: /run/secrets/hsm_so_pin
