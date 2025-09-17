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

**Public Key Operations**:
- Public key extraction for certificate generation
- RSA encryption/decryption operations
- Key wrapping and unwrapping

EC (Elliptic Curve) Key Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Key Generation**:
- EC key pair generation within HSM
- Supported curves: P-256, P-384, P-521, secp256k1
- Curve parameter validation

**Signing Operations**:
- ECDSA signature generation
- Deterministic ECDSA (RFC 6979) support
- Hash algorithm flexibility (SHA-256, SHA-384, SHA-512)
- ASN.1 DER encoded signatures

**Key Management**:
- Named curve support via OID mapping
- Public key point extraction
- EC parameter validation

AES Key Operations
~~~~~~~~~~~~~~~~~~

**Symmetric Key Generation**:
- AES key generation in HSM
- Supported key lengths: 128, 192, 256 bits
- Primary use for KEK storage

**Key Wrapping**:
- AES Key Wrap (RFC 3394) mechanism
- DEK wrapping and unwrapping operations
- Secure key transport between software and HSM

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
- Hardware random number generation
- Entropy seeding capabilities
- Cryptographically secure randomness

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
- KEK stored in HSM, never exported
- DEK wrapped by KEK, cached at startup
- Database fields encrypted with AES-256-CBC

Docker Integration
------------------

Container Configuration
~~~~~~~~~~~~~~~~~~~~~~~

The Trustpoint container includes pre-configured SoftHSM support with token directory and configuration file setup. HSM PINs are managed through Docker secrets for secure credential handling.

**Docker Compose Secrets**:

````yaml
secrets:
  hsm_pin:
    file: hsm_pin.txt
  hsm_so_pin:
    file: hsm_so_pin.txt

environment:
  HSM_PIN_FILE: /run/secrets/hsm_pin
  HSM_SO_PIN_FILE: /run/secrets/hsm_so_pin