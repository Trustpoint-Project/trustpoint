# Cryptography and Key Management

Trustpoint separates certificate metadata (stored in PostgreSQL) from private-key operations (delegated to PKCS#11 providers). This separation enables hardware HSM support, key-access auditing, and crypto-agile design.

## Cryptographic Architecture

```{mermaid}
flowchart TB
    PKI_SERVICE["PKI domain services / certificate issuance, signing"]
    CRYPTO_API["Crypto provider abstraction / trustpoint/crypto/"]
    
    PKI_SERVICE --> CRYPTO_API
    
    CRYPTO_API --> PROVIDER_PROFILE["Provider profile / PKCS#11 config / token selector"]
    
    PROVIDER_PROFILE --> ADAPTER{Crypto adapter}
    
    ADAPTER -->|Production| PKCS11_ADAPTER["PKCS#11 adapter / generic PKCS#11 module"]
    ADAPTER -->|Development| SOFTWARE_ADAPTER["Software adapter / in-memory keys"]
    ADAPTER -->|Future| FUTURE_ADAPTER[REST, KMS, other providers]
    
    PKCS11_ADAPTER --> MODULE["PKCS#11 module / libsofthsm2.so or hardware HSM"]
    MODULE --> TOKEN["PKCS#11 token / slot + PIN authentication"]
    
    TOKEN --> KEYS["Private keys / RSA, ECDSA"]
    
    CRYPTO_API --> BINDING_DB[("PostgreSQL / key metadata / binding to token")]
```

## Architectural Rules

1. **Private keys never leave the HSM in production:** Keys are generated in the PKCS#11 token and used for signing operations. The private-key bytes are never exported to Trustpoint's database or filesystem.

2. **Metadata separation:** Certificate objects, device records, and domain configuration are stored in PostgreSQL. Private-key metadata (key ID, token serial, public key) is stored in `CryptoManagedKeyModel` and `CryptoManagedKeyPkcs11BindingModel`.

3. **Provider abstraction:** The `crypto` module provides a uniform API for key generation, signing, and public-key retrieval. Different providers (PKCS#11, software, future REST/KMS) implement the same interface.

4. **Token selection:** PKCS#11 providers support multiple tokens. The provider profile specifies token-selection criteria (serial number, label, slot index).

5. **Protected imported credentials (optional):** Trustpoint supports importing externally generated private keys. These keys are encrypted using Trustpoint's application-secret protection and optionally wrapped by a PKCS#11 key. This feature is disabled by default and intended for migration scenarios only.

## Cryptographic Providers

### PKCS#11 Provider

**Purpose:** Generic PKCS#11 module support for hardware and software HSMs

**Module:** `trustpoint/crypto/adapters/pkcs11/`

**Supported HSMs:**
- SoftHSM (development and testing)
- Hardware HSMs: Thales, Utimaco, Gemalto, YubiHSM, etc.
- Cloud HSMs with PKCS#11 interface
- PKCS#11 proxies (e.g., for remote HSMs)

**Configuration fields:**
- `module_path`: Path to PKCS#11 library (e.g., `/usr/lib/libsofthsm2.so`)
- `token_serial`: Token serial number
- `token_label`: Token label
- `slot_index`: Token slot index
- `auth_source`: PIN authentication source (`file`, `environment`, `prompt`)
- `pin_file`: Path to PIN file (if `auth_source=file`)

**Token selection:**
- By serial number (preferred for production)
- By label (human-readable, but may not be unique)
- By slot index (may change on HSM restart)

### Software Provider

**Purpose:** In-memory keys for development and testing

**Module:** `trustpoint/crypto/adapters/software/`

**Characteristics:**
- Keys generated in memory
- Private keys stored in Python objects
- No hardware protection
- **Not secure for production**

**Use cases:**
- Unit testing
- Development without HSM
- CI/CD pipelines
- Quick prototyping

**Limitations:**
- Keys lost on process restart
- No multi-process key sharing
- No audit trail for key operations

## Key Generation

### Supported Key Algorithms

**RSA:**
- `RSA_2048`: 2048-bit RSA (minimum recommended)
- `RSA_3072`: 3072-bit RSA
- `RSA_4096`: 4096-bit RSA

**ECDSA:**
- `ECDSA_P256`: NIST P-256 (secp256r1)
- `ECDSA_P384`: NIST P-384 (secp384r1)
- `ECDSA_P521`: NIST P-521 (secp521r1)

## Security Best Practices

1. **Use hardware HSM in production:** SoftHSM is for development only

2. **Never export private keys:** Configure PKCS#11 with `CKA_EXTRACTABLE=False`

3. **Rotate keys regularly:** Establish key rotation procedures for CAs

4. **Backup HSM keys securely:** Use HSM-specific backup procedures

5. **Protect PIN files:** Restrict filesystem permissions (mode 600, owner www-data)

6. **Use strong PINs:** Minimum 8 characters, mixed case, numbers, symbols

7. **Monitor key operations:** Enable HSM audit logging

8. **Test key recovery:** Verify HSM backup and restore procedures

9. **Separate CA keys:** Use different keys for different CAs

10. **Document key inventory:** Maintain record of all managed keys and their purposes

## Future Enhancements

- **Cloud KMS integration:** AWS KMS, Azure Key Vault, Google Cloud KMS
- **Key rotation automation:** Automatic CA key rotation with overlap period
- **Post-quantum cryptography:** Prepare for PQC algorithms (ML-DSA, SLH-DSA)
- **Key ceremony support:** Structured key generation and backup procedures
- **Hardware security module clustering:** High-availability HSM configuration
- **Key usage auditing:** Detailed audit trail for all key operations
- **Threshold cryptography:** Multi-party signing for critical operations
