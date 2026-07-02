Database Encryption in Trustpoint
==================================

Overview
--------

Trustpoint implements a robust database encryption system to protect sensitive data such as EST passwords, CMP shared secrets, and private keys for credentials created in Trustpoint. The system uses a two-tier key management approach with PKCS#11 hardware security module (HSM) integration, employing AES-256-GCM encryption.

Key Management Architecture
---------------------------

The encryption system follows a hierarchical key structure:

1. **Key Encryption Key (KEK)** - A 256-bit AES key stored in the PKCS#11 HSM
2. **Data Encryption Key (DEK)** - A 256-bit AES key encrypted by the KEK and stored in the database
3. **Field Encryption** - Individual database fields encrypted using the DEK with AES-256-GCM

Key Generation Process
----------------------

KEK Generation
~~~~~~~~~~~~~~

During the setup wizard HSM configuration phase:

1. The system generates a 256-bit AES key directly in the PKCS#11 token
2. The KEK is stored with the label ``trustpoint-kek`` 
3. The key is marked as:
   - ``SENSITIVE`` - Cannot be extracted from the HSM
   - ``TOKEN`` - Persistent across sessions
   - ``EXTRACTABLE=False`` - Cannot be exported

DEK Generation and Wrapping
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The DEK is generated and wrapped during initial setup:

1. Generate a random 256-bit key
2. Open a session with the PKCS#11 token
3. Use the KEK to wrap the DEK using AES-ECB encryption
4. Prepend an 8-byte random IV to the encrypted DEK
5. Store the wrapped DEK (40 bytes: 8-byte IV + 32-byte encrypted DEK) in the database ``encrypted_dek`` field

Runtime Key Management
----------------------

Container Startup
~~~~~~~~~~~~~~~~~

When the Trustpoint container starts:

1. The system attempts to retrieve the cached DEK from Django's cache
2. If not cached, it unwraps the DEK using the PKCS#11 KEK:
   
   - Open session with the PKCS#11 token
   - Retrieve the KEK using label ``trustpoint-kek``
   - Extract the 8-byte IV and 32-byte encrypted DEK from ``encrypted_dek``
   - Decrypt using AES-ECB with the KEK
   - Cache the decrypted DEK indefinitely

3. The DEK remains in memory cache for the container's lifetime

DEK Caching Strategy
~~~~~~~~~~~~~~~~~~~~

- **Cache Key**: ``trustpoint-dek-chache-{token_label}`` (token-specific)
- **Cache Duration**: Indefinite (``None`` timeout)
- **Cache Backend**: Django's configured cache
- **Security**: DEK can be manually cleared using ``clear_dek_cache()`` method

Database Field Encryption
--------------------------

Encrypted Field Types
~~~~~~~~~~~~~~~~~~~~~

Two field types are provided for database encryption:

- ``EncryptedCharField`` - For short sensitive strings (passwords, secrets)
- ``EncryptedTextField`` - For longer sensitive text content

Encryption Process
~~~~~~~~~~~~~~~~~~

When saving data to encrypted fields:

1. **Check Encryption**: Verify if HSM-based encryption is enabled via ``KeyStorageConfig``
2. **Retrieve DEK**: Get the cached DEK from the PKCS#11 token
3. **Generate Nonce**: Create a random 12-byte nonce for GCM mode
4. **Padding**: Add random padding (0-15 bytes) to obscure length patterns
5. **Encryption**: Encrypt using AES-256-GCM with the DEK and nonce
6. **Combine**: Concatenate nonce (12 bytes) + authentication tag (16 bytes) + ciphertext
7. **Encoding**: Base64 encode the combined data
8. **Storage**: Store the encoded result in the database

Decryption Process
~~~~~~~~~~~~~~~~~~

When reading data from encrypted fields:

1. **Check Encryption**: Verify if HSM-based encryption is enabled
2. **Retrieve DEK**: Get the cached DEK
3. **Decode**: Base64 decode the stored value
4. **Extract Components**: Separate nonce (first 12 bytes), authentication tag (next 16 bytes), and ciphertext
5. **Decryption**: Decrypt using AES-256-GCM and verify authentication tag
6. **Unpadding**: Remove random padding based on last byte value
7. **Return**: Return the original plaintext

Protected Data Types
--------------------

The following sensitive fields use database encryption:

Device Model Fields
~~~~~~~~~~~~~~~~~~~

- ``est_password`` (EncryptedCharField, max_length=128) - EST authentication passwords
- ``cmp_shared_secret`` (EncryptedCharField, max_length=128) - CMP protocol shared secrets

Credential Model Fields
~~~~~~~~~~~~~~~~~~~~~~~

- ``private_key`` (EncryptedCharField, max_length=65536) - PEM-encoded private keys for credentials created in Trustpoint

**Note**: Encryption is only active when ``KeyStorageConfig.storage_type`` is set to ``SOFTHSM`` or ``PHYSICAL_HSM``. When using software-based key storage, data is stored in plaintext.

UML Sequence Diagram
--------------------

.. uml::

   @startuml
   !theme plain
   
   participant "Setup Wizard" as Setup
   participant "PKCS11Token" as Token
   participant "HSM/SoftHSM" as HSM
   participant "Database" as DB
   participant "EncryptedField" as Field
   participant "Cache" as Cache
   
   == Setup Phase ==
   Setup -> Token: generate_kek(256)
   Token -> HSM: generate_key(AES-256, "trustpoint-kek")
   HSM --> Token: KEK created
   
   Setup -> Token: generate_and_wrap_dek()
   Token -> Token: os.urandom(32) // Generate DEK
   Token -> HSM: wrap_key(DEK, KEK)
   HSM --> Token: wrapped_dek
   Token -> DB: store wrapped_dek
   
   == Runtime Phase ==
   Field -> Token: get_dek()
   Token -> Cache: get("trustpoint-dek-cache")
   alt Cache Miss
       Token -> HSM: unwrap_key(wrapped_dek, KEK)
       HSM --> Token: decrypted_dek
       Token -> Cache: set("trustpoint-dek-cache", dek, None)
   end
   Token --> Field: dek
   
   == Encryption Phase ==
   Field -> Field: os.urandom(12) // Generate nonce
   Field -> Field: Add random padding (0-15 bytes)
   Field -> Field: AES-256-GCM encrypt(padded_data, dek, nonce)
   Field -> Field: Get authentication tag
   Field -> Field: base64.encode(nonce + tag + ciphertext)
   Field -> DB: store encrypted_value
   
   == Decryption Phase ==
   DB --> Field: encrypted_value
   Field -> Field: base64.decode(encrypted_value)
   Field -> Field: split nonce, tag, ciphertext
   Field -> Field: AES-256-GCM decrypt(ciphertext, dek, nonce, tag)
   Field -> Field: Verify authentication and remove padding
   Field --> Field: plaintext
   
   @enduml

Encryption Implementation Details
---------------------------------

Cryptographic Algorithm
~~~~~~~~~~~~~~~~~~~~~~~

The system uses **AES-256-GCM** (Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode) for field-level encryption:

- **Algorithm**: AES-256
- **Mode**: GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Authentication Tag**: 128 bits (16 bytes)
- **Padding**: Not required (GCM is a stream cipher mode)


Security Properties
~~~~~~~~~~~~~~~~~~~

**Nonce**
  - 12-byte random nonce generated for each encryption operation using ``os.urandom(12)``
  - Ensures identical plaintexts produce different ciphertexts

**Authentication**
  - Built-in authentication prevents tampering
  - 128-bit authentication tag provides strong integrity protection
  - Eliminates padding oracle attacks

**Key Management**
  - 256-bit DEK provides strong cryptographic security
  - KEK stored in HSM prevents key extraction
  - AES-ECB encryption used for DEK wrapping (8-byte IV prepended for format consistency)

Field Encryption/Decryption Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. uml::

   @startuml
   !theme plain
   
   start
   
   if (Operation?) then (Encrypt)
       :Receive plaintext value;
       
       if (Value empty?) then (yes)
           :Return unchanged;
           stop
       endif
       
       :Get DEK from cache/HSM;
       :Generate 12-byte random nonce;
       :Add random padding (0-15 bytes);
       :Create AES-256-GCM cipher;
       :Encrypt padded data;
       :Get 16-byte authentication tag;
       :Combine: nonce + tag + ciphertext;
       :Base64 encode result;
       :Store in database;
       
   else (Decrypt)
       :Receive encrypted value;
       
       if (Value empty?) then (yes)
           :Return unchanged;
           stop
       endif
       
       :Get DEK from cache/HSM;
       :Base64 decode value;
       :Extract components:
       - nonce (12 bytes)
       - tag (16 bytes) 
       - ciphertext (rest);
       :Create AES-256-GCM cipher with tag;
       :Decrypt and verify authentication;
       
       if (Authentication valid?) then (no)
           :Raise ValidationError;
           stop
       endif
       
       :Remove random padding;
       :Return plaintext;
       
   endif
   
   stop
   
   @enduml

Error Handling and Recovery
---------------------------

HSM Unavailable
~~~~~~~~~~~~~~~

If the PKCS#11 token becomes unavailable:

- Encrypted fields will raise ``ValidationError`` during read/write operations
- The system logs detailed error messages for debugging
- Manual intervention required to restore HSM connectivity

**Note**: The DEK remains cached in memory, so existing processes can continue using encrypted fields until the application restarts.

Corrupted DEK
~~~~~~~~~~~~~

If the wrapped DEK becomes corrupted:

- The system detects invalid wrapped data during unwrapping
- Error messages indicate potential data corruption  
- Manual DEK regeneration using ``generate_and_wrap_dek()`` will be required
- **Warning**: Regenerating the DEK will make all previously encrypted data unrecoverable

Key Rotation
~~~~~~~~~~~~

Currently, key rotation is not implemented. Future versions may include:

- Automated KEK rotation with dual-key support
- DEK re-wrapping with new KEKs
- Gradual field re-encryption with new DEKs
