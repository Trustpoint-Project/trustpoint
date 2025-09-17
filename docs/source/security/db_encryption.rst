Database Encryption in Trustpoint
==================================

Overview
--------

Trustpoint implements a robust database encryption system to protect sensitive data such as EST passwords CMP shared secrets or private Keys for credentials which were created in Trustpoint. The system uses a two-tier key management approach with PKCS#11 hardware security module (HSM) integration, employing AES-256 encryption.

Key Management Architecture
---------------------------

The encryption system follows a hierarchical key structure:

1. **Key Encryption Key (KEK)** - A 256-bit AES key stored in the PKCS#11 HSM
2. **Data Encryption Key (DEK)** - A 256-bit AES key encrypted by the KEK and stored in the database
3. **Field Encryption** - Individual database fields encrypted using the DEK with AES-256-CBC

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
2. Create a temporary session object in the PKCS#11 token
3. Use the KEK to wrap the DEK using AES Key Wrap mechanism
4. Store the wrapped DEK in the database ``encrypted_dek`` field

Runtime Key Management
----------------------

Container Startup
~~~~~~~~~~~~~~~~~

When the Trustpoint container starts:

1. The system attempts to retrieve the cached DEK from Django's cache
2. If not cached, it unwraps the DEK using the PKCS#11 KEK:
   
   - Open session with the PKCS#11 token
   - Retrieve the KEK using label ``trustpoint-kek``
   - Unwrap the stored ``encrypted_dek`` using AES Key Wrap
   - Cache the decrypted DEK indefinitely

3. The DEK remains in memory cache for the container's lifetime

DEK Caching Strategy
~~~~~~~~~~~~~~~~~~~~

- **Cache Key**: ``trustpoint-dek-cache`` 
- **Cache Duration**: Indefinite (``None`` timeout)
- **Cache Backend**: Django's configured cache
- **Security**: DEK is cleared from cache when PKCS11Token object is destroyed

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

1. **Retrieve DEK**: Get the cached DEK from the PKCS#11 token
2. **Generate IV**: Create a random 16-byte initialization vector
3. **Padding**: Apply PKCS#7 padding to the plaintext
4. **Encryption**: Encrypt using AES-256-CBC with the DEK and IV
5. **Encoding**: Base64 encode the concatenated IV + ciphertext
6. **Storage**: Store the encoded result in the database

Decryption Process
~~~~~~~~~~~~~~~~~~

When reading data from encrypted fields:

1. **Retrieve DEK**: Get the cached DEK
2. **Decode**: Base64 decode the stored value
3. **Extract Components**: Separate IV (first 16 bytes) and ciphertext
4. **Decryption**: Decrypt using AES-256-CBC
5. **Unpadding**: Remove PKCS#7 padding
6. **Return**: Return the original plaintext

Protected Data Types
--------------------

The following sensitive fields use database encryption:

Device Model Fields
~~~~~~~~~~~~~~~~~~~

- ``est_password`` (EncryptedCharField) - EST authentication passwords
- ``cmp_shared_secret`` (EncryptedCharField) - CMP protocol shared secrets

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
   Field -> Field: os.urandom(16) // Generate IV
   Field -> Field: AES-256-CBC encrypt(data, dek, iv)
   Field -> Field: base64.encode(iv + ciphertext)
   Field -> DB: store encrypted_value
   
   == Decryption Phase ==
   DB --> Field: encrypted_value
   Field -> Field: base64.decode(encrypted_value)
   Field -> Field: split iv, ciphertext
   Field -> Field: AES-256-CBC decrypt(ciphertext, dek, iv)
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
  - AES Key Wrap (RFC 3394) used for DEK protection

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

- Encrypted fields will raise ``ValidationError`` during access
- The system logs detailed error messages for debugging
- Cache is automatically cleared to prevent stale key usage

Corrupted DEK
~~~~~~~~~~~~~

If the wrapped DEK becomes corrupted:

- The system detects invalid wrapped data during unwrapping
- Error messages indicate potential data corruption
- Manual DEK regeneration may be required (data loss will occur)

Key Rotation
~~~~~~~~~~~~

Currently, key rotation is not implemented. Future versions may include:

- Automated KEK rotation with dual-key support
- DEK re-wrapping with new KEKs
- Gradual field re-encryption with new DEKs
