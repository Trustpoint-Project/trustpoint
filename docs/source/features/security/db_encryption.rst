Database Encryption In Trustpoint 1.0
========================================

Trustpoint encrypts sensitive Django model fields using a random 256-bit Data
Encryption Key (DEK). Both application-secret backends protect that DEK with a
separate Key Encryption Key (KEK). Only the wrapped DEK and non-secret metadata
are persisted in the database. Django's ``SECRET_KEY`` signs Django data and is
independent of both encryption keys.

This is a fresh-installation architecture. Migration of encrypted databases from
pre-1.0 releases is unsupported. The schema transition refuses databases with
pre-existing application-secret key material instead of discarding their keys.
Do not bypass that check with fake migrations.

Software Backend
-------------------

An administrator provisions a random 256-bit KEK outside the database:

.. code-block:: bash

   sudo python3 docker/init_secret.py --type all
   docker compose up -d --build --wait --wait-timeout 300

The file ``secrets/trustpoint_software_kek`` contains exactly 64 hexadecimal
characters, with no whitespace or newline. Compose mounts it read-only at
``/run/secrets/trustpoint_software_kek``. ``TRUSTPOINT_SOFTWARE_KEK_HOST_FILE``
selects a different host source; ``TRUSTPOINT_SOFTWARE_KEK_FILE`` selects the
application's input file and the Compose mount target. Every worker accessing
the same database must receive the same KEK.

The application never generates a software KEK, derives it from Django's signing
key, or stores it in the database. Local development also needs an explicitly
provisioned KEK file; there is no plaintext or automatic-generation fallback.
For non-Docker development, explicitly provision a separate key readable by the
host developer's group (not the container's group):

.. code-block:: bash

   sudo python3 docker/init_secret.py --type kek \
     --path "$PWD/var/development/software_kek" --group-id "$(id -g)"
   export TRUSTPOINT_SOFTWARE_KEK_FILE="$PWD/var/development/software_kek"

This retains root ownership and mode ``0440``. Linux container deployments use
the default group 33 instead.

On first setup, Trustpoint generates a 32-byte DEK and wraps it using the existing
``cryptography`` dependency's AES-256 Key Wrap with Padding (RFC 5649). The binary
envelope contains a format/backend/algorithm/version prefix, a SHA-256 KEK
fingerprint, and the wrapped DEK. The fingerprint identifies the high-entropy KEK;
it does not contain the KEK. The format permits future KEK identification and
DEK rewrapping; rotation workflows are not implemented.

See the upstream `key wrapping API
<https://cryptography.io/en/latest/hazmat/primitives/keywrap/>`_.

PKCS#11 Backend
------------------

Trustpoint locates or generates a 256-bit AES KEK inside the configured token.
The KEK is private, sensitive, and non-extractable where the provider exposes
these attributes. Visible unsafe attributes are rejected. The software KEK file
is neither read nor required for this backend. Do not import the software KEK
into the HSM or expose a raw HSM KEK through Compose secrets.

The token wraps and unwraps temporary DEK key objects using standard AES key-wrap
mechanisms. Providers with encryption/decryption support can use authenticated
AES-GCM with a random 96-bit nonce, a 128-bit tag, and envelope context as AAD.
Unauthenticated CBC and ECB envelopes are not accepted in the 1.0 architecture.
Wrapped envelopes identify their version and protection operation; the PKCS#11
configuration supplies the KEK label and token reference. HSM credentials may
come from PIN files or the existing provider authentication configuration.

The application needs the recovered DEK in memory for database field encryption;
only the KEK remains non-extractable inside the HSM. Persist SoftHSM token and
configuration volumes, including the original PIN files. External hardware HSMs
need vendor-supported key backups and recovery procedures. SoftHSM files do not
provide a hardware security boundary against host compromise.

Initialization And Runtime
-----------------------------

Setup locks the singleton backend row in a database transaction before creating
key material. PostgreSQL serializes competing web/worker initialization. Wrapped
DEK persistence and the durable initialization marker commit together. SQLite
may report a write-lock conflict; the operation rolls back with an explicit
error and can be retried. It never replaces a committed key.

Only a fresh, uninitialized configuration may generate a DEK. An initialized
backend with missing key material fails closed. Existing envelopes are unwrapped,
never regenerated after errors. Backend switching and PKCS#11 connection changes
after initialization are refused. Deleting arbitrary database state is not a
supported reset or recovery procedure.

Each process caches the recovered DEK in memory under a thread lock, keyed by
backend configuration and wrapped material. The software backend validates its
KEK file before cache use and includes its fingerprint in cache identity. A
changed, missing, or malformed software KEK cannot reuse a previous cached DEK.
No Django cache server receives plaintext key material. Restarting or calling
``clear_app_secret_cache()`` clears the process cache. PKCS#11 processes can
continue with an already cached DEK during an HSM outage until cache clearing or
restart; restart all processes when revoking HSM access.

Field Encryption
-------------------

``EncryptedCharField`` and ``EncryptedTextField`` preserve their existing format:
``tpsec:v1:`` followed by Base64 of a random 12-byte nonce, a 16-byte GCM tag,
and ciphertext. Encryption uses AES-256-GCM with the existing application-secret
AAD context. Empty and null field values retain their existing behavior.

Protected data includes device authentication secrets, TLS credential private
keys, and protected imported-key bindings. This is field encryption, not
whole-database or backup-file encryption. Other database columns and metadata
can remain readable. Password-protect backup archives separately when needed.

Backup, Restore, And Troubleshooting
---------------------------------------

Back up the database containing the wrapped DEK and the matching software KEK
file separately, with access controls and encrypted offline copies. Preserve
Django's signing key separately to retain signatures and sessions. An ordinary
database backup does not contain the external KEK. Verify recovery before
discarding any original key material.

For software restores, provision the original KEK file with root ownership,
container group 33, and mode ``0440`` before starting any Django service. Preserve
the exact key across container recreation and image updates. Do not run an
initializer to replace a lost key: a newly generated KEK cannot unwrap an old
DEK. Losing the KEK without a recoverable copy can permanently destroy access
to encrypted fields.

For PKCS#11 restores, restore access to the original token/KEK and original PINs,
plus the database's matching wrapped DEK. Losing the HSM KEK or SoftHSM token
can have the same permanent consequences. Restoring a database alone is
insufficient.

* Missing/unreadable software KEK: check the source file, mount, numeric ownership,
  and ``TRUSTPOINT_SOFTWARE_KEK_FILE``. Restore the original file for an existing
  installation.
* Invalid encoding: use exactly 64 hexadecimal characters, without whitespace.
* Wrong KEK or unwrap failure: restore the original KEK and intact matching
  database backup. No replacement DEK is generated.
* Missing DEK or initialization marker mismatch: restore consistent database
  state. Do not clear the marker or recreate configuration rows.
* Unsupported envelope: use a supported 1.0 backup. Pre-1.0 encrypted databases
  cannot be upgraded through this implementation.
* Missing token, invalid PIN, or PKCS#11 wrapping failure: restore token access
  and check the provider's mechanism support. Never reinitialize an existing
  token to resolve missing keys.

Automatic KEK/DEK rotation and switching existing installations between backends
are out of scope. Rewrapping could support future KEK rotation without changing
field ciphertext, but must be implemented as an explicit coordinated operation.

Security Boundary
--------------------

Separating the KEK from the database protects encrypted fields against a
database-only compromise. File-based Compose secrets are read-only mounts, not
an HSM or encrypted secret store. A fully compromised application host or process
can read the software KEK and recovered DEK. Even an HSM-backed application must
hold the DEK and plaintext fields in process memory. Restrict host access and
protect backups and runtime credentials accordingly.
