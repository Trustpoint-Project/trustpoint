.. _auto_restore:

Auto Restore Workflow
======================

Overview
--------

The auto restore workflow is triggered when a Trustpoint container with HSM-based storage (SoftHSM or Physical HSM) is restarted after initial setup. This process ensures that encrypted private keys can be recovered using a backup password, even if the HSM's volatile key encryption key (KEK) is lost.

**Key Point:** For SOFTWARE storage type, no auto restore is needed - the container restarts normally.

Workflow Process
----------------

HSM-Based Storage (SoftHSM or Physical HSM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using HSM-based storage, the container restart follows this workflow:

.. code-block:: text

    Container Restart (SOFTHSM + WIZARD_COMPLETED)
        ↓
    managestartup.py
        ↓
    sudo wizard_auto_restore_password_set.sh
        ↓
    WIZARD_AUTO_RESTORE_PASSWORD state created
        ↓
    entrypoint.sh detects state → skips unwrap/config
        ↓
    User accesses web → /setup-wizard/auto_restore_password/
        ↓
    BackupAutoRestorePasswordView
        ↓
    DEK recovery + TLS extraction
        ↓
    sudo wizard_auto_restore_success.sh
        ↓
    Apache & TLS config → WIZARD_COMPLETED
        ↓
    Done!

SOFTWARE Storage Type
~~~~~~~~~~~~~~~~~~~~~

For SOFTWARE storage type:

.. code-block:: text

    Container Restart (SOFTWARE + WIZARD_COMPLETED)
        ↓
    managestartup.py
        ↓
    No auto restore needed
        ↓
    Normal container startup continues
        ↓
    Done!

Why Auto Restore is Needed for HSM
-----------------------------------

When using HSM-based storage, the encryption keys follow a layered security model:

1. Private keys are encrypted with a Data Encryption Key (DEK)
2. The DEK is protected by a Key Encryption Key (KEK) in the HSM
3. The DEK also has a backup protected by the user's backup password
4. **When the container restarts, the HSM's volatile KEK is lost** (by design for security)
5. The backup password is needed to recover the DEK and generate a new KEK

For SOFTWARE storage, keys are stored directly on disk and persist across restarts, so no recovery is needed.


Security Considerations
-----------------------

Key Hierarchy
~~~~~~~~~~~~~

.. code-block:: text

    Backup Password (User Input)
         ↓ (Argon2 KDF)
    BEK (Backup Encryption Key)
         ↓ (Encrypts)
    DEK (Data Encryption Key)
         ↓ (Encrypts)
    Private Keys (RSA, ECDSA)

And during normal operation:

.. code-block:: text

    KEK (Key Encryption Key in HSM)
         ↓ (Wraps)
    DEK (Data Encryption Key)
         ↓ (Encrypts)
    Private Keys (RSA, ECDSA)








