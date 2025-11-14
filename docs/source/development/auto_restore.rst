.. _auto_restore:

Auto Restore Workflow
======================

Overview
--------

The auto restore workflow is triggered when a Trustpoint container with HSM-based storage (SoftHSM or Physical HSM) is restarted and the database contains encrypted data, but the HSM's Key Encryption Key (KEK) is not available. This process ensures that encrypted private keys can be recovered using a backup password, even if the HSM's volatile KEK is lost.

**Key Point:** For SOFTWARE storage type, no auto restore is needed - the container restarts normally.

Workflow Process
----------------

HSM-Based Storage (SoftHSM or Physical HSM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The auto restore workflow varies depending on what HSM components are available:

**Scenario 1: KEK Lost, Token Exists**

.. code-block:: text

    Container Restart (SOFTHSM + WIZARD_COMPLETED + encrypted DB)
        ↓
    managestartup.py detects KEK lost but token exists
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

**Scenario 2: HSM Completely Lost (New HSM Installation)**

.. code-block:: text

    Container Restart (SOFTHSM + WIZARD_COMPLETED + encrypted DB)
        ↓
    managestartup.py detects new KEK scenario (token missing)
        ↓
    WIZARD_SETUP_HSM_AUTORESTORE state created
        ↓
    entrypoint.sh detects state → skips unwrap/config
        ↓
    User accesses web → /setup-wizard/auto-restore-hsm-setup/<hsm_type>/
        ↓
    AutoRestoreHsmSetupView
        ↓
    sudo wizard_setup_hsm.sh <module> <slot> <label> auto_restore_setup
        ↓
    HSM token initialized → WIZARD_AUTO_RESTORE_PASSWORD state created
        ↓
    User accesses web → /setup-wizard/auto_restore_password/
        ↓
    BackupAutoRestorePasswordView
        ↓
    DEK recovery + TLS extraction + CA deactivation
        ↓
    sudo wizard_auto_restore_success.sh
        ↓
    Apache & TLS config → WIZARD_COMPLETED
        ↓
    Done!

**Scenario 3: KEK Available (Normal Restart)**

.. code-block:: text

    Container Restart (SOFTHSM + WIZARD_COMPLETED + encrypted DB)
        ↓
    managestartup.py detects KEK available
        ↓
    Normal startup continues
        ↓
    DEK unwrapped using existing KEK
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


