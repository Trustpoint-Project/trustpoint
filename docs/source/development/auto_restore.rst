.. _auto_restore:

Recovery after restart
======================

Normal startup
--------------

Completed installations use ``startup_manager`` to run migrations, require the
configured application-secret backend, and restore the active TLS credential
from the database. The container then starts the web and background services.
The old filesystem wizard states and their transition scripts are no longer used.

Startup and setup code
----------------------

The ``setup_wizard`` app owns the ``bootstrap_manager``, ``startup_manager``,
``apply_bootstrap_config``, ``auto_setup_from_env``, and ``finalize_setup``
management commands. Startup context and strategies live beside them in
``setup_wizard/startup_context.py`` and ``setup_wizard/startup_strategies.py``.
Database restore and isolated provider probes live in ``backup_restore.py`` and
``pkcs11_probe.py``. Docker's privileged launchers remain under ``docker``.

Auto-setup publishes its operational ready marker only after setup, startup, and
the runtime switch succeed. A failed attempt keeps its retry marker and starts
in bootstrap mode again. Fresh install rejects an already configured database;
use Connect Existing to attach to that installation.

Fresh install commits its application-version record together with the target
database configuration. If the bootstrap save is interrupted after that commit,
use Connect Existing to validate the committed installation and finish attaching
instead of applying fresh-install settings again.

Required recovery material
--------------------------

Preserve the database, deployment volumes, Django signing key, and the original
key-encryption key (KEK). Software storage requires the installation's
``trustpoint_software_kek`` secret. PKCS#11 storage requires the original HSM
key/token, provider configuration, and authentication material. SoftHSM also
requires its original token/configuration volumes and PIN files.

A database backup alone cannot recover encrypted credentials. Do not initialize
a replacement key or token over an existing installation when startup reports
missing key material. Restore the original deployment material first.

Use the current setup wizard's backup restore flow for a new installation.
For deployment persistence and backup requirements, see
:doc:`../features/management/docker_deployment`.
