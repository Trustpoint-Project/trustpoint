==========================
Backup And Restore Concept
==========================

Trustpoint backups are intentionally split into two artifacts:

* the database payload, currently the PostgreSQL dump produced by
  ``django-dbbackup``/``trustpointbackup`` as ``.dump.gz``;
* a manifest sidecar named ``<backup>.manifest.json``.

The payload remains compatible with the existing ``dbrestore`` command. The
manifest records the Trustpoint version, database engine, active crypto backend
kind, active app-secret backend kind, payload format, creation timestamp, and a
SHA-256 digest of the exact payload bytes.

Restore Contract
================

Restore always restores the database payload first. When a manifest sidecar is
available, it must verify before restore proceeds:

* the manifest version is supported;
* the backup payload exists;
* the manifest contains a payload SHA-256 digest;
* the digest matches the payload bytes.

The setup wizard can still accept raw PostgreSQL dumps for compatibility, but
Trustpoint-created backups should include the sidecar. CI verifies the manifest
before restoring the payload.

Django Signing Key
==================

The Django signing key is deployment state. The administrator provisions the host
file ``secrets/django_secret_key`` once; Compose mounts it read-only at
``/run/secrets/django_secret_key`` in web and worker containers. Preserve the file
alongside database backups to retain existing signatures and sessions. Images
and production startup never generate signing keys.

Preserve the current key before restoring or recreating a 1.0 installation.
See :doc:`../../features/management/docker_deployment` for the procedure and
recovery requirements. The signing key is separate from application-secret
encryption keys and HSM key material.

Database Encryption Keys
========================

Trustpoint 1.0 stores only wrapped DEKs in the database. Software deployments
must separately back up ``secrets/trustpoint_software_kek`` with restrictive
permissions and encrypted offline protection. Restore the original root:33/0440
KEK file before starting any web or worker process. A different KEK cannot decrypt
the database; losing it may permanently prevent recovery of encrypted fields.

PKCS#11 deployments need the original HSM KEK/token and authentication credentials.
SoftHSM token and configuration volumes, including PIN files, must be backed up
and restored together. HSM KEKs are not included in a database dump or supplied
as raw Docker secrets. Use vendor-supported hardware HSM backups.

Database-only compromise does not expose the separate software KEK, but a fully
compromised application host can access plaintext keys in memory and files.
Compose file secrets provide no hardware security boundary. See
:doc:`../../features/security/db_encryption` for details. Migration of encrypted
databases from pre-1.0 releases is unsupported.

Out Of Scope
============

The sidecar does not encrypt the backup. Password-protected backup archives are
handled separately by the restore wizard's GPG decrypt path. Future backup
packages may bundle the payload and manifest into a single archive, but the
sidecar format keeps the current ``dbbackup``/``dbrestore`` workflow stable.
