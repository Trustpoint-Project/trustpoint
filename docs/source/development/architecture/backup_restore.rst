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

Out Of Scope
============

The sidecar does not encrypt the backup. Password-protected backup archives are
handled separately by the restore wizard's GPG decrypt path. Future backup
packages may bundle the payload and manifest into a single archive, but the
sidecar format keeps the current ``dbbackup``/``dbrestore`` workflow stable.
