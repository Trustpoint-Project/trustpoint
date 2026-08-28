.. _auto_restore:

Application-Secret Recovery
===========================

Trustpoint does not reconstruct missing HSM keys from a database backup. A
database restore can recover the protected application-secret DEK, but the KEK
needed to recover that DEK remains in the configured PKCS#11 token.

PKCS#11-backed deployments
--------------------------

For PKCS#11 application-secret protection, disaster recovery therefore requires
all of the following:

* the Trustpoint database backup;
* access to the same token key objects, or an HSM backup restored with the
  vendor's supported procedure;
* the matching PKCS#11 module, provider configuration, token selector, and PIN.

On startup, Trustpoint resolves the configured token and KEK, recovers the DEK,
and then restores encrypted TLS material from PostgreSQL. If the token or KEK
is unavailable, startup fails closed. There is currently no backup-password
workflow that can replace a lost KEK.

Software-backed deployments
----------------------------

The software application-secret DEK is stored in the database configuration.
A complete database backup therefore contains the material required to decrypt
encrypted fields after restore. This is operationally simpler but does not
provide hardware-rooted protection.

Operational guidance
--------------------

Test database and HSM recovery together. Never assume that a successful
database restore is sufficient for a PKCS#11-backed installation, and use only
the HSM vendor's supported key-backup and replication process.
