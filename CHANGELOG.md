# Changelog

## 1.0.1

Trustpoint 1.0.1 updates 1.0.0 in place and keeps the existing database, keys,
and persistent state. Pending migrations apply at startup.

### Highlights

- Audit events form a SHA-256 hash chain with optional signed checkpoints,
  integrity verification, and evidence exports. Traceability Credentials manage
  the signing identity, including rotation.
- CAs now have a role: Management CAs issue user-authentication and TLS server
  certificates, while Issuing CAs are reserved for endpoint certificates.
  Auto-generated PKI is replaced by named self-signed CAs.
- CMP adds key update (KUR/KUP) and CA certificate retrieval (`genm`/`genp`),
  with authenticated upstream responses. EST adds `csrattrs`, full discovery,
  and TLS channel binding. SCEP and AOKI enrollment fixes are included.
- Notifications add alerts for credential expiry, backend availability, account
  lockouts, workflow failures/overdue approvals, and backup failures.
- Security hardening covers permission checks, login lockout and OTP for API
  tokens, GDS key handling, enrollment validation, and concurrency.
- SFTP backups pin a verified server host key, and backup downloads stream.

### Upgrade notes

- Back up the database and preserve the 1.0.0 signing key, KEK/HSM material,
  `.env`, and volumes before upgrading.
- `pki.0003_tp_v1_0_1` aborts if saved certificate-profile labels are missing or
  ambiguous. `onboarding.0003_tp_v1_0_1` needs the application-secret keys to
  encrypt existing CMP/EST/REST secrets.
- Existing SFTP backup settings need a verified server host key.
- `DATABASE_PASSWORD` is now required, and unset `TP_SECURITY_MODE` keeps the
  stored preset.
- Prometheus metrics require `TRUSTPOINT_PROMETHEUS_METRICS_TOKEN`. The bundled
  database image is PostgreSQL 18.7.
- The default failed-login lockout is now 5 attempts.

### Known limitations

- Audit signing does not make the database write-once; retain checkpoints and
  signatures outside Trustpoint for real tamper evidence.
- The 1.0.0 limitations remain (AOKI proof of concept, incomplete SCEP polling
  operations, PKCS#11 ML-DSA, and CA rollover distribution).

## 1.0.0

Trustpoint 1.0.0 is the first stable release of the platform.

### Initial installation

Trustpoint 1.0.0 is the first stable version and the baseline for compatibility.
Start with a fresh database and installation-specific secrets. Preserve the
resulting database, device identities, CA trust, keys, and runtime state for
subsequent updates and recovery.

Use the Linux Docker Compose deployment and complete the setup wizard. Automatic
setup and demo data are intended for disposable testing/demo environments; demo
data is optional and must not be injected into an instance holding real data.

### Capabilities

- EST, CMP, SCEP, and Trustpoint-specific REST enrollment paths, with authentication
  and certificate-profile choices determined by device/domain/security policy.
- Local managed CAs, upstream EST/CMP CA requests, and remote EST/CMP RA forwarding.
- Certificate inventory, revocation/CRL management, and local-CA rollover workflows
  using imported material or generated keys with EST/CMP certificate acquisition.
- Software and PKCS#11 cryptographic backends; application-secret envelope encryption
  using a database-held wrapped DEK and a separately retained software/HSM KEK.
- SMTP and SFTP credentials encrypted at rest, with replacement-only secret fields
  and explicit controls for clearing stored credentials.
- Device/agent management, OPC UA GDS Push, workflow approvals, webhooks, mail,
  notifications, and operational logging/metrics.

Protocol and backend availability depends on the configured security policy,
profiles, and provider mechanisms. The capability guide documents these
requirements and limitations.

### Recovery and compatible updates

Before an update, create and download a current database backup and its matching
manifest. Preserve the Django signing key, software KEK (where used), `.env`, and
bootstrap/media/HSM volumes. PKCS#11 recovery also requires the original HSM KEK,
token objects, provider configuration, and authentication credentials. SoftHSM
token/configuration volumes and original PIN files must stay together.

A database dump does not contain the external KEK or hardware-HSM state. The
manifest's SHA-256 digest checks consistency with the payload; it does not make
an untrusted backup authentic or encrypt the dump. Missing original encryption
material may permanently prevent recovery. Software KEK/DEK rotation is not
implemented and must not be attempted as part of an ordinary rebuild.

Only update between releases whose notes explicitly support the installed schema
and key format. Keep the same Compose project and persistent state. Same-image
container recreation is not evidence of cross-version database compatibility.
Do not use `docker compose down -v`, volume pruning, or token reinitialization for
routine updates.

### Known limitations

- AOKI remains a proof of concept.
- SCEP does not implement `GetNextCACert`, `GetCert`, `GetCRL`, `CertPoll`, or
  asynchronous `PENDING` responses. SCEP is not currently connected to workflow
  approval/polling processing.
- ML-DSA key generation/signing is available through the software backend;
  PKCS#11 ML-DSA key generation/signing is not implemented.
- Local-CA rollover does not automatically distribute replacement trust to every
  device. Remote-CA rollover is not available.
