# Changelog

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
