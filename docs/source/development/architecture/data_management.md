# Data Management

This document describes how Trustpoint stores, manages, and protects operational data, including devices, certificates, workflows, and cryptographic key metadata.

## Data Ownership and Storage

| Data category | Primary storage | Backup and protection | Notes |
|---|---|---|---|
| Devices and identities | PostgreSQL | Database backups | Device inventory, state, credentials |
| Certificates and chains | PostgreSQL | Database backups | Certificate objects, validity, revocation status |
| Trust domains and policies | PostgreSQL | Database backups | Domain configuration, certificate profiles |
| Workflow state | PostgreSQL | Database backups | Job queue, approvals, execution history |
| Issuing CA private keys | PKCS#11 token or HSM | HSM-specific backup | **Never** stored in PostgreSQL in production |
| Device private keys | On device | Device-specific backup | Generated on device, never known to Trustpoint |
| Application secrets | PostgreSQL (encrypted) | Database backups | Encrypted using `appsecrets` module |
| CRLs and trust anchors | PostgreSQL + filesystem | Database + file backups | CRLs served via HTTP endpoints |
| Logs and audit trails | Filesystem (`media/log/`) | External log aggregation | Should be forwarded to SIEM |
| Backups | Filesystem (`media/backups/`) | External backup storage | Encrypted database dumps |
| Bootstrap configuration | SQLite + filesystem | Container volume | Used during initial setup only |

**Note:** Detailed database schema is available in the auto-generated [Model Relationships](generated/model_relationships.rst) documentation.

## Backup and Restore

### Database Restore

**Setup Wizard:** Integrated restore during initial Trustpoint setup
   - Upload backup file during bootstrap phase
   - Automatic database restoration
   - Validates backup integrity before restoration

### Media Backup

**Backup methods:**

Trustpoint includes a dedicated backup module with the following capabilities:
- **Local download:** Manual backup download via web UI
- **SFTP upload:** Automated backup to remote SFTP server
- **Scheduled backups:** Configurable backup intervals
- **Retention policies:** Automatic cleanup of old backups

**Backup strategy:**
1. Configure backup module via web UI (Management → Backup)
2. Enable SFTP for automated offsite storage (recommended)
3. Set retention policies based on compliance requirements
4. Monitor backup status and verify integrity
5. Test restore procedures regularly

### HSM Key Backup

**Important:** Issuing CA keys in HSM must be backed up separately.

**Backup procedures:**
- **SoftHSM:** Backup token directory (`/var/lib/trustpoint/hsm/tokens/`)
- **Hardware HSM:** Follow vendor-specific procedures (key wrapping, secure backup)
- **Cloud HSM:** Use cloud provider's backup features

**Best practices:**
- Store HSM backups securely (encrypted, offline)
- Test key recovery procedures
- Document backup and restore steps
- Implement M-of-N backup key splitting for critical CAs

## Data Security Best Practices

1. **Encrypt database backups** - Use GPG or similar encryption
2. **Protect backup storage** - Restrict access to backup files
3. **Rotate encryption keys** - Implement key rotation for backup encryption
4. **Monitor database access** - Enable PostgreSQL audit logging
5. **Use strong passwords** - Enforce password policies for database users
6. **Limit database access** - Bind PostgreSQL to loopback only
7. **Regular backups** - Automate daily backups with offsite storage
8. **Test restore procedures** - Verify backups can be restored successfully
9. **Secure HSM backups** - Store HSM key backups in secure offline storage
10. **Implement data retention policies** - Define and enforce retention periods
