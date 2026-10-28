# Backups

Trustpoint supports local backups and optional remote backup storage via SFTP.

Access: **Management > Backups**

## Local backups

The local backup table lists backups stored on the Trustpoint system.

Available actions:

- **Create Local Backup** creates a new backup on the Trustpoint system.
- **Download (tar.gz)** downloads selected backups as a tar archive.
- **Download (zip)** downloads selected backups as a zip archive.
- **Delete** removes selected local backups.

## Before upgrading

Create a new local backup through **Management > Backups > Create Local Backup**
before every upgrade, then download it using the row's **Download** action or the
**Download Selected** archive actions. Keep the database payload and matching
manifest sidecar together in a protected location outside the Trustpoint instance.
Do not continue with the upgrade if creation or download fails.

Database backups do not include the external software KEK, Django signing key, or
HSM token. Preserve those separately as described in the [upgrade guide](upgrading.rst).

The matching manifest checks the payload digest and compatibility metadata. It
does not encrypt the payload or authenticate an untrusted backup source. Only
restore backups from a trusted source for an explicitly compatible release.
A raw PostgreSQL dump must still match the intended database schema and encryption
format. See the [backup/restore contract](../../development/architecture/backup_restore.rst)
for the separate signing-key, software KEK, and HSM recovery requirements.

## SFTP backup

SFTP backup stores backups on a remote server.

Enable **Use SFTP storage** and configure:

| Setting | Description |
|---|---|
| Host | SFTP server hostname or IP address. |
| Port | SFTP port, usually `22` or `2222`. |
| Username | SFTP user name. |
| Authentication Method | Authentication method used for the SFTP connection. |
| Password | Password for password-based authentication. |
| SSH Private Key / Key Passphrase | PEM private key and optional passphrase for SSH-key authentication. |
| Remote Directory | Directory on the SFTP server, for example `/upload/trustpoint/`. |

Use **Save Settings** to store the SFTP configuration. Use **Reset Settings** to
remove the saved configuration.

Passwords, SSH private keys, and key passphrases are encrypted using the
application-secret backend and are never displayed in the form. Leave a secret
field blank to keep its value, supply a replacement to change it, or select its
**Clear stored** checkbox to remove it. Required credentials cannot be cleared
while that authentication method is enabled; disable SFTP storage or change
authentication method first. Changing the method removes the stored credentials
for the previous method. **Test Connection** uses these same choices without
saving the configuration. Access to the backup page requires backup-management
permission, including when only viewing settings.

## Notes

The notification cycle warns when no completed local backup is available from the
last **7 days**, including when no backups exist. Set `BACKUP_MAX_AGE_DAYS` in
Django settings to change this threshold, or override it for a manual check:

```bash
# From the repository root, with the intended instance configuration:
uv run trustpoint/manage.py check_backup_age --max-age-days 3
```

The check uses the completion timestamp in the manifest written after a successful
`trustpointbackup` command. Only nonempty local backup payloads with supported
manifests and valid timestamps are counted. Legacy backups without manifests are
not counted. It checks availability and age without verifying payload checksums or
contacting SFTP storage. A missing backup directory is treated as no available backup.
Repeated overdue checks update the same warning and preserve its status; a recent
backup stops further warnings but does not automatically close the historical notification.

Backups should be stored outside the Trustpoint host if they are required for disaster recovery. Protect backup files because they may contain sensitive Trustpoint configuration and PKI data.
