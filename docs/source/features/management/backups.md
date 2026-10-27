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
| Remote Directory | Directory on the SFTP server, for example `/upload/trustpoint/`. |

Use **Save Settings** to store the SFTP configuration. Use **Reset Settings** to discard changes.

## Notes

The notification cycle warns when no completed local backup is available from the
last **7 days**, including when no backups exist. Set `BACKUP_MAX_AGE_DAYS` in
Django settings to change this threshold, or override it for a manual check:

```console
python manage.py check_backup_age --max-age-days 3
```

The check uses the completion timestamp in the manifest written after a successful
`trustpointbackup` command. Only nonempty local backup payloads with supported
manifests and valid timestamps are counted. Legacy backups without manifests are
not counted. It checks availability and age without verifying payload checksums or
contacting SFTP storage. A missing backup directory is treated as no available backup.
Repeated overdue checks update the same warning and preserve its status; a recent
backup stops further warnings but does not automatically close the historical notification.

Backups should be stored outside the Trustpoint host if they are required for disaster recovery. Protect backup files because they may contain sensitive Trustpoint configuration and PKI data.
