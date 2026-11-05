# Logging

Trustpoint provides access to application log files for operational review and troubleshooting.

Access: **Management > Logging**

## Log files

The logging view lists available log files with their first and last recorded log entry.

## Actions

- **View**: inspect a log file directly in Trustpoint.
- **Download**: download a single log file.
- **Download selected (tar.gz)**: download selected log files as a compressed tar archive.
- **Download selected (zip)**: download selected log files as a ZIP archive.

## Notes

The notification cycle checks the combined size of `trustpoint.log` and its numbered
rotated backups. It creates a system warning when the total exceeds **10 MiB**.
This leaves headroom above the normal retention of approximately 8 MiB (one 1 MiB
active file plus seven backups). Repeated checks update the existing warning and
preserve its status. No logs are deleted by this check.

Set `LOG_SIZE_WARNING_THRESHOLD_MIB` in Django settings to change the default, or
override it for a manual check:

```console
python manage.py check_log_size --max-size-mib 20
```

Only regular application log files in `LOG_DIR_PATH` are counted; database audit
logs are separate. The check uses file metadata and does not read log contents.

Logs are intended for troubleshooting and operational analysis. They are separate from the audit log, which records security-relevant state changes.
