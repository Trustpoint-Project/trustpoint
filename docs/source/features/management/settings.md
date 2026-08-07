# Settings

Trustpoint settings define global behavior for the web interface, security defaults, workflows, email delivery, logging, notifications, and metrics.

Access: **Management > Settings**

## Internationalization

Configure how Trustpoint displays regional information.

| Setting | Description |
|---|---|
| Date Format | Format used for dates and timestamps in the UI. |
| System Language | Default language used by the application. |
| Timezone | Timezone used for displayed timestamps. |

## User Interface

Configure the appearance and navigation behavior of the Trustpoint interface.

| Setting | Description |
|---|---|
| View Mode | Switch between the standard view and a simplified view. |

## Security

Configure global security defaults and restrictions.

Security level presets provide predefined configurations, for example for lab setups, brownfield-compatible environments, industrial standard deployments, hardened production systems, and critical infrastructure.

Advanced settings include:

- local auto-generated PKI
- minimum RSA key size
- maximum certificate validity
- maximum CRL validity
- CA certificate issuance
- self-signed CA import
- private key import
- permitted onboarding protocols
- permitted non-onboarding PKI protocols

Use stricter presets for production environments. Use relaxed settings only when required for compatibility with existing devices.

## Workflow Execution

Configure how background workflows are executed.

| Setting | Description |
|---|---|
| Mode | Defines whether workflows run through a worker, inline, or automatically depending on worker availability. |
| Worker stale after seconds | Time after which a worker is treated as unavailable if no heartbeat was received. |

When automatic or inline execution is enabled, the web process can process queued workflow jobs if no worker is available.

## SMTP Email

Configure outgoing email delivery for workflow and system messages.

| Setting | Description |
|---|---|
| Use SMTP server | Enables SMTP delivery. If disabled, email is written to Django's console backend. |
| SMTP host / port | Address and port of the SMTP server. |
| Default sender address | Sender address used when no specific sender is configured. |
| STARTTLS / SSL/TLS | Transport security mode. |
| Username / Password | Optional SMTP authentication credentials. |
| Test recipient | Address used to send a test email. |

## Logging

Configure the application log level.

Available levels:

- `DEBUG`
- `INFO`
- `WARNING`
- `ERROR`
- `CRITICAL`

Higher verbosity can help during troubleshooting. Secrets, raw key material, and signatures are not logged.

## Notifications

Configure global notification behavior and expiry warning thresholds.

| Setting | Description |
|---|---|
| Enabled | Enables or disables notifications globally. |
| Certificate expiry warning days | Days before a certificate expires to trigger a warning. |
| Issuing CA expiry warning days | Days before an Issuing CA certificate expires to trigger a warning. |
| CRL expiry warning days | Days before a CRL expires to trigger a warning. |

The page also shows the next scheduled notification check.

## Metrics

Configure Prometheus metrics export and view basic runtime metrics.

| Area | Description |
|---|---|
| Prometheus export | Enables the `/prometheus/metrics` endpoint for scraping. |
| Application metrics | Shows uptime, start time, and database size. |
| Container metrics | Shows memory usage, disk I/O, and network I/O. |

Container metrics are updated when the page is refreshed.