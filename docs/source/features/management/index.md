# Management

The **Management** section contains global Trustpoint settings. These settings affect the whole instance and should usually be changed only by administrators.

Open it via **Management > Settings**.

## Available Settings

| Area | Purpose |
|---|---|
| Internationalization | Configure language and regional settings. |
| User Interface | Configure UI-related options. |
| Security | Define global security presets, key limits, certificate limits, and permitted PKI protocols. |
| Workflow Execution | Configure how Trustpoint workflows are executed. |
| SMTP Email | Configure outgoing email delivery. |
| Logging | Configure application logging behavior. |
| Notifications | Enable and configure how Trustpoint creates notifications. |
| Metrics | Enable or disable application metrics. |

Additional management pages are available directly in the sidebar.

| Page | Purpose |
|---|---|
| Logging | View and configure application log output. |
| Audit Log | Review security-relevant actions and configuration changes. |
| TLS | Configure TLS settings for the Trustpoint web interface and services. |
| Backups | Create, download, and manage Trustpoint backups. |
| Crypto Backend | Configure cryptographic backend settings. |
| Notifications | Manage notification settings and delivery behavior. |

## Logging

The **Logging** page is used to inspect or configure Trustpoint application logs. Logs help operators troubleshoot errors, failed workflows, protocol issues, and unexpected system behavior.

## Audit Log

The **Audit Log** records security-relevant actions in Trustpoint. Use it to review administrative changes, PKI operations, and other events that must be traceable.

## TLS Configuration

The **TLS** page is used to configure TLS for Trustpoint services. This includes the certificates and settings used to secure access to the Trustpoint web interface and related endpoints.

## Backups

The **Backups** page is used to create and manage backups of the Trustpoint instance.

## Crypto Backend

The **Crypto Backend** page contains settings for cryptographic operations. Use it to configure how Trustpoint handles keys and cryptographic material.

## Notifications

The **Notifications** page controls notification behavior. Depending on the configured delivery channels, Trustpoint can use notifications to inform administrators about relevant system or PKI events

```{toctree}
:maxdepth: 2

settings
logging
audit_logs
tls_settings
backups
notifications
```
