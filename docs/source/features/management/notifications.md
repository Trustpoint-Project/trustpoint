# Notifications

Scheduled checks cover configured certificate, device, backup, log, and policy
conditions. Automated system-health assessment and vulnerability scanning are
unavailable. If a check fails to execute, the remaining checks still run and the
overall task reports failure to its caller.

When notifications are enabled, failed EST, CMP and REST requests handled by the
shared request response path create a warning immediately. SCEP malformed messages
and CertRep failures also create warnings, including protocol failures returned
with HTTP 200. Successful requests and requests awaiting workflow approval do not
create failure notifications.

Each failed request creates one warning with its protocol, operation and resolved
device/domain references where available. Request bodies, credentials and raw
exception messages are not stored in the notification. Repeated response building
for the same request context does not create duplicates. Notification storage
failures are logged without changing the protocol response.

Notifications show relevant system, domain, device, issuing CA, and certificate events in Trustpoint.

Access: **Management****Notifications**

## Overview

The notification list shows all generated notifications with type, source, description, creation time, and available actions.

Notifications can be filtered by:

- severity: `Critical`, `Warning`, `Info`, `Setup`
- source: `System`, `Domain`, `Device`, `Issuing CA`, `Certificate`
- time range: `Today`, `Last 7 Days`, `Last 30 Days`, `All`
- read state: show only unread notifications

Use **Refresh** to reload the list and **Mark All as Read** to clear unread indicators.

## Notification details

Open a notification to view its full context.

Use **Mark as Read** to acknowledge a notification.

## Typical use

Use notifications to identify items that need attention, such as devices that are not onboarded, certificates or CRLs approaching expiry, issuing CA warnings, or setup-related system messages.

Notification behavior and expiry warning thresholds are configured under **Management > Settings > Notifications**.

User client certificates listed under **Profile > Certificate Authentication** are
included in the scheduled certificate checks. They produce a warning within the
configured **Cert expiry warning days** and a critical notification once expired.
These notifications identify the user and certificate identifier. Repeated checks
do not duplicate the same expiry event for a certificate. Enable notifications
and automatic notification checks in Settings to run these checks periodically.

## Operational alerts

The notification cycle also checks:

- **API credential expiry:** Active credentials for active service accounts use
  the earlier of their explicit expiry and the maximum lifetime in Account
  Security settings. Warnings use **Cert expiry warning days**; expiration is
  critical. Credentials with no expiry or lifetime policy do not generate alerts.
- **Cryptographic backend availability:** A live capability probe of the
  configured backend and authenticated PKCS#11 session check create a critical
  notification on failure. The check avoids login attempts when the token reports
  a PIN lockout risk. After an authentication failure, automatic login retries
  pause; correct the configuration and mark the alert solved to allow another
  check. Unresolved authentication-failure alerts cannot be deleted, preserving
  this pause. No backend configured means no availability alert.
- **Account lockouts:** Repeated failed logins create a warning immediately when
  an account is blocked. Scheduled checks also detect existing blocked accounts.
  Unblocking the account resolves the alert immediately, so a subsequent lockout
  becomes unread even before the next scheduled check.
- **Workflow failures and overdue approvals:** Workflow instances in error or
  timed-out states generate warnings. Pending or expired approvals generate
  warnings after their configured deadline while the instance is awaiting a
  decision or has timed out. Approvals without a deadline do not generate overdue
  alerts. Existing stored failures are included when checks are enabled.

Local database backup creation and SFTP backup upload failures create critical
notifications immediately. Application logs contain the failure details; raw
errors, secrets, API client IDs, and workflow payloads are omitted from alerts.
Local backup outcome notifications are updated while the shared backup lock is
held, so an earlier success cannot clear a later failure.

Repeated checks update the same alert for each issue. Recovery marks backend,
backup, credential, account-lockout, and approval alerts solved; a recurrence
reopens the alert as unread. Credential alerts also become unread when escalating
from warning to critical. Workflow failure notifications remain as history and
are not reprocessed or reopened by subsequent checks.

Scheduled checks propagate notification storage errors to the runner, which
reports the failed checks but still schedules the next cycle. Login and backup
operations continue to report their original outcome if notification storage
fails.

Authenticated page renders check for a missed notification cycle independently of
the Django-Q2 worker. A warning appears when the stored next-run time is overdue
by one configured interval, with a minimum grace of five minutes, or when the
enabled cycle has no scheduled timestamp. Successful scheduling clears this
warning on the next page render. This detects worker stalls while the web app and
database remain available; external monitoring is still needed for a complete
application outage or periods with no page requests.
