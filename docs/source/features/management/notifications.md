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
