# Audit Log

The audit log records important state changes in Trustpoint. It is intended for traceability and operational review, not for storing secrets or full request payloads.

Access: **Management > Audit Log**

## What is recorded

Each audit log entry contains:

| Field | Description |
|---|---|
| Timestamp | Time when the event was recorded. |
| Operation | Type of change or security-relevant action. |
| Target Type | Object type affected by the action. |
| Target | Human-readable object label captured at the time of the action. |
| Actor | User who triggered the action, or `System` for automated actions. |
| Details | Optional structured metadata.  |

The target label is preserved even if the original object is later deleted.

## Operations

Trustpoint records audit events for changes such as:

- credential issuance, renewal, revocation, and deletion
- device, domain, CA, signer, and user changes
- security configuration changes
- TLS certificate changes
- signing operations
- crypto backend operations such as key generation, signing, verification, and key destruction
