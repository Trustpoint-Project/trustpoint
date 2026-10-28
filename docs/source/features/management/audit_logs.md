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

## Writing audit events

Each business operation has one audit owner: the view, API handler, or service
that coordinates the complete operation. Replace an existing audit call when
adopting a helper for the same event. Model saves and signals do not independently
write security-change events.

For registered security-sensitive objects, use
`management.security_change_audit.security_change(target=instance, actor=user)`
around the complete update, including related-object changes. The scope reads the
original database state, waits for all saves to finish, and writes one entry with
the final persisted differences. Unchanged submissions produce no entry. Changes
and their audit entry share a transaction; an audit write failure rolls back the
change. Use `action='deleted'` for deletion to retain the original object identity.

For creation, call `audit_security_change(target=instance, actor=user, before=None,
action='created')` after saving, within the same transaction. Import forms that
persist during validation require a transaction around validation as well.
Backend setup uses `provider_configuration_changes(actor=user_or_none)` to capture
one event per changed configuration object, including initialization and removal;
nested setup scopes share the outer audit owner.

The helpers select object-specific operations, preserve the actor, and redact
sensitive configuration references. Domain certificate-profile assignments and
truststore certificate membership are included in their parent object's event.
Do not additionally audit each through-model save for those operations.
Distinct business events, such as credential issuance and crypto signing, retain
their dedicated operation types and owners.

`MODEL_CREATED`, `MODEL_UPDATED`, and `MODEL_DELETED` remain available as legacy
filter choices for historical rows. New production writers use specific types.
Existing audit history is preserved by the operation-choice migration.
