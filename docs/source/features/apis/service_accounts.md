# Service Accounts

Trustpoint supports API-only service accounts for non-interactive automation. These accounts are intentionally restricted from the Web UI and authenticate with OAuth 2.0 client credentials instead of human username/password login.

## Why use service accounts?

Service accounts are useful when an external system, workflow, or integration needs access to the Trustpoint API without interactive browser login. Typical use cases include:

- CI/CD automation
- internal integration services
- ticketing or provisioning jobs
- headless system automation

These users are meant for programmatic access only and should not be used for human logins.

## Create a service account

You can create a service account from the management UI or from the command line:

```bash
uv run trustpoint/manage.py create_service_account my_integration
```

The command creates a service account and emits a client ID and secret once. Save the secret immediately because it is not retrievable later.

The default role is **Service Account**. Initialize built-in groups during setup
before running the command. To select another existing role, pass
`--role '<role-name>'` and review its permissions; `Default` is not a built-in role.

## Request an access token

Use the OAuth 2.0 client credentials grant against the token endpoint:
replace the hostname and CA-bundle path below with your deployment's values.

```bash
curl -X POST 'https://<trustpoint-host>/api/token/' \
  --cacert /path/to/trustpoint-server-ca.pem \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "sa_...",
    "client_secret": "..."
  }'
```

The response is a JWT token payload similar to:

```json
{
  "access": "<jwt-access-token>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## Use the token

Include the access token in the `Authorization` header for protected API requests:

```bash
curl --cacert /path/to/trustpoint-server-ca.pem \
  -H 'Authorization: Bearer <access_token>' 'https://<trustpoint-host>/api/devices/'
```

## Security notes

- Service accounts are API-only and are blocked from browser-based access.
- The secret should be treated like a private credential and rotated when needed.
- Prefer short-lived credentials and least-privilege permissions for integrations.
- Do not share a service account secret across multiple services unless you intentionally want a shared automation identity.

## Related docs

- [Trustpoint APIs Overview](index.md)
- [Trustpoint Management API](rest_api.rst)
