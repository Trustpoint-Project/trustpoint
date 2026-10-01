# Environment Configuration

Trustpoint can be configured through environment variables using a `.env` file.

Create the file from the provided example:

```bash
cp .env.example .env
```

Unless stated otherwise, all variables are optional.

## Startup

| Variable | Values / Default | Description |
|---|---|---|
| `TRUSTPOINT_PHASE` | `auto`, `bootstrap`, `operational` | Controls whether Trustpoint determines the startup phase automatically, starts the setup wizard, or starts directly in operational mode. |

## Database

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `trustpoint_db` | PostgreSQL database name. |
| `DATABASE_USER` | `admin` | PostgreSQL user. |
| `DATABASE_PASSWORD` | `testing321` | PostgreSQL password. Change for production deployments. |
| `DATABASE_HOST` | `postgres` | PostgreSQL hostname. |
| `DATABASE_PORT` | `5432` | PostgreSQL port. |
| `DATABASE_ENGINE` | `django.db.backends.postgresql` | Django database backend. |

## TLS and Network Configuration

| Variable | Default | Description |
|---|---|---|
| `TP_TLS_IPV4_ADDRESSES` | `127.0.0.1` | Comma-separated IPv4 addresses used for TLS SANs, Django `ALLOWED_HOSTS`, and CSRF configuration. |
| `TP_TLS_IPV6_ADDRESSES` | `::1` | Comma-separated IPv6 addresses. |
| `TP_TLS_DNS_NAMES` | `localhost` | Comma-separated DNS names. |
| `TP_HTTP_PORT` | `80` | HTTP port. |
| `TP_HTTPS_PORT` | `443` | HTTPS port. |

## Outgoing Mail

If `EMAIL_HOST` is not configured, Trustpoint uses Django's console email backend.

| Variable | Default | Description |
|---|---|---|
| `DEFAULT_FROM_EMAIL` | `no-reply.trustpoint@localhost` | Sender address used for outgoing email. |
| `EMAIL_HOST` | unset | SMTP server. Setting this enables SMTP delivery. |
| `EMAIL_PORT` | `587` | SMTP server port. |
| `EMAIL_USE_TLS` | automatic | Enable STARTTLS. |
| `EMAIL_USE_SSL` | automatic | Enable implicit TLS. |
| `EMAIL_HOST_USER` | unset | SMTP username. |
| `EMAIL_HOST_PASSWORD` | unset | SMTP password. |
| `EMAIL_TIMEOUT` | `10` | SMTP connection timeout in seconds. |

## Security Configuration

`TP_SECURITY_MODE` defines the security baseline. Additional security variables may only make the selected preset more restrictive.

| Variable | Values | Description |
|---|---|---|
| `TP_SECURITY_MODE` | `LAB`, `BROWNFIELD`, `INDUSTRIAL`, `HARDENED`, `CRITICAL` | Selects the security preset. |
| `TP_SECURITY_RSA_MINIMUM_KEY_SIZE` | Integer / `null` | Minimum allowed RSA key size. |
| `TP_SECURITY_MAX_CERT_VALIDITY_DAYS` | Integer / `null` | Maximum certificate validity period. |
| `TP_SECURITY_MAX_CRL_VALIDITY_DAYS` | Integer / `null` | Maximum CRL validity period. |
| `TP_SECURITY_ALLOW_CA_ISSUANCE` | Boolean | Allow issuance of CA certificates. |
| `TP_SECURITY_ALLOW_AUTO_GEN_PKI` | Boolean | Allow use of the automatically generated PKI. |
| `TP_SECURITY_ALLOW_SELF_SIGNED_CA` | Boolean | Allow importing self-signed CAs. |
| `TP_SECURITY_ALLOW_IMPORTED_PRIVATE_KEYS` | Boolean | Allow importing existing private-key credentials. |
| `TP_SECURITY_AUTO_GEN_PKI` | Boolean | Enable the local automatically generated PKI. |
| `TP_SECURITY_PERMITTED_NO_ONBOARDING_PKI_PROTOCOLS` | Comma-separated list | Allowed PKI protocols without onboarding. |
| `TP_SECURITY_PERMITTED_ONBOARDING_PROTOCOLS` | Comma-separated list | Allowed onboarding protocols. |

Supported no-onboarding protocols:

```text
CMP_SHARED_SECRET
EST_USERNAME_PASSWORD
MANUAL
REST_USERNAME_PASSWORD
```

Supported onboarding protocols:

```text
MANUAL
CMP_IDEVID
CMP_SHARED_SECRET
EST_IDEVID
EST_USERNAME_PASSWORD
AOKI
BRSKI
OPC_GDS_PUSH
REST_USERNAME_PASSWORD
AGENT
```

Boolean values accept `true`, `false`, `1`, `0`, `yes`, `no`, `on`, and `off`.

Unset security restriction variables inherit the selected preset. Environment restrictions cannot enable functionality that is prohibited by the preset.

If a new security configuration conflicts with existing devices or CAs, the requested change is rejected, the previous valid configuration remains active, and the conflict is logged.

## Automatic Setup

Automatic setup can be used for automated testing and repeatable deployments.

| Variable | Default | Description |
|---|---|---|
| `TP_AUTO_SETUP` | `false` | Skip the interactive setup wizard and configure Trustpoint from environment variables. |
| `TP_ADMIN_USERNAME` | unset | Superuser username. Required when auto-setup is enabled. |
| `TP_ADMIN_PASSWORD` | unset | Superuser password. Required when auto-setup is enabled. |
| `TP_ADMIN_EMAIL` | unset | Optional superuser email address. |
| `TP_INJECT_DEMO_DATA` | `false` | Inject example devices and certificates for development and demonstration environments. |

When automatic setup is enabled, the TLS certificate is generated using the configured `TP_TLS_*` values.
