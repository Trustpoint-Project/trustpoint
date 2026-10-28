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

The container entrypoint records privileged deployment paths and ports in a
root-owned file at `/run/trustpoint/deployment.json` before starting the web
application. Configure these through the deployment environment. The web
application cannot override these settings through sudo or wizard state.

Wizard handoff files retain their `operational.env` / `operational.pending.env`
names but must contain JSON data. Do not shell-source them. Shell assignments,
malformed JSON, and unsupported settings are rejected.

Runtime switching exposes only the `--pending` and `--final` sudo actions. Both
select the corresponding deployment-configured file; arbitrary file arguments
are rejected. Wizard values and application environment variables are applied
only after dropping privileges to `www-data`.

The default application home and uv cache are `/run/trustpoint/home` and
`/run/trustpoint/uv-cache`. Overrides require an existing root-controlled parent
directory; these directories cannot be symlinks.

The application code, virtual environment, dependency metadata, and documentation
sources are root-owned and not writable by `www-data`. Translation catalogs are
compiled during the image build. Writable application paths are limited to
`trustpoint/media`, `trustpoint/collected_static`, `docker/trustpoint/nginx/tls`,
and `docs/build`, plus separately configured runtime state outside the source tree.
Documentation build locks are stored under `MEDIA_ROOT`. Mount additional code
or configuration read-only to preserve this boundary.

The privileged boundary has an isolated Linux regression test using real sudo
rules and process identities. It replaces service operations with observations,
so it does not start Trustpoint or require a database:

```bash
docker build -f tests/docker_security/Dockerfile -t trustpoint-runtime-boundary-test .
docker run --rm --network=none trustpoint-runtime-boundary-test
```

## Django signing key

Initialize the deployment's key once with `sudo python3 docker/init_secret.py`.
The helper creates `secrets/django_secret_key` on the host with owner root, group
33 (`www-data` in the image), and mode `0440`. Existing keys are never overwritten
or silently repaired. Compose mounts the file read-only in web and worker.

| Variable | Default | Description |
|---|---|---|
| `DJANGO_SECRET_KEY_HOST_FILE` | `./secrets/django_secret_key` | Host source file for the Compose secret. |
| `DJANGO_SECRET_KEY_FILE` | `/run/secrets/django_secret_key` | Mounted path read by production Django settings. |
| `TRUSTPOINT_IMAGE` | `trustpointproject/trustpoint:latest` | Application image used by web and worker. |
| `TRUSTPOINT_NETWORK_NAME` | `trustpoint-net` | Network name for the standard and worker configurations. |

Production never generates a key and fails if the mounted file is missing,
empty, or unreadable. A separate local-development key is cached under the ignored
`var/development/` directory only when running non-Docker development settings.

Keep the host key across upgrades. Import an existing installation's exact key
with `sudo python3 docker/init_secret.py --import-from /path/to/saved-key` before
replacing its containers. A conflicting existing destination is left unchanged
and reported as an error. See the [Docker deployment guide](docker_deployment.rst)
for fresh installation, upgrades, and recovery. Importing Django signing keys
does not provide a migration path for pre-1.0 encrypted databases.

## Database

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `trustpoint_db` | PostgreSQL database name. |
| `DATABASE_USER` | `admin` | PostgreSQL user. |
| `DATABASE_PASSWORD` | `testing321` | PostgreSQL password. Change for production deployments. |
| `DATABASE_PASSWORD_FILE` | unset | Path to a mounted database-password secret. Takes precedence over `DATABASE_PASSWORD`; startup fails if the configured file cannot be read. |
| `DATABASE_HOST` | `postgres` | PostgreSQL hostname. |
| `DATABASE_PORT` | `5432` | PostgreSQL port. |
| `DATABASE_ENGINE` | `django.db.backends.postgresql` | Django database backend. |

The setup wizard requires its database password to match either the mounted
`DATABASE_PASSWORD_FILE` secret or `DATABASE_PASSWORD` supplied by the deployment.
The operational handoff file stores connection settings and the secret-file path,
but never the password itself. Keep the external credential available to the web
container and workers across restarts. Supply or mount a replacement credential
before applying a password change in the wizard.

## TLS and Network Configuration

| Variable | Default | Description |
|---|---|---|
| `TP_TLS_IPV4_ADDRESSES` | `127.0.0.1` | Comma-separated IPv4 addresses used for TLS SANs, Django `ALLOWED_HOSTS`, and CSRF configuration. |
| `TP_TLS_IPV6_ADDRESSES` | `::1` | Comma-separated IPv6 addresses. |
| `TP_TLS_DNS_NAMES` | `localhost` | Comma-separated DNS names. |
| `TP_HTTP_PORT` | `80` | HTTP port. |
| `TP_HTTPS_PORT` | `443` | HTTPS port. |

## Outgoing Mail

Trustpoint maps the following environment variables to Django's `MAILERS['default']` configuration.
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
| `TP_SECURITY_PERMITTED_CMP_HMAC_ALGORITHMS` | Comma-separated HMAC names | Restrict accepted CMP MACs, e.g. `HMAC_SHA256,HMAC_SHA384,HMAC_SHA512`. Empty disables shared-secret authentication. Lab / Custom permits any supported HMAC. |
| `TP_SECURITY_ALLOW_CMP_HMAC_SHA1` | Boolean | Accept CMP HMAC-SHA1 protection (including the OpenSSL default). Allowed by Lab and Brownfield presets; may be further restricted to false. |
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

### Software database KEK (Trustpoint 1.0)

Initialize the independent software KEK with `sudo python3 docker/init_secret.py --type kek`
or provision both secrets using `--type all`. Compose mounts `secrets/trustpoint_software_kek`
read-only at `/run/secrets/trustpoint_software_kek`. Set `TRUSTPOINT_SOFTWARE_KEK_HOST_FILE`
to change the host source; `TRUSTPOINT_SOFTWARE_KEK_FILE` selects the application input.
The input must contain exactly 64 hexadecimal characters, without whitespace.
It is never derived from Django's signing key or generated by application startup.
Preserve it separately alongside database backups: losing it may permanently prevent
recovery of encrypted fields. PKCS#11-only deployments use the HSM KEK instead and
must select the documented Compose overrides to omit the software-secret mount.
Pre-1.0 encrypted database migration and key rotation are unsupported.
