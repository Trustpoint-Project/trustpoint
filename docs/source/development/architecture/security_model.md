# Security Model

This document describes Trustpoint's security architecture, trust boundaries, authentication mechanisms, and security-relevant design decisions.

## Trust Boundaries

NGINX forms the external network boundary, terminating TLS and forwarding authenticated requests to Django via HTTP on `127.0.0.1:8000`.

```{mermaid}
flowchart LR
    UNTRUSTED["Untrusted network / devices, browsers, API clients"]

    subgraph TRUST_BOUNDARY[Trustpoint container]
        NGINX["NGINX / :80 HTTP: CMP, CRL only / :443 HTTPS: all other traffic / TLS 1.2/1.3 / optional mTLS"]
        GUNICORN["Gunicorn + Django / :8000 HTTP on loopback / trusted proxy headers"]
        STATIC["Static files / /collected_static"]
    end

    DB[("PostgreSQL / 127.0.0.1:5432 / not externally reachable")]
    
    HSM["HSM or PKCS#11 provider / local or network HSM"]

    UNTRUSTED -->|HTTP| NGINX
    UNTRUSTED -->|HTTPS + optional client cert| NGINX
    NGINX -->|Serve| STATIC
    NGINX -->|Proxy with SSL headers| GUNICORN
    GUNICORN <--> DB
    GUNICORN --> HSM
```

## Security Boundaries

| Boundary | Role | Key Controls |
|---|---|---|
| **NGINX Perimeter** | External network boundary | TLS 1.2/1.3, strong ciphers, optional mTLS, HTTP only for CMP/CRL |
| **Trusted Proxy Headers** | Pass client cert metadata | Headers set by NGINX only, Django trusts via `SECURE_PROXY_SSL_HEADER` |
| **PostgreSQL Isolation** | Database access control | Listens on 127.0.0.1:5432 only, no external exposure |
| **HSM Access Control** | Cryptographic key protection | PKCS#11 access restricted, PIN authentication, keys never exported in production |
| **File System Permissions** | Protect sensitive files | Django runs as `www-data` (non-root), restricted file ownership |

**Headers passed by NGINX:**
- `SSL-Client-Cert`: Client certificate (PEM, URL-encoded)
- `X-SSL-Client-Verify`: Verification status
- `X-SSL-Client-S-DN`: Client certificate subject DN

Upstream EST/CMP certificates undergo shared path validation before storage,
including CA signing permissions, validity, path length, name constraints and
critical extensions. Configured truststore entries are explicit CA trust anchors;
response certificates cannot add trust. Unsupported certificate-policy constraints
fail closed. Profile checks separately bind the issued key, identity and extensions
to the authorized request; path validation does not fetch CRLs or OCSP responses.

## Authentication Mechanisms

### Web UI Authentication

- **Method:** Django session-based authentication
- **Login:** `/users/login/`
- **Security:** HTTPS-only cookies, CSRF protection, Argon2 password hashing
- **Session timeout:** Configurable
- **Password requirements:** Minimum 8 characters, Django validators

### REST API Authentication

- **Method:** JWT (JSON Web Tokens) via `djangorestframework-simplejwt`
- **Token endpoints:** `POST /rest/auth/login/`, `POST /rest/auth/refresh/`
- **Usage:** `Authorization: Bearer <access_token>`
- **Token lifetime:** Access 5min, Refresh 24h (configurable)
- **Security:** Token rotation, blacklist support, audience/issuer validation

### EST Protocol Authentication

| Method | Use Case | Details |
|---|---|---|
| **HTTP Basic Auth** | Operator enrollment | Username/password against Django user DB |
| **Client certificate** | Device authentication | mTLS with IDevID, subject DN extraction |

**Endpoints:** `/.well-known/est/<domain>/`

### CMP Protocol Authentication

| Method | Use Case | Details |
|---|---|---|
| **Shared secret (PBMAC1)** | Bootstrap enrollment | Pre-shared secret, one-time or per-device |
| **Client certificate** | Renewal/rekeying | mTLS certificate-based |

**Endpoints:** `/.well-known/cmp/<domain>/`

Upstream CMP transactions currently use PBM shared-secret protection. Replies
must authenticate and match the request's transaction ID, nonces, operation and
certificate request ID before status handling or certificate extraction. PBM work
is bounded; unprotected replies and unsupported protection modes are rejected.
TLS certificate verification remains disabled for these upstream connections.

#### Explicit CMP certificate confirmation

CMP responses advertise a persisted confirmation deadline; retries do not extend
it. `TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_SECONDS` defaults to `300` (must be positive).
`TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_POLICY` selects `revoke` (default) or `log`
(retain the certificate), as allowed by
[RFC 9483 §4.1.1](https://www.rfc-editor.org/rfc/rfc9483.html#section-4.1.1).
Expiry rejects the transaction and invalidates initialization bootstrap secrets,
leaving onboarding pending. Late confirmations are rejected.

Apply migrations before deployment; existing pending confirmations receive a
five-minute grace period. Cleanup runs every minute through Django-Q (`qcluster`
with scheduling enabled), or run `python trustpoint/manage.py expire_cmp_confirmations`
from an external scheduler. Transaction lookups and secret rotation also trigger cleanup.

### Other Protocols

- **AOKI:** Protocol-specific bootstrap credentials
- **OPC UA GDS Push:** Certificate-based with OPC UA security policies

## Known Security Limitations

2. **Audit trail:** Logs not cryptographically signed or tamper-proof
3. **Certificate Transparency:** CT log submission not implemented
4. **Multi-tenancy:** No tenant isolation (separate instances required)
5. **Key rollover:** Manual CA key rotation requires downtime
6. **Rate limiting:** No built-in rate limiting (use reverse proxy)
7. **Brute-force protection:** No automatic account lockout

## Security Best Practices

1. **Use hardware HSM in production** - SoftHSM for development only
2. **Enable mutual TLS** - Authenticate devices with certificates in sensitive environments
3. **Rotate JWT tokens frequently** - Keep access token lifetime short
4. **Forward logs to SIEM** - Enable centralized security monitoring
5. **Encrypt database backups** - Protect sensitive data at rest
6. **Review approval workflows** - Ensure proper segregation of duties
7. **Keep software updated** - Apply security patches promptly
8. **Use strong passwords** - Enforce complexity and rotation policies
9. **Limit admin access** - Apply principle of least privilege
10. **Monitor certificate lifecycle** - Alert on anomalous issuance or revocation patterns
