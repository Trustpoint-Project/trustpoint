# Trustpoint APIs Overview

Trustpoint provides two distinct REST API interfaces for different purposes:

## 1. Certificate Management APIs (PKI Protocols)

Certificate enrollment and lifecycle management using industry-standard PKI protocols and a simplified REST interface.

### Available Protocols

| Protocol | Base URL | Purpose | Standard |
|----------|----------|---------|----------|
| **CMP** | `/.well-known/cmp/` | Full-featured PKI protocol | RFC 4210, RFC 9480 |
| **EST** | `/.well-known/est/` | Simple enrollment over TLS | RFC 7030 |
| **REST PKI** | `/rest/` | JSON-based enrollment (Trustpoint-specific) | Custom |

---

## 2. Trustpoint Management API

RESTful API for managing Trustpoint resources, configuration, and administration.

### Base URL

```
https://<trustpoint-host>/api/
```

### Features

- **Certificate Authority Management**: Manage CAs, domains, and certificate profiles
- **Device Management**: Device registration, onboarding, and monitoring
- **User Management**: User accounts, authentication, and authorization
- **Workflow Management**: Approval workflows and automation
- **System Configuration**: Security settings, logging, and system health

### Authentication

The Management API uses JWT (JSON Web Tokens) for authentication:

```bash
# Obtain access token
curl -X POST https://trustpoint.example.com/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use token in requests
curl -X GET https://trustpoint.example.com/api/domains/ \
  -H "Authorization: Bearer <access_token>"
```

### OpenAPI Documentation

The complete API specification is available in **OpenAPI (Swagger)** format:

- **Swagger UI**: `https://<trustpoint-host>/api/schema/swagger-ui/`

---

```{toctree}
:maxdepth: 2

est
rest
cmp
rest_api
```
