# Runtime and Container Architecture

Trustpoint is implemented as a Django application deployed in Docker containers. The standard deployment uses three containers: the main web application, a workflow worker, and a PostgreSQL database.

## Container Architecture

```mermaid
flowchart TB
    subgraph CLIENTS[Clients and devices]
        BROWSER[Web browser]
        API[API clients<br/>JWT authentication]
        DEVICE[Industrial devices<br/>EST, CMP, AOKI]
        OPC_UA[OPC UA clients]
    end

    subgraph WEB_EDGE[Web edge: NGINX]
        NGINX[NGINX<br/>TLS termination<br/>static assets<br/>optional mTLS]
    end

    subgraph TRUSTPOINT_WEB[Trustpoint web container]
        GUNICORN[Gunicorn WSGI server<br/>4 workers, 300s timeout]
        DJANGO[Django application<br/>protocol handlers<br/>REST APIs<br/>web UI]
        QCLUSTER[Django-Q2 qcluster<br/>scheduled tasks<br/>CRL generation<br/>notifications]
    end

    subgraph TRUSTPOINT_WORKER[Trustpoint worker container]
        WF_WORKER[workflows2_worker<br/>long-running jobs<br/>approvals<br/>webhooks]
    end

    subgraph DATA_LAYER[Data and cryptography]
        POSTGRES[(PostgreSQL<br/>operational state)]
        FILES[Filesystem<br/>media, logs, backups]
        CRYPTO_API[Crypto provider abstraction]
        PKCS11_IMPL[PKCS#11 provider<br/>SoftHSM or hardware HSM]
    end

    subgraph EXTERNAL_SVC[External services]
        EXTERNAL_CA[External CA<br/>RA mode]
        WEBHOOK_TARGET[Webhook endpoints<br/>ERP, MES, IAM]
        SMTP[SMTP server]
        PROMETHEUS[Prometheus metrics]
    end

    BROWSER -->|HTTPS| NGINX
    API -->|HTTPS, JWT| NGINX
    DEVICE -->|EST, CMP, AOKI| NGINX
    OPC_UA -->|GDS Push| NGINX

    NGINX -->|Proxy to :8000| GUNICORN
    NGINX -.->|Serve static files| FILES
    GUNICORN --> DJANGO

    DJANGO <--> POSTGRES
    DJANGO <--> FILES
    DJANGO --> CRYPTO_API
    QCLUSTER <--> POSTGRES

    WF_WORKER <--> POSTGRES
    WF_WORKER --> CRYPTO_API

    CRYPTO_API --> PKCS11_IMPL

    DJANGO -.->|RA requests| EXTERNAL_CA
    WF_WORKER --> WEBHOOK_TARGET
    WF_WORKER --> SMTP
    DJANGO --> PROMETHEUS
```

## Container Roles

### Trustpoint Web Container

**Processes:**

| Process | Role | Details |
|---|---|---|
| **NGINX** | TLS termination, routing | Port 80 (HTTP for CMP/CRL only), Port 443 (HTTPS, TLS 1.2/1.3), proxies to Gunicorn on 127.0.0.1:8000 |
| **Gunicorn** | WSGI server | 4 workers, 300s timeout, handles protocol endpoints, REST API, web UI |
| **Django** | Application logic | Protocol handlers, REST API, web UI views, certificate operations |
| **Django-Q2 qcluster** | Scheduled tasks | CRL generation, certificate expiry notifications, maintenance |

**Entry point:** `/docker/trustpoint/entrypoint.sh` with `TRUSTPOINT_SERVICE_ROLE=web`

### Trustpoint Worker Container

**Process:** `workflows2_worker` - Background job processor

**Responsibilities:**
- Claims jobs from database queue
- Executes approval workflows
- Calls external webhooks
- Sends email notifications
- Handles long-running certificate operations
- Lease-based job locking (default: 30 seconds)

**Entry point:** `/docker/trustpoint/entrypoint.sh` with `TRUSTPOINT_SERVICE_ROLE=worker`

### PostgreSQL Container

- Stores all operational data (devices, certificates, domains, workflows, users)
- Listens on `127.0.0.1:5432` (not exposed to external network)
- Data persisted in `postgres_data` Docker volume

## Bootstrap vs Operational Phases

Trustpoint operates in two distinct phases:

### Phase Comparison

| Aspect | Bootstrap Phase | Operational Phase |
|---|---|---|
| **Purpose** | Initial setup and configuration | Normal production operation |
| **Active when** | No operational config file, first-time deployment | Operational config exists, `TRUSTPOINT_PHASE=operational/auto` |
| **Features** | Setup wizard UI, bootstrap SQLite DB, TLS cert generation, minimal routes | Full functionality, protocol endpoints, REST API, workflows |
| **Services** | Web container only | All three containers (web, worker, postgres) |
| **Database** | SQLite (temporary) | PostgreSQL |

### Phase Transition

```mermaid
stateDiagram-v2
    [*] --> AutoDetection
    AutoDetection --> Bootstrap: No operational marker
    AutoDetection --> Operational: Operational configuration present

    Bootstrap --> SetupWizard: Configure admin, database, crypto, TLS
    SetupWizard --> OperationalHandoff: Validate and persist configuration
    OperationalHandoff --> Operational: Restart or switch runtime

    Operational --> Operational: Full application active
```

**Phase detection logic:**
1. Check `TRUSTPOINT_PHASE` environment variable
2. If `auto`, check for operational marker files (`/var/lib/trustpoint/bootstrap/operational.env`, `operational.ready`)
3. Files exist → operational phase; otherwise → bootstrap phase

**Security benefit:** Limits exposed endpoints until system is properly configured.
