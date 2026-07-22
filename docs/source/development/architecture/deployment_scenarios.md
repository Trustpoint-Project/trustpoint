# Deployment Scenarios

This document describes common deployment scenarios for Trustpoint, including network topology, security considerations, and configuration patterns.

## Scenario 1: Local CA in Isolated OT Network

**Use Case:** Air-gapped OT network with self-contained PKI, no enterprise CA connection

```{mermaid}
graph TB
    subgraph "Isolated OT Network"
        DEV1[PLC] -.EST/CMP.-> TP["Trustpoint / Local CA Mode"]
        DEV2[RTU] -.EST/CMP.-> TP
        DEV3[SCADA] -.EST/CMP.-> TP
        TP --> HSM["Hardware HSM / CA Key Storage"]
        TP --> DB[("PostgreSQL / Certificate DB")]
        ADMIN[Admin Workstation] -->|HTTPS| TP
    end
    

    
    style TP fill:#2196F3,color:#fff
    style HSM fill:#FF5722,color:#fff
```

**Configuration:**
- CA mode: `LOCAL_PKCS11` (production) or `AUTOGEN` (testing)
- Network: Single interface, no internet, optional mDNS
- Security: HSM for CA key, certificate-based device auth

**Pros:** Full control, no external dependencies, air-gap compatible

**Cons:** Requires HSM deployment, manual trust anchor distribution, no external CRL/OCSP

---

## Scenario 2: RA Connected to Enterprise PKI

**Use Case:** OT devices receive certificates from enterprise CA, centralized PKI management

```{mermaid}
graph TB
    subgraph "Enterprise Network"
        ENT_CA["Enterprise CA / EST/CMP Server"]
    end
    
    subgraph "OT Network"
        DEV1[PLC] -.EST.-> TP["Trustpoint / RA Mode"]
        DEV2[RTU] -.CMP.-> TP
        TP -.EST/CMP.-> FW[Firewall]
    end
    
    FW --> ENT_CA
    
    style TP fill:#2196F3,color:#fff
    style ENT_CA fill:#4CAF50,color:#fff
    style FW fill:#FF5722,color:#fff
```

**Configuration:**
- RA mode: `REMOTE_EST_RA` or `REMOTE_CMP_RA`
- Network: Firewall between OT and enterprise, outbound HTTPS to CA
- Security: TLS client auth to enterprise CA, network segmentation

**Firewall Rules:**
- Outbound: TCP 443 to enterprise CA
- Inbound: TCP 443 from device subnets
- Deny all other inter-network traffic

**Pros:** Centralized PKI, enterprise policy compliance, no Trustpoint HSM needed

**Cons:** Dependency on external CA availability, network connectivity required

---

## Scenario 3: Headless Device-Onboarding Service

**Use Case:** Large-scale automated provisioning via API, no web UI

```{mermaid}
graph LR
    subgraph "Device Management Platform"
        DMP[Orchestrator] -->|REST API| TP["Trustpoint / API-only"]
    end
    
    subgraph "Device Fleet"
        DEV1[Device 1] -.EST.-> TP
        DEV2[Device 2] -.EST.-> TP
        DEV3[Device N] -.EST.-> TP
    end
    
    TP --> CA["Enterprise CA / or Local CA"]
    
    style TP fill:#FF9800,color:#fff
    style DMP fill:#2196F3,color:#fff
```

**Configuration:**
- Headless mode: API-only access, JWT authentication
- REST API: Enable `rest_pki` app, rate limiting
- Monitoring: Prometheus `/metrics`, health check `/health/`

**Pros:** Scalable, no manual intervention, rapid deployment

**Cons:** Requires robust automation, reduced oversight

---

## Scenario 4: Development Deployment

**Use Case:** Local development and testing on single machine

```{mermaid}
graph TB
    DEV[Developer Machine] --> DC[Docker Compose]
    
    subgraph "Docker Compose Stack"
        DC --> TP[Trustpoint Container]
        DC --> PG[PostgreSQL Container]
        DC --> WORKER[Trustpoint Worker]
    end
    
    TP --> PG
    WORKER --> PG
    
    style DEV fill:#2196F3,color:#fff
    style DC fill:#4CAF50,color:#fff
```

**Configuration:**
- Deployment: `docker-compose.yml`
- CA mode: `AUTOGEN` (testing only)
- Database: PostgreSQL in container
- TLS: Self-signed certificate
- Tools: Django Debug Toolbar, hot reload, HTTP access

**Command:** `docker-compose up`

**Pros:** Fast setup, integrated environment, isolated

**Cons:** Not production-suitable, no persistent storage, no hardware security

---

## Best Practices

1. **Use HSM in production** - Protect CA keys with hardware HSM
2. **Implement monitoring** - Prometheus metrics, log aggregation, alerting
3. **Automate backups** - Daily database backups, offsite storage, regular restore testing
4. **Network segmentation** - Isolate OT networks, use firewalls
5. **TLS everywhere** - Enforce HTTPS, strong cipher suites, HSTS
6. **Regular updates** - Apply security patches, update dependencies
7. **Disaster recovery plan** - Document and test recovery procedures
8. **Access control** - Least privilege, MFA for admin accounts
9. **Audit logging** - Track certificate operations, integrate with SIEM
10. **Performance testing** - Load test before production deployment
