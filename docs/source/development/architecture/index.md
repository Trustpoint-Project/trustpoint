# Trustpoint Architecture

Trustpoint is an open-source platform for managing digital machine identities and certificate lifecycles in industrial IT and OT environments. It provides device onboarding, certificate issuance and renewal, policy enforcement, revocation management, and integration with industrial workflows through standardized enrollment protocols and APIs.

> **Project status:** Trustpoint is currently a technology preview (beta). The architecture described here reflects the current implementation in the repository. Features, APIs, and deployment patterns may evolve between releases.

---

## Purpose and Scope

Trustpoint addresses the challenge of deploying and managing digital identities for machines, devices, and services in industrial environments where:

- Networks are segmented, air-gapped, or intermittently connected
- Devices have limited resources and diverse capabilities
- Certificate lifecycles span years or decades
- Manual certificate handling creates operational risk
- Enterprise PKI systems are designed for IT, not OT

Trustpoint acts as a trust anchor, issuing CA, or registration authority depending on deployment requirements. It manages the complete identity lifecycle from device onboarding through certificate renewal, revocation, and decommissioning.

---

## Architecture Principles

The Trustpoint design follows these core principles:

- **OT suitability:** Support segmented networks, offline operation, and constrained devices.
- **Standards-based protocols:** Use EST (RFC 7030), CMP (RFC 9483), and OPC UA GDS Push for interoperability.
- **Lifecycle management:** Treat certificates as managed identities with state, not isolated artifacts.
- **Deployment flexibility:** Operate as a local CA, external RA, or hybrid depending on trust-domain ownership.
- **Crypto separation:** Abstract key storage and signing operations from certificate-management logic.
- **Workflow integration:** Support zero-touch automation, manual approval, webhooks, and notifications.
- **Modular extensibility:** Isolate protocol handlers, PKI services, workflows, cryptography, and UI concerns.

---

## System Context

Trustpoint integrates industrial devices, human operators, business systems, and PKI or HSM infrastructure into a unified certificate-management platform.

```{mermaid}
flowchart LR
    subgraph INDUSTRIAL[Industrial environment]
        DEV[Devices / machines / sensors / controllers]
        OPC[OPC UA servers]
        ENG[Engineering tools]
    end

    subgraph USERS[Human operators]
        ADMIN[System administrators]
        OPS[Operators and integrators]
        AUDIT[Security and compliance]
    end

    subgraph ENTERPRISE[Enterprise integration]
        ERP[ERP / MES systems]
        IAM[Identity providers]
        MON[Monitoring / SIEM]
        MAIL[Mail notification]
    end

    TP[Trustpoint Platform]

    EPKI[External PKI / Enterprise CA]
    HSM[HSM or PKCS#11 / key storage]

    DEV -->|EST, CMP, AOKI / certificate requests| TP
    OPC -->|OPC UA GDS Push| TP
    ENG -->|REST API / remote downloads| TP

    ADMIN -->|Web UI / configuration| TP
    OPS -->|Web UI / approvals| TP
    AUDIT -->|Dashboard / logs, metrics| TP

    TP -->|RA certificate requests| EPKI
    TP -->|Key operations / signing| HSM
    TP -->|Webhooks / events| ERP
    TP -.->|Future: identity sync| IAM
    TP -->|Metrics / logs| MON
    TP -->|Notifications| MAIL
```

**Key relationships:**

- **Devices** enroll, renew, and retrieve certificates via protocol endpoints.
- **Operators** configure domains, approve onboarding requests, and monitor system state.
- **External PKI** issues certificates when Trustpoint operates in RA mode.
- **HSM** performs private-key operations for Trustpoint-managed issuing CAs.
- **Business systems** receive lifecycle events via webhooks and notifications.

---

## Documentation Structure

This architecture documentation is organized into the following topics:

### Core Architecture


- **[Runtime Architecture](runtime_architecture.md)** - Container structure, processes, lifecycle phases
- **[Component Structure](component_structure.md)** - Django applications, logical layers, URL routing

### Security and Trust

- **[Security Model](security_model.md)** - Trust boundaries, authentication, authorization
- **[PKI Modes](pki_modes.md)** - CA vs RA operating modes, hybrid deployments

### Device and Certificate Management

- **[Device Lifecycle](device_lifecycle.md)** - Onboarding flow, certificate lifecycle, state machines

### Infrastructure

- **[Cryptography](cryptography.md)** - Key management, PKCS#11, HSM integration
- **[Data Management](data_management.md)** - Data storage, backup procedures, retention policies

### Deployment and Operations

- **[Deployment Scenarios](deployment_scenarios.md)** - Common deployment patterns and configurations
- **[Operations and Maintenance](operations.md)** - Monitoring, logging, troubleshooting, performance tuning

### Extensibility

- **[Extensions and Future Development](extensions.md)** - Extension points, planned features, roadmap

---

```{toctree}
:maxdepth: 2

overview
runtime_architecture
component_structure
security_model
pki_modes
device_lifecycle

cryptography
data_management
deployment_scenarios
operations
extensions
generated/index
generated/app_dependencies
generated/model_relationships
generated/url_routing
credentials
backup_restore
crypto_implementation_plan
crypto_redesign
```