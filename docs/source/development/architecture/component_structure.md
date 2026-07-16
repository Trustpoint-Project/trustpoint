# Component Structure

Trustpoint is organized as a modular Django monolith. Each Django app represents a bounded functional area with dedicated models, views, and services.

## Logical Architecture

```mermaid
flowchart TB
    subgraph ACCESS[Access and presentation layer]
        UI[home: dashboard and navigation]
        REST_API[rest_pki: REST API and JWT auth]
        USERS[users: authentication and sessions]
        HELP[help_pages: in-app documentation]
        SHARED[shared: UI components and utilities]
    end

    subgraph PROTOCOLS[Protocol adapters]
        EST[est: RFC 7030 enrollment]
        CMP[cmp: RFC 9483 enrollment]
        AOKI[aoki: zero-touch onboarding]
        SIGNER[signer: hash-and-sign API]
    end

    subgraph DOMAIN_LAYER[Core domain logic]
        DEVICES[devices: device inventory and identities]
        ONBOARDING[onboarding: onboarding orchestration]
        PKI[pki: domains, CAs, certificates, CRLs]
    end

    subgraph WORKFLOW_LAYER[Workflow and automation]
        WORKFLOWS2[workflows2: job queue, approvals, execution]
        MGMT[management: settings, notifications, backup]
    end

    subgraph CRYPTO_LAYER[Cryptography and key management]
        CRYPTO[crypto: provider abstraction, PKCS#11, key repository]
        APPSECRETS[appsecrets: application secret protection]
    end

    subgraph INFRA_LAYER[Infrastructure and bootstrap]
        SETUP[setup_wizard: bootstrap and configuration]
        DB[(PostgreSQL: operational data)]
        HSM[HSM / PKCS#11 token]
        EXT_CA[External CA for RA mode]
    end

    ACCESS --> PROTOCOLS
    ACCESS --> DOMAIN_LAYER
    PROTOCOLS --> DOMAIN_LAYER
    DOMAIN_LAYER --> WORKFLOW_LAYER
    DOMAIN_LAYER --> CRYPTO_LAYER
    WORKFLOW_LAYER --> CRYPTO_LAYER
    DOMAIN_LAYER --> DB
    WORKFLOW_LAYER --> DB
    CRYPTO_LAYER --> HSM
    CRYPTO_LAYER --> DB
    PROTOCOLS -.->|RA mode| EXT_CA
    SETUP --> DB
```

## Django Application Map

The following Django apps are installed and active in operational mode:

| Application | Responsibility | Key Models | Notes |
|---|---|---|---|
| `home` | Dashboard, navigation, UI entry points | — | Main user-facing UI |
| `users` | User authentication, sessions, permissions | User, Group | Django built-in with custom extensions |
| `devices` | Device inventory, credentials, remote downloads | `DeviceModel`, `RemoteDeviceCredentialDownloadModel` | Core device management |
| `onboarding` | Onboarding methods, protocols, configuration | `OnboardingConfigModel`, `OnboardingProtocol` | Device-onboarding logic |
| `pki` | Domains, CAs, certificates, CRLs, revocation | `DomainModel`, `CaModel`, `CertificateModel`, `IssuedCredentialModel`, `CrlModel` | Core PKI domain |
| `est` | EST protocol endpoints (RFC 7030) | — | Protocol adapter |
| `cmp` | CMP protocol endpoints (RFC 9483) | — | Protocol adapter |
| `aoki` | AOKI zero-touch onboarding | — | Protocol adapter |
| `signer` | Hash-and-sign signing authority | — | Signing service |
| `rest_pki` | REST API, JWT authentication, OpenAPI spec | — | External API |
| `crypto` | Cryptographic provider abstraction, PKCS#11, key management | `CryptoProviderProfileModel`, `CryptoManagedKeyModel` | Crypto backend layer |
| `appsecrets` | Application secret protection and encryption | `AppSecretModel` | Secret management |
| `workflows2` | Workflow definitions, jobs, approvals, execution | `Workflow2Instance`, `Workflow2Job`, `Workflow2Approval` | Workflow engine |
| `management` | System settings, notifications, backup, logging | `NotificationConfig`, `BackupConfig` | Operational configuration |
| `setup_wizard` | Bootstrap wizard, initial setup | — | Active only in bootstrap phase |
| `shared` | Shared UI components, utilities | — | Cross-app utilities |
| `help_pages` | In-app help and documentation | — | User assistance |

