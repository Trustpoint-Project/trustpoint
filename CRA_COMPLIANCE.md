<p align="center">
  <img src=".github-assets/trustpoint_banner.png" alt="Trustpoint Logo" width="600">
</p>

<h1 align="center">Trustpoint — CRA Conformity Assessment</h1>

<p align="center">
  <strong>EU Cyber Resilience Act Self-Assessment</strong><br>
  <em>Open Source Trust Anchor Software for Industrial Environments</em>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Owner-Trustpoint_Project-0A66C2?style=for-the-badge" alt="Owner"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Version-1.0-555?style=for-the-badge" alt="Version"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Effective-2026--06--26-success?style=for-the-badge" alt="Effective Date"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Review-Quarterly-orange?style=for-the-badge" alt="Review Cycle"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Status-In_Progress-yellow?style=for-the-badge" alt="Status"/></a>
</p>

**📋 Document Owner:** Trustpoint Project Maintainers | **📄 Version:** 1.0 | **📅 Last Updated:** 2026-06-30 (UTC)  
**🔄 Review Cycle:** Quarterly | **⏰ Next Review:** 2026-09-26

---

## **Purpose Statement**

**Trustpoint** is an open-source trust anchor software designed to solve the critical challenge of digital identity management in industrial and OT environments. As a security-critical infrastructure component managing PKI and certificate lifecycle operations, Trustpoint's commitment to CRA readiness demonstrates our dedication to cybersecurity excellence, transparency, and maintainable evidence.

This CRA conformity assessment documents Trustpoint's alignment with the EU Cyber Resilience Act (Regulation (EU) 2024/2847). It consolidates the current security evidence chain from threat identification through risk treatment and controls to conformity evidence.

The assessment is based on the following maintained artefacts:

* [`THREAT_MODEL.md`](./THREAT_MODEL.md) — identified threats to Trustpoint assets and components
* [`RISK_REGISTER.md`](./RISK_REGISTER.md) — evaluated cybersecurity risks and residual risk decisions
* [`CONTROLS.md`](./CONTROLS.md) — implemented, in-progress, and planned security controls
* [`SECURITY.md`](./SECURITY.md) — vulnerability disclosure and security contact process

---

## **Purpose & Scope**

This CRA conformity assessment provides technical documentation supporting Article 31 and Annex VII technical documentation obligations, Article 13 cybersecurity risk assessment obligations, Article 32 conformity assessment preparation, and Annex I essential cybersecurity requirements.

**Scope:** Trustpoint server software, web application, API, CA/RA logic, enrollment services, certificate lifecycle management, key handling, database, configuration, monitoring, and release process.

**Product Context:** Trustpoint manages digital identities, certificates, and trust relationships for industrial devices, supporting protocols including EST, CMP, AOKI, and OPC UA GDS Push.

**Out of Scope:** Physical host security, customer-specific network security, third-party PKI operation, relying-party device security, and customer-specific operating procedures.

---

## **Risk Management and Evidence Process**

Trustpoint follows a structured security risk management and CRA evidence process.

```text
Threat Model → Risk Register → Controls → Evidence → Review
```

| Step | Document | Purpose |
| ---- | -------- | ------- |
| 1. Threat Model | [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Identifies threats to Trustpoint assets and affected components |
| 2. Risk Register | [`RISK_REGISTER.md`](./RISK_REGISTER.md) | Groups threats into cybersecurity risks, evaluates inherent and residual risk |
| 3. Controls | [`CONTROLS.md`](./CONTROLS.md) | Documents implemented, in-progress, and planned controls |
| 4. Evidence | [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) - [![Critical][badge-you-are-here]]() · [`SECURITY.md`](./SECURITY.md) · CI/CD artifacts · SBOM | Provides evidence for implemented controls, vulnerability handling, release processes, and security maintenance |
| 5. Review | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) · [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) | Ensures that threats, risks, controls, and evidence remain current over time |

---

## 1️⃣ **Project Identification**

*Supports CRA Article 31 and Annex VII § 1 - Product Description Requirements, including intended purpose and software versions affecting compliance.*

| Field | Value |
| ----- | ----- |
| Product | Trustpoint Trust Anchor Software |
| Version Tag | 0.6.0.dev1 (Beta - Technology Preview) |
| Repository | https://github.com/Trustpoint-Project/trustpoint |
| Security Contact | trustpoint@campus-schwarzwald.de |
| Purpose (1-2 lines) | Open-source trust anchor software for managing digital identities, PKI infrastructure, and certificate lifecycle operations in industrial and OT environments |
| Market | Open Source (Non-commercial) |

### Market Category: [![OSS](https://img.shields.io/badge/Market-Open_Source-lightgreen?style=flat-square&logo=github&logoColor=white)](#project-identification)

### Confidentiality Level: [![High](https://img.shields.io/badge/C-High-blue?style=flat-square)](#project-identification)

**Justification:** Trustpoint manages cryptographic keys, certificates, device identity data, trust anchors, configuration, and operational records. Confidentiality protection is required for private key material, secrets, credentials, configuration data, and security-relevant operational information.

### Integrity Level: [![Critical](https://img.shields.io/badge/I-Critical-red?style=flat-square)](#project-identification)

**Justification:** Trustpoint acts as a trust anchor and PKI management platform. Unauthorized changes to certificate policies, trust anchors, issuance workflows, revocation information, configuration, or release artifacts could compromise all dependent systems and devices.

### Availability Level: [![High](https://img.shields.io/badge/A-High-orange?style=flat-square)](#project-identification)

**Justification:** Certificate issuance, renewal, revocation, and onboarding processes must remain available to prevent disruption of industrial communication and device lifecycle operations.

### Recovery Time Objective: [![High](https://img.shields.io/badge/RTO-High_(1--4hrs)-yellow?style=flat-square)](#project-identification)

**Justification:** Critical certificate operations should be restored within 1-4 hours to minimize impact on industrial environments.

### Recovery Point Objective: [![Minimal](https://img.shields.io/badge/RPO-Minimal_(15--60min)-yellow?style=flat-square)](#project-identification)

**Justification:** Certificate, identity, revocation, and configuration data changes should be recoverable with minimal loss to ensure consistency of trust infrastructure.

| Attribute | Level | Justification |
| --------- | ----- | ------------- |
| **Confidentiality** | [![High][badge-cia-high]](#project-identification) | Protects cryptographic keys, secrets, credentials, identity data, and security-relevant configuration |
| **Integrity** | [![Critical][badge-cia-critical]](#project-identification) | Trust anchor function; integrity compromise could affect dependent industrial systems |
| **Availability** | [![High][badge-cia-high]](#project-identification) | Certificate lifecycle operations are required for secure industrial operation |
| **RTO** | [![1-4hrs][badge-rto]](#project-identification) | Critical certificate operations restored within 1-4 hours |
| **RPO** | [![15-60min][badge-rpo]](#project-identification) | Minimal data loss ensures trust infrastructure consistency |

---

## 2️⃣ **CRA Scope & Classification**

*Supports CRA Article 2 - Scope, Article 7 - Important Products with Digital Elements, Article 8 - Critical Products with Digital Elements, and Annex III / Annex IV classification assessment.*

### CRA Applicability: [![Non-commercial OSS](https://img.shields.io/badge/Applicability-Non--commercial_OSS-lightgreen?style=flat-square&logo=github&logoColor=white)](#cra-scope--classification)

### Distribution Method: [![Community](https://img.shields.io/badge/Distribution-Community-green?style=flat-square&logo=users&logoColor=white)](#cra-scope--classification)

### CRA Classification: [![Important Class I](https://img.shields.io/badge/CRA-Important_Class_I-orange?style=flat-square&logo=clipboard-check&logoColor=white)](#cra-scope--classification)

**Scope Justification:** Trustpoint is open-source software distributed via GitHub and Docker Hub under the MIT license. Trustpoint provides PKI, certificate lifecycle, certificate issuance, CA/RA, and machine identity management functionality for industrial environments. The CRA applicability analysis must therefore distinguish the current community / technology-preview distribution from any future placing on the EU market in the course of a commercial activity.

**Classification Rationale:**

* Trustpoint appears to match CRA Annex III Class I, point 9: public key infrastructure and digital certificate issuance software.
* Trustpoint is not currently assessed as a CRA Annex IV critical product.
* The conformity route for an Important Class I product depends on Article 32: internal control may be available where applicable harmonised standards, common specifications, or recognised certification schemes are applied; otherwise Module B+C or Module H may be required.
* For free and open-source software that falls under Annex III, Article 32(5) should be considered: conformity can be demonstrated using one of the Article 32(1) procedures provided the Article 31 technical documentation is made public at the time of placing on the market.
* The current document therefore records a conservative readiness classification as Important Class I Candidate / Technology Preview rather than a final CE-market classification.

---

## 3️⃣ **Technical Documentation**

*Supports BSI TR-03183-1 v0.10.0 — Part 1: General Requirements, especially the risk-based approach and its required inputs, activities, outputs, and evidence.*

This section follows the legal content requirements of CRA Article 31 and Annex VII and uses BSI TR-03183-1 as a structuring aid for the risk-based parts of that documentation. The detailed risk analysis remains in [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`RISK_REGISTER.md`](./RISK_REGISTER.md), and [`CONTROLS.md`](./CONTROLS.md). This document acts as the conformity evidence index and records whether the required artefacts are available, linked, and reviewable.


### CRA Annex VII Content Check

| CRA Annex VII Item | Status | Trustpoint Evidence / Gap | Primary Evidence |
| ------------------ | ------ | ------------------------- | ---------------- |
| **1(a) General product description and intended purpose** | ✅ | Product purpose, scope, PKI / certificate lifecycle functionality, and operating context are documented. | Section 1 · [README](./README.md) · [ReadTheDocs][readthedocs] |
| **1(b) Software versions affecting compliance** | 🔄 | Current beta version is identified; v1.0 must define which software versions are covered by the conformity assessment and support period. | Section 1 · [Releases][releases] |
| **1(c) Hardware photographs / layout** | N/A | Trustpoint is software; no hardware product documentation is applicable. | N/A |
| **1(d) User information and instructions from Annex II** | 🔄 | Documentation exists, but Annex II-specific user information should be checked before v1.0, including secure installation, operation, update, support-period, vulnerability contact, and decommissioning guidance. | [ReadTheDocs][readthedocs] · [`SECURITY.md`](./SECURITY.md) |
| **2(a) Design and development information, including system architecture** | ✅ / 🔄 | Components, system boundaries, CA/RA logic, enrollment, lifecycle, key handling, database, monitoring, and external integrations are documented; architecture evidence should be kept release-specific. | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [ReadTheDocs][readthedocs] |
| **2(b) Vulnerability handling processes, SBOM, CVD policy, contact address, secure update distribution** | ✅ / 🔄 | SBOM, security contact, and private disclosure process exist; supported-version policy, secure update process, release notes, and advisory workflow should be matured before v1.0. | [`SECURITY.md`](./SECURITY.md) · [SBOMs][sbom-portal] · [Releases][releases] |
| **2(c) Production, monitoring, and validation processes** | ✅ / 🔄 | CI/CD, tests, type checking, linting, dependency scanning, OpenSSF, Docker builds, and release workflow evidence are available; release attestations remain planned. | [GitHub Actions][actions] · [OpenSSF][openssf] · [Docker builds][docker-builds] |
| **3 Cybersecurity risk assessment and Annex I applicability** | ✅ | Threat model, risk register, control mapping, inherent / residual risk, and treatment decisions are documented. | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) |
| **4 Support-period determination information** | 🔄 | RTO/RPO and security maintenance are documented, but the formal support period and rationale under Article 13(8) must be defined before placing on the market. | Section 9 · [`SECURITY.md`](./SECURITY.md) |
| **5 Harmonised standards, common specifications, certification schemes, or alternative technical specifications** | 🔄 | Relevant standards are listed; formal harmonised-standard applicability and any alternative solution rationale must be completed when standards are available / selected. | Section 8 · Related Documents |
| **6 Test reports verifying product and vulnerability-handling conformity with Annex I Parts I and II** | ✅ / 🔄 | Automated test, type-checking, lint, security review, dependency scan, and CI evidence exist; specific Annex I conformity test reports should be generated for v1.0. | [Pytest][pytest] · [codecov][codecov] · [MyPy][mypy] · [Ruff][ruff] |
| **7 EU Declaration of Conformity** | 🔄 | Deferred until the product is placed on the EU market after technology-preview / beta phase. | Section 8 |
| **8 SBOM for market surveillance request, where applicable** | ✅ / 🔄 | CycloneDX / SPDX SBOM evidence exists; retention, access control, and response procedure for market-surveillance requests should be defined before v1.0. | [SBOMs][sbom-portal] |

### BSI TR-03183-1 Documentation Baseline

| TR-03183-1 Area | Status | Trustpoint Documentation / Implementation | Evidence |
| --------------- | ------ | ----------------------------------------- | -------- |
| **Assessment scope** | ✅ | Scope covers Trustpoint server software, web application, API, CA/RA logic, enrollment services, certificate lifecycle management, key handling, database, configuration, monitoring, and release process. Out-of-scope items are explicitly listed. | This document · [`THREAT_MODEL.md`](./THREAT_MODEL.md) |
| **Product description and intended purpose** | ✅ | Trustpoint is documented as an open-source trust anchor and certificate lifecycle management platform for industrial and OT environments. Intended functionality includes digital identity management, PKI operation, CA/RA workflows, enrollment, renewal, revocation, and trust anchor management. | Section 1 · [README](./README.md) · [ReadTheDocs][readthedocs] |
| **Reasonably foreseeable use and misuse** | ✅ / 🔄 | Foreseeable OT deployment conditions and misuse cases are reflected in the threat model, including weak/default credentials, exposed administrative interfaces, Brownfield onboarding ambiguity, delayed updates in segmented or air-gapped environments, and misconfiguration due to limited PKI expertise. | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · TM-TP-002 · TM-TP-015 · TM-TP-021 · TM-TP-025 · TM-TP-026 |
| **System / component boundaries** | ✅ | Product components are identified and used consistently across the risk chain: web application, API layer, authentication and authorization, CA/RA logic, policy/profile management, enrollment services, lifecycle management, key and secret management, database, audit logging, deployment, monitoring, CI/CD, and external PKI / relying-party integrations. | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · Component Overview C-01-C-14 |
| **Asset identification** | ✅ | Security-relevant assets are identified before risk evaluation, including CA private keys, RA credentials, trust anchors, certificate profiles, device identity data, issued certificates, revocation data, administrative accounts, configuration/secrets, database contents, audit logs, backups, dependencies, source code, release artifacts, and documentation. | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · Asset Overview A-01-A-15 |
| **Threat modelling** | ✅ | Threat identification uses STRIDE plus PKI, web/API, supply-chain, OT deployment, and foreseeable misuse context. The current baseline contains 26 identified threats mapped to assets and components. | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · Section 4 of this document |
| **Risk identification and grouping** | ✅ | Threats are grouped into 9 cybersecurity risks with traceability from each risk to related `TM-TP-xxx` threats. | [`RISK_REGISTER.md`](./RISK_REGISTER.md) · Risk, Threat, and Control Traceability |
| **Risk estimation** | ✅ | Each risk records likelihood, confidentiality/integrity/availability impact, and inherent risk level. The likelihood model and C/I/A impact model are documented in the risk register. | [`RISK_REGISTER.md`](./RISK_REGISTER.md) · Methodology · Active Risks |
| **Risk evaluation** | ✅ | Residual risks are evaluated and summarized in a portfolio view. Current residual risk is Low for six risks and Medium for three risks; no residual Critical or High risks are currently recorded. | [`RISK_REGISTER.md`](./RISK_REGISTER.md) · Risk Summary · Section 4 of this document |
| **Risk treatment decision** | ✅ / 🔄 | Risks are treated through implemented, in-progress, and planned controls. Medium residual risks are explicitly accepted / under treatment for protocol weaknesses, service disruption, and vulnerability handling maturity. | [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) |
| **Control selection and mapping** | ✅ / 🔄 | 25 controls are documented and mapped to the 9 risks. Controls cover authentication, authorization, auditability, session handling, key protection, cryptographic defaults, certificate lifecycle, device identity verification, revocation, deployment configuration, TLS, secret management, backup/recovery, monitoring, sensitive-data logging, dependency management, CI, review, SBOM, release integrity, vulnerability disclosure, triage, security updates, and supported versions. | [`CONTROLS.md`](./CONTROLS.md) · Control-to-Risk Mapping · Section 6 of this document |
| **Implementation evidence** | ✅ / 🔄 | Evidence is linked through project documentation, source repository artefacts, CI/CD workflows, SBOM portal, GitHub Security Advisories, release notes, Docker Hub, and maintained security documentation. | [`SECURITY.md`](./SECURITY.md) · [SBOMs][sbom-portal] · [GitHub Actions][actions] · [Releases][releases] · [Docker Hub][dockerhub] |
| **Vulnerability handling evidence** | ✅ / 🔄 | Vulnerability reporting is private via GitHub Security Advisories. Reports are acknowledged within 5 business days, triaged by maintainers, and handled through security updates and release notes. Process maturation remains part of pre-v1.0 work. | [`SECURITY.md`](./SECURITY.md) · C-TP-022 · C-TP-023 · C-TP-024 · C-TP-025 |
| **Review and maintenance** | ✅ | Threats, risks, controls, and CRA evidence are reviewed quarterly and on major releases, architecture changes, security incidents, new protocols/deployment models, and CRA/BSI guidance updates. | This document · [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) |


### Notes for v1.0 Hardening

The following items should remain visible in the technical documentation until they are completed or formally accepted:

* Complete release integrity improvements, including release attestations and SLSA provenance.
* Mature the vulnerability handling process, including supported-version communication and security update workflow.
* Expand protocol security evidence for EST, CMP, AOKI, and OPC UA GDS Push.
* Validate backup, recovery, and monitoring evidence against the stated RTO/RPO targets.

---

## 4️⃣ **Threat and Risk Assessment**

*Supports CRA Article 13(2)-(4), Article 31, Annex VII § 3, and Annex I risk-based essential cybersecurity requirements.*

**Complete Threat Model:** [`THREAT_MODEL.md`](./THREAT_MODEL.md)  
**Complete Risk Register:** [`RISK_REGISTER.md`](./RISK_REGISTER.md)  
**Complete Control Catalogue:** [`CONTROLS.md`](./CONTROLS.md)

### Threat Baseline

| Threat Area | Count | Primary CRA Relevance |
| ----------- | ----: | --------------------- |
| Identity and access | 3 | Access control, secure by default, authorization |
| Key and cryptography | 3 | Cryptographic security, key protection, secure configuration |
| Certificate lifecycle | 5 | Secure issuance, renewal, revocation, identity binding |
| Enrollment and onboarding | 4 | Device identity verification, replay/tamper resistance, foreseeable misuse |
| Data, logs, and backups | 3 | Confidentiality, integrity, recovery, auditability |
| Deployment and configuration | 3 | Secure deployment, TLS, administrative interface exposure |
| Supply chain and release | 3 | Dependency security, CI/CD, artifact integrity, SBOM |
| OT-specific operation | 2 | Segmented environments, air-gapped operation, operator usability |
| **Total Threats** | **26** | **Input to risk evaluation and control selection** |

### Risk Portfolio

| Portfolio Overview | Current | Target |
| ------------------ | ------: | -----: |
| Total Risks | 9 | 9 |
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 6 | 4 |
| Low | 3 | 5 |

**Risk Statement:** MODERATE — Trustpoint has defined controls for core PKI, access control, lifecycle, supply chain, and vulnerability handling risks. Residual medium risks remain primarily in protocol hardening, service disruption resilience, and vulnerability handling process maturation before v1.0.

**Risk Acceptance:** Trustpoint Project Maintainers — 2026-06-26

### Risk, Threat, and Control Traceability

| Risk ID | Risk Category | Related Threats | Main Controls | Residual |
| ------- | ------------- | --------------- | ------------- | -------- |
| **R-TP-001** | Supply Chain Attack | TM-TP-022 · TM-TP-023 · TM-TP-024 | C-TP-017 · C-TP-018 · C-TP-019 · C-TP-020 · C-TP-021 | **L** |
| **R-TP-002** | Unauthorized Access | TM-TP-001 · TM-TP-002 · TM-TP-003 · TM-TP-021 | C-TP-001 · C-TP-002 · C-TP-003 · C-TP-004 · C-TP-011 · C-TP-012 | **L** |
| **R-TP-003** | Private Key Compromise | TM-TP-004 · TM-TP-005 | C-TP-005 · C-TP-006 · C-TP-013 · C-TP-014 | **L** |
| **R-TP-004** | Certificate Forgery | TM-TP-006 · TM-TP-007 · TM-TP-008 · TM-TP-012 · TM-TP-013 · TM-TP-014 | C-TP-002 · C-TP-005 · C-TP-006 · C-TP-007 · C-TP-008 · C-TP-009 · C-TP-010 | **L** |
| **R-TP-005** | Component Vulnerabilities | TM-TP-022 | C-TP-017 · C-TP-018 · C-TP-019 · C-TP-020 · C-TP-024 | **L** |
| **R-TP-006** | Protocol Weaknesses | TM-TP-013 · TM-TP-014 · TM-TP-020 | C-TP-006 · C-TP-007 · C-TP-009 · C-TP-012 | **M** |
| **R-TP-007** | Data Breach | TM-TP-016 · TM-TP-017 · TM-TP-018 · TM-TP-024 | C-TP-003 · C-TP-004 · C-TP-011 · C-TP-012 · C-TP-013 · C-TP-014 · C-TP-016 · C-TP-021 | **L** |
| **R-TP-008** | Service Disruption | TM-TP-009 · TM-TP-010 · TM-TP-018 · TM-TP-025 · TM-TP-026 | C-TP-008 · C-TP-010 · C-TP-011 · C-TP-014 · C-TP-015 · C-TP-024 · C-TP-025 | **M** |
| **R-TP-009** | Incomplete Vulnerability Handling | TM-TP-022 · TM-TP-023 · TM-TP-024 | C-TP-017 · C-TP-022 · C-TP-023 · C-TP-024 · C-TP-025 | **M** |

### Risk Treatment Summary

**Mitigated (Low):** R-TP-001, R-TP-002, R-TP-003, R-TP-004, R-TP-005, R-TP-007

**Accepted / Under Treatment (Medium):**

* **R-TP-006 — Protocol Weaknesses:** Ongoing protocol security reviews, TLS/mTLS guidance, and protocol tests
* **R-TP-008 — Service Disruption:** Continued improvement of backup/recovery, monitoring, deployment guidance, and operational resilience
* **R-TP-009 — Incomplete Vulnerability Handling:** Process maturation before v1.0, including supported versions policy, triage, release notes, and update communication

---

## 5️⃣ **Essential Cybersecurity Requirements**

*Supports CRA Article 6, Article 13(1)-(4), and Annex I Parts I and II.*

| CRA Requirement | Status | Implementation / Evidence | Related Risks |
| --------------- | ------ | ------------------------- | ------------- |
| **Annex I Part I (1): appropriate level of cybersecurity based on risks** | ✅ / 🔄 | Threat model, risk register, control catalogue, secure architecture boundaries, and residual-risk review. | R-TP-002 · R-TP-004 · R-TP-006 · R-TP-007 · R-TP-008 |
| **Annex I Part I (2)(a): no known exploitable vulnerabilities when made available** | 🔄 | Dependency monitoring, security advisories, maintainer review, release readiness checks; final release gate required before v1.0. | R-TP-001 · R-TP-005 · R-TP-009 |
| **Annex I Part I (2)(b): secure by default configuration** | ✅ / 🔄 | Authentication required, secure cryptographic defaults, TLS guidance, production settings, debug-disabled production guidance. | R-TP-002 · R-TP-006 · R-TP-007 |
| **Annex I Part I (2)(c): vulnerabilities addressable through security updates** | ✅ / 🔄 | Versioned releases, Docker images, release notes, update workflow; automatic security update expectations are not currently claimed and should be documented for the product model. | R-TP-005 · R-TP-008 · R-TP-009 |
| **Annex I Part I (2)(d): protection from unauthorised access** | ✅ / 🔄 | Django authentication, session handling, API authentication, RBAC, permission checks, audit logs. | R-TP-002 · R-TP-004 · R-TP-007 |
| **Annex I Part I (2)(e)-(g): confidentiality, integrity, and data minimisation** | ✅ / 🔄 | PKCS#11 / HSM support, encrypted storage, secret handling, sensitive-data logging controls, minimal PII approach, backup protection. | R-TP-003 · R-TP-007 · R-TP-008 |
| **Annex I Part I (2)(h)-(i): availability, resilience, and limited negative impact on other services** | 🔄 | Backup and recovery, monitoring and metrics, Docker deployment, RTO/RPO targets; resilience evidence should be validated before v1.0. | R-TP-008 |
| **Annex I Part I (2)(j)-(k): reduced attack surface and incident-impact limitation** | ✅ / 🔄 | Deployment guidance, administrative interface guidance, TLS/mTLS, secure configuration, review and hardening activities. | R-TP-002 · R-TP-006 · R-TP-007 |
| **Annex I Part I (2)(l): security-related logging and monitoring** | ✅ / 🔄 | Administrative auditability, lifecycle event logging, application logs, monitoring resources. | R-TP-002 · R-TP-007 · R-TP-008 |
| **Annex I Part I (2)(m): secure removal of data and settings** | 🔄 | Needs explicit user guidance and, where applicable, implementation evidence for secure decommissioning and data removal. | R-TP-007 · R-TP-008 |
| **Annex I Part II (1): identify and document vulnerabilities and components, including SBOM** | ✅ | CycloneDX + SPDX SBOM generation, dependency tracking, vulnerability monitoring. | R-TP-001 · R-TP-005 · R-TP-009 |
| **Annex I Part II (2)-(4): remediate vulnerabilities, test/review security, disclose fixed vulnerabilities** | ✅ / 🔄 | Dependabot, CI, tests, maintainer review, release notes; fixed-vulnerability disclosure practice should be formalised before v1.0. | R-TP-005 · R-TP-009 |
| **Annex I Part II (5)-(6): coordinated vulnerability disclosure and reporting contact** | ✅ | Private GitHub Security Advisory reporting, security contact address, 5-business-day acknowledgment, required report contents. | R-TP-009 |
| **Annex I Part II (7)-(8): secure update distribution and free security updates with advisory messages** | ✅ / 🔄 | Versioned releases and Docker images are available; secure update distribution, supported-version policy, and advisory-message workflow remain v1.0 hardening items. | R-TP-001 · R-TP-008 · R-TP-009 |
| **Annex II user information and instructions** | 🔄 | Documentation should explicitly cover secure commissioning, operation, updates, support period, vulnerability contact, secure decommissioning, and integration guidance. | R-TP-006 · R-TP-008 · R-TP-009 |

**Status:** REQUIREMENTS_DOCUMENTED_AND_LEGISLATION_ALIGNED — Security requirements are documented and linked to threats, risks, controls, and evidence. Several controls remain in progress as part of the pre-v1.0 hardening and process maturation phase.

**Security Reporting:** Private via GitHub Security Advisories, 5-business-day acknowledgment, public recognition unless anonymity is requested.  
**Contact:** trustpoint@campus-schwarzwald.de

---

## 6️⃣ **Conformity Assessment Evidence**

*Supports CRA Article 31 - Technical Documentation, Article 32 - Conformity Assessment Procedures, and Annex VIII - Conformity Assessment Procedures.*

### Control Evidence Summary

| Control Area | Controls | Status | Evidence Examples |
| ------------ | -------: | ------ | ----------------- |
| Access control | 4 | ✅ / 🔄 | Django auth configuration, source code, authorization tests, audit logs, deployment documentation |
| Cryptographic security | 2 | ✅ / 🔄 | PKCS#11 integration, HSM configuration, crypto tests, certificate profile code |
| Certificate lifecycle security | 4 | ✅ | CA/RA implementation, lifecycle workflows, revocation implementation, protocol tests, documentation |
| Secure deployment | 4 | ✅ / 🔄 | Docker configuration, deployment documentation, TLS guidance, backup configuration, recovery documentation |
| Logging and monitoring | 2 | ✅ / 🔄 | Audit log implementation, application logs, monitoring and metrics configuration |
| Supply chain security | 5 | ✅ / 🔄 | Dependabot, `uv.lock`, GitHub Actions, maintainer review, SBOM generation, release artifacts |
| Vulnerability handling | 4 | ✅ / 🔄 | [`SECURITY.md`](./SECURITY.md), GitHub Security Advisories, triage process, release notes, supported versions policy |
| **Total Controls** | **25** | **Initial Version / In Progress** | **Control catalogue maintained in [`CONTROLS.md`](./CONTROLS.md)** |

### Quality & Security Automation Status

| Control | Requirement | Implementation | Evidence |
| ------- | ----------- | -------------- | -------- |
| Unit Testing | ≥80% coverage target | 🔄 [![codecov][badge-codecov]][codecov] current, target 80% | [Pytest][pytest] · [codecov][codecov] |
| Type Checking | Complete coverage | ✅ | [MyPy][mypy] |
| Code Quality | Lint + format | ✅ | [Ruff][ruff] |
| Dependency Scan | Automated detection | ✅ | [Dependabot][dependabot] |
| Best Practices | Standards compliance | ✅ | [OpenSSF][openssf] passing |
| SBOM | CycloneDX + SPDX | ✅ | [SBOM Portal][sbom-portal] |
| CI/CD | Automated testing and checks | ✅ | [GitHub Actions][actions] |
| Container Security | Secure deployment and image build process | ✅ / 🔄 | [Docker builds][docker-builds] |
| Release Integrity | Verifiable release artifacts | 🔄 | Release process · planned attestations |
| Vulnerability Handling | Private disclosure, triage, release communication | ✅ / 🔄 | [`SECURITY.md`](./SECURITY.md) · GitHub advisories |

**Badges:**

[![OpenSSF][badge-openssf]][openssf]
[![Pytest][badge-pytest]][pytest]
[![codecov][badge-codecov]][codecov]
[![MyPy][badge-mypy]][mypy]
[![Ruff][badge-ruff]][ruff]
[![License: MIT][badge-license]][license]

**Evidence Status:**

* ✅ Threat model, risk register, and control catalogue established
* ✅ Test suite, type checking, code quality, dependency scanning, CI/CD verification, OpenSSF compliance, and SBOM generation available
* 🔄 Release attestations planned for v1.0
* 🔄 SLSA provenance planned for v1.0
* 🔄 Vulnerability handling process and supported versions policy to mature before v1.0

---

## 7️⃣ **Security Maintenance and Vulnerability Handling**

*Supports CRA Article 13(6)-(11), Article 13(17)-(23), Article 14 reporting obligations, and Annex I Part II vulnerability handling requirements.*

| Obligation | Implementation | Frequency | Trigger | Evidence |
| ---------- | -------------- | --------- | ------- | -------- |
| **Vulnerability Monitoring** | CVE feeds, GitHub Security Advisories, Dependabot, CodeQL, secret scanning, maintainer review | Continuous | Dependency alert, security advisory, reported vulnerability | Dependabot alerts · GitHub Security |
| **Vulnerability Intake** | Private reporting through GitHub Security Advisories, security contact, required report content | As needed | External or internal vulnerability report | [`SECURITY.md`](./SECURITY.md) |
| **Vulnerability Triage** | Maintainer review, severity and impact assessment, affected version analysis, fix planning | As needed | New vulnerability report or alert | GitHub advisories · issue tracking |
| **Security Update Process** | Fix development, tests, release notes, release artifacts, communication | As needed | Validated vulnerability requiring a fix | Release history · release notes |
| **Incident Reporting** | GitHub tracking and advisory process | As needed | Security incident | Security advisories |
| **Security Posture Monitoring** | OpenSSF scorecard, CI/CD checks, dependency status | Continuous | Score decline or failing check | OpenSSF badge · GitHub Actions |
| **Update Distribution** | [Releases][releases] and [Docker Hub][dockerhub] | As needed | Critical patches, regular releases | Release history · Docker tags |
| **Review Cycle** | Threat, risk, control, and CRA evidence review | Quarterly and before major releases | Review date, architecture change, incident, regulatory update | Documentation history |

**Monitoring Resources:** [GitHub Security][security] · [CI/CD Status][actions] · [OpenSSF][openssf]

---

## 8️⃣ **EU Declaration of Conformity**

*Supports CRA Article 28 - EU Declaration of Conformity*

> **To be completed when placing the product on the EU market after the technology preview / beta phase.**

**Manufacturer:** Trustpoint Project  
**Product:** Trustpoint Trust Anchor Software v0.6.0.dev1  
**Classification:** Important Class I Candidate / Technology Preview  
**Assessment:** Conformity route to be determined under CRA Article 32; Annex VIII Module A may be available where applicable harmonised standards, common specifications, or recognised certification schemes are applied, otherwise Module B+C or Module H may be required for Important Class I products.  
**Standards and References:** RFC 7030 (EST), RFC 9483 (CMP), OPC UA GDS Push, Django Security, OWASP ASVS, BSI TR-03183-1-oriented risk management documentation

**Status:** Pre-market / Technology Preview / Beta

---

## 9️⃣ **Assessment Completion & Approval**

*Supports internal approval for CRA Article 13 manufacturer obligations, Article 31 technical documentation, Article 32 conformity assessment preparation, Annex I essential cybersecurity requirements, and Annex VII technical documentation content.*

**Status:** IN_PROGRESS

**Completed:**

* ✅ Annex I requirements documented against Part I product security properties and Part II vulnerability handling requirements
* ✅ Annex VII technical documentation structure established
* ✅ Threat model created with 26 identified threats
* ✅ Risk register created with 9 evaluated risks
* ✅ Control catalogue created with 25 security controls
* ✅ Article 6 / Annex I essential cybersecurity requirements mapped to risks and controls
* ✅ Article 13 / Article 14 / Annex I Part II security maintenance and vulnerability handling procedures documented
* ✅ SBOM automation in CI/CD

**Outstanding:**

1. Increase automated test coverage from [![codecov][badge-codecov]][codecov] toward the 80% target
2. Mature vulnerability triage, supported versions policy, and release communication before v1.0
3. Define the formal CRA support period and support-period rationale under Article 13(8)
4. Complete release attestations and SLSA provenance planning for v1.0
5. Complete production release v1.0 readiness review and Article 32 conformity-route decision
6. Consider third-party security audit before or around v1.0

| Role | Name | Date | Attestation |
| ---- | ---- | ---- | ----------- |
| Security Assessment | Trustpoint Maintainers | 2026-06-26 | Essential requirements documented and linked to threat/risk/control evidence |
| Product Responsibility | Trustpoint Project | 2026-06-26 | Technical documentation framework established |
| Compliance Review | Trustpoint Project | 2026-06-30 | CRA evidence aligned with `THREAT_MODEL.md`, `RISK_REGISTER.md`, and `CONTROLS.md` |

---

## **CRA Assessment Maintenance**

### Update Triggers *(CRA Article 15 - Substantial Modification)*

1. Security architecture changes, including authentication methods, enrollment protocols, CA/RA logic, or cryptographic configuration
2. Changes affecting essential cybersecurity requirements
3. Major dependencies with security implications
4. Risk profile changes, including new threats or changed residual risk ratings
5. New or substantially changed controls
6. Regulatory or standards updates affecting PKI, certificate lifecycle management, or vulnerability handling
7. Major version releases
8. Security incidents or vulnerability disclosures requiring reassessment

**Principle:** Routine maintenance updates do not require full reassessment unless they affect Trustpoint's security architecture, risk profile, or CRA essential requirement coverage.

---

## **Related Documents**

**Project:** [ReadTheDocs][readthedocs] · [SECURITY.md](./SECURITY.md) · [LICENSE](./LICENSE) · [CONTRIBUTING.md](./CONTRIBUTING.md) · [AUTHORS.md](./AUTHORS.md)

**CRA Evidence Chain:** [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) · [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md)

**Standards:** RFC 7030 (EST) · RFC 9483 (CMP) · OPC UA GDS Push v1.05 · Django Security · OWASP ASVS · BSI TR-03183-1

**Regulatory:** [EU CRA][cra-regulation] · Article 13 (Manufacturer obligations) · Article 31 / Annex VII (Technical documentation) · Article 32 / Annex VIII (Conformity assessment) · Annex I (Essential cybersecurity requirements) · Annex V (EU Declaration of Conformity)

**Security:** [OpenSSF][openssf] · [GitHub Security][security] · [CI/CD][actions] · [Coverage][codecov]

---

<!-- Reference Links -->
[cra-regulation]: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
[readthedocs]: https://trustpoint.readthedocs.io
[sbom-portal]: https://trustpoint-project.github.io/trustpoint/
[dockerhub]: https://hub.docker.com/r/trustpointproject/trustpoint
[releases]: https://github.com/Trustpoint-Project/trustpoint/releases
[dependabot]: https://github.com/Trustpoint-Project/trustpoint/security/dependabot
[security]: https://github.com/Trustpoint-Project/trustpoint/security
[actions]: https://github.com/Trustpoint-Project/trustpoint/actions
[pytest]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml
[mypy]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml
[ruff]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml
[codecov]: https://codecov.io/gh/Trustpoint-Project/trustpoint
[openssf]: https://www.bestpractices.dev/projects/11535
[docker-builds]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/docker-manual.yml
[license]: https://opensource.org/licenses/MIT

<!-- Badges -->
[badge-cia-high]: https://img.shields.io/badge/High-blue?style=flat-square
[badge-cia-critical]: https://img.shields.io/badge/Critical-red?style=flat-square
[badge-rto]: https://img.shields.io/badge/1--4hrs-yellow?style=flat-square
[badge-rpo]: https://img.shields.io/badge/15--60min-yellow?style=flat-square
[badge-oss]: https://img.shields.io/badge/Non--commercial_OSS-lightgreen?style=flat-square&logo=github&logoColor=white
[badge-community]: https://img.shields.io/badge/Community-green?style=flat-square&logo=users&logoColor=white
[badge-standard]: https://img.shields.io/badge/Standard-green?style=flat-square&logo=clipboard-check&logoColor=white
[badge-you-are-here]: https://img.shields.io/badge/You%20are%20here-blue?style=flat-square
[badge-openssf]: https://www.bestpractices.dev/projects/11535/badge
[badge-pytest]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml/badge.svg?branch=main
[badge-codecov]: https://codecov.io/gh/Trustpoint-Project/trustpoint/graph/badge.svg?token=0N31L1QWPE
[badge-mypy]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml/badge.svg?branch=main
[badge-ruff]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml/badge.svg?branch=main
[badge-license]: https://img.shields.io/badge/License-MIT-yellow.svg
