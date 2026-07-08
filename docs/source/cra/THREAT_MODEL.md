<p align="center">
  <img src="../_static/trustpoint_banner.png" alt="Trustpoint Logo" width="600">
</p>

{.text-center}
# Threat Model

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Owner-Trustpoint_Project-0A66C2?style=for-the-badge" alt="Owner"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Version-1.0-555?style=for-the-badge" alt="Version"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Effective-2026--07--01-success?style=for-the-badge" alt="Effective Date"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Review-Quarterly-orange?style=for-the-badge" alt="Review Cycle"/></a>
</p>

**📋 Document Owner:** Trustpoint Project Maintainers | **📄 Version:** 1.0 | **📅 Last Updated:** 2026-07-01
**🔄 Review Cycle:** Quarterly | **⏰ Next Review:** 2026-09-26

---

## **Purpose**

Threat model documenting identified threats to Trustpoint’s assets and affected product components, supporting CRA readiness and BSI TR-03183-1 RH_RA.1.1.2 Threat Modelling.

This document focuses on threat identification only. Likelihood, impact, residual risk, and treatment are handled in the related Risk Register.

---

## **Risk Management Process**

Trustpoint follows a structured security risk management process.

```text
Threat Model → Risk Register → Controls → Evidence → Review
```

| Step             | Document                                                                                                                       | Purpose                                                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| 1. Threat Model  | [`THREAT_MODEL.md`](./THREAT_MODEL.md)   -  [![Critical][badge-you-are-here]]()                                                                                         | Identifies threats to Trustpoint                                  |
| 2. Risk Register | [`RISK_REGISTER.md`](./RISK_REGISTER.md)                                                                                   | Groups threats into cybersecurity risks
| 3. Controls      | [`CONTROLS.md`](./CONTROLS.md)                                                                                     | Documents implemented and planned controls                               |
| 4. Evidence      | [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) · [`SECURITY.md`][security] · CI/CD artifacts · SBOM                           | Provides evidence for implemented controls, vulnerability handling, release processes, and security maintenance       |
| 5. Review        | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) · [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) | Ensures that threats, risks, controls, and evidence remain current over time        

---

## **Scope**

**In Scope:** Trustpoint server software, web application, API, CA/RA logic, enrollment services, certificate lifecycle management, key handling, database, configuration, monitoring, and release process.

**Out of Scope:** Physical host security, customer-specific network security, third-party PKI operation, relying-party device security, and customer-specific operating procedures.

---

## **Methodology**

Threats are identified using a structured approach based on:

**STRIDE:** Spoofing · Tampering · Repudiation · Information Disclosure · Denial of Service · Elevation of Privilege
**Additional Context:** PKI threats · Web/API threats · Supply chain threats · OT deployment threats · Foreseeable misuse

Threats are identified independently of likelihood and impact. Risk evaluation is performed separately in `RISK_REGISTER.md`.

---

## **Input Summary**

| BSI TR-03183 Input                              | Trustpoint Source                                  |
| ----------------------------------------------- | -------------------------------------------------- |
| Intended purpose and reasonably foreseeable use | README · CRA documentation · Product documentation |
| Product architecture                            | Architecture documentation · Deployment model      |
| List of assets                                  | Asset overview below                               |
| Threat catalogue                                | STRIDE · OWASP · PKI/OT-specific scenarios         |

---

## **Asset Overview**

| Asset ID | Asset                                | Security Relevance                                                |
| -------- | ------------------------------------ | ----------------------------------------------------------------- |
| A-01     | CA private keys                      | Critical trust anchor material                                    |
| A-02     | RA credentials                       | Authorisation for registration operations                         |
| A-03     | Trust anchors                        | Basis for certificate trust decisions                             |
| A-04     | Certificate profiles and policies    | Define issuance rules and certificate semantics                   |
| A-05     | Device identity data                 | Used for onboarding and identity binding                          |
| A-06     | Issued certificates                  | Used for authentication and secure communication                  |
| A-07     | Revocation data                      | Required to invalidate certificates                               |
| A-08     | Administrative accounts and sessions | Control access to security-critical functions                     |
| A-09     | Configuration and secrets            | Define runtime security behaviour                                 |
| A-10     | Database contents                    | Persistent state for certificates, identities, policies, and logs |
| A-11     | Audit logs                           | Evidence for security-relevant actions                            |
| A-12     | Backups                              | Required for recovery and continuity                              |
| A-13     | Dependencies                         | Relevant for software supply chain security                       |
| A-14     | Source code and release artifacts    | Define and distribute product behaviour                           |
| A-15     | Documentation                        | Guides secure deployment and operation                            |

---

## **Component Overview**

| Component ID | Component                                   |
| ------------ | ------------------------------------------- |
| C-01         | Web application                             |
| C-02         | API layer                                   |
| C-03         | Authentication and authorization            |
| C-04         | CA / RA logic                               |
| C-05         | Policy and certificate profile management   |
| C-06         | Enrollment services                         |
| C-07         | Certificate lifecycle management            |
| C-08         | Key and secret management                   |
| C-09         | Database                                    |
| C-10         | Audit logging                               |
| C-11         | Configuration and deployment                |
| C-12         | Monitoring and metrics                      |
| C-13         | CI/CD and release process                   |
| C-14         | External PKI and relying-party integrations |

---

## **Threat Summary**

**Next Review:** 2026-09-26

| Threat Area                  |  Count |
| ---------------------------- | -----: |
| Identity and access          |      3 |
| Key and cryptography         |      3 |
| Certificate lifecycle        |      5 |
| Enrollment and onboarding    |      4 |
| Data, logs, and backups      |      3 |
| Deployment and configuration |      3 |
| Supply chain and release     |      3 |
| OT-specific operation        |      2 |
| **Total Threats**            | **26** |

---

## **Identified Threats**

### **TM-TP-001: Administrative Account Compromise**

| Field           | Value                                                                                                                          |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Category**    | Identity and Access                                                                                                            |
| **STRIDE**      | Spoofing · Elevation of Privilege                                                                                              |
| **Assets**      | A-08 · A-09 · A-10 · A-11                                                                                                      |
| **Components**  | C-01 · C-02 · C-03                                                                                                             |
| **Description** | An attacker gains access to an administrative account and performs unauthorized certificate, policy, or configuration changes. |

---

### **TM-TP-002: Weak or Default Credentials**

| Field           | Value                                                             |
| --------------- | ----------------------------------------------------------------- |
| **Category**    | Identity and Access                                               |
| **STRIDE**      | Spoofing · Elevation of Privilege                                 |
| **Assets**      | A-08 · A-09                                                       |
| **Components**  | C-03 · C-11                                                       |
| **Description** | Trustpoint is deployed with weak, reused, or default credentials. |

---

### **TM-TP-003: Missing Authorization Checks**

| Field           | Value                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| **Category**    | Identity and Access                                                                                    |
| **STRIDE**      | Elevation of Privilege                                                                                 |
| **Assets**      | A-04 · A-06 · A-07 · A-09                                                                              |
| **Components**  | C-01 · C-02 · C-03 · C-04                                                                              |
| **Description** | A user performs certificate, lifecycle, or configuration operations beyond their intended permissions. |

---

### **TM-TP-004: CA Private Key Compromise**

| Field           | Value                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------------- |
| **Category**    | Key Management                                                                                       |
| **STRIDE**      | Information Disclosure · Tampering                                                                   |
| **Assets**      | A-01 · A-03 · A-06                                                                                   |
| **Components**  | C-04 · C-08 · C-09 · C-11                                                                            |
| **Description** | A CA private key is exposed, copied, or used by an unauthorized party, enabling certificate forgery. |

---

### **TM-TP-005: Weak Key or Secret Storage**

| Field           | Value                                                                         |
| --------------- | ----------------------------------------------------------------------------- |
| **Category**    | Key Management                                                                |
| **STRIDE**      | Information Disclosure                                                        |
| **Assets**      | A-01 · A-02 · A-09 · A-12                                                     |
| **Components**  | C-08 · C-09 · C-11                                                            |
| **Description** | Private keys, credentials, or secrets are stored without adequate protection. |

---

### **TM-TP-006: Weak Cryptographic Algorithms or Profiles**

| Field           | Value                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Category**    | Cryptographic Security                                                                                              |
| **STRIDE**      | Spoofing · Tampering                                                                                                |
| **Assets**      | A-04 · A-06                                                                                                         |
| **Components**  | C-04 · C-05 · C-06 · C-07                                                                                           |
| **Description** | Certificate profiles or cryptographic settings use weak algorithms, insufficient key sizes, or insecure parameters. |

---

### **TM-TP-007: Unauthorized Certificate Issuance**

| Field           | Value                                                                            |
| --------------- | -------------------------------------------------------------------------------- |
| **Category**    | Certificate Lifecycle                                                            |
| **STRIDE**      | Tampering · Elevation of Privilege                                               |
| **Assets**      | A-04 · A-05 · A-06                                                               |
| **Components**  | C-04 · C-05 · C-06 · C-07                                                        |
| **Description** | Certificates are issued to unauthorized users, devices, services, or components. |

---

### **TM-TP-008: Incorrect Identity Binding**

| Field           | Value                                                                       |
| --------------- | --------------------------------------------------------------------------- |
| **Category**    | Certificate Lifecycle                                                       |
| **STRIDE**      | Spoofing · Tampering                                                        |
| **Assets**      | A-05 · A-06                                                                 |
| **Components**  | C-06 · C-07                                                                 |
| **Description** | A certificate is bound to the wrong device, service, user, or trust domain. |

---

### **TM-TP-009: Certificate Expiry**

| Field           | Value                                                                                                   |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| **Category**    | Certificate Lifecycle                                                                                   |
| **STRIDE**      | Denial of Service                                                                                       |
| **Assets**      | A-06                                                                                                    |
| **Components**  | C-07 · C-12 · C-14                                                                                      |
| **Description** | Certificates expire without renewal, causing disruption of industrial services or device communication. |

---

### **TM-TP-010: Revocation Failure**

| Field           | Value                                                                                                          |
| --------------- | -------------------------------------------------------------------------------------------------------------- |
| **Category**    | Certificate Lifecycle                                                                                          |
| **STRIDE**      | Tampering · Denial of Service                                                                                  |
| **Assets**      | A-07                                                                                                           |
| **Components**  | C-07 · C-12 · C-14                                                                                             |
| **Description** | Compromised, obsolete, or incorrectly issued certificates are not revoked or revocation status is unavailable. |

---

### **TM-TP-011: Trust Anchor Misconfiguration**

| Field           | Value                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------- |
| **Category**    | Certificate Lifecycle                                                                           |
| **STRIDE**      | Spoofing · Tampering                                                                            |
| **Assets**      | A-03 · A-04 · A-09                                                                              |
| **Components**  | C-05 · C-07 · C-11 · C-14                                                                       |
| **Description** | Incorrect trust anchors are configured, resulting in misplaced trust or communication failures. |

---

### **TM-TP-012: Rogue Device Enrollment**

| Field           | Value                                                                   |
| --------------- | ----------------------------------------------------------------------- |
| **Category**    | Enrollment and Onboarding                                               |
| **STRIDE**      | Spoofing                                                                |
| **Assets**      | A-05 · A-06                                                             |
| **Components**  | C-06 · C-07 · C-14                                                      |
| **Description** | An unauthorized device successfully enrolls and receives a certificate. |

---

### **TM-TP-013: Enrollment Request Tampering or Replay**

| Field           | Value                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------ |
| **Category**    | Enrollment and Onboarding                                                                  |
| **STRIDE**      | Spoofing · Tampering                                                                       |
| **Assets**      | A-05 · A-06                                                                                |
| **Components**  | C-06                                                                                       |
| **Description** | Enrollment requests are modified, replayed, or reused to obtain unauthorized certificates. |

---

### **TM-TP-014: Weak Device Identity Verification**

| Field           | Value                                                                       |
| --------------- | --------------------------------------------------------------------------- |
| **Category**    | Enrollment and Onboarding                                                   |
| **STRIDE**      | Spoofing                                                                    |
| **Assets**      | A-05 · A-06                                                                 |
| **Components**  | C-06 · C-07                                                                 |
| **Description** | Trustpoint accepts insufficient proof of device identity during onboarding. |

---

### **TM-TP-015: Brownfield Onboarding Ambiguity**

| Field           | Value                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------- |
| **Category**    | Enrollment and Onboarding                                                                                 |
| **STRIDE**      | Spoofing · Tampering                                                                                      |
| **Assets**      | A-05 · A-06                                                                                               |
| **Components**  | C-06 · C-07 · C-14                                                                                        |
| **Description** | Legacy or Brownfield devices without strong initial identities are incorrectly trusted during onboarding. |

---

### **TM-TP-016: Database Compromise**

| Field           | Value                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------- |
| **Category**    | Data Protection                                                                                 |
| **STRIDE**      | Information Disclosure · Tampering                                                              |
| **Assets**      | A-05 · A-06 · A-07 · A-08 · A-10 · A-11                                                         |
| **Components**  | C-09                                                                                            |
| **Description** | An attacker gains unauthorized access to Trustpoint’s database or manipulates persistent state. |

---

### **TM-TP-017: Audit Log Tampering**

| Field           | Value                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------- |
| **Category**    | Logging and Auditability                                                                        |
| **STRIDE**      | Repudiation · Tampering                                                                         |
| **Assets**      | A-11                                                                                            |
| **Components**  | C-09 · C-10                                                                                     |
| **Description** | Security-relevant logs are modified, deleted, incomplete, or unavailable for incident analysis. |

---

### **TM-TP-018: Backup Compromise or Backup Failure**

| Field           | Value                                                                            |
| --------------- | -------------------------------------------------------------------------------- |
| **Category**    | Backup and Recovery                                                              |
| **STRIDE**      | Information Disclosure · Tampering · Denial of Service                           |
| **Assets**      | A-01 · A-09 · A-10 · A-12                                                        |
| **Components**  | C-09 · C-11                                                                      |
| **Description** | Backups are exposed, modified, missing, incomplete, or unusable during recovery. |

---

### **TM-TP-019: Insecure Deployment Configuration**

| Field           | Value                                                                                                            |
| --------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Category**    | Configuration and Deployment                                                                                     |
| **STRIDE**      | Information Disclosure · Elevation of Privilege                                                                  |
| **Assets**      | A-08 · A-09 · A-10                                                                                               |
| **Components**  | C-01 · C-02 · C-11                                                                                               |
| **Description** | Trustpoint is deployed with insecure runtime settings, debug options, exposed services, or weak secret handling. |

---

### **TM-TP-020: Missing or Weak TLS Configuration**

| Field           | Value                                                                                       |
| --------------- | ------------------------------------------------------------------------------------------- |
| **Category**    | Configuration and Deployment                                                                |
| **STRIDE**      | Information Disclosure · Tampering                                                          |
| **Assets**      | A-05 · A-06 · A-08 · A-09                                                                   |
| **Components**  | C-01 · C-02 · C-06 · C-11                                                                   |
| **Description** | Communication with Trustpoint is not adequately protected by TLS or uses weak TLS settings. |

---

### **TM-TP-021: Exposed Administrative Interfaces**

| Field           | Value                                                            |
| --------------- | ---------------------------------------------------------------- |
| **Category**    | Configuration and Deployment                                     |
| **STRIDE**      | Spoofing · Elevation of Privilege                                |
| **Assets**      | A-08 · A-09                                                      |
| **Components**  | C-01 · C-02 · C-11                                               |
| **Description** | Administrative interfaces are reachable from untrusted networks. |

---

### **TM-TP-022: Vulnerable Dependency**

| Field           | Value                                                                            |
| --------------- | -------------------------------------------------------------------------------- |
| **Category**    | Supply Chain Security                                                            |
| **STRIDE**      | Tampering · Information Disclosure · Denial of Service                           |
| **Assets**      | A-13 · A-14                                                                      |
| **Components**  | C-11 · C-13                                                                      |
| **Description** | A third-party dependency contains a vulnerability affecting Trustpoint security. |

---

### **TM-TP-023: Build or Release Pipeline Compromise**

| Field           | Value                                                                                    |
| --------------- | ---------------------------------------------------------------------------------------- |
| **Category**    | Supply Chain Security                                                                    |
| **STRIDE**      | Tampering · Elevation of Privilege                                                       |
| **Assets**      | A-13 · A-14                                                                              |
| **Components**  | C-13                                                                                     |
| **Description** | The CI/CD pipeline is compromised and produces malicious or untrusted release artifacts. |

---

### **TM-TP-024: Release Artifact Tampering**

| Field           | Value                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------- |
| **Category**    | Supply Chain Security                                                                               |
| **STRIDE**      | Tampering · Repudiation                                                                             |
| **Assets**      | A-14                                                                                                |
| **Components**  | C-13                                                                                                |
| **Description** | Docker images, packages, tags, or release artifacts are modified after build or cannot be verified. |

---

### **TM-TP-025: Delayed Updates in Segmented or Air-Gapped Environments**

| Field           | Value                                                                                                                          |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Category**    | OT Operation                                                                                                                   |
| **STRIDE**      | Denial of Service · Tampering                                                                                                  |
| **Assets**      | A-13 · A-14                                                                                                                    |
| **Components**  | C-11 · C-13                                                                                                                    |
| **Description** | Security updates are delayed because Trustpoint is operated in segmented, restricted-connectivity, or air-gapped environments. |

---

### **TM-TP-026: Misconfiguration due to Limited PKI Expertise**

| Field           | Value                                                                                                                   |
| --------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Category**    | OT Operation                                                                                                            |
| **STRIDE**      | Tampering · Denial of Service                                                                                           |
| **Assets**      | A-03 · A-04 · A-06 · A-09 · A-15                                                                                        |
| **Components**  | C-01 · C-05 · C-07 · C-11                                                                                               |
| **Description** | Operators with limited PKI expertise misconfigure certificate profiles, trust anchors, policies, or lifecycle settings. |

---

## **Output**

The output of this activity is the initial list of identified threats to Trustpoint assets and affected product components.

This output serves as input for:

* [`RISK_REGISTER.md`](./RISK_REGISTER.md)
* [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md)
* security requirements,
* security test planning,
* vulnerability handling,
* release readiness reviews.

---

## **Related Documents**

* [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md)
* [`RISK_REGISTER.md`](./RISK_REGISTER.md)
* [`SECURITY.md`][security]
* [`README.md`][readme]
* [Trustpoint documentation](https://trustpoint.readthedocs.io)
* [BSI TR-03183-1](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-1_v0_10_0.pdf?__blob=publicationFile&v=1)
* EU Cyber Resilience Act

<!-- Reference Links -->
[security]: https://github.com/Trustpoint-Project/trustpoint/blob/main/SECURITY.md
[readme]: https://github.com/Trustpoint-Project/trustpoint/blob/main/README.md

[badge-you-are-here]: https://img.shields.io/badge/You%20are%20here-blue?style=flat-square