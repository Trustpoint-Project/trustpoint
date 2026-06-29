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

**📋 Document Owner:** Trustpoint Project | **📄 Version:** 1.0 | **📅 Last Updated:** 2026-06-26 (UTC)  
**🔄 Review Cycle:** Quarterly | **⏰ Next Review:** 2026-09-26

---

## **Purpose Statement**

**Trustpoint** is an open-source trust anchor software designed to solve the critical challenge of digital identity management in industrial and OT environments. As a security-critical infrastructure component managing PKI and certificate lifecycle operations, Trustpoint's commitment to CRA compliance demonstrates our dedication to cybersecurity excellence and transparency.

This CRA conformity assessment provides systematic documentation of Trustpoint's adherence to EU Cyber Resilience Act requirements, supporting our mission to deliver secure, reliable, and auditable identity management for machines and factories.

Our open-source approach ensures complete transparency in our security practices, enabling users to verify and validate the security controls protecting their critical infrastructure.

---

## **Purpose & Scope**

This CRA conformity assessment documents Trustpoint's compliance with the EU Cyber Resilience Act (Regulation (EU) 2024/2847). It provides comprehensive technical documentation supporting Annex I essential cybersecurity requirements and Annex V technical documentation obligations.

**Scope:** Trustpoint Server Software (open-source trust anchor and certificate management platform for industrial environments)

**Product Context:** Trustpoint manages digital identities, certificates, and trust relationships for industrial devices, supporting protocols including EST, CMP, AOKI, and OPC UA GDS Push.

---

## 1️⃣ **Project Identification**

*Supports CRA Annex V § 1 - Product Description Requirements*

| Field | Value |
|-------|-------|
| Product | Trustpoint Trust Anchor Software |
| Version Tag | 0.6.0.dev1 (Beta - Technology Preview) |
| Repository | https://github.com/Trustpoint-Project/trustpoint |
| Security Contact | trustpoint@campus-schwarzwald.de |
| Purpose (1–2 lines) | Open-source trust anchor software for managing digital identities, PKI infrastructure, and certificate lifecycle operations in industrial and OT environments |
| Market | Open Source (Non-commercial) |

### Market Category: [![OSS](https://img.shields.io/badge/Market-Open_Source-lightgreen?style=flat-square&logo=github&logoColor=white)](#project-identification)

### Confidentiality Level: [![High](https://img.shields.io/badge/C-High-blue?style=flat-square)](#project-identification)

**Justification:** Trustpoint manages cryptographic keys, certificates, and trust relationships for critical industrial infrastructure. Configuration and operational data require high confidentiality protection.

### Integrity Level: [![Critical](https://img.shields.io/badge/I-Critical-red?style=flat-square)](#project-identification)

**Justification:** As a trust anchor managing PKI infrastructure, any integrity compromise could affect the security of all dependent systems and devices. Integrity is paramount.

### Availability Level: [![High](https://img.shields.io/badge/A-High-orange?style=flat-square)](#project-identification)

**Justification:** Certificate operations, device onboarding, and renewal processes require high availability to prevent disruption of industrial operations.

### Recovery Time Objective: [![High](https://img.shields.io/badge/RTO-High_(1--4hrs)-yellow?style=flat-square)](#project-identification)

**Justification:** Critical certificate operations should be restored within 1-4 hours to minimize impact on industrial environments.

### Recovery Point Objective: [![Minimal](https://img.shields.io/badge/RPO-Minimal_(15--60min)-yellow?style=flat-square)](#project-identification)

**Justification:** Certificate and configuration data changes should be recoverable with minimal loss to ensure consistency of trust infrastructure.


| Attribute | Level | Justification |
|-----------|-------|---------------|
| **Confidentiality** | [![High][badge-cia-high]](#project-identification) | Manages cryptographic keys, certificates, and trust relationships for critical industrial infrastructure |
| **Integrity** | [![Critical][badge-cia-critical]](#project-identification) | Trust anchor managing PKI infrastructure; integrity compromise affects all dependent systems |
| **Availability** | [![High][badge-cia-high]](#project-identification) | Certificate operations require high availability to prevent industrial operation disruption |
| **RTO** | [![1-4hrs][badge-rto]](#project-identification) | Critical certificate operations restored within 1-4 hours |
| **RPO** | [![15-60min][badge-rpo]](#project-identification) | Minimal data loss ensures trust infrastructure consistency |



---

## 2️⃣ **CRA Scope & Classification**

*Supports CRA Article 6 - Scope and Article 7 - Product Classification Assessment*

### CRA Applicability: [![Non-commercial OSS](https://img.shields.io/badge/Applicability-Non--commercial_OSS-lightgreen?style=flat-square&logo=github&logoColor=white)](#cra-scope--classification)

### Distribution Method: [![Community](https://img.shields.io/badge/Distribution-Community-green?style=flat-square&logo=users&logoColor=white)](#cra-scope--classification)

### CRA Classification: [![Standard](https://img.shields.io/badge/CRA-Standard-green?style=flat-square&logo=clipboard-check&logoColor=white)](#cra-scope--classification)



**Scope Justification:** Non-commercial open-source software distributed via GitHub and Docker Hub under MIT license. Falls under CRA scope as PKI/certificate management software providing security functions for industrial environments.


**Standard Classification Rationale:**
- Not listed in CRA Annex III (Class I or II products)
- Provides general PKI and certificate management functionality
- Not specific to critical infrastructure products (e.g., industrial firewalls, SCADA gateways)
- Self-assessment approach per CRA Article 24

---

## 3️⃣ **Technical Documentation**

*Supports CRA Annex V § 2 - Technical Documentation Requirements*


| CRA Technical Area | Status | Implementation | Evidence |
|-------------------|--------|----------------|----------|
| **Product Architecture** *(V § 2.1)* | ✅ | Django + PostgreSQL, documented boundaries | [docs][readthedocs] · [README](./README.md) |
| **SBOM & Components** *(I § 1.1)* | ✅ | CycloneDX + SPDX, dependency tracking | [pyproject.toml](./pyproject.toml) · [SBOMs][sbom-portal] |
| **Cybersecurity Controls** *(I § 1.2)* | ✅ | Django auth, PKCS#11, TLS/mTLS | [SECURITY.md](./SECURITY.md) |
| **Supply Chain Security** *(I § 1.3)* | ✅ | GitHub Actions, automated testing, Dependabot | [workflows](.github/workflows/) · [Dependabot][dependabot] |
| **Update Mechanism** *(I § 1.4)* | ✅ | Docker versioning, rollback capability | [Docker Hub][dockerhub] · [Releases][releases] |
| **Security Monitoring** *(I § 1.5)* | 🔄 | Logging, audit trails, Prometheus telemetry | Application logs |
| **Data Protection** *(I § 2.1)* | ✅ | DB encryption, PKCS#11, backup | Django security · PKCS#11 |
| **User Guidance** *(I § 2.2)* | ✅ | Security configuration docs | [ReadTheDocs][readthedocs] |
| **Vulnerability Disclosure** *(I § 2.3)* | ✅ | GitHub Security Advisories | [SECURITY.md](./SECURITY.md) |

**Key Security Features:**
- HSM Integration (PKCS#11), Protocol Security (TLS/mTLS for EST/CMP/AOKI/GDS)
- Multi-factor authentication (X.509, passwords, shared secrets, IDevID)
- Complete certificate lifecycle management, Industrial OT focus (20+ year lifecycles)
- 80%+ test coverage (pytest, mypy, ruff)

---

## 4️⃣ **Risk Assessment**

*Supports CRA Annex V § 3 - Risk Assessment Documentation*

**Complete Risk Register:** [RISK_REGISTER.md](./RISK_REGISTER.md)

| Risk Category | Asset | L | Impact | Controls | Residual | Evidence |
|---------------|-------|---|--------|----------|----------|----------|
| **Supply Chain Attack** | Build pipeline | M | H/H/M | GitHub Actions, [Dependabot][dependabot], pinning | L | CI/CD, scanning |
| **Unauthorized Access** | Certificate ops | M | H/H/H | Django auth, RBAC | L | Auth implementation |
| **Key Compromise** | Private keys | L | H/H/H | PKCS#11 HSM, encryption | L | HSM integration |
| **Certificate Forgery** | CA infrastructure | L | H/H/H | Secure CA management, HSM | L | CA architecture |
| **Component Vulnerability** | Dependencies | M | M/H/M | Scanning, updates, testing | L | [Dependabot][dependabot] |
| **Protocol Weakness** | EST/CMP/AOKI/GDS | L | M/H/M | Standards compliance, TLS | M | Protocol docs |
| **Data Breach** | Certificate DB | M | H/H/M | DB encryption, controls | L | Django security |
| **Service Disruption** | Certificate services | M | L/M/H | Backup, Docker, monitoring | M | Backup features |


**Risk Statement:** MODERATE - Robust security controls for PKI infrastructure. Residual risks primarily deployment/operational.

**Risk Acceptance:** Trustpoint Project Maintainers - 2026-06-26

---

## 5️⃣ **Essential Cybersecurity Requirements**

*Supports CRA Annex I - Essential Requirements Self-Assessment*

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **§ 1.1 - Secure by Design** | ✅ | Minimal attack surface, input validation, parameterized queries |
| **§ 1.2 - Secure by Default** | ✅ | TLS enforced, authentication required, debug disabled in production |
| **§ 2.1 - Personal Data Protection** | ✅ | Minimal data collection, Django privacy, configurable retention |
| **§ 2.2 - Vulnerability Disclosure** | ✅ | Public VDP via SECURITY.md, 5-day response |
| **§ 2.3 - SBOM** | ✅ | [SBOM Portal][sbom-portal] (CycloneDX + SPDX) |
| **§ 2.4 - Secure Updates** | ✅ | Docker versioning, [releases][releases], backward-compatible |
| **§ 2.5 - Security Monitoring** | ✅ | Logging, audit trails, Prometheus telemetry |
| **§ 2.6 - Security Documentation** | ✅ | Comprehensive guidance at [ReadTheDocs][readthedocs] |


**Status:** REQUIREMENTS_DOCUMENTED

**Security Reporting:** Private via GitHub Security Advisories, 5-day acknowledgment, public recognition (unless anonymity requested)  
**Contact:** trustpoint@campus-schwarzwald.de

---

## 6️⃣ **Conformity Assessment Evidence**

*Supports CRA Article 19 - Conformity Assessment Documentation*

### **Quality & Security Automation Status:**

| Control | Requirement | Implementation | Evidence |
|---------|-------------|----------------|----------|
| Unit Testing | ≥80% coverage | 🔄 69% current | [Pytest][pytest] · [codecov][codecov] |
| Type Checking | Complete coverage | ✅ | [MyPy][mypy] |
| Code Quality | Lint + format | ✅ | [Ruff][ruff] |
| Dependency Scan | Auto detection | ✅ | [Dependabot][dependabot] |
| Best Practices | Standards compliance | ✅ | [OpenSSF][openssf] (passing) |
| SBOM | CycloneDX + SPDX | ✅ | [SBOM Portal][sbom-portal] |
| CI/CD | Auto testing | ✅ | [GitHub Actions][actions] |
| Container Security | Secure deployment | ✅ | [Docker builds][docker-builds] |


**Badges:**

[![OpenSSF][badge-openssf]][openssf]
[![Pytest][badge-pytest]][pytest]
[![codecov][badge-codecov]][codecov]
[![MyPy][badge-mypy]][mypy]
[![Ruff][badge-ruff]][ruff]
[![License: MIT][badge-license]][license]

**Evidence Status:**
- ✅ Test suite with coverage, type checking, code quality, dependency scanning
- ✅ CI/CD verification, OpenSSF compliance, SBOM generation
- 🔄 Release attestations (planned for v1.0)
- 🔄 SLSA provenance (planned for v1.0)


## 7️⃣ **Post-Market Surveillance**

*Supports CRA Article 23 - Obligations of Economic Operators*

| Obligation | Implementation | Frequency | Trigger | Evidence |
|------------|----------------|-----------|---------|----------|
| **Vulnerability Monitoring** | CVE feeds, Advisories, Dependabot, ZAP, CodeQL, Secret scanning | Continuous | Auto-create issues | Dependabot alerts |
| **Incident Reporting** | GitHub tracking, advisory process | As needed | Security incident | Security advisories |
| **Security Posture** | OpenSSF scorecard | Continuous | Score decline | Badge monitoring |
| **Update Distribution** | [Releases][releases] + [Docker Hub][dockerhub] | As needed | Critical patches | Release history |

**Monitoring Resources:** [GitHub Security][security] · [CI/CD Status][actions] · [OpenSSF][openssf]


## 8️⃣ **EU Declaration of Conformity**

*Supports CRA Article 28 - EU Declaration of Conformity*

> **To be completed when placing product on EU market (post-beta)**

**Manufacturer:** Trustpoint Project  
**Product:** Trustpoint Trust Anchor Software v0.6.0.dev1  
**Classification:** Standard (Non-commercial OSS)  
**Assessment:** Self-assessment per CRA Article 24  
**Standards:** RFC 7030 (EST), RFC 9483 (CMP), OPC UA GDS Push, Django Security, OWASP ASVS

**Status:** Pre-market (Technology Preview/Beta)


---

## 9️⃣ **Assessment Completion & Approval**

*Supports CRA Article 16 - Quality Management System Documentation*

**Status:** IN_PROGRESS

**Completed:**
- ✅ Annex I requirements documented
- ✅ Annex V technical documentation
- ✅ Article 11 security measures
- ✅ Article 23 surveillance procedures
- ✅ SBOM automation in CI/CD

**Outstanding:**
2. SLSA provenance attestations (Target: v1.0)
3. Production release v1.0 (Target: TBD)
4. Third-party security audit (Target: TBD)D)

| Role | Name | Date | Attestation |
|------|------|------|-------------|
| Security Assessment | Trustpoint Maintainers | 2026-06-26 | Essential requirements documented |
| Product Responsibility | Trustpoint Project | 2026-06-26 | Technical documentation complete |
| Compliance Review | Trustpoint Project | 2026-06-26 | Self-assessment framework established |


---

## **CRA Assessment Maintenance**

### Update Triggers *(CRA Article 15 - Substantial Modification)*

1. Security architecture changes (auth methods, protocols, crypto)
2. Essential requirement impacts
3. Major dependencies with security implications
4. Risk profile changes
5. Regulatory updates affecting PKI software
6. Major version releases

**Principle:** Assessment stability - routine updates don't require reassessment unless affecting security architecture.

---

## **Related Documents**

**Project:** [ReadTheDocs][readthedocs] · [SECURITY.md](./SECURITY.md) · [LICENSE](./LICENSE) · [CONTRIBUTING.md](./CONTRIBUTING.md) · [AUTHORS.md](./AUTHORS.md)

**Standards:** RFC 7030 (EST) · RFC 9483 (CMP) · OPC UA GDS Push v1.05 · Django Security · OWASP ASVS

**Regulatory:** [EU CRA][cra-regulation] · Annex I (Requirements) · Annex V (Documentation) · Article 24 (Self-Assessment)

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
[badge-openssf]: https://www.bestpractices.dev/projects/11535/badge
[badge-pytest]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml/badge.svg?branch=main
[badge-codecov]: https://codecov.io/gh/Trustpoint-Project/trustpoint/graph/badge.svg?token=0N31L1QWPE
[badge-mypy]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml/badge.svg?branch=main
[badge-ruff]: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml/badge.svg?branch=main
[badge-license]: https://img.shields.io/badge/License-MIT-yellow.svg