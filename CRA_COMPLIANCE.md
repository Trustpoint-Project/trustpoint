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

---

## 2️⃣ **CRA Scope & Classification**

*Supports CRA Article 6 - Scope and Article 7 - Product Classification Assessment*

### CRA Applicability: [![Non-commercial OSS](https://img.shields.io/badge/Applicability-Non--commercial_OSS-lightgreen?style=flat-square&logo=github&logoColor=white)](#cra-scope--classification)

### Distribution Method: [![Community](https://img.shields.io/badge/Distribution-Community-green?style=flat-square&logo=users&logoColor=white)](#cra-scope--classification)

### CRA Classification: [![Standard](https://img.shields.io/badge/CRA-Standard-green?style=flat-square&logo=clipboard-check&logoColor=white)](#cra-scope--classification)

**CRA Scope Justification:** 

Trustpoint is a non-commercial open-source software project distributed through GitHub and Docker Hub under MIT license. As PKI/certificate management software for industrial environments, it falls under CRA scope as a product with digital elements providing security functions.

**Standard Classification Rationale:**
- Not explicitly listed in CRA Annex III (Class I or II products)
- Provides general PKI and certificate management functionality
- Does not perform functions specific to critical infrastructure products (e.g., industrial firewalls, SCADA gateways)
- Self-assessment approach is appropriate per CRA Article 24

**Classification Impact:**
- **Standard:** Self-assessment documentation (this assessment)
- **Evidence:** GitHub releases with test reports, security scans, and documentation
- **Conformity:** EU Declaration of Conformity based on self-assessment

---

## 3️⃣ **Technical Documentation**

*Supports CRA Annex V § 2 - Technical Documentation Requirements*

| CRA Technical Area | ✅ Status | 📝 Implementation Summary | 📋 Evidence (Direct Links) |
|----------------------|-----------|-------------------------|---------------------------|
| **Product Architecture** *(Annex V § 2.1)* | ✅ Implemented | Django-based web application with PostgreSQL backend, high-level data & trust boundaries documented | [docs](https://trustpoint.readthedocs.io/en/latest/) · [README.md](./README.md) · Architecture documentation |
| **SBOM & Components** *(Annex I § 1.1)* | ✅ Implemented | CycloneDX and SPDX SBOMS, Complete dependency enumeration via uv lock file | [pyproject.toml](./pyproject.toml) · [uv.lock](./uv.lock) · [SBOMs](https://trustpoint-project.github.io/trustpoint/) |
| **Cybersecurity Controls** *(Annex I § 1.2)* | ✅ Implemented | Django authentication, PKCS#11 HSM support, TLS/mTLS enforcement | [SECURITY.md](./SECURITY.md) · Security implementation in source |
| **Supply Chain Security** *(Annex I § 1.3)* | ✅ Implemented | GitHub Actions CI/CD, automated testing, Dependabot scanning | [.github/workflows/](./.github/workflows/) · [Dependabot](https://github.com/Trustpoint-Project/trustpoint/security/dependabot) configuration |
| **Update Mechanism** *(Annex I § 1.4)* | ✅ Implemented | Docker-based deployment with version tags, GitHub releases, rollback capability | [Docker Hub](https://hub.docker.com/r/trustpointproject/trustpoint) · [GitHub Releases](https://github.com/Trustpoint-Project/trustpoint/releases) |
| **Security Monitoring** *(Annex I § 1.5)* | 🔄 Partial | Django logging framework, audit trails for certificate operations; Prometheus telemetry data | Application logs · Monitoring implementation |
| **Data Protection** *(Annex I § 2.1)* | ✅ Implemented | Database encryption support, PKCS#11 secure key storage, backup functionality, minimal personal data | Django security features · PKCS#11 integration · Backup system |
| **User Guidance** *(Annex I § 2.2)* | ✅ Implemented | Comprehensive security configuration and deployment documentation | [ReadTheDocs](https://trustpoint.readthedocs.io) |
| **Vulnerability Disclosure** *(Annex I § 2.3)* | ✅ Implemented | Coordinated vulnerability disclosure via GitHub Security Advisories | [SECURITY.md](./SECURITY.md) |

**Key Security Features:**
- **HSM Integration:** PKCS#11 support for hardware security module key storage
- **Protocol Security:** TLS/mTLS enforcement for EST (RFC 7030), CMP (RFC 9483), AOKI, and OPC UA GDS Push
- **Authentication:** Multiple authentication mechanisms (X.509 certificates, passwords, shared secrets, IDevID)
- **Certificate Lifecycle:** Complete lifecycle management including issuance, renewal, revocation, and automated rotation
- **Industrial Focus:** Purpose-built for OT environments with 20+ year device lifecycles
- **Containerized Deployment:** Docker-based deployment for consistency and security
- **Quality Assurance:** 80%+ test coverage with pytest, mypy type checking, ruff linting

---

## 4️⃣ **Risk Assessment**

*Supports CRA Annex V § 3 - Risk Assessment Documentation*

| **CRA Risk Category** | Asset | Likelihood | Impact (C/I/A) | CRA Control Implementation | Residual | Evidence |
|--------------------------|----------|---------------|------------------|------------------------------|-------------|-------------|
| **Supply Chain Attack** *(Art. 11)* | Build pipeline | M | H/H/M | GitHub Actions, [Dependabot](https://github.com/Trustpoint-Project/trustpoint/security/dependabot), dependency pinning in uv.lock | L | CI/CD workflows, dependency scanning |
| **Unauthorized Access** *(Art. 11)* | Certificate operations | M | H/H/H | Django authentication, role-based access control | L | Authentication implementation |
| **Key Compromise** *(Art. 11)* | Private keys | L | H/H/H | PKCS#11 HSM support, encrypted key storage | L | HSM integration code |
| **Certificate Forgery** *(Art. 11)* | CA infrastructure | L | H/H/H | Secure CA key management, HSM support, access controls | L | CA security architecture |
| **Component Vulnerability** *(Art. 11)* | Dependencies | M | M/H/M | Automated dependency scanning, timely updates, test coverage | L | [Dependabot](https://github.com/Trustpoint-Project/trustpoint/security/dependabot) alerts, test reports |
| **Protocol Weakness** *(Art. 11)* | EST/CMP/AOKI/GDS | L | M/H/M | Standards-compliant implementation, TLS enforcement | M | Protocol documentation |
| **Data Breach** *(Art. 11)* | Certificate database | M | H/H/M | Database encryption, access controls, backup encryption | L | Django security configuration |
| **Service Disruption** *(Art. 11)* | Certificate services | M | L/M/H | Database backup, Docker deployment, health monitoring | M | Backup and monitoring features |

**⚖️ CRA Risk Statement:** MODERATE - Trustpoint implements robust security controls appropriate for PKI infrastructure. Residual risks are primarily related to deployment configuration and operational procedures outside software scope.

**✅ Risk Acceptance:** Trustpoint Project Maintainers - 2026-06-26

**Key Risk Mitigations:**
- **HSM Integration:** Optional PKCS#11 support reduces key compromise risk
- **Automated Testing:** 80%+ code coverage ensures reliability (pytest, mypy, ruff)
- **Dependency Management:** uv lock file ensures reproducible, validated builds
- **Continuous Scanning:** [Dependabot](https://github.com/Trustpoint-Project/trustpoint/security/dependabot) and security workflows identify vulnerabilities early
- **Documentation:** Comprehensive ReadTheDocs guides support secure deployment

---

## 5️⃣ **Essential Cybersecurity Requirements**

*Supports CRA Annex I - Essential Requirements Self-Assessment*

| 📋 **CRA Annex I Requirement** | ✅ Status | 📋 Implementation Evidence |
|--------------------------------|-----------|---------------------------|
| **§ 1.1 - Secure by Design** | [x] | Minimal attack surface: Django framework with security middleware, input validation, parameterized queries |
| **§ 1.2 - Secure by Default** | [x] | Default configurations enforce TLS, require authentication, disable debug mode in production |
| **§ 2.1 - Personal Data Protection** | [x] | Minimal personal data collection, Django privacy features, configurable data retention |
| **§ 2.2 - Vulnerability Disclosure** | [x] | Public VDP via `SECURITY.md` with GitHub Security Advisories, 5-day response commitment |
| **§ 2.3 - Software Bill of Materials** | [x] | [SBOM Portal](https://trustpoint-project.github.io/trustpoint/) |
| **§ 2.4 - Secure Updates** | [x] | Docker image versioning, [GitHub releases](https://github.com/Trustpoint-Project/trustpoint/releases), backward-compatible update path |
| **§ 2.5 - Security Monitoring** | [x] | Django logging framework, audit trails for certificate operations, configurable log levels, [Prometheus](https://prometheus.io) telemetry |
| **§ 2.6 - Security Documentation** | [x] | Comprehensive security guidance at https://trustpoint.readthedocs.io |

**CRA Self-Assessment Status:** REQUIREMENTS_DOCUMENTED

**🔍Security Reporting Process:**

Trustpoint implements standardized security reporting via `SECURITY.md`:

- **Private Reporting:** GitHub Security Advisories for confidential disclosure
- **Response Timeline:** 5 business days acknowledgment, timely validation and resolution
- **Recognition Program:** Public acknowledgment unless anonymity requested  
- **Security Updates:** Maintained for current stable version
- **Vulnerability Scope:** Authentication bypass, injection attacks, cryptographic weaknesses, key management issues, protocol implementation flaws

**Contact:** trustpoint@campus-schwarzwald.de

---

## 6️⃣ **Conformity Assessment Evidence**

*Supports CRA Article 19 - Conformity Assessment Documentation*

### **Quality & Security Automation Status:**

| Control | Requirement | Implementation | Evidence |
|-------------|---------------|------------------|-------------|
| Unit Testing | ≥80% line coverage | 🔄 In Progress (69% current) | [Pytest](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml) with [codecov.io](https://app.codecov.io/gh/Trustpoint-Project/trustpoint) reporting |
| Type Checking | Complete type coverage | ✅ Implemented | [MyPy](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml) with strict configuration |
| Code Quality | Linting and formatting | ✅ Implemented | [Ruff](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml) for linting and formatting |
| Dependency Scanning | Automated vulnerability detection | ✅ Implemented | [Dependabot](https://github.com/Trustpoint-Project/trustpoint/security/dependabot) integration |
| Security Best Practices | Industry standards compliance | ✅ In Progress | [OpenSSF Best Practices](https://www.bestpractices.dev/de/projects/11535/baseline-3) (passing) |
| SBOM | CycloneDX & SPDX formats | ✅ Implemented | [SBOM Portal](https://trustpoint-project.github.io/trustpoint/) |
| CI/CD Pipeline | Automated testing and validation | ✅ Implemented | [GitHub Actions](https://github.com/Trustpoint-Project/trustpoint/actions) workflows |
| Container Security | Secure Docker deployment | ✅ Implemented | [Docker Hub automated builds](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/docker-manual.yml) |

### **Security & Compliance Badges:**

**Quality & Testing:**
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11535/badge)](https://www.bestpractices.dev/projects/11535)
[![Pytest Status](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml/badge.svg?branch=main)](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml)
[![codecov](https://codecov.io/gh/Trustpoint-Project/trustpoint/graph/badge.svg?token=0N31L1QWPE)](https://codecov.io/gh/Trustpoint-Project/trustpoint)

**Code Quality:**
[![MyPy](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml/badge.svg?branch=main)](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml)
[![Ruff Status](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml/badge.svg?branch=main)](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml)

**License:**
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Project Resources:**
- **Documentation:** https://trustpoint.readthedocs.io
- **SBOM Portal:** https://trustpoint-project.github.io/trustpoint/ (CycloneDX & SPDX formats)
- **Docker Hub:** https://hub.docker.com/r/trustpointproject/trustpoint
- **Discussions:** https://github.com/orgs/Trustpoint-Project/discussions
- **Security Policy:** https://github.com/Trustpoint-Project/trustpoint/blob/main/SECURITY.md

### 📋 Evidence Availability:

**Current Evidence Status:**
- ✅ Automated test suite with coverage reporting
- ✅ Static type checking with MyPy
- ✅ Code quality validation with Ruff
- ✅ Dependency vulnerability scanning via [Dependabot](https://github.com/Trustpoint-Project/trustpoint/security/dependabot)
- ✅ CI/CD pipeline verification via GitHub Actions
- ✅ OpenSSF Best Practices compliance (passing level)
- ✅ SBOM generation (CycloneDX & SPDX) published at [SBOM Portal](https://trustpoint-project.github.io/trustpoint/)
- 🔄 Release attestations (to be implemented)
- 🔄 SLSA provenance (to be implemented)


## 7️⃣ **Post-Market Surveillance**

*Supports CRA Article 23 - Obligations of Economic Operators*

| **CRA Monitoring Obligation** | Implementation | Frequency | Action Trigger | Evidence |
|----------------------------------|-------------------|-------------|------------------|-------------|
| **Vulnerability Monitoring** *(Art. 23.1)* | CVE feeds + GitHub Security Advisories + Dependabot +  [ZAP Baseline Scan](./.github/workflows/zap.yml) + [CodeQL](https://github.com/Trustpoint-Project/trustpoint/security/code-scanning) + [Secret scanning](https://github.com/Trustpoint-Project/trustpoint/security/secret-scanning) | Continuous | Auto-create security issues | Dependabot alerts |
| **Incident Reporting** *(Art. 23.2)* | GitHub issue tracking, security advisory process | As needed | Security incident creation | Security advisories |
| **Security Posture Tracking** *(Art. 23.3)* | OpenSSF Best Practices scorecard | Continuous | Score decline investigation | Badge monitoring |
| **Update Distribution** *(Art. 23.4)* | [GitHub releases](https://github.com/Trustpoint-Project/trustpoint/releases) + [Docker Hub](https://hub.docker.com/r/trustpointproject/trustpoint) | As needed | Critical vulnerability patches | Release history |

**CRA Reporting Readiness:** 

Trustpoint maintains security monitoring and incident response capabilities:

- **Continuous Monitoring:** GitHub [Dependabot](https://github.com/Trustpoint-Project/trustpoint/security/dependabot) scans dependencies daily
- **Issue Tracking:** Security issues tracked via GitHub Security Advisories
- **Quality Metrics:** OpenSSF Best Practices badge tracks security posture
- **Update Process:** Docker-based deployment enables rapid security updates
- **Contact:** trustpoint@campus-schwarzwald.de for security coordination

**Monitoring Resources:**
- **GitHub Security:** https://github.com/Trustpoint-Project/trustpoint/security
- **CI/CD Status:** https://github.com/Trustpoint-Project/trustpoint/actions
- **Best Practices:** https://www.bestpractices.dev/projects/11535


## 8️⃣ **EU Declaration of Conformity**

*Supports CRA Article 28 - EU Declaration of Conformity*

> **To be completed when placing product on EU market (post-beta)**

**Manufacturer:** Trustpoint Project  
**Product:** Trustpoint Trust Anchor Software v0.6.0.dev1  
**CRA Classification:** Standard (Non-commercial Open Source Software)  
**Assessment:** Self-assessment documentation per CRA Article 24  
**Standards Referenced:** 
- RFC 7030 (EST)
- RFC 9483 (CMP)
- OPC UA GDS Push Specification
- Django Security Best Practices
- OWASP Application Security Verification Standard (ASVS)

**Declaration Status:** Pre-market (Technology Preview/Beta)

**Technical Documentation:** This CRA assessment + GitHub repository documentation

---

## 9️⃣ **Assessment Completion & Approval**

*Supports CRA Article 16 - Quality Management System Documentation*

### **CRA Self-Assessment Summary**

**Overall CRA Documentation Status:** IN_PROGRESS

**Key CRA Documentation Areas:**
- ✅ Annex I essential requirements documented and assessed
- ✅ Annex V technical documentation structured  
- ✅ Article 11 security measures documented
- ✅ Article 23 post-market surveillance procedures documented
- 🔄 Release attestations (to be implemented)
- 🔄 Production-ready status (currently beta)

**Outstanding Items:**
1. **SBOM Automation:** Implement automated SBOM generation in CI/CD pipeline (Target: v1.0 release)
2. **SLSA Attestations:** Add SLSA provenance attestations to GitHub releases (Target: v1.0 release)
3. **Production Release:** Complete beta testing phase and release v1.0 (Target: TBD)
4. **Security Audit:** Consider third-party security audit before production release (Target: TBD)

### ✅ **Formal Approval**

| **Role** | **Name** | **Date** | **Assessment Attestation** |
|------------|-------------|-------------|-------------------------------|
| **CRA Security Assessment** | Trustpoint Maintainers | 2026-06-26 | Essential requirements documented and assessed |
| **Product Responsibility** | Trustpoint Project | 2026-06-26 | Technical documentation complete and structured |
| **Compliance Review** | Trustpoint Project | 2026-06-26 | CRA self-assessment framework established |

**CRA Assessment Status:** SELF_ASSESSMENT_DOCUMENTED (Beta Phase)

---

## **CRA Assessment Maintenance**

### **Update Triggers** 
*Per CRA Article 15 - Substantial Modification*

This CRA assessment will be updated when changes constitute "substantial modification" under CRA:

1. **Security Architecture Changes:** New authentication methods, protocols, or cryptographic implementations
2. **Essential Requirement Impact:** Changes affecting CRA Annex I compliance
3. **Major Dependencies:** New core dependencies with security implications (e.g., new protocols, frameworks)
4. **Risk Profile Changes:** New threat models or vulnerability classes
5. **Regulatory Updates:** CRA implementing acts or guidance affecting PKI/certificate management software
6. **Release Milestones:** Major version releases (e.g., beta to v1.0)

**Maintenance Principle:** Assessment stability preferred - routine dependency updates and minor features do not require CRA assessment updates unless they impact security architecture.

### **Current Assessment Status**

**Product Version:** 0.6.0.dev1 (Beta - Technology Preview)  
**CRA Documentation:** This assessment + [GitHub Repository](https://github.com/Trustpoint-Project/trustpoint)  
**Security Resources:** [SECURITY.md](https://github.com/Trustpoint-Project/trustpoint/blob/main/SECURITY.md)  
**Assessment Status:** ![CRA Status](https://img.shields.io/badge/CRA_Self_Assessment-In_Progress-yellow)

---

## **Related Documents & Resources**

### **Project Documentation**
- **ReadTheDocs:** https://trustpoint.readthedocs.io - Comprehensive user and deployment documentation
- **Security Policy:** [SECURITY.md](./SECURITY.md) - Vulnerability disclosure and security practices
- **License:** [LICENSE](./LICENSE) - MIT License
- **Contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines
- **Authors**: [AUTHORS.md](./AUTHORS.md) - Contributing authors

### **Technical Standards & Specifications**
- **RFC 7030:** EST (Enrollment over Secure Transport)
- **RFC 9483:** CMP (Certificate Management Protocol)
- **OPC UA GDS Push:** OPC Foundation GDS Push Specification v1.05
- **Django Security:** Django Framework Security Best Practices
- **OWASP ASVS:** Application Security Verification Standard

### **Regulatory Framework**
- **EU CRA:** Cyber Resilience Act (Regulation (EU) 2024/2847)
- **CRA Annex I:** Essential Cybersecurity Requirements
- **CRA Annex V:** Technical Documentation Requirements
- **CRA Article 24:** Self-Assessment Procedures

### **Security & Quality Resources**
- **OpenSSF Best Practices:** https://www.bestpractices.dev/projects/11535
- **GitHub Security:** https://github.com/Trustpoint-Project/trustpoint/security
- **CI/CD Pipelines:** https://github.com/Trustpoint-Project/trustpoint/actions
- **Code Coverage:** https://codecov.io/gh/Trustpoint-Project/trustpoint

---

## **CRA Regulatory Alignment**

### **CRA Article Cross-References**
- **Article 6:** Scope determination → Section 2 (CRA Classification)
- **Article 11:** Essential cybersecurity requirements → Section 5 (Requirements Assessment)  
- **Article 19:** Conformity assessment → Section 6 (Evidence Documentation)
- **Article 23:** Post-market obligations → Section 7 (Surveillance Documentation)
- **Article 24:** Self-assessment procedures → Complete document structure
- **Article 28:** Declaration of conformity → Section 8 (DoC Template)
- **Annex I:** Technical requirements → Section 5 (Requirements self-assessment mapping)
- **Annex V:** Technical documentation → Complete template structure

### **Open Source Software Considerations**

**CRA OSS Steward Model:**
Trustpoint operates under the CRA's open-source software provisions:
- **Non-commercial:** Distributed freely via GitHub and Docker Hub
- **Community-driven:** Maintained by Trustpoint Project contributors
- **Transparency:** Full source code availability enables security review
- **No Support Obligations:** Users responsible for deployment and operation
- **Voluntary Standards:** Following industry best practices without commercial obligations

**CRA Application to OSS:**
- Standard products (non-Class I/II) benefit from simplified self-assessment
- Open-source transparency supports technical documentation requirements
- Community security practices align with essential cybersecurity requirements
- GitHub-based development provides audit trails and provenance


