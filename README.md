![Trustpoint](.github-assets/trustpoint_banner.png)

<div align="center">

**The open source trust anchor software for machines and factories to manage digital identities.**

[![Landing Page](https://img.shields.io/badge/Landing_Page-014BAD)](https://trustpoint.campus-schwarzwald.de/en/)
[![GitHub Discussions](https://img.shields.io/badge/GitHub-Discussions-014BAD)](https://github.com/orgs/Trustpoint-Project/discussions)
[![Read the Docs](https://img.shields.io/readthedocs/trustpoint)](https://trustpoint.readthedocs.io)
[![Docker Automated](https://img.shields.io/docker/automated/trustpointproject/trustpoint)](https://hub.docker.com/r/trustpointproject/trustpoint)
![Status](https://img.shields.io/badge/Status-Beta-red)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11535/badge)](https://www.bestpractices.dev/projects/11535)
[![Pytest Status](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml/badge.svg?branch=main)](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml)
[![codecov](https://codecov.io/gh/Trustpoint-Project/trustpoint/graph/badge.svg?token=0N31L1QWPE)](https://codecov.io/gh/Trustpoint-Project/trustpoint)
[![MyPy](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml/badge.svg?branch=main)](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml)
[![Ruff Status](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml/badge.svg?branch=main)](https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml)
</div>

> [!CAUTION]
> Trustpoint is currently in a **technology preview** (beta) state. Do not use it in production.

## Why Trustpoint?

Industrial environments are becoming increasingly connected, intelligent, and automated — but secure identity management has not kept pace. In OT, many established IT security processes cannot be applied 1:1. Networks are highly segmented, devices are resource-constrained, and machine lifecycles often span 20+ years. These realities create major barriers to deploying and managing digital identities at scale.

The result is what many manufacturers face today:
manual certificate handling, isolated certificate silos, self-signed certificatesd, vendor lock-in, and a growing security skill gap. These challenges frequently lead to digital identities being implemented inconsistently, inadequately, or not at all.

**Trustpoint solves this.**
It abstracts the complexity of PKI and certificate lifecycle management, providing an open, flexible, and automatable platform purpose-built for OT environments — from factory floors to field devices.

Trustpoint enables machine builders, operators, and integrators to:

* Deploy digital identities easily and securely — without requiring PKI or cryptography expertise
* Automate certificate provisioning, renewal, and decommissioning across the device lifecycle
* Use onboarding workflows that fit OT realities, including Zero-Touch onboarding, semi-automated flows, and operator-driven enrollment
* Avoid vendor lock-in through open standards, an open-source foundation, and interoperable protocols
* Reduce operational risk by consolidating fragmented certificate silos into a unified, manageable trust layer

## What are the features?

### 1. Device Onboarding & Certificate Management

Trustpoint supports a variety of PKI protocols and authentication methods for both device onboarding (initial LDevID issuance) and operational certificate management (TLS, authentication, signing certificates).
The following options provide a complete lifecycle—from zero-touch onboarding to renewal and re-enrollment.

Trustpoint supports multiple enrollment and onboarding methods:

**[AOKI](https://trustpoint.readthedocs.io/en/latest/devices/aoki.html)** (Zero-Touch Onboarding)

A secure, automated onboarding protocol designed specifically for industrial environments.
Zero-touch issuance of initial device credentials (LDevID)

---

**EST** (Enrollment over Secure Transport) [[RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030)]

Supports both onboarding and application certificate enrollment.

Authentication Methods:
* Username + Password (operator-driven onboarding or enrollment)
* IDevID-based authentication (secure manufacturer-anchored onboarding)
* Client Certificate (mTLS) for renewal and re-enrollment

Capabilities:
* Device onboarding (LDevID issuance)
* Application certificate enrollment
* Certificate renewal and re-enrollment

---

**CMP** (Certificate Management Protocol) [[RFC 9483](https://datatracker.ietf.org/doc/rfc9483/)]

Flexible onboarding and certificate management for constrained or industrial devices.

Authentication Methods:
* Shared Secret authentication (bootstrap or one-time enrollment)
* IDevID-based authentication (manufacturer identity onboarding)
* Client Certificate (mTLS) for operational certificate renewal and rekeying

Capabilities:
* Onboarding (LDevID issuance)
* Application certificate enrollment
* Automated renewal and rekeying

---

**Additional Certificate Issuance Options**

Manual Download
* Trustpoint generates both the keypair and certificate
* Downloadable in PKCS#12 and PEM formats

Remote Credential Download
* Device retrieves credentials directly via its browser
* Secured with a one-time password (OTP)

### 2. Certificate Authority (CA) Modes

- **Import Issuing CA**: Integrate with an existing PKI by importing external CAs.
- **Auto-Generated CA**: Create a root and issuing CA for testing purposes.

### 3. Miscellaneous

Trustpoint includes several supporting capabilities that enhance usability, integration, and operational workflows:
* **RESTful API** for device management, certificate issuance, identity lifecycle operations, and system integration.
* **Workflow Engine** with manual approval steps, webhook integrations (ERP, MES, IAM, etc.), and email notifications to fit seamlessly into existing operational processes.
* **Signing Authority** (Hash & Sign) allowing devices or services to submit a hash and receive a signed artifact.
* Additional Features including a **web-based UI**, **system dashboard**, **Docker deployment**, **CRL & certificate revocation management**, and **multi-language** support.

## Who is developing Trustpoint?

Trustpoint is currently being developed by a consortium of five organizations: Campus Schwarzwald, Keyfactor, achelos
GmbH, Hamm-Lippstadt University of Applied Sciences and asvin GmbH. Several industrial companies are also part of the
project as associated partners. These include ARBURG GmbH + Co KG, Belden Inc., Diebold Nixdorf, Homag GmbH, J. Schmalz
GmbH, PHOENIX CONTACT GmbH & Co. KG and Siemens AG.

Trustpoint is funded as part of a project sponsored by the German Federal Ministry of Education and Research. Questions
can be asked in [Discussions](https://github.com/orgs/Trustpoint-Project/discussions) and will be answered by us. We
look forward to hearing about your experiences with Trustpoint. You can send suggestions to
trustpoint@campus-schwarzwald.de.

## Documentation and Installation Instructions

For more details see the full [Trustpoint Documentation](https://trustpoint.readthedocs.io/en/latest/).

For a quick setup and first impression use
our [Quickstart Setup Guide](https://trustpoint.readthedocs.io/en/latest/getting_started/quickstart_setup.html)

### Docker Hub

We are also providing the Trustpoint as a docker-container. Please see
[Trustpoint on Docker Hub](https://hub.docker.com/r/trustpointproject/trustpoint) or follow the
instructions in our [Trustpoint Documentation](https://trustpoint.readthedocs.io/en/latest/) to build the
container yourself.
