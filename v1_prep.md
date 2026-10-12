# Trustpoint v1.0 Release Readiness Assessment

**Assessment date:** 21 September 2026
**Repository:** `Trustpoint-Project/trustpoint`
**Current latest release observed:** v0.6.0, released 22 July 2026

This assessment follows the requested evidence-based review of Trustpoint as a complete open-source product rather than only as a codebase. The distinction requested between **stable OSS release readiness** and **production readiness** is especially important for Trustpoint because it is security-critical PKI software.

A limitation of this assessment is that I could inspect the current public repository, releases, documentation and visible CI evidence, but independent checkout/test execution could not be completed because the execution environment could not resolve GitHub. I therefore do **not** claim to have independently executed the current test suite.

---

# 1. Executive Summary

Trustpoint is **not yet ready to publish v1.0.0 today**, but it is substantially closer than a typical beta project.

The current repository already contains most of the engineering foundations expected from a credible security-focused open-source project:

* CA and RA operation
* EST and CMP
* OPC UA GDS Push
* certificate enrollment, renewal, rekeying and revocation
* CA rollover
* PKCS#11/HSM abstraction
* REST/headless operation
* users, roles and organizations
* audit logging
* Prometheus metrics
* backup mechanisms
* workflow automation
* SBOM-related work
* threat modelling, risk register and CRA/security-control documentation
* pytest/Behave testing
* MyPy and Ruff
* CodeQL
* OWASP ZAP
* dependency automation
* documented vulnerability reporting

v0.6.0 specifically added CA rollover, HSM integration, initial RBAC/organization support, audit logging, REST/headless integration and Prometheus monitoring.

However, the project itself still explicitly states:

> Trustpoint is a technology preview and is not intended for production use.

This is present in both the README and architecture documentation. The architecture documentation additionally states that features, APIs and deployment patterns may change between releases.

The main problem is therefore **not a lack of features**. It is that Trustpoint has not yet established the operational and compatibility contracts that the `1.0.0` version number should imply.

### My assessment identifies six actual v1.0 blockers

1. **A supported and tested upgrade/migration path must be defined.**
2. **Database + HSM + application-secret disaster recovery must be demonstrated as one coherent recovery process.**
3. **The interfaces that become stable with v1.0 must be explicitly defined.**
4. **A current v1.0 release-acceptance test result must exist for the critical PKI paths.**
5. **A supported-version and security-update policy must be published.**
6. **A minimum secure deployment profile must be defined and validated.**

Everything else identified below can either be handled as HIGH/MEDIUM work or explicitly declared a limitation.

This distinction matters. Trustpoint does **not** need enterprise HA, automatic HSM clustering, Certificate Transparency, multi-tenancy, PQC, every conceivable enrollment protocol, or perfect coverage before v1.0.

---

# 2. What v1.0 Means for Trustpoint

For Trustpoint, `v1.0.0` should mean:

**The supported core is stable enough that an external administrator can install Trustpoint, establish a CA or RA configuration, onboard devices, issue/renew/revoke certificates, back the installation up, restore it, update it to the next compatible release, and understand which interfaces and configurations the maintainers promise not to break without appropriate versioning.**

It should **not** mean that every experimental feature is stable.

I recommend establishing three interface categories for v1.0:

| Category                       | Examples                                                                                                                    | v1.0 treatment               |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| **Stable core**                | CA/RA operation, domains, certificates, devices, revocation, renewal/rekeying, EST, supported CMP functions, backup/restore | Compatibility commitment     |
| **Stable integration surface** | selected REST API endpoints, configuration/env variables required for production deployment, Docker deployment contract     | Versioned/deprecation policy |
| **Experimental**               | AOKI proof of concept, selected workflow capabilities, emerging agents/integrations                                         | Explicitly allowed to change |

The README already labels AOKI as a **proof of concept**, so there is no reason for AOKI maturity to delay v1.0.

---

# 3. Release-Readiness Matrix

| Area                         | Status              | Evidence / assessment                                                                      | Key gap                                                                   | v1.0 blocker? |
| ---------------------------- | ------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- | ------------- |
| Core functionality           | 🟡 Mostly ready     | Broad lifecycle, CA/RA, EST, CMP, GDS, agents and workflows documented and shipped in v0.6 | Release-level integration evidence                                        | Partly        |
| Architecture                 | 🟡 Mostly ready     | Modular crypto-provider architecture and separation of DB metadata from key operations     | Architecture explicitly still allowed to evolve                           | No            |
| Security                     | 🟠 Significant gaps | HSM, encryption, threat model, CodeQL/ZAP present                                          | Production baseline and some operational controls incomplete              | **Yes**       |
| PKI lifecycle                | 🟡 Mostly ready     | Issuance, renewal, rekeying, revocation and CA rollover present                            | Recovery, rollover and failure-path validation                            | **Yes**       |
| Authentication/authorization | 🟡 Mostly ready     | Sessions, JWT, protocol auth, initial RBAC                                                 | No built-in brute-force lockout/rate limiting                             | No            |
| Testing                      | 🟠 Significant gaps | pytest + Behave + security pipelines are established                                       | Published acceptance evidence remains incomplete/stale                    | **Yes**       |
| CI                           | 🟡 Mostly ready     | pytest, Behave, MyPy, Ruff, CodeQL, ZAP visible                                            | Required-check/branch-protection configuration not independently verified | No            |
| Supply-chain security        | 🟡 Mostly ready     | Lockfile, Renovate, SBOM work, signed GitHub release commits                               | Release attestations/SLSA still planned                                   | No            |
| Deployment                   | 🟠 Significant gaps | Docker wizard and deployment scenarios documented                                          | No finalized secure production deployment contract                        | **Yes**       |
| Backup/restore               | 🟠 Significant gaps | Real backup/manifest design exists                                                         | Operator docs contradict architecture docs; HSM recovery external         | **Yes**       |
| Upgrade/migration            | 🔴 Not ready        | Historical releases required rebuilding environments                                       | No stable supported upgrade contract                                      | **Yes**       |
| Observability                | 🟡 Mostly ready     | Prometheus, logging, audit trail documented                                                | Audit trail not tamper-resistant                                          | No            |
| Documentation                | 🟠 Significant gaps | Extensive documentation                                                                    | Material contradictions and missing v1 contracts                          | Partly        |
| API stability                | 🔴 Not ready        | REST/headless APIs exist                                                                   | Docs explicitly state APIs may change                                     | **Yes**       |
| OSS governance               | 🟡 Mostly ready     | LICENSE, AUTHORS, CONTRIBUTING, CoC, SECURITY present                                      | Support/release responsibilities need v1 formalization                    | No            |
| Vulnerability management     | 🟡 Mostly ready     | Private reporting and response expectations established                                    | Supported-version/update policy unfinished                                | **Yes**       |
| Release engineering          | 🟠 Significant gaps | Versioned releases, CI, signed release commits                                             | Provenance/attestations and formal release gate incomplete                | No            |
| CRA/security engineering     | 🟡 Mostly ready     | Threat model, controls and conformity material unusually mature for beta                   | Several controls explicitly remain pre-v1 work                            | No            |

The repository contains the expected OSS project files including `LICENSE`, `AUTHORS.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `uv.lock` and `renovate.json`.

---

# 4. Detailed Findings by Area

## A. Core Functionality — 🟡 Mostly ready

**Verified**

The public product surface now covers the important machine-identity lifecycle: onboarding, enrollment, renewal/re-enrollment, rekeying, revocation and decommissioning. EST, CMP and OPC UA GDS Push are documented protocol surfaces. CA and RA modes are also present.

The README distinguishes protocol capabilities and already marks AOKI as proof-of-concept rather than representing every onboarding method as equally mature.

**Concern**

The question for v1.0 is now less “does the feature exist?” and more:

> Can the project prove that the supported lifecycle continues working across failure, recovery and upgrade conditions?

**Classification:** HIGH until critical-path acceptance testing is complete.

---

## B. Architecture — 🟡 Mostly ready

The architecture is increasingly coherent.

In particular, key operations are abstracted from certificate metadata, and the documented production model places private-key operations behind PKCS#11 rather than storing CA private-key bytes in PostgreSQL. The software crypto provider is explicitly described as development/test only.

This is a strong direction for v1.0.

The main architectural concern is **stability rather than structure**: the architecture documentation still tells consumers that APIs and deployment patterns may change between releases.

**Classification:** MEDIUM technically; BLOCKER specifically for the compatibility contract.

---

## C. Security — 🟠 Significant gaps

There are several positive properties:

* Argon2 password hashing is documented.
* HTTPS-only cookies and CSRF protection are documented.
* REST authentication uses short-lived JWTs with rotation/blacklisting support.
* EST supports password/client-certificate authentication.
* CMP supports PBMAC1/client-certificate authentication.
* production CA keys can reside in PKCS#11 HSMs.

The project also maintains an explicit threat model covering administrative compromise, CA-key compromise, unauthorized issuance, enrollment replay, revocation failure, backup failure, insecure deployment and release-pipeline compromise.

That is materially better than treating security as only a scanner result.

However, the project's own security model lists:

* audit records are not cryptographically tamper-proof;
* no tenant isolation;
* manual CA key rotation may require downtime;
* no built-in rate limiting;
* no automatic brute-force lockout.

These are not all v1.0 blockers.

For example, **multi-tenancy is not required** if separate instances are the supported model. Certificate Transparency is likewise not inherently required for an industrial/private PKI.

Rate limiting and brute-force protection can be handled through the supported reverse-proxy/deployment profile rather than necessarily implemented in Django.

**Classification:** HIGH overall.

---

## D. PKI Lifecycle — 🟡 Mostly ready

The functional surface is strong enough for v1.0: issuance, renewal, rekeying, revocation, CRLs, profile handling and CA rollover are represented in current functionality.

A useful historical issue shows why failure-path regression testing matters: issue #198 documented that onboarding a device twice could produce duplicate active LDevIDs and subsequently break detail/revocation/delete operations. That issue is closed, but the scenario should remain a permanent regression test because it represents exactly the class of identity-state corruption a PKI system must resist.

**Classification:** HIGH for failure-case testing, not for feature completeness.

---

## E. Tests — 🟠 Significant gaps

CI documentation confirms use of:

* pytest
* Behave
* Codecov
* MyPy
* Ruff
* CodeQL
* OWASP ZAP.

ZAP scans both HTTP and HTTPS deployments and is documented to fail the pipeline on medium/high findings. CodeQL covers Python, JavaScript/TypeScript and GitHub Actions.

A current GitHub Actions run also provides observable evidence that requirement-specific Behave workflows continue to execute successfully.

Historically, v0.4 reported 2,425 tests and 71% unit-test coverage. I would **not** use that number as the current v0.6 coverage figure. Current CRA documentation instead describes coverage as progressing toward an 80% target.

More importantly, the published test plan still lists acceptance criteria as pending and end-user acceptance testing plus the comprehensive final test report as “Not Started.”

This may partly be stale documentation, because observable CI is clearly more advanced. But that is itself the problem: **there is no unambiguous current release-acceptance evidence package.**

**Classification:** BLOCKER for the v1 release candidate, not because coverage must reach an arbitrary percentage.

---

## F. CI/CD — 🟡 Mostly ready

This area is one of Trustpoint's strengths.

Automated unit/BDD testing, static typing, linting, CodeQL and dynamic ZAP testing are already part of the engineering process.

Before v1.0 I would verify, rather than redesign, CI:

* main branch protection;
* required checks;
* no administrator bypass for release-critical controls where practical;
* release build uses the same reviewed commit that passed CI.

**Classification:** MEDIUM.

---

## G. Supply-Chain Security — 🟡 Mostly ready

Positive evidence includes:

* `uv.lock`;
* Renovate configuration;
* security dependency updates;
* SBOM work;
* verified GitHub release commits.

The CRA material explicitly says release attestations and SLSA provenance are still planned for v1.0.

Release notes also show third-party Actions referenced by version tags such as `docker/login-action@v4`; immutable commit-SHA pinning would reduce workflow supply-chain risk.

I would implement provenance for v1 if practical, but I would **not hold the whole release indefinitely** solely because full SLSA maturity is unfinished.

**Classification:** HIGH for provenance; MEDIUM for SHA-pinning.

---

## H. Deployment and Operations — 🟠 Significant gaps

The setup experience is already substantial. The wizard provides a guided Docker installation, and deployment scenarios cover isolated OT CA, enterprise-connected RA, headless operation and development.

Testing credentials are clearly labelled as testing-only. That is good and should not be misclassified as an insecure-default blocker.

However, current setup documentation uses `:latest` Docker image tags. That is acceptable for experimentation but inappropriate as the primary v1 production installation path because it makes deployment and rollback less reproducible.

The deployment documentation recommends HSM, monitoring, backups, segmentation, HTTPS/HSTS, least privilege, SIEM and MFA. But the security model separately states that no automatic account lockout or built-in rate limiter exists.

v1 therefore needs one **normative secure deployment profile** telling operators which external controls are mandatory.

**Classification:** BLOCKER for that baseline; other operational enhancements HIGH/MEDIUM.

---

## I. Backup, Restore and Upgradeability — 🔴 Critical v1 area

There has been significant progress.

Current architecture documentation describes:

* PostgreSQL backup payload;
* backup manifest;
* Trustpoint version;
* backend metadata;
* SHA-256 payload integrity;
* verification before restore.

Data-management documentation also describes scheduled/SFTP backup and explicitly states that HSM-held CA keys require separate HSM-specific backup.

However, another current Usage Guide still says backup, update and restore are not implemented and that configuration cannot be carried forward.

That statement is evidently stale with respect to backup functionality, but it makes the public operational contract ambiguous.

Upgradeability is even more concerning historically: the v0.5.0 release explicitly instructed users to create a new Docker environment when upgrading.

For v1, “we have Django migrations” is insufficient.

There must be one supported migration scenario from an explicitly named pre-v1 release to v1.0.0 using realistic state.

**Classification:** BLOCKER.

---

## J. Crypto-State Recovery — 🔴 Critical v1 area

This deserves separate treatment from database backup.

Trustpoint correctly keeps HSM CA keys outside PostgreSQL. Consequently:

> a database backup alone is not a Trustpoint disaster-recovery backup.

Current documentation acknowledges that HSM keys need vendor-specific backup and recovery.

There is another dependency: application-secret encryption. Trustpoint uses AES-256-GCM with a DEK that can itself be protected by a PKCS#11 KEK. The documentation explicitly warns that loss/corruption of the DEK can make previously encrypted values unrecoverable, and application-secret key rotation is not currently implemented.

This creates an important v1 requirement:

**The recovery unit must be explicitly defined as database + application-secret material + relevant HSM keys/configuration + required filesystem state.**

A restore must fail safely when the wrong HSM/token/key set is supplied; it must never silently regenerate keys and leave existing encrypted state unusable.

**Classification:** BLOCKER.

---

## K. API and Compatibility Stability — 🔴 Not ready

REST APIs are now a claimed product capability and are intended for MES/ERP/IAM/automation integration.

But the architecture documentation still explicitly reserves the right for APIs and deployment patterns to evolve.

That is appropriate for v0.x.

It is not sufficient for v1.0.

The solution does **not** require freezing every endpoint. It requires a declaration such as:

* Management REST API v1: stable.
* EST endpoints: standards-defined/stable.
* CMP supported operation subset: stable.
* configuration keys documented as stable.
* experimental workflow/AOKI APIs: unstable.
* incompatible stable-interface changes require a major version.
* removals require a defined deprecation period.

**Classification:** BLOCKER.

---

## L. OSS Governance and Vulnerability Management — 🟡 Mostly ready

The OSS basics are solid:

* MIT license;
* AUTHORS;
* contributor documentation;
* Code of Conduct;
* Security Policy;
* contribution/testing requirements.

The vulnerability process specifies acknowledgement within five business days and private handling expectations.

The missing piece is lifecycle policy.

Trustpoint's own CRA documentation explicitly lists maturation of the **supported versions policy, triage, release notes and update communication before v1.0**.

That should be resolved before declaring the first stable release.

**Classification:** BLOCKER for supported-version/security-update policy; governance otherwise ready.

---

# 5. Security-Critical Findings

| Finding                                                                                   | Classification            | Why it matters                                                                          |
| ----------------------------------------------------------------------------------------- | ------------------------- | --------------------------------------------------------------------------------------- |
| Complete DB + HSM + app-secret recovery has not been demonstrated as one release contract | **BLOCKER**               | Failure can permanently remove access to CA keys or encrypted operational secrets       |
| No stable upgrade contract                                                                | **BLOCKER**               | PKI state is too valuable to require manual/rebuild-style migration after v1            |
| Stable external interfaces are undefined                                                  | **BLOCKER**               | Automation and device integrations need predictable compatibility                       |
| Production security baseline not normative                                                | **BLOCKER**               | Operators could accidentally deploy a technically functional but insecure configuration |
| Application-secret key rotation not implemented                                           | **HIGH**                  | Long-lived PKI deployments need eventual cryptographic key lifecycle management         |
| No built-in rate limiting / account lockout                                               | **HIGH**                  | Administrative and API authentication needs compensating protection                     |
| Audit log not cryptographically tamper-proof                                              | **HIGH**                  | PKI administrative actions have high evidentiary value                                  |
| CA key rotation can require downtime                                                      | **HIGH**                  | Must have controlled, tested operating procedure                                        |
| Hardware-HSM compatibility claims exceed publicly visible vendor-validation evidence      | **MEDIUM**                | Generic PKCS#11 support does not guarantee device-specific interoperability             |
| No multi-tenant isolation                                                                 | **NOT REQUIRED FOR V1.0** | Separate instances are a viable supported architecture                                  |
| Certificate Transparency absent                                                           | **NOT REQUIRED FOR V1.0** | CT is not generally required for private industrial PKI                                 |
| Automated HSM clustering/HA                                                               | **NOT REQUIRED FOR V1.0** | Enterprise availability feature rather than first-stable-release requirement            |
| PQC                                                                                       | **NOT REQUIRED FOR V1.0** | Important roadmap item, not a reason to postpone v1                                     |

The documented known security limitations support several of these conclusions directly.

---

# 6. v1.0 Blockers

| #      | Blocker                                   | Evidence                                                                                            | Risk                                                       | Recommended action                                                                              | Effort   |
| ------ | ----------------------------------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------- |
| **B1** | Supported upgrade/migration path          | v0.5 required a new environment; current docs do not establish a stable upgrade contract            | Lost configuration/state or mandatory rebuild after v1     | Test and document upgrade from designated supported pre-v1 release to v1.0, including rollback  | **L**    |
| **B2** | Complete disaster-recovery contract       | DB backups exist, but HSM state is separate and application-secret loss can make data unrecoverable | Permanent CA/key/secret loss                               | Define backup set and perform automated/manual recovery drills including HSM mismatch scenarios | **L–XL** |
| **B3** | v1 interface stability policy             | Architecture explicitly says APIs/deployment may evolve                                             | Integration breakage immediately after “stable”            | Publish stable/experimental matrix and compatibility/deprecation policy                         | **M**    |
| **B4** | Current release-acceptance evidence       | Test plan still shows acceptance/report work incomplete                                             | Stable release without demonstrated critical-path behavior | Produce v1 RC test report mapping critical workflows and threats to passing tests               | **M–L**  |
| **B5** | Supported versions/security update policy | Project's CRA work explicitly lists it as pre-v1 work                                               | Users cannot know whether/when security fixes are provided | Define support window, security releases, EOL and advisory communication                        | **S–M**  |
| **B6** | Minimum secure deployment profile         | Known limitations rely on deployment controls such as proxy rate limiting                           | Easy insecure deployment of a security product             | Publish and validate one normative hardened v1 deployment profile                               | **M**    |

### Why these are actual blockers

None requires Trustpoint to become an enterprise-grade commercial PKI.

They establish the minimum promises implied by **stable**:

* state survives upgrades;
* state can be recovered;
* supported interfaces do not arbitrarily break;
* the supported core has been tested;
* users know whether security fixes apply to them;
* the documented deployment model is safe enough to operate.

---

# 7. v1.0 Test Gap List

These are the tests I would specifically add or make mandatory in the v1 release suite.

### Critical

| Priority | Concrete test                                                                                                                                                    |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | **Upgrade supported pre-v1 → v1.0 with realistic PKI state**: CAs, domains, devices, active/revoked certificates, profiles, workflows, users and secrets survive |
| 2        | **Interrupted DB migration** followed by documented rollback/restore                                                                                             |
| 3        | **Full backup/restore with PKCS#11 CA** and application-secret protection, followed by real signing/enrollment                                                   |
| 4        | Restore database with **missing/wrong HSM token** → clear safe failure, no destructive reinitialization                                                          |
| 5        | Restore with **corrupted/wrong DEK/KEK** → no silent key replacement                                                                                             |
| 6        | **CA rollover** while valid device certificates from the old CA remain deployed                                                                                  |
| 7        | Revocation and CRL continuity across CA rollover                                                                                                                 |
| 8        | **HSM disappears during signing/enrollment** → no partially persisted/duplicate certificate state                                                                |
| 9        | DB failure **after CA signing but before persistence** → deterministic reconciliation                                                                            |
| 10       | Concurrent enrollment requests for the same device/identity                                                                                                      |
| 11       | Regression for duplicate onboarding / multiple active LDevIDs as previously reported in issue #198                                                               |
| 12       | EST `simplereenroll` using expired certificate                                                                                                                   |
| 13       | EST reenrollment using revoked certificate                                                                                                                       |
| 14       | EST rekey: new key/certificate succeeds while old certificate transitions correctly                                                                              |
| 15       | CMP replayed request / duplicated transaction identifier                                                                                                         |
| 16       | CMP invalid nonce / protection / certConf sequence                                                                                                               |
| 17       | External CA unavailable during RA request; retry does not produce duplicate issuance                                                                             |
| 18       | Malformed CSR                                                                                                                                                    |
| 19       | CSR requesting unauthorized SAN/subject/profile attributes                                                                                                       |
| 20       | CSR attempting CA/basicConstraints escalation                                                                                                                    |
| 21       | Unsupported/weak key algorithm or below-minimum key length                                                                                                       |
| 22       | Issuing CA expired or nearly expired during issuance                                                                                                             |
| 23       | Role × operation authorization matrix for CA creation, configuration, issuance, revocation, users, security settings and key operations                          |
| 24       | Backup manifest hash altered/truncated/version incompatible → restore rejected                                                                                   |

### High

* JWT expiration, refresh, blacklist and privilege-change scenarios.
* Repeated failed login under the supported reverse-proxy rate-limiting configuration.
* OPC UA GDS certificate update interrupted halfway through deployment.
* Trust-list update failure preserving the previous working configuration.
* Agent renewal failure preserving the currently valid credential.
* Secrets/passwords/private material absent from application and audit logs.
* Certificate/profile boundary dates and clock-skew scenarios.
* Air-gapped update from a pinned release artifact.
* Release SBOM matches the actual shipped dependencies.

The existing test policy already requires normal, edge, error and security-relevant code-path coverage; these cases would turn that general policy into explicit PKI regression protection.

---

# 8. Documentation Gaps

## Mandatory before v1.0

* [ ] **Supported v1 functionality and compatibility matrix**
* [ ] **Upgrade guide** from designated pre-v1 release(s)
* [ ] **Rollback/recovery procedure** for failed upgrade
* [ ] **Complete backup/restore runbook**
* [ ] Explicitly document HSM key backup as part of disaster recovery
* [ ] Explicitly document application-secret/DEK/KEK recovery requirements
* [ ] **Production security baseline**
* [ ] Supported Docker image/tag/digest strategy instead of relying on `latest`
* [ ] Supported versions and security-maintenance policy
* [ ] REST/API compatibility and deprecation policy
* [ ] Known limitations page
* [ ] Release-specific migration notes
* [ ] v1 release test/acceptance report
* [ ] Remove the contradiction where one current page says backup/restore is unavailable while other documentation describes the implemented feature.

## Recommended

* [ ] Validated HSM compatibility matrix: vendor/model/firmware/PKCS#11 library/test status
* [ ] EST interoperability matrix
* [ ] CMP interoperability matrix
* [ ] OPC UA GDS interoperability matrix
* [ ] CA rollover operator runbook
* [ ] HSM replacement runbook
* [ ] Performance/capacity guidance tied to measured tests
* [ ] Security-control → automated-test evidence mapping
* [ ] Secure decommissioning guidance

## Post-v1.0

* [ ] HSM clustering/HA
* [ ] tamper-evident/cryptographically protected audit architecture
* [ ] automatic DEK/KEK rotation
* [ ] native multi-tenancy
* [ ] CT integration where applicable
* [ ] cloud KMS integrations
* [ ] PQC support
* [ ] sophisticated enterprise HA orchestration

---

# 9. Milestone 1 – Required Before v1.0

### M1.1 Upgrade guarantee

Addresses **B1**.

Define a single supported pre-v1 source release, ideally v0.6.x or the final release candidate, and prove upgrade to v1.0 with realistic persistent data.

### M1.2 Disaster-recovery qualification

Addresses **B2**.

Perform recovery from:

* database backup;
* HSM backup;
* app-secret state;
* required filesystem/configuration state.

Include wrong/missing-HSM negative tests.

### M1.3 Stable-interface declaration

Addresses **B3**.

Publish `STABILITY.md` or equivalent defining:

**Stable:** core PKI lifecycle, EST, supported CMP subset, selected REST API/configuration interfaces.

**Experimental:** AOKI and any other surfaces the team does not want to freeze yet.

### M1.4 v1 release acceptance

Addresses **B4**.

Generate a versioned v1 RC test report demonstrating the critical PKI, authorization, backup, upgrade and negative-security tests.

### M1.5 Maintenance contract

Addresses **B5**.

Add supported versions, security update policy and EOL communication to `SECURITY.md`/release documentation.

### M1.6 Secure deployment baseline

Addresses **B6**.

Document and test one reference configuration with:

* version-pinned images;
* HTTPS/TLS;
* strong generated credentials;
* hardware HSM where Trustpoint operates a production CA;
* external rate limiting;
* restricted admin interface;
* network segmentation;
* protected secrets;
* backup encryption;
* log/SIEM forwarding;
* Prometheus monitoring;
* dev/demo modes disabled.

---

# 10. Milestone 2 – Recommended for v1.0

These materially strengthen the first stable release but should not individually hold it indefinitely:

1. Finish release attestations/provenance work already identified in the project's CRA roadmap.
2. Pin third-party GitHub Actions to immutable commit SHAs.
3. Add a tested hardware-HSM compatibility matrix.
4. Introduce or document stronger administrative brute-force protection.
5. Define integrity protection/remote immutable storage strategy for audit records.
6. Add protocol interoperability evidence against independent EST/CMP implementations.
7. Complete control-to-test evidence links.
8. Bring the test-plan status page into sync with actual CI.
9. Establish a formal v1 release checklist in the repository.
10. Perform an external security review focused on CA/RA authorization, enrollment protocols and key management.

A third-party audit would be highly valuable for a PKI product, but even Trustpoint's CRA document treats it as something to **consider before or around v1.0**, rather than an absolute prerequisite.

---

# 11. Milestone 3 – Post-v1.0

The following work should explicitly **not delay v1.0**:

* automatic CA/HSM key rollover without downtime;
* cloud KMS backends;
* HSM clustering;
* HA orchestration;
* native tenant isolation;
* Certificate Transparency integration;
* Post-Quantum Cryptography;
* additional enrollment protocols;
* additional enterprise PKI products;
* sophisticated autoscaling;
* every OpenSSF recommendation reaching its theoretical maximum;
* 100% code coverage.

A stable v1 can state these as limitations or roadmap items.

---

# 12. Proposed Trustpoint v1.0 Release Gate

Trustpoint v1.0.0 may be released when all of the following are true.

### Scope and compatibility

* [ ] All BLOCKER findings are closed.
* [ ] Stable and experimental functionality is explicitly documented.
* [ ] Compatibility/deprecation policy is published.
* [ ] Supported configuration/environment interfaces are documented.

### CI and security

* [ ] Exact release commit passes pytest.
* [ ] Exact release commit passes required Behave suites.
* [ ] MyPy passes.
* [ ] Ruff passes.
* [ ] CodeQL passes.
* [ ] ZAP baseline passes with no unaccepted medium/high findings.
* [ ] Docker deployment/setup tests pass.
* [ ] No unresolved critical security vulnerability affects the release.
* [ ] Any accepted HIGH risk has a documented mitigation and owner.

### PKI acceptance

* [ ] CA issuance tested.
* [ ] RA issuance against a real supported external CA tested.
* [ ] EST enrollment + reenrollment tested.
* [ ] CMP enrollment + renewal/rekeying tested.
* [ ] Revocation and CRL publication tested.
* [ ] CA rollover tested.
* [ ] HSM unavailable/recovery scenario tested.
* [ ] duplicate/concurrent enrollment scenario tested.
* [ ] malformed/unauthorized CSR tests pass.

### Installation, upgrade and recovery

* [ ] Clean installation performed solely from published v1 documentation.
* [ ] Installation uses immutable/versioned release artifacts.
* [ ] Upgrade from designated supported pre-v1 version passes.
* [ ] Failed-upgrade recovery procedure passes.
* [ ] Database backup/restore passes.
* [ ] HSM-backed CA restore passes.
* [ ] Application-secret recovery passes.
* [ ] Wrong/missing-HSM restore fails safely.
* [ ] Restored instance successfully performs a real certificate issuance.

### Release engineering

* [ ] SBOM generated for the exact v1 artifact.
* [ ] Release artifacts originate from controlled CI.
* [ ] Release/tag authenticity can be verified.
* [ ] Release notes contain breaking changes and migration notes.
* [ ] Release provenance/attestation implemented or explicitly documented as remaining HIGH work.

### Operations and documentation

* [ ] Secure production deployment baseline published and tested.
* [ ] Backup and disaster-recovery runbook published.
* [ ] Upgrade/rollback guide published.
* [ ] Known limitations published.
* [ ] Hardware-HSM support wording distinguishes validated hardware from generic PKCS#11 compatibility.
* [ ] Documentation contains no known contradiction about backup/update/restore support.
* [ ] Documentation is versioned for v1.0.

### Maintenance

* [ ] Supported-version policy published.
* [ ] Security-update process published.
* [ ] Private vulnerability reporting tested/verified.
* [ ] Responsible disclosure contact works.
* [ ] Support/EOL expectations for v1.x are defined.

Only after this gate passes should the README's current “technology preview / not intended for production use” warning be replaced with the v1 support statement.

---

# 13. Items That Could Not Be Verified

The following cannot be conclusively determined from the public evidence inspected:

1. **Current exact test count.**
   v0.4 historically reported 2,425 tests, but that should not be presented as the v0.6/main figure.

2. **Current exact coverage percentage.**
   Current documentation establishes an 80% target but not a sufficiently clear current figure.

3. **Whether every GitHub Action shown is a mandatory branch-protection check.**

4. **Whether administrators can bypass branch protections.**

5. **Whether all TODO/FIXME/HACK/skip/xfail occurrences have been reviewed.**
   Web search does not provide the completeness of a local repository-wide grep, and local checkout was unavailable during this review.

6. **Physical HSM interoperability.**
   Documentation names generic PKCS#11-compatible hardware vendors, but I did not find sufficient public evidence of a maintained vendor/model/firmware validation matrix.

7. **Actual recovery success from a hardware HSM failure.**

8. **Full protocol interoperability against independent EST/CMP/GDS implementations.**

9. **Load/performance characteristics at the documented deployment sizes.**

10. **Current unresolved private security findings**, by definition.

11. **Actual production operation by external users**, beyond the public project evidence.

---

# Final Readiness Statements

## Stable OSS release readiness

**Not ready for v1.0 today, but relatively close.**

The core application and engineering infrastructure are sufficiently mature that I would **not recommend another large feature cycle before v1**.

The remaining work should primarily harden the baseline:

**upgrade → recovery → compatibility → acceptance → maintenance policy → secure deployment.**

Once B1–B6 are closed, calling the resulting baseline `v1.0.0` would be reasonable.

## Production deployment readiness

**The current public release should not yet be presented as production-ready for security-sensitive industrial PKI deployments.**

This aligns with the project's own explicit current warning.

The largest production-readiness uncertainties are HSM/application-secret disaster recovery, upgrade reliability, secure deployment requirements, administrative protection and release acceptance evidence.

## Security maturity

**Strong for a pre-1.0 OSS project, but not yet complete as a production security product.**

The combination of threat modelling, control/risk documentation, HSM architecture, CodeQL, ZAP, SBOM activities and private vulnerability reporting is a significant foundation. The project's own CRA material correctly identifies vulnerability-management maturation, release integrity and v1 production-readiness work as remaining tasks.

## Documentation and operational maturity

**Broad but currently inconsistent.**

The quantity and depth of architecture/security material are good. The problem is authority: an external administrator currently encounters mutually incompatible statements about backup/restore, evolving APIs and production suitability.

For v1, documentation needs to change from primarily explaining **what Trustpoint can do** to defining **what Trustpoint guarantees**.

---

## Bottom line

The path to v1.0 should **not** be “add more features.”

It should be:

**freeze the supported core → prove upgrade and recovery → declare compatibility → execute the release-acceptance suite → publish the security/maintenance contract → ship v1.0.**

That would turn the existing technically capable beta into a defensible first stable OSS release without imposing enterprise-product requirements that do not belong in the v1.0 gate.
