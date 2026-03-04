# WBM Onboarding — Feature Concept

> **This document describes the overall architecture and design decisions.**
> For implementation details see:
> - `wbm_trustpoint_implementation.md` — changes inside the Trustpoint Django project
> - `wbm_agent_implementation.md` — the standalone `trustpoint-wbm-agent` package

## Problem & Motivation

Many brownfield OT devices only allow certificate changes through a Web-Based Management (WBM) interface—no EST, CMP, ACME, or any programmatic API. This makes certificate renewals and trust-store updates slow, manual, and error-prone, creating real outage risk when certificates expire.

Trustpoint solves this by adding WBM certificate automation: a lightweight **WBM Agent** running inside the production cell (close to the devices) polls Trustpoint for pending certificate updates, then uses Playwright browser automation to operate the device's web UI like a human operator would—log in, navigate to the certificate page, upload a new certificate/key pair (or CA bundle), click apply, optionally trigger a device reboot/service restart, and verify success (UI confirmation plus HTTPS probe/fingerprint check).

---

## Stakeholder Feedback & Constraints

The following concerns were raised during concept review and directly shape the architecture:

### 1. High-privilege credential storage is a security risk

Storing WBM passwords — credentials with sufficient privilege to replace device certificates — centrally in Trustpoint creates a high-value attack target. A single database breach would expose credentials for every managed device simultaneously.

**Mitigation in revised design:** Credentials are stored in the WBM Agent, which runs locally inside the production cell, not in Trustpoint. Trustpoint only stores certificate material and workflow metadata. The attack surface at the central Trustpoint server is thus limited to what it already holds today (PKI keys and issued certificates).

### 2. MFA and Passkeys block browser automation

Modern network components are increasingly protected by TOTP-based 2FA or Passkeys. Playwright automation has no reliable path through interactive MFA flows.

**Mitigation:** For devices with MFA-protected WBM interfaces, the browser-automation path is not viable. An operator-assisted workflow (the agent prepares the certificate bundle and opens a guided browser session for the human operator to complete) can be explored as a fallback. API-based automation (REST/NETCONF) is out of scope for the current implementation and deferred to future work.

### 3. Network topology — IEC 62443 zone/conduit compliance

Trustpoint typically sits centrally in an upper OT network layer. CMP and EST are designed for devices to initiate connections *upward* to Trustpoint. A Trustpoint-initiated push would require inbound firewall openings *into* production cells — violating IEC 62443-3-3 zone/conduit segmentation requirements (no unsolicited inbound connections from a higher-trust zone into a lower-trust cell).

**Mitigation — reversed connection direction:** The WBM Agent is deployed *inside* the production cell. It polls Trustpoint outbound (same direction as CMP/EST), retrieves pending work items, executes automation locally against the device's WBM (both agent and device are in the same cell network segment), and reports results back to Trustpoint. No inbound firewall rules are required.

---

## Architecture Overview

The feature spans two components:

### Trustpoint (central server — existing Django project)

A new Django app `wbm` adds the following:

- **WbmWorkflowDefinition** — reusable, shareable Playwright-style JSON automation scripts, one per device family/firmware variant. Contains no credentials.
- **WbmCertificateTarget** — links a `WbmWorkflowDefinition` to a `CertificateProfileModel` and describes *what* certificate to push to *which* device slot.
- **WbmJobQueue** — a lightweight outbox table. When a certificate is due for renewal, Trustpoint writes a job record (certificate material + workflow reference) that the agent polls for. This replaces the need for Trustpoint to initiate any network connection.
- **REST endpoint** (`/api/wbm/jobs/`) — the agent authenticates to Trustpoint (mutual TLS or API token) and polls for pending jobs, claims them, and posts results back.

### WBM Agent (edge component — deployed inside the production cell)

A small, standalone Python process (packaged separately, e.g. as a Docker container or systemd service) that:

- Runs **inside** the production cell, co-located with the devices it manages.
- Holds device WBM credentials **locally** (e.g. in an encrypted local config file or a cell-local secrets manager). Credentials never leave the cell.
- Connects **outbound** to Trustpoint to poll for jobs (same direction as CMP/EST device connections).
- Executes Playwright automation locally against the device WBM over the cell-internal network.
- Reports job outcomes back to Trustpoint.

This design keeps the connection direction consistent with IEC 62443 zone/conduit requirements (all connections originate from inside the production cell) and limits credential exposure to the cell where the devices reside.

```
  [Production Cell]                        [Upper OT Network]
  ┌──────────────────────────────┐         ┌──────────────────┐
  │  Device WBM  ←──Playwright── │         │                  │
  │                              │         │   Trustpoint     │
  │  WBM Agent ──────poll/report─┼────────►│   (central)      │
  │  (holds creds locally)       │  HTTPS  │   /api/wbm/jobs/ │
  └──────────────────────────────┘  outbound└──────────────────┘
         No inbound firewall rules required
```

The `DeviceModel` is extended with a nullable FK to `WbmCertificateTarget`, following the same pattern as the existing `onboarding_config` and `no_onboarding_config` FKs.

Certificate push runs are triggered either manually (via the UI) or automatically when a certificate issued to the device is about to expire (hooked into the existing Django-Q2 scheduler, which writes a `WbmJobQueue` record rather than directly executing Playwright).

---

## Data Model

### `wbm.WbmWorkflowDefinition` — reusable automation script (unchanged)

Stores the Playwright-style JSON automation profile. A single workflow definition can be reused by many devices of the same family/firmware. Workflow definitions are versioned and can be imported/exported via the UI. **This model holds no credentials.**

```python
class WbmWorkflowDefinition(models.Model):
    """A reusable Playwright-style automation script for a specific device family or firmware variant."""

    name = models.CharField(verbose_name=_("Name"), max_length=200)
    vendor = models.CharField(verbose_name=_("Vendor"), max_length=120, blank=True)
    device_family = models.CharField(verbose_name=_("Device Family"), max_length=120, blank=True)
    firmware_hint = models.CharField(
        verbose_name=_("Firmware Hint"),
        max_length=120,
        blank=True,
        help_text=_("Optional firmware version or build string to help operators pick the right profile."),
    )
    version = models.CharField(verbose_name=_("Version"), max_length=40, default="1.0")
    description = models.TextField(verbose_name=_("Description"), blank=True)

    profile = models.JSONField(
        verbose_name=_("Workflow Profile"),
        help_text=_("JSON array of automation steps. See workflow schema documentation."),
    )
    is_active = models.BooleanField(
        verbose_name=_("Active"),
        default=True,
        help_text=_("Inactive definitions are hidden from selection but preserved for audit purposes."),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("name", "version")]

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmWorkflowDefinition({self.name} v{self.version})"
```

#### Workflow JSON schema (example)

The `profile` field contains a JSON array of step objects. Each step has a `type` and type-specific parameters. Reserved variable placeholders (`{{cert_pem}}`, `{{key_pem}}`, `{{ca_bundle_pem}}`, `{{base_url}}`) are substituted by the **WBM Agent** at runtime — `{{username}}` and `{{password}}` are **only** substituted locally on the agent and are never transmitted to Trustpoint.

```json
[
  { "type": "goto",       "url": "{{base_url}}/login" },
  { "type": "fill",       "selector": "#username", "value": "{{username}}" },
  { "type": "fill",       "selector": "#password", "value": "{{password}}" },
  { "type": "click",      "selector": "#login-btn" },
  { "type": "waitFor",    "selector": ".dashboard", "timeout_ms": 10000 },
  { "type": "goto",       "url": "{{base_url}}/settings/certificates" },
  { "type": "uploadFile", "selector": "#cert-upload",  "content": "{{cert_pem}}" },
  { "type": "uploadFile", "selector": "#key-upload",   "content": "{{key_pem}}" },
  { "type": "uploadFile", "selector": "#ca-upload",    "content": "{{ca_bundle_pem}}" },
  { "type": "click",      "selector": "#apply-btn" },
  { "type": "expect",     "selector": ".success-banner", "text": "Certificate updated" },
  { "type": "waitFor",    "selector": ".reboot-complete", "timeout_ms": 60000 }
]
```

Supported step types: `goto`, `click`, `fill`, `uploadFile`, `waitFor`, `expect`, `screenshot` (debug capture), `reboot` (click + reconnect-wait).

---

### `wbm.WbmCertificateTarget` — what to push and how

Links a `WbmWorkflowDefinition` to a `CertificateProfileModel` and a device. One target = one certificate slot on the device. A device with multiple certificate slots (e.g., TLS server cert + client cert) has one `WbmCertificateTarget` per slot. **No credentials are stored here.**

```python
class WbmCertificateTarget(models.Model):
    """Describes a single certificate slot on a device WBM and the workflow used to update it."""

    class SlotPurpose(models.TextChoices):
        """Semantic purpose of the certificate slot."""

        TLS_SERVER = "tls_server", _("TLS Server Certificate")
        TLS_CLIENT = "tls_client", _("TLS Client Certificate")
        CA_BUNDLE  = "ca_bundle",  _("CA / Trust-Store Bundle")
        OTHER      = "other",      _("Other")

    device = models.ForeignKey(
        "devices.DeviceModel",
        verbose_name=_("Device"),
        on_delete=models.CASCADE,
        related_name="wbm_targets",
    )
    certificate_profile = models.ForeignKey(
        "pki.CertificateProfileModel",
        verbose_name=_("Certificate Profile"),
        on_delete=models.PROTECT,
        related_name="wbm_targets",
    )
    workflow = models.ForeignKey(
        "wbm.WbmWorkflowDefinition",
        verbose_name=_("Workflow Definition"),
        on_delete=models.PROTECT,
        related_name="targets",
    )

    # The agent_id identifies which WBM Agent instance is responsible for this target.
    # The agent is registered by the cell operator; Trustpoint only knows its identity, not its credentials.
    agent_id = models.CharField(
        verbose_name=_("Agent ID"),
        max_length=120,
        help_text=_("Identifier of the WBM Agent instance responsible for this target (registered by the cell operator)."),
    )
    # base_url is the address of the WBM as seen from inside the cell network.
    # Credentials are NOT stored here; the agent resolves them locally by device address.
    base_url = models.URLField(
        verbose_name=_("WBM Base URL"),
        help_text=_("Address of the device WBM as reachable from within the production cell (e.g. https://192.168.1.10)."),
    )

    purpose = models.CharField(
        verbose_name=_("Slot Purpose"),
        max_length=20,
        choices=SlotPurpose,
        default=SlotPurpose.TLS_SERVER,
    )
    slot = models.CharField(
        verbose_name=_("Slot Identifier"),
        max_length=80,
        blank=True,
        default="",
        help_text=_("Optional device-specific slot name (e.g. 'slot0'), for devices with multiple cert slots."),
    )
    enabled = models.BooleanField(verbose_name=_("Enabled"), default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("device", "purpose", "slot")]

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmCertificateTarget({self.device} {self.purpose}/{self.slot} → {self.certificate_profile})"
```

---

### `wbm.WbmJobQueue` — outbox for the agent

An outbox table written by Trustpoint's scheduler. The agent polls this table via the REST API. This decouples scheduling (Trustpoint) from execution (agent) and avoids any need for Trustpoint to initiate a connection.

```python
class WbmJob(models.Model):
    """A pending or completed certificate-push job for a WBM Agent to execute."""

    class Status(models.TextChoices):
        """Lifecycle state of the job."""

        PENDING   = "pending",   _("Pending")
        CLAIMED   = "claimed",   _("Claimed by Agent")
        SUCCEEDED = "succeeded", _("Succeeded")
        FAILED    = "failed",    _("Failed")

    target = models.ForeignKey(
        "wbm.WbmCertificateTarget",
        verbose_name=_("Certificate Target"),
        on_delete=models.CASCADE,
        related_name="jobs",
    )
    status = models.CharField(
        verbose_name=_("Status"),
        max_length=20,
        choices=Status,
        default=Status.PENDING,
        db_index=True,
    )

    # Certificate material delivered to the agent — no private key stored here beyond what
    # Trustpoint already holds for issued credentials.
    cert_pem = models.TextField(verbose_name=_("Certificate (PEM)"))
    key_pem = models.TextField(verbose_name=_("Private Key (PEM)"), blank=True)
    ca_bundle_pem = models.TextField(verbose_name=_("CA Bundle (PEM)"), blank=True)

    claimed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    result_detail = models.TextField(verbose_name=_("Result Detail"), blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmJob({self.pk} {self.status} → {self.target})"
```



## Execution Flow

1. **Trigger** — A Django-Q2 task (`wbm.tasks.schedule_push`) is enqueued either manually (UI button) or by the certificate-expiry scheduler when an issued credential is within the configured renewal window. The task writes a `WbmJob` record (status `PENDING`) and exits. **No Playwright process runs inside Trustpoint.**
2. **Agent poll** — The WBM Agent (running inside the production cell) calls `GET /api/wbm/jobs/?agent_id=<id>&status=pending`, authenticating with its own mTLS client certificate or long-lived API token issued by Trustpoint.
3. **Job claim** — The agent atomically transitions the job to `CLAIMED` (`PATCH /api/wbm/jobs/<id>/claim/`) to prevent duplicate execution.
4. **Credential resolution** — The agent resolves `{{username}}` and `{{password}}` from its **local** encrypted config, keyed by `base_url`. These values never leave the cell.
5. **Variable substitution** — `cert_pem`, `key_pem`, `ca_bundle_pem`, `base_url` (from the job) plus the locally resolved credentials are substituted into the workflow profile before execution.
6. **Playwright execution** — The agent executes the workflow steps sequentially against the device WBM over the cell-internal network. Per-step and overall timeouts are enforced. On failure the current page is screenshotted (stored locally or uploaded to Trustpoint as an opaque blob).
7. **Verification** — After the final workflow step, the agent opens an HTTPS connection to `base_url` and compares the TLS leaf certificate fingerprint against the newly issued certificate. A mismatch counts as failure.
8. **Result reporting** — The agent posts the outcome, duration, and any error detail to `PATCH /api/wbm/jobs/<id>/result/`. Trustpoint updates the job status and notifies the operator if configured.
9. **Retry** — The agent retries the full workflow (up to the configured retry count from its local config) before reporting failure.

---

## Agent — Package Structure & Deployment

### Design principle: write once, deploy anywhere

The deployment method is a **thin wrapper** around identical core logic. Configuration sourcing and process supervision are the only things that vary — the polling loop, Playwright executor, and credential store are the same code regardless of how the agent is run.

```
┌─────────────────────────────────────────┐
│  Runtime wrapper (Docker)               │  ← swap per environment
├─────────────────────────────────────────┤
│  Entry point  (__main__.py)             │  ← identical in all cases
├─────────────────────────────────────────┤
│  Core logic  (poll / execute / report)  │  ← written once
└─────────────────────────────────────────┘
```

### Package layout

```
trustpoint-wbm-agent/
├── pyproject.toml
├── Dockerfile                              ← two-stage build
├── docker-compose.yml                      ← ready-to-use compose file
└── trustpoint_wbm_agent/
    ├── __main__.py                         ← single entry point
    ├── config.py                           ← reads env vars, same code path always
    ├── agent.py                            ← polling loop
    ├── executor.py                         ← Playwright step runner
    └── credentials.py                      ← local encrypted credential store
```

### Single entry point

```python
# trustpoint_wbm_agent/__main__.py
import asyncio
from .config import AgentConfig
from .agent import run

if __name__ == "__main__":
    config = AgentConfig()
    asyncio.run(run(config))
```

`CMD ["python", "-m", "trustpoint_wbm_agent"]` in the Dockerfile. The same command works if the package is ever run without Docker (e.g. during development).

### Configuration — via environment variables

`pydantic-settings` reads environment variables. All runtime parameters are injected from outside; no hardcoded values in the image:

```python
# config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

class AgentConfig(BaseSettings):
    trustpoint_url: str                  # e.g. https://trustpoint.example.com
    agent_id: str
    client_cert_path: Path              # mTLS client cert issued by Trustpoint
    client_key_path: Path
    credentials_file: Path = Path("/run/secrets/credentials.enc")
    poll_interval_seconds: int = 30

    model_config = SettingsConfigDict(env_prefix="WBM_")
```

Secrets (client cert/key, credentials file) are injected as Docker secrets or bind-mounted volumes — never baked into the image.

### Dockerfile — two-stage build

Separating Python deps from the Playwright/Chromium layer means code changes do not re-download the browser (~300 MB):

```dockerfile
# Stage 1: install Python deps
FROM python:3.12-slim AS deps
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Stage 2: add Playwright + Chromium as a separately cacheable layer
FROM deps AS agent
RUN uv pip install playwright \
 && playwright install --with-deps chromium
COPY . .
CMD ["python", "-m", "trustpoint_wbm_agent"]
```

**Approximate image sizes:** Python slim base ~130 MB + agent deps ~50 MB + Playwright/Chromium ~300 MB = **~480 MB total**.

### docker-compose.yml

```yaml
services:
  wbm-agent:
    image: trustpointproject/wbm-agent:latest
    restart: unless-stopped
    environment:
      WBM_TRUSTPOINT_URL: "https://trustpoint.example.com"
      WBM_AGENT_ID: "cell-a-agent-1"
      WBM_CLIENT_CERT_PATH: "/run/secrets/agent.crt"
      WBM_CLIENT_KEY_PATH: "/run/secrets/agent.key"
      WBM_CREDENTIALS_FILE: "/run/secrets/credentials.enc"
    secrets:
      - agent.crt
      - agent.key
      - credentials.enc

secrets:
  agent.crt:
    file: ./secrets/agent.crt
  agent.key:
    file: ./secrets/agent.key
  credentials.enc:
    file: ./secrets/credentials.enc
```

### Chromium in constrained environments

The 300 MB Chromium download is the main constraint on storage-limited cell hardware. Two mitigations:

1. **Private registry** — pre-pull the agent image once onto a cell-local registry; individual hosts pull from there without internet access.
2. **System Chromium** — on Debian/Ubuntu hosts `apt install chromium` (~120 MB) works with Playwright via `PLAYWRIGHT_BROWSERS_PATH=0` and an explicit `executable_path`. Replace the `playwright install` step in the Dockerfile with `apt-get install -y chromium`.

---

## Open Questions / Future Work

- **Credential isolation**: Credentials reside on the agent, scoped to the cell. If the cell is compromised, only that cell's credentials are exposed — not Trustpoint's entire device fleet. Per-device credential isolation (one encrypted entry per `base_url`) on the agent is recommended.
- **MFA / Passkeys**: Browser automation cannot handle interactive 2FA. For MFA-protected devices, an operator-assisted fallback (agent prepares the certificate bundle; operator completes the WBM session manually) can bridge the gap. API-based automation (REST/NETCONF) is a potential future extension but is out of scope for the initial implementation.
- **Agent authentication to Trustpoint**: The agent should authenticate with a client certificate issued by Trustpoint (mTLS), giving Trustpoint full control over agent lifecycle (revoke the cert to decommission an agent). A static API token is an acceptable fallback for constrained environments.
- **Playwright dependency**: See *Chromium in constrained environments* above. The `playwright` package should be an opt-in `[playwright]` extra in `pyproject.toml` to keep the base install minimal.
- **Workflow validation**: The `profile` JSON field should be validated against a JSON Schema on save (either in `Model.clean()` or a custom `JSONSchemaValidator`).
- **UI**: A workflow definition editor/importer, a per-device "push now" button, and an execution log list view are needed in the `wbm` app's views and templates.
- **Secret rotation**: When a device password changes, only the agent's local credentials file needs updating — the workflow definition stored in Trustpoint is reusable across that change.
