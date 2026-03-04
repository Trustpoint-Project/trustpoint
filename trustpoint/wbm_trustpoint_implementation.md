# WBM Onboarding — Trustpoint Implementation

> **Scope:** Changes required inside the existing Trustpoint Django project to support the WBM onboarding feature.
> See `wbm_onboarding_concept.md` for the overall architecture and `wbm_agent_implementation.md` for the agent side.

---

## Architecture: Agent Polls, Trustpoint Decides, Agent Generates Keys

**Trustpoint owns the schedule.** It decides which certificate targets need updating. The agent polls on a regular interval, and for each due job it **generates the key pair locally**, submits a CSR, and Trustpoint signs and returns the certificate. The private key never leaves the agent.

The poll interval is configured **in Trustpoint** per `TrustpointAgent` and returned in the check-in response so the agent self-configures without redeployment.

```
Agent                                  Trustpoint
  |                                        |
  |  [every poll_interval_seconds]         |
  |── GET /api/agents/wbm/check-in/ ──────▶|  "Any work for me?"
  |◀── 200 { poll_interval_seconds,        |  Trustpoint lists due targets:
  |          jobs: [{ job_id, base_url,    |  job_id, base_url, key_spec,
  |                  key_spec, subject,    |  subject (for CSR), workflow
  |                  workflow }] }         |  (no cert or key in this response)
  |                                        |
  |  [Agent generates key pair + CSR]      |
  |                                        |
  |── POST /api/agents/wbm/submit-csr/ ───▶|  { job_id, csr_pem }
  |◀── 200 { cert_pem, ca_bundle_pem } ────|  Trustpoint signs CSR, returns cert
  |                                        |
  |  [Playwright executes workflow]        |  (key stays on agent, never sent)
  |                                        |
  |── POST /api/agents/wbm/push-result/ ──▶|  "job_id X: Succeeded / Failed"
  |◀── 200 ────────────────────────────────|
```

Consequences:
- **Private key never leaves the agent.** Trustpoint only ever sees the public key (via the CSR).
- **`WbmJob` stores no private key** — `key_pem` field is eliminated.
- **Trustpoint holds all scheduling logic** — renewal window, expiry threshold, operator "push now" trigger.
- **Poll interval is server-side configurable** — changing `TrustpointAgent.poll_interval_seconds` takes effect on the next check-in.

---

## 1. New Django App: `agents`

Everything agent-related lives in one Django app. The top level of the app contains the **generic, capability-agnostic** pipeline layer. WBM-specific code lives in a `wbm/` sub-package. Future capabilities (e.g. firmware updates) each get their own sub-package and re-use the generic layer.

```
trustpoint/agents/
├── __init__.py
├── apps.py
├── models.py              ← TrustpointAgent (generic) +
│                             WbmWorkflowDefinition, WbmCertificateTarget, WbmJob
│
│  ── generic pipeline layer (capability-agnostic) ──────────────────────────
├── request_context.py     ← AgentRequestContext (extends RestBaseRequestContext)
│                             holds only: agent, protocol="agent"
├── authentication.py      ← AgentAuthentication (fingerprint → TrustpointAgent)
├── authorization.py       ← AgentActiveAuthorization (is_active guard)
├── views.py               ← AgentPipelineMixin (generic pipeline runner)
│
│  ── WBM sub-package ────────────────────────────────────────────────────────
├── wbm/
│   ├── __init__.py
│   ├── request_context.py ← WbmAgentRequestContext (extends AgentRequestContext)
│   │                         adds check-in / submit-csr / push-result fields
│   ├── authorization.py   ← WbmSubmitCsrAuthorization, WbmPushResultAuthorization
│   ├── message_parser.py  ← WbmCheckInParser, WbmSubmitCsrParser, WbmPushResultParser
│   ├── operation_processor/
│   │   ├── __init__.py
│   │   ├── check_in.py    ← WbmCheckInProcessor
│   │   ├── submit_csr.py  ← WbmSubmitCsrProcessor (delegates to CertificateIssueProcessor)
│   │   └── push_result.py ← WbmPushResultProcessor
│   ├── message_responder.py ← WbmCheckInResponder, WbmSubmitCsrResponder,
│   │                          WbmPushResultResponder, WbmErrorResponder
│   └── views.py           ← WbmCheckInView, WbmSubmitCsrView, WbmPushResultView
│
├── urls.py                ← /api/agents/ routing (includes wbm.urls)
├── admin.py               ← admin registrations for all models
└── migrations/
    └── 0001_initial.py
```

---

## 2. Models

### 2.1 `TrustpointAgent`

Generic identity record for any automation agent. Not WBM-specific.

```python
# agents/models.py

class TrustpointAgent(models.Model):
    """A registered automation agent deployed inside a production cell.

    Acts as the identity anchor for all agent-executed job types.
    WBM certificate pushing is the first supported capability.
    """

    class Capability(models.TextChoices):
        """Known job types an agent may support. An agent may declare multiple."""

        WBM_CERT_PUSH = "wbm_cert_push", _("WBM Certificate Push")
        # Future entries, e.g.:
        # FIRMWARE_UPDATE = "firmware_update", _("Firmware Update")

    name = models.CharField(
        verbose_name=_("Name"),
        max_length=120,
        unique=True,
        help_text=_("Human-readable name, e.g. 'Cell A Agent 1'."),
    )
    agent_id = models.CharField(
        verbose_name=_("Agent ID"),
        max_length=120,
        unique=True,
        help_text=_(
            "Stable identifier sent by the agent in every API request. "
            "Must match AGENT_ID in the agent's runtime config."
        ),
    )
    # SHA-256 fingerprint (hex, uppercase, no colons) of the mTLS client certificate
    # issued to this agent by Trustpoint. Verified on every REST API request.
    # Updated automatically when a new agent cert is issued via the registration flow.
    certificate_fingerprint = models.CharField(
        verbose_name=_("Certificate Fingerprint (SHA-256)"),
        max_length=64,
        unique=True,
        help_text=_(
            "SHA-256 fingerprint of the agent's mTLS client certificate. "
            "Revoke the cert to decommission the agent at the TLS layer."
        ),
    )
    # JSON array of Capability values, e.g. ["wbm_cert_push"].
    # JSONField keeps us SQLite-compatible (ArrayField requires PostgreSQL).
    capabilities = models.JSONField(
        verbose_name=_("Capabilities"),
        default=list,
        help_text=_(
            "List of job types this agent supports, e.g. [\"wbm_cert_push\"]. "
            "Used for display and validation; does not restrict API access at runtime."
        ),
    )
    cell_location = models.CharField(
        verbose_name=_("Cell Location"),
        max_length=200,
        blank=True,
        help_text=_("Free-text description of the production cell, e.g. 'Building 3 / Cell A'."),
    )
    is_active = models.BooleanField(
        verbose_name=_("Active"),
        default=True,
        help_text=_("Inactive agents are rejected by the API even if their certificate is still valid."),
    )
    poll_interval_seconds = models.PositiveIntegerField(
        verbose_name=_("Poll Interval (seconds)"),
        default=300,
        help_text=_(
            "How often this agent should call the check-in endpoint. "
            "Returned in every check-in response so the agent self-configures. "
            "Lower values increase responsiveness; higher values reduce server load."
        ),
    )
    last_seen_at = models.DateTimeField(
        verbose_name=_("Last Seen"),
        null=True,
        blank=True,
        help_text=_("Updated on every authenticated API call. Use for liveness monitoring."),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"TrustpointAgent({self.name} / {self.agent_id})"

    def clean(self) -> None:
        """Validate that all declared capabilities are known values."""
        from django.core.exceptions import ValidationError

        valid = {c.value for c in TrustpointAgent.Capability}
        unknown = [c for c in self.capabilities if c not in valid]
        if unknown:
            raise ValidationError({"capabilities": f"Unknown capabilities: {unknown}"})
```

**Decommissioning:** revoke the agent's mTLS certificate in Trustpoint *and* set `is_active = False`. The revoked cert is rejected at the TLS layer; `is_active = False` is an immediate software kill-switch while CRL propagation completes.

---

### 2.2 `WbmWorkflowDefinition`

Reusable, versioned Playwright-style automation profile. Managed by operators in Trustpoint. No credentials stored here.

```python
class WbmWorkflowDefinition(models.Model):
    """A reusable Playwright automation script for a specific device family or firmware variant."""

    name = models.CharField(verbose_name=_("Name"), max_length=200)
    vendor = models.CharField(verbose_name=_("Vendor"), max_length=120, blank=True)
    device_family = models.CharField(verbose_name=_("Device Family"), max_length=120, blank=True)
    firmware_hint = models.CharField(
        verbose_name=_("Firmware Hint"),
        max_length=120,
        blank=True,
        help_text=_("Optional firmware version string to help operators select the right profile."),
    )
    version = models.CharField(verbose_name=_("Version"), max_length=40, default="1.0")
    description = models.TextField(verbose_name=_("Description"), blank=True)
    profile = models.JSONField(
        verbose_name=_("Workflow Profile"),
        help_text=_("JSON array of Playwright-style automation steps. Validated on save."),
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

`clean()` validates `profile` against `WORKFLOW_STEP_SCHEMA` (see Section 5).

---

### 2.3 `WbmCertificateTarget`

Describes one certificate slot on a device WBM. Links device, certificate profile, workflow, and the responsible agent. No credentials.

```python
class WbmCertificateTarget(models.Model):
    """A single certificate slot on a device WBM, with the workflow and agent responsible for updates."""

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
        "agents.WbmWorkflowDefinition",
        verbose_name=_("Workflow Definition"),
        on_delete=models.PROTECT,
        related_name="targets",
    )
    # The agent responsible for executing pushes to this target.
    # PROTECT prevents accidental deletion of an agent that still owns active targets.
    agent = models.ForeignKey(
        "agents.TrustpointAgent",
        verbose_name=_("Agent"),
        on_delete=models.PROTECT,
        related_name="wbm_targets",
        help_text=_("The agent deployed in the production cell that can reach this device."),
    )
    # WBM address as reachable from inside the cell — never accessed by Trustpoint directly.
    base_url = models.URLField(
        verbose_name=_("WBM Base URL"),
        help_text=_("e.g. https://192.168.1.10 — resolved by the agent, not by Trustpoint."),
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
        help_text=_("Optional device-specific slot name, e.g. 'slot0'."),
    )
    enabled = models.BooleanField(verbose_name=_("Enabled"), default=True)
    renewal_threshold_days = models.PositiveIntegerField(
        verbose_name=_("Renewal Threshold (days)"),
        default=30,
        help_text=_(
            "Trustpoint will include this target in the agent's check-in response when the "
            "currently issued certificate expires within this many days. Set to 0 to only push "
            "when explicitly triggered by an operator."
        ),
    )
    push_requested = models.BooleanField(
        verbose_name=_("Push Requested"),
        default=False,
        help_text=_(
            "Set to True by the operator ('push now') to force a push on the next check-in, "
            "regardless of the certificate expiry window. Cleared automatically once the agent "
            "picks up the job."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("device", "purpose", "slot")]

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmCertificateTarget({self.device} — {self.purpose}/{self.slot} via {self.agent})"
```

---

### 2.4 `WbmJob`

History record. Written by Trustpoint when it handles a push-request from the agent. The agent never creates this record — it only reads back the `job_id` and later posts a result.

```python
class WbmJob(models.Model):
    """Audit record for a single WBM certificate-push operation.

    Created by Trustpoint when the agent requests a push.
    Closed when the agent reports the result.
    """

    class Status(models.TextChoices):
        """Lifecycle state of the job."""

        PENDING_CSR = "pending_csr", _("Pending CSR")   # created at check-in; waiting for agent's CSR
        IN_PROGRESS = "in_progress", _("In Progress")   # CSR signed; agent is executing the workflow
        SUCCEEDED   = "succeeded",   _("Succeeded")
        FAILED      = "failed",      _("Failed")

    target = models.ForeignKey(
        "agents.WbmCertificateTarget",
        verbose_name=_("Certificate Target"),
        on_delete=models.CASCADE,
        related_name="jobs",
    )
    status = models.CharField(
        verbose_name=_("Status"),
        max_length=20,
        choices=Status,
        default=Status.IN_PROGRESS,
        db_index=True,
    )
    # Certificate material.
    # The private key is generated by the agent and never transmitted to Trustpoint.
    # key_spec and subject are sent to the agent in the check-in response so it can
    # build a correct CSR. Trustpoint signs the CSR and stores only the issued cert.
    key_spec = models.CharField(
        verbose_name=_("Key Spec"),
        max_length=40,
        default="EC_P256",
        help_text=_("Algorithm and size for key generation, e.g. 'EC_P256', 'RSA_2048'."),
    )
    subject = models.JSONField(
        verbose_name=_("Subject"),
        default=dict,
        help_text=_(
            "X.509 subject attributes to embed in the CSR, "
            "e.g. {\"CN\": \"device.example.com\", \"O\": \"Acme\"}."
        ),
    )
    csr_pem = models.TextField(
        verbose_name=_("CSR (PEM)"),
        blank=True,
        help_text=_("Stored after the agent submits the CSR, before the cert is issued."),
    )
    cert_pem = models.TextField(verbose_name=_("Certificate (PEM)"), blank=True)
    ca_bundle_pem = models.TextField(verbose_name=_("CA Bundle (PEM)"), blank=True)

    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    result_detail = models.TextField(verbose_name=_("Result Detail"), blank=True)

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmJob({self.pk} {self.status} → {self.target})"
```

---

## 3. `devices.DeviceModel` — no change needed

`WbmCertificateTarget` already holds a FK to `DeviceModel`. Targets are reachable as `device.wbm_targets.all()` via the reverse relation. `DeviceModel` gains no direct dependency on the `agents` app.

---

## 4. REST API

All endpoints live under `/api/agents/`. They follow the **same request pipeline** used by EST and CMP: `RequestContext → Parser → Authentication → Authorization → OperationProcessor → MessageResponder`. Each stage is a dedicated class that reads from and writes to the context, keeping views thin.

The pipeline is split into two layers:
- **Generic layer** (`agents/`) — capability-agnostic; handles agent identity, active check, and pipeline execution. Reused by every future capability.
- **WBM layer** (`agents/wbm/`) — WBM-specific parsers, processors, responders, and context fields.

### 4.1 Endpoints

| Method | URL | Description |
|---|---|---|
| `GET`  | `/api/agents/wbm/check-in/` | Agent polls for pending work. Returns due jobs with `key_spec` and `subject` for CSR generation. No cert or key in this response. |
| `POST` | `/api/agents/wbm/submit-csr/` | Agent submits a CSR for a job. Trustpoint signs it and returns `cert_pem` + `ca_bundle_pem`. |
| `POST` | `/api/agents/wbm/push-result/` | Agent reports the outcome of a completed push. Trustpoint closes the `WbmJob`. |

The private key is generated on the agent and **never transmitted to Trustpoint**.

### 4.2 Generic request context

The base context holds only what is common to **all** agent API calls: the resolved `TrustpointAgent` and the standard HTTP fields inherited from `RestBaseRequestContext`. Capability-specific sub-classes extend this.

```python
# agents/request_context.py
from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING

from request.request_context import RestBaseRequestContext

if TYPE_CHECKING:
    from agents.models import TrustpointAgent


@dataclass(kw_only=True)
class AgentRequestContext(RestBaseRequestContext):
    """Base request context for all Trustpoint agent API endpoints.

    Holds only the resolved :class:`TrustpointAgent` identity plus the HTTP
    fields inherited from :class:`RestBaseRequestContext`.  Capability-specific
    sub-classes (e.g. :class:`WbmAgentRequestContext`) extend this with the
    fields needed by their own parsers, processors and responders.
    """

    # Set by AgentAuthentication; None until authentication succeeds.
    agent: TrustpointAgent | None = None
```

```python
# agents/wbm/request_context.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agents.request_context import AgentRequestContext

if TYPE_CHECKING:
    from agents.models import WbmJob


@dataclass(kw_only=True)
class WbmAgentRequestContext(AgentRequestContext):
    """Request context for all three WBM agent API endpoints.

    Extends :class:`AgentRequestContext` with WBM-specific input/output fields.
    Each pipeline stage populates only the fields it is responsible for:

    - Parser        → ``operation`` + operation-specific *input* fields
    - Authorizer    → validates inputs, stores fetched DB objects (e.g. job)
    - Processor     → performs the work, sets *output* fields
    - Responder     → serialises output fields into ``http_response_*``
    """

    # ── check-in output ───────────────────────────────────────────────────────
    # Set by WbmCheckInProcessor
    pending_jobs: list[dict[str, Any]] = field(default_factory=list)

    # ── submit-csr input / output ─────────────────────────────────────────────
    # Set by WbmSubmitCsrParser
    submit_csr_job_id: int | None = None
    submit_csr_csr_pem: str | None = None
    # Set by WbmSubmitCsrAuthorization (fetched once, shared with processor)
    submit_csr_job: WbmJob | None = None

    # ── push-result input ─────────────────────────────────────────────────────
    # Set by WbmPushResultParser
    push_result_job_id: int | None = None
    push_result_status: str | None = None
    push_result_detail: str = ""
```

### 4.3 Generic authentication

`AgentAuthentication` is **not WBM-specific** — it works for any `AgentRequestContext` sub-class. It resolves the `TrustpointAgent` by SHA-256 fingerprint of the mTLS client certificate, mirroring `ClientCertificateAuthentication` for devices.

```python
# agents/authentication.py
import hashlib

from django.utils import timezone
from request.authentication.base import AuthenticationComponent
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from .models import TrustpointAgent
from .request_context import AgentRequestContext


class AgentAuthentication(AuthenticationComponent, LoggerMixin):
    """Authenticate any Trustpoint agent via its mTLS client-certificate fingerprint.

    Protocol-agnostic: works for any :class:`AgentRequestContext` sub-class.
    Reads the DER-encoded client certificate from ``SSL_CLIENT_CERT_DER``,
    computes its SHA-256 fingerprint, and looks up the matching
    :class:`TrustpointAgent` record. Raises ``ValueError`` on failure,
    consistent with all other authentication components.
    """

    def authenticate(self, context: BaseRequestContext) -> None:
        """Resolve the agent and store it on the context."""
        if not isinstance(context, AgentRequestContext):
            return

        if context.raw_message is None:
            raise ValueError("No raw HTTP request in context.")

        der: bytes | None = context.raw_message.META.get("SSL_CLIENT_CERT_DER")
        if der is None:
            self.logger.warning("Agent request received without a client certificate.")
            raise ValueError("No client certificate presented.")

        fingerprint = hashlib.sha256(der).hexdigest().upper()

        try:
            agent = TrustpointAgent.objects.get(
                certificate_fingerprint=fingerprint, is_active=True
            )
        except TrustpointAgent.DoesNotExist:
            self.logger.warning(
                "Agent authentication failed: unknown or inactive fingerprint %s",
                fingerprint,
            )
            raise ValueError("Unknown or inactive agent.")

        TrustpointAgent.objects.filter(pk=agent.pk).update(last_seen_at=timezone.now())
        context.agent = agent
        self.logger.info("Agent authenticated: %s", agent.agent_id)
```

### 4.4 Generic authorization

`AgentActiveAuthorization` is also **not WBM-specific**. It guards every agent endpoint. WBM-specific checks live in `agents/wbm/authorization.py`.

```python
# agents/authorization.py
from request.authorization.base import AuthorizationComponent
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from .request_context import AgentRequestContext


class AgentActiveAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the resolved agent is active.

    Applied to every agent endpoint regardless of capability.  The
    authentication stage already filters on ``is_active``, but this
    component makes the check explicit in the authorization stage for
    clarity and defence-in-depth.
    """

    def authorize(self, context: BaseRequestContext) -> None:
        """Raise ``ValueError`` if the agent is not active."""
        if not isinstance(context, AgentRequestContext):
            return
        if context.agent is None or not context.agent.is_active:
            raise ValueError("Agent is not active.")
        self.logger.debug("Agent active check passed for %s", context.agent.agent_id)
```

```python
# agents/wbm/authorization.py
from request.authorization.base import AuthorizationComponent
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from agents.models import WbmJob
from agents.wbm.request_context import WbmAgentRequestContext


class WbmSubmitCsrAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the job referenced in submit-csr belongs to the calling agent.

    Fetches the ``WbmJob`` and stores it on the context so the operation
    processor does not need to repeat the query.
    """

    def authorize(self, context: BaseRequestContext) -> None:
        """Verify job ownership and state; store job on context."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        if context.operation != "submit-csr":
            return

        job = (
            WbmJob.objects
            .select_related("target__certificate_profile", "target__device")
            .filter(
                pk=context.submit_csr_job_id,
                status=WbmJob.Status.PENDING_CSR,
                target__agent=context.agent,
            )
            .first()
        )
        if job is None:
            raise ValueError("Job not found or not in PENDING_CSR state.")
        context.submit_csr_job = job
        self.logger.debug("WBM submit-csr authorization passed for job %s", job.pk)


class WbmPushResultAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the job referenced in push-result belongs to the calling agent."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Verify the agent owns the in-progress job."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        if context.operation != "push-result":
            return

        exists = WbmJob.objects.filter(
            pk=context.push_result_job_id,
            status=WbmJob.Status.IN_PROGRESS,
            target__agent=context.agent,
        ).exists()
        if not exists:
            raise ValueError("Job not found or not in IN_PROGRESS state.")
        self.logger.debug(
            "WBM push-result authorization passed for job %s", context.push_result_job_id
        )
```

### 4.5 WBM message parsers

Each WBM operation gets a dedicated parser that reads from `raw_message` and populates the WBM-specific context fields. All extend `ParsingComponent` from `request.message_parser.base`.

```python
# agents/wbm/message_parser.py
import json

from request.message_parser.base import ParsingComponent
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from agents.wbm.request_context import WbmAgentRequestContext


class WbmCheckInParser(ParsingComponent, LoggerMixin):
    """Parse a GET /check-in/ request.

    No request body — agent identity is resolved by AgentAuthentication.
    """

    def parse(self, context: BaseRequestContext) -> None:
        """Set operation; no body fields to parse for check-in."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        context.operation = "check-in"


class WbmSubmitCsrParser(ParsingComponent, LoggerMixin):
    """Parse a POST /submit-csr/ request body into context fields."""

    def parse(self, context: BaseRequestContext) -> None:
        """Extract ``job_id`` and ``csr_pem`` from the JSON body."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        context.operation = "submit-csr"

        if context.raw_message is None:
            raise ValueError("No raw HTTP request in context.")

        try:
            body: dict = json.loads(context.raw_message.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Request body is not valid JSON.") from exc

        job_id = body.get("job_id")
        csr_pem = body.get("csr_pem", "")

        if job_id is None:
            raise ValueError("'job_id' is required.")
        if not csr_pem:
            raise ValueError("'csr_pem' is required.")

        context.submit_csr_job_id = int(job_id)
        context.submit_csr_csr_pem = csr_pem


class WbmPushResultParser(ParsingComponent, LoggerMixin):
    """Parse a POST /push-result/ request body into context fields."""

    def parse(self, context: BaseRequestContext) -> None:
        """Extract ``job_id``, ``status``, and ``detail`` from the JSON body."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        context.operation = "push-result"

        if context.raw_message is None:
            raise ValueError("No raw HTTP request in context.")

        try:
            body: dict = json.loads(context.raw_message.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Request body is not valid JSON.") from exc

        job_id = body.get("job_id")
        if job_id is None:
            raise ValueError("'job_id' is required.")

        from agents.models import WbmJob
        context.push_result_job_id = int(job_id)
        context.push_result_status = body.get("status", WbmJob.Status.FAILED)
        context.push_result_detail = body.get("detail", "")
```

### 4.6 Operation processors

Each operation has a processor that extends `AbstractOperationProcessor` from `request.operation_processor.base`. The `submit-csr` processor re-uses `CertificateIssueProcessor` from the existing PKI pipeline to sign the CSR, keeping certificate issuance logic in one place.

```python
# agents/wbm/operation_processor/check_in.py
from datetime import timedelta

from django.utils import timezone
from request.operation_processor.base import AbstractOperationProcessor
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from agents.models import IssuedCredentialModel, WbmCertificateTarget, WbmJob
from agents.wbm.request_context import WbmAgentRequestContext


class WbmCheckInProcessor(AbstractOperationProcessor, LoggerMixin):
    """Discover due targets for the calling agent and create PENDING_CSR jobs.

    A target is *due* when either:

    - ``push_requested`` is ``True`` (operator-triggered), or
    - The most recently issued certificate expires within
      ``renewal_threshold_days`` days (automatic renewal window).

    For each due target a :class:`WbmJob` with status ``PENDING_CSR`` is
    created. ``push_requested`` is cleared atomically on the target.
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Populate ``context.pending_jobs`` with descriptors for each due target."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        if context.agent is None:
            raise ValueError("Agent not set on context.")

        targets = (
            WbmCertificateTarget.objects
            .filter(agent=context.agent, enabled=True)
            .select_related("device", "certificate_profile", "workflow")
        )

        jobs: list[dict] = []
        for target in targets:
            if self._is_due(target):
                jobs.append(self._create_job(target))

        context.pending_jobs = jobs
        self.logger.info(
            "Check-in for agent %s: %d job(s) pending.", context.agent.agent_id, len(jobs)
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_due(target: WbmCertificateTarget) -> bool:
        """Return True if the target needs a certificate push in this cycle."""
        if target.push_requested:
            return True
        if target.renewal_threshold_days == 0:
            return False
        credential = (
            IssuedCredentialModel.objects
            .filter(
                device=target.device,
                issued_using_cert_profile=target.certificate_profile.unique_name,
            )
            .order_by("-created_at")
            .select_related("credential")
            .first()
        )
        if credential is None:
            return True  # no cert yet — issue a fresh one
        not_after = credential.credential.get_not_after()
        return not_after <= timezone.now() + timedelta(days=target.renewal_threshold_days)

    @staticmethod
    def _create_job(target: WbmCertificateTarget) -> dict:
        """Create a PENDING_CSR WbmJob and return its check-in descriptor."""
        profile = target.certificate_profile
        job = WbmJob.objects.create(
            target=target,
            status=WbmJob.Status.PENDING_CSR,
            key_spec=profile.key_algorithm,      # e.g. "EC_P256"
            subject=profile.get_subject_dict(),  # e.g. {"CN": "...", "O": "..."}
        )
        WbmCertificateTarget.objects.filter(pk=target.pk).update(push_requested=False)
        return {
            "job_id": job.pk,
            "base_url": target.base_url,
            "key_spec": job.key_spec,
            "subject": job.subject,
            "workflow": target.workflow.profile,
        }
```

```python
# agents/wbm/operation_processor/submit_csr.py
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from request.operation_processor.base import AbstractOperationProcessor
from request.request_context import BaseRequestContext, EstCertificateRequestContext
from request.operation_processor.issue_cert import CertificateIssueProcessor
from trustpoint.logger import LoggerMixin

from agents.models import WbmJob
from agents.wbm.request_context import WbmAgentRequestContext


class WbmSubmitCsrProcessor(AbstractOperationProcessor, LoggerMixin):
    """Sign the agent-submitted CSR using the existing PKI CertificateIssueProcessor.

    The CSR is loaded from ``context.submit_csr_csr_pem``, placed into a
    temporary :class:`EstCertificateRequestContext` that is already understood
    by :class:`CertificateIssueProcessor`, and then the issued certificate is
    pulled back out and stored on the ``WbmJob``.

    This approach keeps all certificate signing logic in
    ``request.operation_processor.issue_cert`` — the WBM processor is just a
    thin adapter that translates between the agent job context and the
    established PKI pipeline context.
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Issue the certificate for the CSR and advance the job to IN_PROGRESS."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        job = context.submit_csr_job
        if job is None:
            raise ValueError("WbmJob not set on context.")
        if not context.submit_csr_csr_pem:
            raise ValueError("CSR PEM not set on context.")

        # Parse the PEM CSR.
        csr = x509.load_pem_x509_csr(context.submit_csr_csr_pem.encode())

        target = job.target

        # Build a minimal EstCertificateRequestContext so CertificateIssueProcessor
        # can be reused without modification.
        pki_ctx = EstCertificateRequestContext(
            protocol="wbm_agent",
            operation="submit-csr",
            domain_str=target.device.domain.unique_name if target.device.domain else None,
            cert_profile_str=target.certificate_profile.unique_name,
            cert_requested=csr,
            device=target.device,
            certificate_profile_model=target.certificate_profile,
        )

        CertificateIssueProcessor().process_operation(pki_ctx)

        if pki_ctx.issued_certificate is None:
            raise ValueError("CertificateIssueProcessor did not produce a certificate.")

        cert_pem = pki_ctx.issued_certificate.public_bytes(Encoding.PEM).decode()
        ca_bundle_pem = _build_ca_bundle(pki_ctx)

        WbmJob.objects.filter(pk=job.pk).update(
            status=WbmJob.Status.IN_PROGRESS,
            csr_pem=context.submit_csr_csr_pem,
            cert_pem=cert_pem,
            ca_bundle_pem=ca_bundle_pem,
        )

        # Refresh the job instance so the responder can read cert_pem / ca_bundle_pem.
        context.submit_csr_job = WbmJob.objects.get(pk=job.pk)
        self.logger.info("WBM CSR signed and job %s advanced to IN_PROGRESS.", job.pk)


def _build_ca_bundle(pki_ctx: EstCertificateRequestContext) -> str:
    """Concatenate the issued certificate chain into a PEM CA bundle string."""
    chain = pki_ctx.issued_certificate_chain or []
    return "".join(cert.public_bytes(Encoding.PEM).decode() for cert in chain)
```

```python
# agents/wbm/operation_processor/push_result.py
from django.utils import timezone
from request.operation_processor.base import AbstractOperationProcessor
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from agents.models import WbmJob
from agents.wbm.request_context import WbmAgentRequestContext


class WbmPushResultProcessor(AbstractOperationProcessor, LoggerMixin):
    """Close a WbmJob with the outcome reported by the agent."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Update the job status and completion timestamp."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        updated = WbmJob.objects.filter(
            pk=context.push_result_job_id,
            status=WbmJob.Status.IN_PROGRESS,
            target__agent=context.agent,
        ).update(
            status=context.push_result_status,
            result_detail=context.push_result_detail,
            completed_at=timezone.now(),
        )

        if not updated:
            raise ValueError("Job not found or not in IN_PROGRESS state.")

        self.logger.info(
            "WBM job %s closed with status '%s'.",
            context.push_result_job_id,
            context.push_result_status,
        )
```

### 4.7 Message responders

Responders read the output fields set by the operation processor and write the final HTTP response into the context, mirroring `EstMessageResponder`.

```python
# agents/wbm/message_responder.py
import json

from request.message_responder.base import AbstractMessageResponder
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from agents.request_context import AgentRequestContext
from agents.wbm.request_context import WbmAgentRequestContext


class WbmCheckInResponder(AbstractMessageResponder, LoggerMixin):
    """Serialise the check-in job list into a JSON HTTP response."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Write poll_interval_seconds and jobs list into the context."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        if context.agent is None:
            return
        body = {
            "poll_interval_seconds": context.agent.poll_interval_seconds,
            "jobs": context.pending_jobs,
        }
        context.http_response_content = json.dumps(body)
        context.http_response_status = 200
        context.http_response_content_type = "application/json"


class WbmSubmitCsrResponder(AbstractMessageResponder, LoggerMixin):
    """Serialise cert_pem and ca_bundle_pem into a JSON HTTP response."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Write signed certificate material into the context."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        job = context.submit_csr_job
        if job is None:
            return
        body = {
            "cert_pem": job.cert_pem,
            "ca_bundle_pem": job.ca_bundle_pem,
        }
        context.http_response_content = json.dumps(body)
        context.http_response_status = 200
        context.http_response_content_type = "application/json"


class WbmPushResultResponder(AbstractMessageResponder, LoggerMixin):
    """Acknowledge a successfully closed job."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Write the final status into the context."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        body = {"status": context.push_result_status}
        context.http_response_content = json.dumps(body)
        context.http_response_status = 200
        context.http_response_content_type = "application/json"


class WbmErrorResponder(AbstractMessageResponder, LoggerMixin):
    """Return a plain-text error response for any WBM pipeline failure."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Ensure an error status and message are set on the context."""
        if not isinstance(context, AgentRequestContext):
            return
        if not context.http_response_status or context.http_response_status < 400:
            context.http_response_status = 500
        if not context.http_response_content:
            context.http_response_content = "Internal server error."
        context.http_response_content_type = "text/plain"
```

### 4.8 Views

The view layer is split into two files mirroring the two-layer architecture:

- **`agents/views.py`** — `AgentPipelineMixin`: generic pipeline runner, reusable by every capability. Handles context construction, stage ordering, and error fallback. Not WBM-specific.
- **`agents/wbm/views.py`** — the three thin WBM views that inject the correct WBM-specific parser/processor/responder into the mixin.

```python
# agents/views.py
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.http import HttpRequest, HttpResponse

from trustpoint.logger import LoggerMixin

from .authentication import AgentAuthentication
from .authorization import AgentActiveAuthorization
from .request_context import AgentRequestContext

if TYPE_CHECKING:
    from request.authorization.base import AuthorizationComponent
    from request.message_parser.base import ParsingComponent
    from request.message_responder.base import AbstractMessageResponder
    from request.operation_processor.base import AbstractOperationProcessor


class AgentPipelineMixin(LoggerMixin):
    """Generic pipeline runner for all Trustpoint agent views.

    Mirrors ``EstSimpleEnrollmentMixin``: build context → parse →
    authenticate → authorize → process → respond.  On any exception the
    ``error_responder`` is called so the pipeline always produces a
    well-formed HTTP response.

    Subclasses provide a capability-specific :class:`AgentRequestContext`
    sub-class as ``context_class``, and call :meth:`_run_pipeline` with the
    matching parser, authorizers, processor and responders.  The generic
    :class:`AgentAuthentication` and :class:`AgentActiveAuthorization` are
    always applied first; capability-specific authorizers are appended.
    """

    #: Override in sub-packages with the capability-specific context class.
    context_class: type[AgentRequestContext] = AgentRequestContext

    def _run_pipeline(
        self,
        request: HttpRequest,
        operation: str,
        parser: ParsingComponent,
        extra_authorizers: list[AuthorizationComponent],
        processor: AbstractOperationProcessor,
        responder: AbstractMessageResponder,
        error_responder: AbstractMessageResponder,
    ) -> HttpResponse:
        """Execute the full request pipeline for a single agent operation."""
        self.logger.info(
            "Agent request: operation=%s method=%s path=%s",
            operation, request.method, request.path,
        )

        try:
            ctx = self.context_class(
                raw_message=request,
                protocol="agent",
                operation=operation,
            )
        except Exception:
            self.logger.exception("Failed to build %s.", self.context_class.__name__)
            return HttpResponse("Internal server error.", status=500)

        try:
            # 1. Parse
            parser.parse(ctx)

            # 2. Authenticate (generic — fingerprint → TrustpointAgent)
            AgentAuthentication().authenticate(ctx)

            # 3. Authorize (generic active check + capability-specific checks)
            AgentActiveAuthorization().authorize(ctx)
            for authorizer in extra_authorizers:
                authorizer.authorize(ctx)

            # 4. Process
            processor.process_operation(ctx)

            # 5. Respond
            responder.build_response(ctx)

        except Exception:
            self.logger.exception(
                "Error in agent pipeline for operation '%s'.", operation
            )
            error_responder.build_response(ctx)

        return ctx.to_http_response()
```

```python
# agents/wbm/views.py
from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from agents.views import AgentPipelineMixin

from .authorization import WbmPushResultAuthorization, WbmSubmitCsrAuthorization
from .message_parser import WbmCheckInParser, WbmPushResultParser, WbmSubmitCsrParser
from .message_responder import (
    WbmCheckInResponder,
    WbmErrorResponder,
    WbmPushResultResponder,
    WbmSubmitCsrResponder,
)
from .operation_processor.check_in import WbmCheckInProcessor
from .operation_processor.push_result import WbmPushResultProcessor
from .operation_processor.submit_csr import WbmSubmitCsrProcessor
from .request_context import WbmAgentRequestContext


class WbmPipelineMixin(AgentPipelineMixin):
    """Pipeline mixin for WBM views.

    Sets ``context_class`` to :class:`WbmAgentRequestContext` so the generic
    runner constructs the right context sub-class on every request.
    """

    context_class = WbmAgentRequestContext


@method_decorator(csrf_exempt, name="dispatch")
class WbmCheckInView(WbmPipelineMixin, View):
    """GET /api/agents/wbm/check-in/ — agent polls for pending work."""

    def get(self, request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        """Run the WBM check-in pipeline."""
        return self._run_pipeline(
            request,
            operation="check-in",
            parser=WbmCheckInParser(),
            extra_authorizers=[],
            processor=WbmCheckInProcessor(),
            responder=WbmCheckInResponder(),
            error_responder=WbmErrorResponder(),
        )


@method_decorator(csrf_exempt, name="dispatch")
class WbmSubmitCsrView(WbmPipelineMixin, View):
    """POST /api/agents/wbm/submit-csr/ — agent submits CSR, receives signed cert."""

    def post(self, request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        """Run the WBM submit-csr pipeline."""
        return self._run_pipeline(
            request,
            operation="submit-csr",
            parser=WbmSubmitCsrParser(),
            extra_authorizers=[WbmSubmitCsrAuthorization()],
            processor=WbmSubmitCsrProcessor(),
            responder=WbmSubmitCsrResponder(),
            error_responder=WbmErrorResponder(),
        )


@method_decorator(csrf_exempt, name="dispatch")
class WbmPushResultView(WbmPipelineMixin, View):
    """POST /api/agents/wbm/push-result/ — agent reports push outcome."""

    def post(self, request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        """Run the WBM push-result pipeline."""
        return self._run_pipeline(
            request,
            operation="push-result",
            parser=WbmPushResultParser(),
            extra_authorizers=[WbmPushResultAuthorization()],
            processor=WbmPushResultProcessor(),
            responder=WbmPushResultResponder(),
            error_responder=WbmErrorResponder(),
        )
```

### 4.9 Message payloads (reference)

**Check-in response:**
```json
{
  "poll_interval_seconds": 300,
  "jobs": [
    {
      "job_id": 42,
      "base_url": "https://192.168.1.10",
      "key_spec": "EC_P256",
      "subject": { "CN": "device-a.cell1.example.com", "O": "Acme" },
      "workflow": [
        { "type": "goto",       "url": "{{base_url}}/login" },
        { "type": "fill",       "selector": "#username", "value": "{{username}}" },
        { "type": "fill",       "selector": "#password", "value": "{{password}}" },
        { "type": "click",      "selector": "#login-btn" },
        { "type": "uploadFile", "selector": "#cert-upload", "content": "{{cert_pem}}" },
        { "type": "click",      "selector": "#apply-btn" },
        { "type": "expect",     "selector": ".success-banner", "text": "Certificate updated" }
      ]
    }
  ]
}
```

**Submit-CSR request / response:**
```json
{ "job_id": 42, "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..." }
```
```json
{ "cert_pem": "-----BEGIN CERTIFICATE-----...", "ca_bundle_pem": "-----BEGIN CERTIFICATE-----..." }
```

**Push-result request / response:**
```json
{ "job_id": 42, "status": "succeeded", "detail": "" }
```
```json
{ "status": "succeeded" }
```

---

## 5. Workflow JSON Schema Validation

Validate `WbmWorkflowDefinition.profile` on save using `jsonschema`.

```python
# agents/models.py — module-level constant

WORKFLOW_STEP_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["type"],
        "properties": {
            "type": {"type": "string", "enum": [
                "goto", "click", "fill", "uploadFile",
                "waitFor", "expect", "screenshot", "reboot"
            ]},
            "selector":   {"type": "string"},
            "url":        {"type": "string"},
            "value":      {"type": "string"},
            "content":    {"type": "string"},
            "text":       {"type": "string"},
            "timeout_ms": {"type": "integer", "minimum": 0},
        },
        "additionalProperties": False,
    },
}
```

Called from `WbmWorkflowDefinition.clean()`:

```python
import jsonschema
from django.core.exceptions import ValidationError

def clean(self) -> None:
    """Validate the workflow profile against the step schema."""
    try:
        jsonschema.validate(self.profile, WORKFLOW_STEP_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ValidationError({"profile": exc.message}) from exc
```

---

## 6. Django Admin

All four models are registered under the single `agents` app admin.

```python
# agents/admin.py
from django.contrib import admin
from .models import TrustpointAgent, WbmWorkflowDefinition, WbmCertificateTarget, WbmJob


@admin.register(TrustpointAgent)
class TrustpointAgentAdmin(admin.ModelAdmin):
    list_display    = ["name", "agent_id", "capabilities", "cell_location", "is_active", "poll_interval_seconds", "last_seen_at"]
    list_filter     = ["is_active"]
    search_fields   = ["name", "agent_id", "cell_location"]
    readonly_fields = ["last_seen_at", "created_at", "updated_at"]


@admin.register(WbmWorkflowDefinition)
class WbmWorkflowDefinitionAdmin(admin.ModelAdmin):
    list_display  = ["name", "version", "vendor", "device_family", "is_active", "updated_at"]
    list_filter   = ["is_active", "vendor"]
    search_fields = ["name", "vendor", "device_family"]


@admin.register(WbmCertificateTarget)
class WbmCertificateTargetAdmin(admin.ModelAdmin):
    list_display  = ["device", "purpose", "slot", "agent", "base_url", "enabled", "renewal_threshold_days", "push_requested"]
    list_filter   = ["purpose", "enabled", "agent", "push_requested"]
    search_fields = ["device__common_name", "agent__name", "base_url"]
    actions       = ["trigger_push_now"]

    @admin.action(description="Request immediate push on next check-in")
    def trigger_push_now(self, request: Any, queryset: Any) -> None:
        """Set push_requested=True on selected targets so they are included in the next check-in."""
        queryset.update(push_requested=True)


@admin.register(WbmJob)
class WbmJobAdmin(admin.ModelAdmin):
    list_display    = ["pk", "target", "status", "started_at", "completed_at"]
    list_filter     = ["status"]
    readonly_fields = ["key_spec", "subject", "csr_pem", "cert_pem", "ca_bundle_pem", "result_detail", "started_at", "completed_at"]
```

---

## 7. Open Items (Trustpoint side)

- **`WbmSubmitCsrProcessor` — domain lookup** — `WbmSubmitCsrProcessor` builds an `EstCertificateRequestContext` and reuses `CertificateIssueProcessor`. The domain is derived from `target.device.domain`; verify that all `DeviceModel` instances that can be WBM targets have a domain FK, or add a fallback that selects the domain from the `CertificateProfileModel`.
- **Issued credential linking** — after `CertificateIssueProcessor` completes, the resulting `IssuedCredentialModel` should be linked back to the `WbmJob` (add an optional FK `WbmJob.issued_credential`) so the issued certificate appears in the standard certificate inventory and expiry tracking works out-of-the-box.
- **UI views** — `TrustpointAgent` registration wizard, workflow definition editor/importer, per-target job history with CSR/cert viewer, agent liveness dashboard, "Push Now" button (sets `push_requested=True`).
- **Notifications** — hook `WbmJob` close (succeeded / failed) into the existing `notifications` app.
- **Agent certificate issuance** — integrate `TrustpointAgent` registration with the existing Trustpoint cert issuance flow so `certificate_fingerprint` is populated automatically.
- **Liveness alerting** — alert when `TrustpointAgent.last_seen_at` exceeds a configurable threshold (e.g. `3 × poll_interval_seconds`).
- **Duplicate job guard** — if the agent calls check-in while a `PENDING_CSR` or `IN_PROGRESS` job already exists for a target, skip re-creating it. Add a check in `WbmCheckInProcessor._is_due()` or `_create_job()`.
- **Error HTTP status codes** — `AgentPipelineMixin` currently maps all exceptions to 500. Differentiate authentication/authorisation failures (401/403) from validation failures (400) by catching typed errors or inspecting `ctx.http_response_status` before calling `error_responder`.
- **Adding a second capability** — create `agents/firmware/` mirroring `agents/wbm/`: define a `FirmwareAgentRequestContext(AgentRequestContext)`, implement capability-specific parsers/processors/responders, subclass `AgentPipelineMixin` with `context_class = FirmwareAgentRequestContext`. The generic authentication, active-check, and pipeline runner require zero changes.
- **Generic job base model** — once a second capability is implemented, extract `AbstractAgentJob` (status, started_at, completed_at, result_detail, agent FK) so each feature only adds its domain fields.
