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
  |── GET /agents/agents/wbm/check-in/ ───▶|  "Any work for me?"
  |◀── 200 { poll_interval_seconds,        |  Trustpoint lists due targets:
  |          jobs: [{ job_id,              |  job_id, key_spec, subject
  |                  key_spec, subject,    |  (for CSR), workflow profile
  |                  workflow }] }         |  (no cert or key in this response)
  |                                        |
  |  [Agent generates key pair + CSR]      |
  |                                        |
  |── POST /agents/agents/wbm/submit-csr/ ▶|  { job_id, csr_pem }
  |◀── 200 { cert_pem, ca_bundle_pem } ────|  Trustpoint signs CSR, returns cert
  |                                        |
  |  [Playwright executes workflow]        |  (key stays on agent, never sent)
  |                                        |
  |── POST /agents/agents/wbm/push-result/▶|  { job_id, status, detail }
  |◀── 200 { status } ─────────────────────|
```

> **URL routing:** `trustpoint/urls.py` mounts `agents/` → `agents/urls.py`, which mounts `agents/wbm/` → `agents/wbm/urls.py`. The full paths therefore contain a double `agents/agents/` segment: `/agents/agents/wbm/<endpoint>/`.

Consequences:
- **Private key never leaves the agent.** Trustpoint only ever sees the public key (via the CSR).
- **`AgentJob` stores no private key** — `key_pem` field does not exist.
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
│                             AgentWorkflowDefinition, AgentCertificateTarget, AgentJob
│
│  ── generic pipeline layer (capability-agnostic) ──────────────────────────
├── request_context.py     ← AgentRequestContext (extends RestBaseRequestContext)
│                             holds only: agent, protocol="agent"
├── authentication.py      ← AgentAuthentication (fingerprint → TrustpointAgent)
├── authorization.py       ← AgentActiveAuthorization (is_active guard)
├── views.py               ← AgentPipelineMixin (generic pipeline runner) +
│                             AgentPipelineConfig (dataclass grouping components) +
│                             AgentPipelineView (base Django view)
├── web_views.py           ← UI views for workflow profiles and managed device targets
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
│   ├── views.py           ← WbmPipelineMixin, WbmCheckInView, WbmSubmitCsrView,
│   │                         WbmPushResultView
│   └── urls.py            ← /agents/wbm/ routing
│
├── urls.py                ← /agents/ routing (includes wbm.urls, web UI routes)
├── admin.py               ← admin registrations for all models
└── migrations/
    └── 0001_tp_v0_5_0_dev1.py
```

---

## 2. Models

### 2.1 `TrustpointAgent`

Generic identity record for any automation agent. Not WBM-specific. Linked to a `DeviceModel` (the agent's own device record) to tie the agent identity into the existing device/onboarding lifecycle.

```python
# agents/models.py

class TrustpointAgent(models.Model):
    """A registered automation agent deployed inside a production cell.

    Acts as the identity anchor for all agent-executed job types.
    WBM certificate pushing is the first supported capability.

    **1-to-1 agent** (``DeviceType.AGENT_ONE_TO_ONE``):
    The associated ``DeviceModel`` represents the agent itself.  It is treated
    like a standalone device — the domain credential *and* all other issued
    certificates belong to that single device record.  Exactly one
    ``TrustpointAgent`` may be linked to the device.

    **1-to-n agent** (``DeviceType.AGENT_ONE_TO_N``):
    The associated ``DeviceModel`` represents the agent process only and holds
    *only* its domain credential (LDevID).  Every device managed by the agent
    is a separate ``DeviceModel`` (type ``AGENT_MANAGED_DEVICE``) referenced via
    ``AgentCertificateTarget.device``.  Application certificates are issued to
    those managed-device records, not to the agent device itself.
    """

    class Capability(models.TextChoices):
        WBM_CERT_PUSH = 'wbm_cert_push', _('WBM Certificate Push')

    name = models.CharField(max_length=120, unique=True, ...)
    agent_id = models.CharField(max_length=120, unique=True, ...)
    device = models.ForeignKey(
        'devices.DeviceModel',
        on_delete=models.PROTECT,
        related_name='agents',
        null=True, blank=True,
        # For 1-to-1: the device IS the agent.
        # For 1-to-n: the agent-process device (holds only domain credential).
    )
    certificate_fingerprint = models.CharField(max_length=64, unique=True, ...)
    capabilities = models.JSONField(default=list, ...)  # e.g. ["wbm_cert_push"]
    cell_location = models.CharField(max_length=200, blank=True, ...)
    is_active = models.BooleanField(default=True, ...)
    poll_interval_seconds = models.PositiveIntegerField(default=300, ...)
    last_seen_at = models.DateTimeField(null=True, blank=True, ...)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

`clean()` validates capabilities and enforces device-type constraints:
- The linked device must be of type `AGENT_ONE_TO_ONE` or `AGENT_ONE_TO_N`.
- For `AGENT_ONE_TO_ONE` devices only a single `TrustpointAgent` may be linked.

**Decommissioning:** revoke the agent's mTLS certificate in Trustpoint *and* set `is_active = False`. The revoked cert is rejected at the TLS layer; `is_active = False` is an immediate software kill-switch while CRL propagation completes.

---

### 2.2 `AgentWorkflowDefinition`

Reusable automation profile. Replaces the earlier `WbmWorkflowDefinition` concept. Metadata (vendor, device_family, etc.) and the automation steps are **stored together inside the `profile` JSON object** rather than as separate columns.

```python
class AgentWorkflowDefinition(models.Model):
    """A reusable automation workflow for a specific device family or firmware variant.

    The profile is a JSON object containing device metadata fields
    (vendor, device_family, firmware_hint, version, description) and a
    'steps' array validated against WORKFLOW_STEP_SCHEMA.
    """

    name = models.CharField(max_length=200, unique=True, ...)
    profile = models.JSONField(
        # JSON object: { vendor, device_family, firmware_hint, version, description, steps: [...] }
    )
    is_active = models.BooleanField(default=True, ...)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

`clean()` validates `profile['steps']` against `WORKFLOW_STEP_SCHEMA` (see Section 5).

**Key differences from the original concept:**
- No separate `vendor`, `device_family`, `firmware_hint`, `version`, `description` columns — all inside `profile`.
- No `unique_together = [("name", "version")]` — `name` alone is unique.

---

### 2.3 `AgentCertificateTarget`

Describes one certificate target on a managed device. Links device, certificate profile, workflow, and the responsible agent. Replaces the earlier `WbmCertificateTarget`. The `base_url` and `purpose`/`slot` fields from the concept **are not present** — the WBM base URL and slot information are instead carried inside the workflow profile or handled by the agent.

```python
class AgentCertificateTarget(models.Model):
    """A certificate target on a managed device.

    Device ownership rules:
    - 1-to-n agent (AGENT_ONE_TO_N): device must be AGENT_MANAGED_DEVICE.
    - 1-to-1 agent (AGENT_ONE_TO_ONE): device must be the agent's own DeviceModel.
    """

    device = models.ForeignKey('devices.DeviceModel', on_delete=models.CASCADE,
                                related_name='agent_targets', ...)
    certificate_profile = models.ForeignKey('pki.CertificateProfileModel',
                                             on_delete=models.PROTECT,
                                             related_name='agent_targets', ...)
    workflow = models.ForeignKey('agents.AgentWorkflowDefinition',
                                  on_delete=models.PROTECT,
                                  related_name='targets',
                                  null=True, blank=True, ...)
    agent = models.ForeignKey('agents.TrustpointAgent', on_delete=models.PROTECT,
                               related_name='agent_targets', ...)
    enabled = models.BooleanField(default=True, ...)
    renewal_threshold_days = models.PositiveIntegerField(default=30, ...)
    push_requested = models.BooleanField(default=False, ...)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('device', 'agent', 'certificate_profile')]
```

`clean()` enforces device-ownership rules: for 1-to-n agents the target device must be `AGENT_MANAGED_DEVICE`; for 1-to-1 agents the target device must be the agent's own device.

---

### 2.4 `AgentJob`

History record. Replaces `WbmJob`. Written by Trustpoint when the check-in processor creates a job. The agent never creates this record — it only reads back the `job_id` and later posts a result.

```python
class AgentJob(models.Model):
    """Audit record for a single agent certificate-provisioning operation."""

    class Status(models.TextChoices):
        PENDING_CSR = 'pending_csr', _('Pending CSR')
        IN_PROGRESS = 'in_progress', _('In Progress')
        SUCCEEDED   = 'succeeded',   _('Succeeded')
        FAILED      = 'failed',      _('Failed')

    target = models.ForeignKey('agents.AgentCertificateTarget',
                                on_delete=models.CASCADE, related_name='jobs', ...)
    status = models.CharField(max_length=20, choices=Status,
                               default=Status.IN_PROGRESS, db_index=True)
    key_spec = models.CharField(max_length=40, default='EC_P256', ...)
    subject = models.JSONField(default=dict, ...)
    csr_pem = models.TextField(blank=True, ...)
    cert_pem = models.TextField(blank=True)
    ca_bundle_pem = models.TextField(blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    result_detail = models.TextField(blank=True)
```

---

## 3. `devices.DeviceModel` — new device types added

Three new `DeviceType` enum values were added to `DeviceModel`:

```python
class DeviceType(models.IntegerChoices):
    GENERIC_DEVICE        = 0, _('Generic Device')
    OPC_UA_GDS            = 1, _('OPC UA GDS')
    OPC_UA_GDS_PUSH       = 2, _('OPC UA GDS Push')
    AGENT_ONE_TO_ONE      = 3, _('Agent (1-to-1)')
    AGENT_ONE_TO_N        = 4, _('Agent (1-to-n)')
    AGENT_MANAGED_DEVICE  = 5, _('Agent Managed Device')
```

`DeviceModel.clean()` now validates agent devices: both `AGENT_ONE_TO_ONE` and `AGENT_ONE_TO_N` must use EST - Username & Password as their onboarding protocol, must not have CMP enabled, and must not use the no-onboarding config.

`AgentCertificateTarget` holds a FK to `DeviceModel`. Targets are reachable as `device.agent_targets.all()` via the reverse relation.

The `DeviceTableView` excludes agent types from the main devices list. A new `AgentTableView` in `devices/views.py` lists only agent devices and auto-creates a `TrustpointAgent` record for any agent device that doesn't have one yet.

---

## 4. REST API

All WBM endpoints are mounted via a two-level `include()` chain:

```
trustpoint/urls.py       path('agents/', include('agents.urls'))
agents/urls.py           path('agents/wbm/', include('agents.wbm.urls'))
agents/wbm/urls.py       path('check-in/' | 'submit-csr/' | 'push-result/')
```

This produces the following absolute paths (the double `agents/` segment is intentional — the outer prefix is for the app, the inner one scopes WBM under the future `agents/<agent_id>/…` resource space):

| Method | Absolute URL | Django name |
|---|---|---|
| `GET`  | `/agents/agents/wbm/check-in/`   | `agents:agents_wbm:check-in`   |
| `POST` | `/agents/agents/wbm/submit-csr/` | `agents:agents_wbm:submit-csr` |
| `POST` | `/agents/agents/wbm/push-result/`| `agents:agents_wbm:push-result`|

They follow the **same request pipeline** used by EST and CMP: `RequestContext → Parser → Authentication → Authorization → OperationProcessor → MessageResponder`.

The pipeline is split into two layers:
- **Generic layer** (`agents/`) — capability-agnostic; handles agent identity, active check, and pipeline execution. Reused by every future capability.
- **WBM layer** (`agents/wbm/`) — WBM-specific parsers, processors, responders, and context fields.

### 4.1 Endpoints

The private key is generated on the agent and **never transmitted to Trustpoint**.

**GET `/agents/agents/wbm/check-in/`**

No request body. Authenticated via mTLS fingerprint. Returns the poll interval and a list of `AgentJob` descriptors the agent must service. Each job carries `key_spec` and `subject` so the agent can build a CSR locally. The workflow profile object is included so the agent knows which automation steps to execute after the cert is pushed.

**POST `/agents/agents/wbm/submit-csr/`**

```json
{ "job_id": 42, "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..." }
```

Trustpoint verifies the job belongs to the calling agent, signs the CSR using `CertificateIssueProcessor`, advances the job status to `IN_PROGRESS`, and returns:

```json
{ "cert_pem": "-----BEGIN CERTIFICATE-----...", "ca_bundle_pem": "-----BEGIN CERTIFICATE-----..." }
```

**POST `/agents/agents/wbm/push-result/`**

```json
{ "job_id": 42, "status": "succeeded", "detail": "" }
```

Trustpoint closes the `AgentJob` with the reported status and `completed_at` timestamp. Returns:

```json
{ "status": "succeeded" }
```

### 4.2 Generic request context

The base context holds only what is common to **all** agent API calls: the resolved `TrustpointAgent` and the standard HTTP fields inherited from `RestBaseRequestContext`. Capability-specific sub-classes extend this.

```python
# agents/request_context.py
@dataclass(kw_only=True)
class AgentRequestContext(RestBaseRequestContext):
    """Base request context for all Trustpoint agent API endpoints."""
    agent: TrustpointAgent | None = None
```

```python
# agents/wbm/request_context.py
@dataclass(kw_only=True)
class WbmAgentRequestContext(AgentRequestContext):
    """Request context for all three WBM agent API endpoints."""
    # check-in output (set by WbmCheckInProcessor)
    pending_jobs: list[dict[str, Any]] = field(default_factory=list)
    # submit-csr input (set by WbmSubmitCsrParser)
    submit_csr_job_id: int | None = None
    submit_csr_csr_pem: str | None = None
    # submit-csr fetched object (set by WbmSubmitCsrAuthorization)
    submit_csr_job: AgentJob | None = None
    # push-result input (set by WbmPushResultParser)
    push_result_job_id: int | None = None
    push_result_status: str | None = None
    push_result_detail: str = ""
```

### 4.3 Generic authentication

`AgentAuthentication` resolves the `TrustpointAgent` by SHA-256 fingerprint of the mTLS client certificate, mirroring `ClientCertificateAuthentication` for devices. Reads `SSL_CLIENT_CERT_DER` from `request.META`, updates `last_seen_at` on every call.

### 4.4 Generic authorization

`AgentActiveAuthorization` guards every agent endpoint. WBM-specific ownership/state checks live in `agents/wbm/authorization.py` and are passed as `extra_authorizers` in the `AgentPipelineConfig`.

### 4.5 WBM message parsers

Each WBM operation gets a dedicated parser that reads from `raw_message` and populates WBM-specific context fields. All extend `ParsingComponent`.

- `WbmCheckInParser` — sets `operation = 'check-in'`; no body to parse.
- `WbmSubmitCsrParser` — extracts `job_id` and `csr_pem` from the JSON body.
- `WbmPushResultParser` — extracts `job_id`, `status`, and `detail` from the JSON body.

### 4.6 Operation processors

Each operation has a processor extending `AbstractOperationProcessor`.

**`WbmCheckInProcessor`** — discovers due `AgentCertificateTarget` records for the calling agent. A target is *due* when `push_requested=True` OR the most recently issued certificate (looked up from `IssuedCredentialModel` filtered by device and cert-profile) expires within `renewal_threshold_days` days. Creates an `AgentJob` with `status=PENDING_CSR` for each due target and clears `push_requested` atomically. `key_spec` and `subject` are derived from `target.certificate_profile.profile` (keys `key_algorithm` and `subject`).

**`WbmSubmitCsrProcessor`** — parses the PEM CSR, stores the raw CSR on the job, builds an `EstCertificateRequestContext` (with domain asserted from `target.device.domain` — raises `ValueError` if None), delegates to `CertificateIssueProcessor`, serialises the resulting certificate and chain to PEM, saves `cert_pem`/`ca_bundle_pem` on the job, advances status to `IN_PROGRESS`, and calls `job.refresh_from_db()` so the responder sees the current state.

**`WbmPushResultProcessor`** — maps the incoming status string to a valid `AgentJob.Status` (defaults to `FAILED` for unknown values), updates the job with status, `result_detail`, and `completed_at`. Raises `ValueError` if the job is not found or not in `IN_PROGRESS` state.

### 4.7 Message responders

Responders read output fields set by the processor and write the final HTTP response into the context.

- `WbmCheckInResponder` — returns `{ poll_interval_seconds, jobs: [...] }`.
- `WbmSubmitCsrResponder` — returns `{ cert_pem, ca_bundle_pem }` from `context.submit_csr_job`.
- `WbmPushResultResponder` — returns `{ status }`.
- `WbmErrorResponder` — ensures a 500 status and plain-text error body if not already set.

### 4.8 Views and `AgentPipelineConfig`

The view layer is split into two files. The key change from the concept is the introduction of `AgentPipelineConfig` — a dataclass that groups all per-operation pipeline components to avoid a too-many-arguments linter violation:

```python
# agents/views.py
@dataclass
class AgentPipelineConfig:
    """Groups all per-operation pipeline components into a single parameter object."""
    parser: ParsingComponent
    extra_authorizers: list[AuthorizationComponent]
    processor: AbstractOperationProcessor
    responder: AbstractMessageResponder
    error_responder: AbstractMessageResponder
```

`AgentPipelineMixin._run_pipeline()` now takes `config: AgentPipelineConfig` instead of individual keyword arguments. `AgentPipelineView` is a thin base Django `View` combining the mixin.

WBM views pass a fully populated `AgentPipelineConfig` to `_run_pipeline`:

```python
# agents/wbm/views.py
class WbmCheckInView(WbmPipelineMixin, View):
    def get(self, request, *args, **kwargs):
        return self._run_pipeline(request, 'check-in', AgentPipelineConfig(
            parser=WbmCheckInParser(),
            extra_authorizers=[],
            processor=WbmCheckInProcessor(),
            responder=WbmCheckInResponder(),
            error_responder=WbmErrorResponder(),
        ))
```

### 4.9 Full check-in response example

```json
{
  "poll_interval_seconds": 300,
  "jobs": [
    {
      "job_id": 42,
      "key_spec": "EC_P256",
      "subject": { "CN": "device-a.cell1.example.com", "O": "Acme" },
      "workflow": {
        "vendor": "Vendor Name",
        "device_family": "Device Family",
        "firmware_hint": "3.2",
        "version": "1.0",
        "description": "Push TLS cert via WBM",
        "steps": [
          { "type": "goto",       "url": "https://{{device_ip}}/login" },
          { "type": "fill",       "selector": "#username", "value": "admin" },
          { "type": "fill",       "selector": "#password", "value": "{{wbm_password}}" },
          { "type": "click",      "selector": "#login-btn" },
          { "type": "uploadFile", "selector": "#cert-upload", "content": "{{cert_pem}}" },
          { "type": "click",      "selector": "#apply-btn" },
          { "type": "expect",     "selector": ".success-banner", "text": "Certificate updated" }
        ]
      }
    }
  ]
}
```

---

## 5. Workflow JSON Schema Validation

`AgentWorkflowDefinition.profile` is a JSON **object** (not a plain array). Metadata fields (`vendor`, `device_family`, `firmware_hint`, `version`, `description`) live as top-level keys. The automation steps live under a `steps` key and are validated against `WORKFLOW_STEP_SCHEMA`:

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

Called from `AgentWorkflowDefinition.clean()`:

```python
def clean(self) -> None:
    """Validate the workflow profile against the step schema."""
    if not isinstance(self.profile, dict):
        raise ValidationError({"profile": "Profile must be a JSON object."})
    steps = self.profile.get("steps", [])
    try:
        jsonschema.validate(steps, WORKFLOW_STEP_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ValidationError({"profile": f"Steps validation error: {exc.message}"}) from exc
```

A default profile template (with example steps) is provided by `AgentWorkflowDefinitionConfigView._default_profile_json()` when creating a new definition via the UI.

---

## 6. Django Admin

All four models are registered under the `agents` app admin. Model names reflect the actual implementation.

```python
# agents/admin.py
from django.contrib import admin
from .models import TrustpointAgent, AgentWorkflowDefinition, AgentCertificateTarget, AgentJob


@admin.register(TrustpointAgent)
class TrustpointAgentAdmin(admin.ModelAdmin):
    list_display    = ["name", "agent_id", "is_active", "poll_interval_seconds", "last_seen_at"]
    list_filter     = ["is_active"]
    search_fields   = ["name", "agent_id", "cell_location"]
    readonly_fields = ["last_seen_at", "created_at", "updated_at"]


@admin.register(AgentWorkflowDefinition)
class AgentWorkflowDefinitionAdmin(admin.ModelAdmin):
    list_display  = ["name", "is_active", "created_at", "updated_at"]
    list_filter   = ["is_active"]
    search_fields = ["name"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(AgentCertificateTarget)
class AgentCertificateTargetAdmin(admin.ModelAdmin):
    list_display  = ["device", "agent", "certificate_profile", "enabled", "renewal_threshold_days", "push_requested"]
    list_filter   = ["enabled", "push_requested"]
    search_fields = ["device__common_name", "agent__name"]
    readonly_fields = ["created_at", "updated_at"]
    actions       = ["request_push"]

    @admin.action(description="Request immediate certificate push on next check-in")
    def request_push(self, request: Any, queryset: Any) -> None:
        """Set push_requested=True on selected targets."""
        updated = queryset.update(push_requested=True)
        self.message_user(request, f"{updated} target(s) flagged for immediate push.")


@admin.register(AgentJob)
class AgentJobAdmin(admin.ModelAdmin):
    list_display    = ["pk", "target", "status", "key_spec", "started_at", "completed_at"]
    list_filter     = ["status", "key_spec"]
    search_fields   = ["target__device__common_name"]
    readonly_fields = ["started_at", "completed_at", "csr_pem", "cert_pem", "ca_bundle_pem"]
```

---

## 7. Web UI (implemented)

The following UI views are implemented in `agents/web_views.py` and routed under `/agents/`:

| View | URL | Description |
|---|---|---|
| `AgentWorkflowDefinitionTableView` | `/agents/profiles/` | List all workflow definitions |
| `AgentWorkflowDefinitionConfigView` | `/agents/profiles/<pk>/` | View/edit a workflow definition; includes a JSON editor with default template |
| `AgentWorkflowDefinitionBulkDeleteConfirmView` | `/agents/profiles/delete/<pks>/` | Bulk delete confirmation |
| `AgentManagedDeviceTableView` | `/agents/<agent_id>/targets/` | List managed devices (AgentCertificateTargets) for an agent |
| `AgentManagedDeviceCreateView` | `/agents/<agent_id>/targets/create/` | Create managed device + target in one step |
| `AgentManagedDeviceDeleteView` | `/agents/<agent_id>/targets/delete/<pks>/` | Bulk delete managed devices |

The "Agents" sidebar item in the main navigation (`base.html`) links to the `devices:agents` view (the `AgentTableView` in `devices/views.py`), which lists `AGENT_ONE_TO_ONE` and `AGENT_ONE_TO_N` devices and provides a "Managed Devices" button per agent.

The `ManagedDeviceCreateForm.save()` creates a `DeviceModel` of type `AGENT_MANAGED_DEVICE` with a `NoOnboardingConfigModel` (EST), then creates the `AgentCertificateTarget` atomically in one transaction.

---

## 8. Open Items

- **Error HTTP status codes** — `AgentPipelineMixin` currently maps all exceptions to 500. Differentiate authentication/authorisation failures (401/403) from validation failures (400) by catching typed errors or inspecting `ctx.http_response_status` before calling `error_responder`.
- **Issued credential linking** — after `CertificateIssueProcessor` completes, the resulting `IssuedCredentialModel` should be linked back to the `AgentJob` (add an optional FK `AgentJob.issued_credential`) so the issued certificate appears in the standard certificate inventory and expiry tracking works out-of-the-box.
- **Duplicate job guard** — if the agent calls check-in while a `PENDING_CSR` or `IN_PROGRESS` job already exists for a target, skip re-creating it. Add a check in `WbmCheckInProcessor._is_due()` or `_create_job()`.
- **Notifications** — hook `AgentJob` close (succeeded / failed) into the existing `notifications` app.
- **Agent certificate issuance** — integrate `TrustpointAgent` registration with the existing Trustpoint cert issuance flow so `certificate_fingerprint` is populated automatically when an agent device is onboarded.
- **Liveness alerting** — alert when `TrustpointAgent.last_seen_at` exceeds a configurable threshold (e.g. `3 × poll_interval_seconds`).
- **`base_url` on targets** — `AgentCertificateTarget` currently has no `base_url` field; the WBM device address must be embedded in the workflow profile or added as a dedicated field.
- **`SlotPurpose` / slot identifier** — the `purpose` and `slot` fields from the original concept are not present on `AgentCertificateTarget`. Multi-slot devices require either multiple targets or extending the model.
- **Adding a second capability** — create `agents/firmware/` mirroring `agents/wbm/`: define a `FirmwareAgentRequestContext(AgentRequestContext)`, implement capability-specific parsers/processors/responders, subclass `AgentPipelineMixin` with `context_class = FirmwareAgentRequestContext`. The generic authentication, active-check, and pipeline runner require zero changes.
- **Generic job base model** — once a second capability is implemented, extract `AbstractAgentJob` (status, started_at, completed_at, result_detail, agent FK) so each feature only adds its domain fields.
