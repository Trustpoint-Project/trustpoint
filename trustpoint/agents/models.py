"""Models for the agents application.

Contains:
- TrustpointAgent: generic identity record for any automation agent
- AgentWorkflowDefinition: reusable automation profile for executing jobs on managed devices
- AgentCertificateTarget: certificate target on a managed device
- AgentJob: audit record for a single agent certificate-provisioning operation
"""

from __future__ import annotations

from typing import ClassVar

import jsonschema
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

# ---------------------------------------------------------------------------
# Workflow step JSON schema — used by AgentWorkflowDefinition.clean()
# ---------------------------------------------------------------------------

WORKFLOW_STEP_SCHEMA = {
    'type': 'array',
    'items': {
        'type': 'object',
        'required': ['type'],
        'properties': {
            'type': {
                'type': 'string',
                'enum': [
                    'goto',
                    'click',
                    'fill',
                    'uploadFile',
                    'waitFor',
                    'expect',
                    'screenshot',
                    'reboot',
                ],
            },
            'selector': {'type': 'string'},
            'url': {'type': 'string'},
            'value': {'type': 'string'},
            'content': {'type': 'string'},
            'text': {'type': 'string'},
            'timeout_ms': {'type': 'integer', 'minimum': 0},
        },
        'additionalProperties': False,
    },
}


# ---------------------------------------------------------------------------
# TrustpointAgent
# ---------------------------------------------------------------------------

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
    ``WbmCertificateTarget.device``.  Application certificates are issued to
    those managed-device records, not to the agent device itself.
    """

    class Capability(models.TextChoices):
        """Known job types an agent may support. An agent may declare multiple."""

        WBM_CERT_PUSH = 'wbm_cert_push', _('WBM Certificate Push')

    name = models.CharField(
        verbose_name=_('Name'),
        max_length=120,
        unique=True,
        help_text=_("Human-readable name, e.g. 'Cell A Agent 1'."),
    )
    agent_id = models.CharField(
        verbose_name=_('Agent ID'),
        max_length=120,
        unique=True,
        help_text=_(
            "Stable identifier sent by the agent in every API request. "
            "Must match AGENT_ID in the agent's runtime config."
        ),
    )
    # The DeviceModel this agent is registered against.
    # For AGENT_ONE_TO_ONE: the device IS the agent — it owns the domain credential
    # and all application certificates.  Only one TrustpointAgent may link to it.
    # For AGENT_ONE_TO_N: the device represents the agent process only and carries
    # exclusively the domain credential.  Managed devices are referenced via
    # WbmCertificateTarget.device (must be AGENT_MANAGED_DEVICE, not this record).
    device = models.ForeignKey(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.PROTECT,
        related_name='agents',
        null=True,
        blank=True,
        help_text=_(
            'For 1-to-1 agents: the device that IS the agent (standalone). '
            'For 1-to-n agents: the agent-process device that holds only the domain credential. '
            'Application certificates are issued to separate managed-device records.'
        ),
    )
    # SHA-256 fingerprint (hex, uppercase, no colons) of the mTLS client certificate
    # issued to this agent by Trustpoint. Verified on every REST API request.
    # Updated automatically when a new agent cert is issued via the registration flow.
    certificate_fingerprint = models.CharField(
        verbose_name=_('Certificate Fingerprint (SHA-256)'),
        max_length=64,
        unique=True,
        help_text=_(
            "SHA-256 fingerprint of the agent's mTLS client certificate. "
            'Revoke the cert to decommission the agent at the TLS layer.'
        ),
    )
    # JSON array of Capability values, e.g. ["wbm_cert_push"].
    # JSONField keeps us SQLite-compatible (ArrayField requires PostgreSQL).
    capabilities = models.JSONField(
        verbose_name=_('Capabilities'),
        default=list,
        help_text=_(
            'List of job types this agent supports, e.g. ["wbm_cert_push"]. '
            'Used for display and validation; does not restrict API access at runtime.'
        ),
    )
    cell_location = models.CharField(
        verbose_name=_('Cell Location'),
        max_length=200,
        blank=True,
        help_text=_("Free-text description of the production cell, e.g. 'Building 3 / Cell A'."),
    )
    is_active = models.BooleanField(
        verbose_name=_('Active'),
        default=True,
        help_text=_('Inactive agents are rejected by the API even if their certificate is still valid.'),
    )
    poll_interval_seconds = models.PositiveIntegerField(
        verbose_name=_('Poll Interval (seconds)'),
        default=300,
        help_text=_(
            'How often this agent should call the check-in endpoint. '
            'Returned in every check-in response so the agent self-configures. '
            'Lower values increase responsiveness; higher values reduce server load.'
        ),
    )
    last_seen_at = models.DateTimeField(
        verbose_name=_('Last Seen'),
        null=True,
        blank=True,
        help_text=_('Updated on every authenticated API call. Use for liveness monitoring.'),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta options for TrustpointAgent."""

        verbose_name = _('Trustpoint Agent')
        verbose_name_plural = _('Trustpoint Agents')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'TrustpointAgent({self.name} / {self.agent_id})'

    def clean(self) -> None:
        """Validate that all declared capabilities are known values and enforce device-type constraints."""
        valid = {c.value for c in TrustpointAgent.Capability}
        unknown = [c for c in self.capabilities if c not in valid]
        if unknown:
            raise ValidationError({'capabilities': f'Unknown capabilities: {unknown}'})

        self._validate_device_association()

    def _validate_device_association(self) -> None:
        """Validate device FK constraints based on the device type.

        - The linked device must be of an agent type.
        - For AGENT_ONE_TO_ONE devices only one TrustpointAgent may be linked.
        """
        if self.device_id is None:
            return

        from devices.models import DeviceModel  # noqa: PLC0415

        device = DeviceModel.objects.filter(pk=self.device_id).first()
        if device is None:
            raise ValidationError({'device': 'Selected device does not exist.'})

        _agent_types = (DeviceModel.DeviceType.AGENT_ONE_TO_ONE, DeviceModel.DeviceType.AGENT_ONE_TO_N)
        if device.device_type not in _agent_types:
            raise ValidationError({'device': 'The associated device must be of an agent type.'})

        if device.device_type == DeviceModel.DeviceType.AGENT_ONE_TO_ONE:
            qs = TrustpointAgent.objects.filter(device=device)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                raise ValidationError(
                    {'device': 'A 1-to-1 agent device can only be associated with a single agent.'}
                )


# ---------------------------------------------------------------------------
# AgentWorkflowDefinition
# ---------------------------------------------------------------------------

class AgentWorkflowDefinition(models.Model):
    """A reusable automation workflow for a specific device family or firmware variant.

    Defines how the agent should interact with a managed device — for example
    via its Web-Based Management (WBM) interface — in order to push a
    certificate.  The workflow is expressed as a JSON array of typed steps
    (e.g. ``goto``, ``click``, ``fill``, ``uploadFile``) and is validated
    against :data:`WORKFLOW_STEP_SCHEMA` on save.

    Workflows are intentionally decoupled from credentials and device
    identities so that one definition can be reused across many targets.
    """

    name = models.CharField(verbose_name=_('Name'), max_length=200)
    vendor = models.CharField(verbose_name=_('Vendor'), max_length=120, blank=True)
    device_family = models.CharField(verbose_name=_('Device Family'), max_length=120, blank=True)
    firmware_hint = models.CharField(
        verbose_name=_('Firmware Hint'),
        max_length=120,
        blank=True,
        help_text=_('Optional firmware version string to help operators select the right profile.'),
    )
    version = models.CharField(verbose_name=_('Version'), max_length=40, default='1.0')
    description = models.TextField(verbose_name=_('Description'), blank=True)
    profile = models.JSONField(
        verbose_name=_('Workflow Profile'),
        help_text=_('JSON array of typed automation steps. Validated on save.'),
    )
    is_active = models.BooleanField(
        verbose_name=_('Active'),
        default=True,
        help_text=_(
            'Inactive definitions are hidden from selection but preserved for audit purposes.'
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta options for AgentWorkflowDefinition."""

        unique_together: ClassVar = [('name', 'version')]
        verbose_name = _('Agent Workflow Definition')
        verbose_name_plural = _('Agent Workflow Definitions')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'AgentWorkflowDefinition({self.name} v{self.version})'

    def clean(self) -> None:
        """Validate the workflow profile against the step schema."""
        try:
            jsonschema.validate(self.profile, WORKFLOW_STEP_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ValidationError({'profile': exc.message}) from exc


# ---------------------------------------------------------------------------
# AgentCertificateTarget
# ---------------------------------------------------------------------------

class AgentCertificateTarget(models.Model):
    """A certificate target on a *managed* device.

    Each target represents one certificate that the agent should keep
    provisioned on a managed device.  The agent reaches the device over the
    network (e.g. via its WBM interface) and pushes the certificate using the
    linked workflow.

    **Device ownership rules:**

    - For a 1-to-n agent (``AGENT_ONE_TO_N``): ``device`` must be of type
      ``AGENT_MANAGED_DEVICE`` — never the agent's own ``DeviceModel``.  All
      application certificates are issued to this managed-device record.
    - For a 1-to-1 agent (``AGENT_ONE_TO_ONE``): ``device`` must be the agent's
      own ``DeviceModel`` (the agent IS the device).
    """

    device = models.ForeignKey(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.CASCADE,
        related_name='agent_targets',
        help_text=_(
            'The managed device that owns this certificate target. '
            'For 1-to-n agents this must be an Agent Managed Device, not the agent device itself. '
            "For 1-to-1 agents this must be the agent's own device."
        ),
    )
    certificate_profile = models.ForeignKey(
        'pki.CertificateProfileModel',
        verbose_name=_('Certificate Profile'),
        on_delete=models.PROTECT,
        related_name='agent_targets',
    )
    workflow = models.ForeignKey(
        'agents.AgentWorkflowDefinition',
        verbose_name=_('Workflow Definition'),
        on_delete=models.PROTECT,
        related_name='targets',
    )
    # The agent responsible for executing pushes to this target.
    # PROTECT prevents accidental deletion of an agent that still owns active targets.
    agent = models.ForeignKey(
        'agents.TrustpointAgent',
        verbose_name=_('Agent'),
        on_delete=models.PROTECT,
        related_name='agent_targets',
        help_text=_('The agent deployed in the production cell that can reach this device.'),
    )
    enabled = models.BooleanField(verbose_name=_('Enabled'), default=True)
    renewal_threshold_days = models.PositiveIntegerField(
        verbose_name=_('Renewal Threshold (days)'),
        default=30,
        help_text=_(
            "Trustpoint will include this target in the agent's check-in response when the "
            'currently issued certificate expires within this many days. Set to 0 to only push '
            'when explicitly triggered by an operator.'
        ),
    )
    push_requested = models.BooleanField(
        verbose_name=_('Push Requested'),
        default=False,
        help_text=_(
            "Set to True by the operator ('push now') to force a push on the next check-in, "
            'regardless of the certificate expiry window. Cleared automatically once the agent '
            'picks up the job.'
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta options for AgentCertificateTarget."""

        unique_together: ClassVar = [('device', 'agent', 'certificate_profile')]
        verbose_name = _('Agent Certificate Target')
        verbose_name_plural = _('Agent Certificate Targets')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'AgentCertificateTarget({self.device} via {self.agent})'

    def clean(self) -> None:
        """Validate device-ownership rules based on the linked agent type.

        - 1-to-n agent (AGENT_ONE_TO_N): ``device`` must be of type
          AGENT_MANAGED_DEVICE, never the agent's own DeviceModel.
          Application certificates are issued to the managed-device record,
          not to the agent device.
        - 1-to-1 agent (AGENT_ONE_TO_ONE): ``device`` must be the agent's own
          DeviceModel (the agent IS the device).
        """
        from devices.models import DeviceModel  # noqa: PLC0415

        if self.agent_id is None or self.device_id is None:
            return

        agent: TrustpointAgent | None = (
            TrustpointAgent.objects.select_related('device').filter(pk=self.agent_id).first()
        )
        if agent is None or agent.device is None:
            return

        device: DeviceModel | None = DeviceModel.objects.filter(pk=self.device_id).first()
        if device is None:
            return

        if agent.device.device_type == DeviceModel.DeviceType.AGENT_ONE_TO_N:
            if device.pk == agent.device.pk:
                raise ValidationError({
                    'device': (
                        'For a 1-to-n agent the target device must be an Agent Managed Device, '
                        'not the agent device itself.'
                    )
                })
            if device.device_type != DeviceModel.DeviceType.AGENT_MANAGED_DEVICE:
                raise ValidationError({
                    'device': (
                        'For a 1-to-n agent the target device must be of type Agent Managed Device.'
                    )
                })

        elif agent.device.device_type == DeviceModel.DeviceType.AGENT_ONE_TO_ONE:
            if device.pk != agent.device.pk:
                raise ValidationError({
                    'device': (
                        "For a 1-to-1 agent the target device must be the agent's own device."
                    )
                })


# ---------------------------------------------------------------------------
# AgentJob
# ---------------------------------------------------------------------------

class AgentJob(models.Model):
    """Audit record for a single agent certificate-provisioning operation.

    Created by Trustpoint when the agent requests to push a certificate to
    a managed device.  Closed when the agent reports the result.
    """

    class Status(models.TextChoices):
        """Lifecycle state of the job."""

        PENDING_CSR = 'pending_csr', _('Pending CSR')
        IN_PROGRESS = 'in_progress', _('In Progress')
        SUCCEEDED = 'succeeded', _('Succeeded')
        FAILED = 'failed', _('Failed')

    target = models.ForeignKey(
        'agents.AgentCertificateTarget',
        verbose_name=_('Certificate Target'),
        on_delete=models.CASCADE,
        related_name='jobs',
    )
    status = models.CharField(
        verbose_name=_('Status'),
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
        verbose_name=_('Key Spec'),
        max_length=40,
        default='EC_P256',
        help_text=_("Algorithm and size for key generation, e.g. 'EC_P256', 'RSA_2048'."),
    )
    subject = models.JSONField(
        verbose_name=_('Subject'),
        default=dict,
        help_text=_(
            'X.509 subject attributes to embed in the CSR, '
            'e.g. {"CN": "device.example.com", "O": "Acme"}.'
        ),
    )
    csr_pem = models.TextField(
        verbose_name=_('CSR (PEM)'),
        blank=True,
        help_text=_('Stored after the agent submits the CSR, before the cert is issued.'),
    )
    cert_pem = models.TextField(verbose_name=_('Certificate (PEM)'), blank=True)
    ca_bundle_pem = models.TextField(verbose_name=_('CA Bundle (PEM)'), blank=True)

    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    result_detail = models.TextField(verbose_name=_('Result Detail'), blank=True)

    class Meta:
        """Meta options for AgentJob."""

        verbose_name = _('Agent Job')
        verbose_name_plural = _('Agent Jobs')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'AgentJob({self.pk} {self.status} → {self.target})'
