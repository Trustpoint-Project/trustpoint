"""Models for the agents application."""

from __future__ import annotations

from datetime import datetime, timedelta
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

class TrustpointAgent(models.Model):
    """A registered automation agent deployed inside a production cell."""

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

    certificate_fingerprint = models.CharField(
        verbose_name=_('Certificate Fingerprint (SHA-256)'),
        max_length=64,
        unique=True,
        help_text=_(
            "SHA-256 fingerprint of the agent's mTLS client certificate. "
            'Revoke the cert to decommission the agent at the TLS layer.'
        ),
    )

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
        """Validate device FK constraints based on the device type."""
        if self.device_id is None:
            return

        from devices.models import DeviceModel  # noqa: PLC0415

        device = DeviceModel.objects.filter(pk=self.device_id).first()
        if device is None:
            raise ValidationError({'device': 'Selected device does not exist.'})

        _agent_types = (
            DeviceModel.DeviceType.AGENT_ONE_TO_ONE,
            DeviceModel.DeviceType.AGENT_ONE_TO_N,
            DeviceModel.DeviceType.AGENT_MANAGED_DEVICE,
        )
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
    """A reusable automation workflow for a specific device family or firmware variant."""

    name = models.CharField(
        verbose_name=_('Name'),
        max_length=200,
        unique=True,
        help_text=_('Unique identifier for this workflow definition.'),
    )
    profile = models.JSONField(
        verbose_name=_('Workflow Profile'),
        help_text=_(
            'JSON object containing device metadata and automation steps. '
            'Metadata fields: vendor, device_family, firmware_hint, version, description. '
            'Steps array contains typed automation steps.'
        ),
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

        verbose_name = _('Agent Workflow Definition')
        verbose_name_plural = _('Agent Workflow Definitions')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'AgentWorkflowDefinition({self.name})'

    def clean(self) -> None:
        """Validate the workflow profile against the step schema."""
        if not isinstance(self.profile, dict):
            raise ValidationError({'profile': 'Profile must be a JSON object.'})

        steps = self.profile.get('steps', [])
        try:
            jsonschema.validate(steps, WORKFLOW_STEP_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ValidationError({'profile': f'Steps validation error: {exc.message}'}) from exc


# ---------------------------------------------------------------------------
# AgentAssignedProfile
# ---------------------------------------------------------------------------

class AgentAssignedProfile(models.Model):
    """Links a workflow profile to an agent with per-assignment renewal settings."""

    agent = models.ForeignKey(
        'agents.TrustpointAgent',
        verbose_name=_('Agent'),
        on_delete=models.CASCADE,
        related_name='assigned_profiles',
        help_text=_('The 1-to-1 agent this profile is assigned to.'),
    )
    workflow_definition = models.ForeignKey(
        'agents.AgentWorkflowDefinition',
        verbose_name=_('Agent Profile'),
        on_delete=models.PROTECT,
        related_name='assigned_to',
        help_text=_('The workflow / renewal profile applied to this agent.'),
    )
    renewal_threshold_days = models.PositiveIntegerField(
        verbose_name=_('Renewal Threshold (days)'),
        default=30,
        help_text=_(
            'Trustpoint will trigger certificate renewal when the currently '
            'issued certificate expires within this many days.'
        ),
    )
    last_certificate_update = models.DateTimeField(
        verbose_name=_('Last Certificate Update'),
        null=True,
        blank=True,
        help_text=_('Timestamp of the most recent successful certificate issuance for this profile.'),
    )
    next_certificate_update_scheduled = models.DateTimeField(
        verbose_name=_('Next Certificate Update'),
        null=True,
        blank=True,
        help_text=_(
            'Manually scheduled next renewal trigger time. '
            'Set to a past datetime to force immediate renewal, or a future datetime to delay it. '
            'Cleared automatically after the next successful certificate update.'
        ),
    )
    enabled = models.BooleanField(
        verbose_name=_('Enabled'),
        default=True,
        help_text=_('Disabled assignments are skipped during renewal scheduling.'),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta options for AgentAssignedProfile."""

        unique_together: ClassVar = [('agent', 'workflow_definition')]
        verbose_name = _('Agent Assigned Profile')
        verbose_name_plural = _('Agent Assigned Profiles')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'AgentAssignedProfile({self.agent.name} / {self.workflow_definition.name})'

    @property
    def next_certificate_update(self) -> datetime:
        """Return the datetime at which renewal should be triggered."""
        from django.utils import timezone  # noqa: PLC0415

        if self.next_certificate_update_scheduled is not None:
            return self.next_certificate_update_scheduled
        if self.last_certificate_update is not None:
            return self.last_certificate_update + timedelta(days=self.renewal_threshold_days)
        return timezone.now()

    def clean(self) -> None:
        """Validate that the linked agent has an associated device."""
        if self.agent_id is None:
            return

        agent: TrustpointAgent | None = (
            TrustpointAgent.objects.select_related('device').filter(pk=self.agent_id).first()
        )
        if agent is None or agent.device is None:
            raise ValidationError({
                'agent': 'The selected agent must have an associated device.'
            })
