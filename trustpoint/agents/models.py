# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Models for the agents application."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import ClassVar

import jsonschema
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from util.encrypted_fields import EncryptedJSONField

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
        'allOf': [
            {'if': {'properties': {'type': {'const': 'goto'}}}, 'then': {'required': ['url']}},
            {'if': {'properties': {'type': {'const': 'click'}}}, 'then': {'required': ['selector']}},
            {
                'if': {'properties': {'type': {'const': 'fill'}}},
                'then': {'required': ['selector', 'value']},
            },
            {
                'if': {'properties': {'type': {'const': 'uploadFile'}}},
                'then': {'required': ['selector', 'value']},
            },
            {'if': {'properties': {'type': {'const': 'waitFor'}}}, 'then': {'required': ['selector']}},
            {'if': {'properties': {'type': {'const': 'expect'}}}, 'then': {'required': ['text']}},
        ],
        'additionalProperties': False,
    },
}

_SECRET_PLACEHOLDER = re.compile(r'\{\{\s*secret:([A-Za-z0-9_.-]+)\s*\}\}')
_PASSWORD_SELECTOR = re.compile(r'password|passwd|passwort|pwd|secret|token', re.IGNORECASE)


def is_literal_password_step(step: dict[str, object]) -> bool:
    """Return whether a step fills a password field with a non-placeholder value."""
    selector = step.get('selector', '')
    value = step.get('value', '')
    return (
        step.get('type') == 'fill'
        and isinstance(selector, str)
        and bool(_PASSWORD_SELECTOR.search(selector))
        and not _SECRET_PLACEHOLDER.fullmatch(value.strip() if isinstance(value, str) else '')
    )


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
            'Stable identifier sent by the agent in every API request. '
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
            'Application certificates are issued to separate managed-device records.'
        ),
    )

    capabilities = models.JSONField(
        verbose_name=_('Capabilities'),
        default=list,
        blank=True,
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
        ),
    )
    os_path = models.CharField(
        verbose_name=_('OS Path'),
        max_length=255,
        default='/etc/trustpoint',
        blank=False,
        help_text=_(
            'The operating system path where the agent will store certificates and keys. '
            'Example: /etc/trustpoint or C:\\trustpoint'
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

    @property
    def is_authenticated(self) -> bool:
        """Allow DRF to treat an agent principal as authenticated for throttling."""
        return True

    @property
    def is_anonymous(self) -> bool:
        """An agent principal is never anonymous."""
        return False

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

        _agent_types = (DeviceModel.DeviceType.AGENT_ONE_TO_ONE,)
        if device.device_type not in _agent_types:
            raise ValidationError({'device': 'The associated device must be of an agent type.'})

        if device.device_type == DeviceModel.DeviceType.AGENT_ONE_TO_ONE:
            qs = TrustpointAgent.objects.filter(device=device)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                raise ValidationError({'device': 'A 1-to-1 agent device can only be associated with a single agent.'})


class AgentProfileDefinition(models.Model):
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
    secrets = EncryptedJSONField(
        verbose_name=_('Secret Values'),
        null=True,
        blank=True,
        default=None,
        help_text=_(
            'Optional JSON object of secret values, stored encrypted. '
            'Reference values from steps with {{ secret:name }}. Do not put passwords in the profile JSON.'
        ),
    )
    is_active = models.BooleanField(
        verbose_name=_('Active'),
        default=True,
        help_text=_(
            'Inactive definitions are hidden from selection and skipped by renewal scheduling, '
            'but preserved for audit purposes.'
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta options for AgentProfileDefinition."""

        verbose_name = _('Agent Profile Definition')
        verbose_name_plural = _('Agent Profile Definitions')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'AgentProfileDefinition({self.name})'

    def certificate_profile_name(self) -> str:
        """Return the certificate profile requested by this workflow."""
        if not isinstance(self.profile, dict):
            return 'domain_credential'
        cert_req = self.profile.get('certificate_request')
        if not isinstance(cert_req, dict):
            return 'domain_credential'
        name = cert_req.get('certificate_profile')
        return name if isinstance(name, str) and name else 'domain_credential'

    def clean(self) -> None:  # noqa: C901, PLR0912 - profile and secret validation are intentionally together.
        """Validate the workflow profile and its encrypted secret values."""
        if not isinstance(self.profile, dict):
            raise ValidationError({'profile': 'Profile must be a JSON object.'})

        for field in ('certificate_request', 'local_storage', 'metadata', 'device'):
            if field in self.profile and not isinstance(self.profile[field], dict):
                raise ValidationError({'profile': f'Profile field "{field}" must be a JSON object.'})

        if self.secrets is None:
            self.secrets = {}
        if not isinstance(self.secrets, dict):
            raise ValidationError({'secrets': 'Secret values must be a JSON object.'})
        for key, value in self.secrets.items():
            if not isinstance(key, str) or not key.strip():
                raise ValidationError({'secrets': 'Secret names must be non-empty strings.'})
            if not isinstance(value, str):
                raise ValidationError({'secrets': f'Secret value for "{key}" must be a string.'})

        steps = self.profile.get('steps', [])
        try:
            jsonschema.validate(steps, WORKFLOW_STEP_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ValidationError({'profile': f'Steps validation error: {exc.message}'}) from exc

        referenced_secrets: set[str] = set()
        for index, step in enumerate(steps):
            if is_literal_password_step(step):
                raise ValidationError(
                    {
                        'profile': (
                            f'Step {index} fills a password field. '
                            'Move the value to the encrypted Secret Values object and use {{ secret:name }}.'
                        )
                    }
                )
            for value in step.values():
                if isinstance(value, str):
                    referenced_secrets.update(_SECRET_PLACEHOLDER.findall(value))

        missing_secrets = sorted(referenced_secrets - set(self.secrets))
        if missing_secrets:
            raise ValidationError({'secrets': f'Missing secret values for: {", ".join(missing_secrets)}.'})


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
        'agents.AgentProfileDefinition',
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
    subject = models.CharField(
        verbose_name=_('Subject'),
        max_length=500,
        blank=True,
        help_text=_(
            'OpenSSL-style subject DN for the CSR, e.g., '
            '"/C=DE/ST=Berlin/L=Berlin/O=Example GmbH/OU=IT/CN=www.example.com". '
            'If empty, the agent will use a default subject.'
        ),
    )
    subject_alt_name = models.CharField(
        verbose_name=_('Subject Alternative Name'),
        max_length=1000,
        blank=True,
        help_text=_(
            'OpenSSL-style SAN extension, e.g., '
            '"DNS:www.example.com,DNS:example.com,DNS:api.example.com,IP:192.0.2.10". '
            'If empty, no SAN extension will be added.'
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
            'Replaced with the certificate-expiry-based schedule after the next successful update.'
        ),
    )
    claimed_at = models.DateTimeField(
        verbose_name=_('Claimed At'),
        null=True,
        blank=True,
        help_text=_('Set while an agent is executing this job. Expired claims are retried.'),
    )
    claim_token = models.UUIDField(
        verbose_name=_('Claim Token'),
        null=True,
        blank=True,
        editable=False,
        help_text=_('Token the agent must return when acknowledging the claimed job.'),
    )
    last_attempt_at = models.DateTimeField(
        verbose_name=_('Last Attempt'),
        null=True,
        blank=True,
        help_text=_('Timestamp of the most recent job execution attempt.'),
    )
    last_error = models.TextField(
        verbose_name=_('Last Error'),
        blank=True,
        default='',
        help_text=_('Most recent failure reported by the agent.'),
    )
    failure_count = models.PositiveIntegerField(
        verbose_name=_('Failure Count'),
        default=0,
        help_text=_('Consecutive failed attempts. Reset after a successful renewal.'),
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
        if self.next_certificate_update_scheduled is not None:
            return self.next_certificate_update_scheduled
        if self.last_certificate_update is not None:
            return self.last_certificate_update + timedelta(days=self.renewal_threshold_days)
        return timezone.now()

    def certificate_not_after(self) -> datetime | None:
        """Return the newest issued certificate expiry for this assignment's profile."""
        agent = self.agent
        device = agent.device
        if agent.device_id is None or device is None:
            return None
        certificate_profile = self.workflow_definition.certificate_profile_name()
        if certificate_profile == 'domain_credential' and device.domain is not None:
            certificate_profile = device.domain.get_domain_credential_profile_name()

        from pki.models import IssuedCredentialModel  # noqa: PLC0415

        credential = (
            IssuedCredentialModel.objects.filter(device_id=agent.device_id)
            .filter(
                Q(certificate_profile__unique_name=certificate_profile)
                | Q(certificate_profile__display_name=certificate_profile)
            )
            .select_related('credential__certificate')
            .order_by('-created_at')
            .first()
        )
        if credential is None or credential.credential.certificate is None:
            return None
        return credential.credential.certificate.not_valid_after

    def next_update_from_certificate(self, now: datetime | None = None) -> datetime | None:
        """Return the expiry-based renewal date, or ``None`` when no certificate exists."""
        current_time = now or timezone.now()
        not_after = self.certificate_not_after()
        if not_after is None:
            return None
        target = not_after - timedelta(days=max(int(self.renewal_threshold_days), 1))
        if target <= current_time:
            # A threshold at or above the certificate lifetime would otherwise renew on every poll.
            return current_time + timedelta(days=1)
        return target

    def clean(self) -> None:
        """Validate that the linked agent has an associated device and one domain credential."""
        if self.agent_id is None:
            return

        agent: TrustpointAgent | None = (
            TrustpointAgent.objects.select_related('device').filter(pk=self.agent_id).first()
        )
        if agent is None or agent.device is None:
            raise ValidationError({'agent': 'The selected agent must have an associated device.'})

        if (
            self.workflow_definition_id is not None
            and self.workflow_definition.certificate_profile_name() == 'domain_credential'
        ):
            other_assignments = (
                AgentAssignedProfile.objects.filter(agent_id=self.agent_id)
                .exclude(pk=self.pk)
                .select_related('workflow_definition')
                .defer('workflow_definition__secrets')
            )
            if any(
                assignment.workflow_definition.certificate_profile_name() == 'domain_credential'
                for assignment in other_assignments
            ):
                raise ValidationError({'workflow_definition': 'This agent already has a domain credential assignment.'})
