"""Models for the agents application.

Contains:
- TrustpointAgent: generic identity record for any automation agent
- WbmWorkflowDefinition: reusable Playwright-style automation profile
- WbmCertificateTarget: one certificate slot on a device WBM
- WbmJob: audit record for a single WBM certificate-push operation
"""

from __future__ import annotations

import jsonschema
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _


# ---------------------------------------------------------------------------
# Workflow step JSON schema — used by WbmWorkflowDefinition.clean()
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
        verbose_name = _('Trustpoint Agent')
        verbose_name_plural = _('Trustpoint Agents')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'TrustpointAgent({self.name} / {self.agent_id})'

    def clean(self) -> None:
        """Validate that all declared capabilities are known values."""
        valid = {c.value for c in TrustpointAgent.Capability}
        unknown = [c for c in self.capabilities if c not in valid]
        if unknown:
            raise ValidationError({'capabilities': f'Unknown capabilities: {unknown}'})


# ---------------------------------------------------------------------------
# WbmWorkflowDefinition
# ---------------------------------------------------------------------------

class WbmWorkflowDefinition(models.Model):
    """A reusable Playwright automation script for a specific device family or firmware variant."""

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
        help_text=_('JSON array of Playwright-style automation steps. Validated on save.'),
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
        unique_together = [('name', 'version')]
        verbose_name = _('WBM Workflow Definition')
        verbose_name_plural = _('WBM Workflow Definitions')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'WbmWorkflowDefinition({self.name} v{self.version})'

    def clean(self) -> None:
        """Validate the workflow profile against the step schema."""
        try:
            jsonschema.validate(self.profile, WORKFLOW_STEP_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ValidationError({'profile': exc.message}) from exc


# ---------------------------------------------------------------------------
# WbmCertificateTarget
# ---------------------------------------------------------------------------

class WbmCertificateTarget(models.Model):
    """A single certificate slot on a device WBM, with the workflow and agent responsible for updates."""

    class SlotPurpose(models.TextChoices):
        """Semantic purpose of the certificate slot."""

        TLS_SERVER = 'tls_server', _('TLS Server Certificate')
        TLS_CLIENT = 'tls_client', _('TLS Client Certificate')
        CA_BUNDLE = 'ca_bundle', _('CA / Trust-Store Bundle')
        OTHER = 'other', _('Other')

    device = models.ForeignKey(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.CASCADE,
        related_name='wbm_targets',
    )
    certificate_profile = models.ForeignKey(
        'pki.CertificateProfileModel',
        verbose_name=_('Certificate Profile'),
        on_delete=models.PROTECT,
        related_name='wbm_targets',
    )
    workflow = models.ForeignKey(
        'agents.WbmWorkflowDefinition',
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
        related_name='wbm_targets',
        help_text=_('The agent deployed in the production cell that can reach this device.'),
    )
    # WBM address as reachable from inside the cell — never accessed by Trustpoint directly.
    base_url = models.URLField(
        verbose_name=_('WBM Base URL'),
        help_text=_('e.g. https://192.168.1.10 — resolved by the agent, not by Trustpoint.'),
    )
    purpose = models.CharField(
        verbose_name=_('Slot Purpose'),
        max_length=20,
        choices=SlotPurpose,
        default=SlotPurpose.TLS_SERVER,
    )
    slot = models.CharField(
        verbose_name=_('Slot Identifier'),
        max_length=80,
        blank=True,
        default='',
        help_text=_("Optional device-specific slot name, e.g. 'slot0'."),
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
        unique_together = [('device', 'purpose', 'slot')]
        verbose_name = _('WBM Certificate Target')
        verbose_name_plural = _('WBM Certificate Targets')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'WbmCertificateTarget({self.device} — {self.purpose}/{self.slot} via {self.agent})'


# ---------------------------------------------------------------------------
# WbmJob
# ---------------------------------------------------------------------------

class WbmJob(models.Model):
    """Audit record for a single WBM certificate-push operation.

    Created by Trustpoint when the agent requests a push.
    Closed when the agent reports the result.
    """

    class Status(models.TextChoices):
        """Lifecycle state of the job."""

        PENDING_CSR = 'pending_csr', _('Pending CSR')
        IN_PROGRESS = 'in_progress', _('In Progress')
        SUCCEEDED = 'succeeded', _('Succeeded')
        FAILED = 'failed', _('Failed')

    target = models.ForeignKey(
        'agents.WbmCertificateTarget',
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
        verbose_name = _('WBM Job')
        verbose_name_plural = _('WBM Jobs')

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f'WbmJob({self.pk} {self.status} → {self.target})'
