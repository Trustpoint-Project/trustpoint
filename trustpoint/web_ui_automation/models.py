# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Database models for Web UI certificate-management automation."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta

from appsecrets.service import decrypt_app_secret, encrypt_app_secret
from onboarding.enums import OnboardingStatus
from pki.models.cert_profile import CertificateProfileModel
from web_ui_automation.schema import (
    calculate_profile_checksum,
    get_certificate_profile_slug,
    profile_supports_operation,
    validate_profile_schema,
)

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser
    from django.db.models.manager import RelatedManager  # type: ignore[attr-defined]

    from pki.models.certificate import CertificateModel


class AuthenticationType(models.TextChoices):
    """Authentication methods supported in the first implementation phase."""

    HTTP_BASIC = 'HTTP_BASIC', _('HTTP Basic Authentication')
    FORM_LOGIN = 'FORM_LOGIN', _('Form-based Login')


class RenewalMode(models.TextChoices):
    """Automatic certificate-renewal scheduling modes."""

    INTERVAL = 'INTERVAL', _('Fixed Interval')
    BEFORE_EXPIRY = 'BEFORE_EXPIRY', _('Before Expiry')


class AutomationOperation(models.TextChoices):
    """Operations executed through a Web UI profile."""

    ONBOARD = 'onboard', _('Onboard')
    RENEW = 'renew', _('Renew')
    INVENTORY = 'inventory', _('Inventory')


class JobStatus(models.TextChoices):
    """Lifecycle states of an automation job."""

    QUEUED = 'QUEUED', _('Queued')
    RUNNING = 'RUNNING', _('Running')
    AWAITING_CONFIRMATION = 'AWAITING_CONFIRMATION', _('Awaiting Confirmation')
    COMPLETED = 'COMPLETED', _('Completed')
    FAILED = 'FAILED', _('Failed')


class JobResult(models.TextChoices):
    """Technical outcomes of an automation job."""

    NONE = 'NONE', _('No Result')
    SUCCESSFUL = 'SUCCESSFUL', _('Successful')
    PARTIALLY_SUCCESSFUL = 'PARTIALLY_SUCCESSFUL', _('Partially Successful')
    FAILED = 'FAILED', _('Failed')


class VerificationStatus(models.TextChoices):
    """Verification outcomes recorded for an automation job."""

    NOT_CONFIGURED = 'NOT_CONFIGURED', _('Not Configured')
    PASSED = 'PASSED', _('Passed')
    PARTIAL = 'PARTIAL', _('Partially Passed')
    FAILED = 'FAILED', _('Failed')


class StepStatus(models.TextChoices):
    """Outcomes recorded for an individual automation step."""

    RUNNING = 'RUNNING', _('Running')
    SUCCESSFUL = 'SUCCESSFUL', _('Successful')
    SKIPPED = 'SKIPPED', _('Skipped')
    FAILED = 'FAILED', _('Failed')


class WebUiAutomationDevice(models.Model):
    """Web UI automation configuration linked to a Trustpoint device."""

    device = models.OneToOneField(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.PROTECT,
        related_name='web_ui_automation',
        help_text=_('The Trustpoint device managed through Web UI automation.'),
    )
    base_url = models.URLField(
        verbose_name=_('Base URL'),
        help_text=_('Base URL of the device management interface, e.g. https://192.168.1.10:8443.'),
    )
    authentication_type = models.CharField(
        verbose_name=_('Authentication Type'),
        max_length=30,
        choices=AuthenticationType.choices,
    )
    encrypted_username = models.TextField(verbose_name=_('Encrypted Username'), editable=False)
    encrypted_password = models.TextField(verbose_name=_('Encrypted Password'), editable=False)
    encrypted_private_key_password = models.TextField(
        verbose_name=_('Encrypted Private-Key Password'),
        editable=False,
        blank=True,
        default='',
    )
    credentials_updated_at = models.DateTimeField(
        verbose_name=_('Credentials Updated At'),
        null=True,
        blank=True,
        editable=False,
    )
    created_at = models.DateTimeField(verbose_name=_('Created At'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated At'), auto_now=True)

    if TYPE_CHECKING:
        assigned_profiles: RelatedManager[WebUiAutomationAssignedProfile]

    class Meta(TypedModelMeta):
        """Meta configuration for WebUiAutomationDevice."""

        ordering: ClassVar[list[str]] = ['device__common_name']
        verbose_name = _('Web UI Automation Device')
        verbose_name_plural = _('Web UI Automation Devices')

    def __str__(self) -> str:
        """Return a human-readable device configuration name."""
        return self.device.common_name if self.device else str(_('Unnamed Device'))

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save the configuration and disable renewal after endpoint changes."""
        old_base_url = ''
        if self.pk:
            old_base_url = type(self).objects.filter(pk=self.pk).values_list('base_url', flat=True).first() or ''
        super().save(*args, **kwargs)
        if old_base_url and old_base_url != self.base_url:
            self.assigned_profiles.filter(automatic_renewal_enabled=True).update(automatic_renewal_enabled=False)

    def clean(self) -> None:
        """Validate and normalize the device base URL."""
        super().clean()
        self.base_url = self.base_url.rstrip('/')

    def set_credentials(self, username: str, password: str, private_key_password: str = '') -> None:
        """Encrypt and store the shared device credential set."""
        self.encrypted_username = encrypt_app_secret(username)
        self.encrypted_password = encrypt_app_secret(password)
        self.encrypted_private_key_password = (
            encrypt_app_secret(private_key_password) if private_key_password else ''
        )
        self.credentials_updated_at = timezone.now()
        self.save(
            update_fields=[
                'encrypted_username',
                'encrypted_password',
                'encrypted_private_key_password',
                'credentials_updated_at',
                'updated_at',
            ]
        )
        self.assigned_profiles.filter(automatic_renewal_enabled=True).update(automatic_renewal_enabled=False)

    def get_username(self) -> str:
        """Decrypt and return the configured username."""
        return decrypt_app_secret(self.encrypted_username)

    def get_password(self) -> str:
        """Decrypt and return the configured password."""
        return decrypt_app_secret(self.encrypted_password)

    def get_private_key_password(self) -> str:
        """Decrypt and return the optional private-key password."""
        if not self.encrypted_private_key_password:
            return ''
        return decrypt_app_secret(self.encrypted_private_key_password)


class WebUiAutomationProfileDefinition(models.Model):
    """Reusable Web UI automation workflow for a device family or firmware variant."""

    name = models.CharField(
        verbose_name=_('Name'),
        max_length=200,
        unique=True,
        help_text=_('Unique identifier for this automation workflow definition.'),
    )
    profile = models.JSONField(
        verbose_name=_('Automation Profile'),
        help_text=_('JSON profile containing metadata, named paths, operations, steps, and postconditions.'),
    )
    checksum = models.CharField(verbose_name=_('Checksum'), max_length=64, editable=False, blank=True)
    created_at = models.DateTimeField(verbose_name=_('Created At'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated At'), auto_now=True)

    if TYPE_CHECKING:
        assigned_to: RelatedManager[WebUiAutomationAssignedProfile]

    class Meta(TypedModelMeta):
        """Meta configuration for WebUiAutomationProfileDefinition."""

        ordering: ClassVar[list[str]] = ['name']
        verbose_name = _('Web UI Automation Profile')
        verbose_name_plural = _('Web UI Automation Profiles')

    def __str__(self) -> str:
        """Return the unique profile name."""
        return self.name

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Store the checksum and disable renewal when an assigned profile changes."""
        old_checksum = ''
        if self.pk:
            old_checksum = type(self).objects.filter(pk=self.pk).values_list('checksum', flat=True).first() or ''
        self.checksum = calculate_profile_checksum(self.profile)
        super().save(*args, **kwargs)
        if old_checksum and old_checksum != self.checksum:
            self.assigned_to.filter(automatic_renewal_enabled=True).update(automatic_renewal_enabled=False)

    @property
    def certificate_profile_slug(self) -> str:
        """Return the referenced Trustpoint certificate-profile slug."""
        return get_certificate_profile_slug(self.profile)

    def clean(self) -> None:
        """Validate JSON schema and the referenced Trustpoint certificate profile."""
        super().clean()
        if not isinstance(self.profile, dict):
            raise ValidationError({'profile': _('The automation profile must be a JSON object.')})
        validate_profile_schema(self.profile)
        if not CertificateProfileModel.objects.filter(unique_name=self.certificate_profile_slug).exists():
            raise ValidationError(
                {'profile': _('Certificate profile "%(slug)s" does not exist.') % {
                    'slug': self.certificate_profile_slug,
                }}
            )

    def validate_before_execution(self) -> None:
        """Repeat schema and certificate-profile validation before job execution."""
        self.clean()


class WebUiAutomationAssignedProfile(models.Model):
    """Assign one automation profile and one credential lifecycle to a device."""

    automation_device = models.ForeignKey(
        WebUiAutomationDevice,
        verbose_name=_('Web UI Automation Device'),
        on_delete=models.CASCADE,
        related_name='assigned_profiles',
    )
    workflow_definition = models.ForeignKey(
        WebUiAutomationProfileDefinition,
        verbose_name=_('Automation Profile'),
        on_delete=models.PROTECT,
        related_name='assigned_to',
    )
    issued_credential = models.OneToOneField(
        'pki.IssuedCredentialModel',
        verbose_name=_('Issued Credential'),
        on_delete=models.PROTECT,
        related_name='web_ui_automation_assignment',
        null=True,
        blank=True,
    )
    onboarding_status = models.IntegerField(
        verbose_name=_('Onboarding Status'),
        choices=OnboardingStatus.choices,
        default=OnboardingStatus.PENDING,
    )
    enabled = models.BooleanField(
        verbose_name=_('Enabled'),
        default=True,
        help_text=_('Disabled assignments cannot be executed manually or automatically.'),
    )
    automatic_renewal_enabled = models.BooleanField(
        verbose_name=_('Automatic Renewal Enabled'),
        default=False,
    )
    renewal_mode = models.CharField(
        verbose_name=_('Renewal Mode'),
        max_length=30,
        choices=RenewalMode.choices,
        default=RenewalMode.BEFORE_EXPIRY,
    )
    renewal_days = models.PositiveIntegerField(
        verbose_name=_('Renewal Days'),
        default=30,
        validators=[MinValueValidator(1)],
        help_text=_(
            'For before-expiry mode, renew when this many days remain. '
            'For interval mode, renew this many days after the last successful update.'
        ),
    )
    last_certificate_update = models.DateTimeField(
        verbose_name=_('Last Certificate Update'),
        null=True,
        blank=True,
    )
    next_certificate_update_scheduled = models.DateTimeField(
        verbose_name=_('Next Certificate Update'),
        null=True,
        blank=True,
        help_text=_('Optional one-time scheduling override. This takes precedence over the calculated date.'),
    )
    confirmed_profile_checksum = models.CharField(
        verbose_name=_('Confirmed Profile Checksum'),
        max_length=64,
        blank=True,
    )
    created_at = models.DateTimeField(verbose_name=_('Created At'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated At'), auto_now=True)

    if TYPE_CHECKING:
        jobs: RelatedManager[WebUiAutomationJob]

    class Meta(TypedModelMeta):
        """Meta configuration for WebUiAutomationAssignedProfile."""

        ordering: ClassVar[list[str]] = ['automation_device__device__common_name', 'workflow_definition__name']
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['automation_device', 'workflow_definition'],
                name='unique_webui_profile_per_device',
            )
        ]
        verbose_name = _('Assigned Web UI Automation Profile')
        verbose_name_plural = _('Assigned Web UI Automation Profiles')

    def __str__(self) -> str:
        """Return a readable device and profile assignment name."""
        return f'{self.automation_device} - {self.workflow_definition}'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Ensure that disabling an assignment also disables automatic renewal."""
        if not self.enabled:
            self.automatic_renewal_enabled = False
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validate credential ownership and automatic-renewal eligibility."""
        super().clean()
        if (self.issued_credential_id and self.issued_credential
                and self.issued_credential.device_id != self.automation_device.device_id):
            raise ValidationError({'issued_credential': _('The issued credential belongs to another device.')})
        if not self.enabled and self.automatic_renewal_enabled:
            raise ValidationError({'automatic_renewal_enabled': _('A disabled assignment cannot renew automatically.')})
        if self.automatic_renewal_enabled:
            self.validate_automatic_renewal_eligibility()

    @property
    def current_certificate(self) -> CertificateModel | None:
        """Return the certificate currently referenced by the managed credential."""
        if not self.issued_credential_id or not self.issued_credential:
            return None
        return self.issued_credential.credential.certificate

    @property
    def next_certificate_update(self) -> datetime.datetime | None:
        """Return the effective next renewal date, including a manual override."""
        if self.next_certificate_update_scheduled:
            return self.next_certificate_update_scheduled
        if self.renewal_mode == RenewalMode.INTERVAL:
            if not self.last_certificate_update:
                return None
            return self.last_certificate_update + datetime.timedelta(days=self.renewal_days)
        certificate = self.current_certificate
        if certificate is None:
            return None
        return certificate.not_valid_after - datetime.timedelta(days=self.renewal_days)

    @property
    def is_due_for_renewal(self) -> bool:
        """Return whether the assignment is currently due for renewal."""
        next_update = self.next_certificate_update
        return next_update is not None and next_update <= timezone.now()

    def validate_automatic_renewal_eligibility(self) -> None:
        """Raise ValidationError if the assignment cannot renew automatically."""
        errors: list[str] = []
        if self.onboarding_status != OnboardingStatus.ONBOARDED:
            errors.append(str(_('The assignment has not been onboarded.')))
        if not self.issued_credential_id:
            errors.append(str(_('The assignment has no issued credential.')))
        if not profile_supports_operation(self.workflow_definition.profile, AutomationOperation.RENEW):
            errors.append(str(_('The profile does not define a renewal operation.')))
        if self.confirmed_profile_checksum != self.workflow_definition.checksum:
            errors.append(str(_('The current profile has not been confirmed by a manual execution.')))
        if errors:
            raise ValidationError({'automatic_renewal_enabled': errors})

    def disable_automatic_renewal(self) -> None:
        """Disable unattended renewal without disabling the complete assignment."""
        if self.automatic_renewal_enabled:
            self.automatic_renewal_enabled = False
            self.save(update_fields=['automatic_renewal_enabled', 'updated_at'])


class WebUiAutomationJob(models.Model):
    """Immutable execution request and result for one profile operation."""

    assignment = models.ForeignKey(
        WebUiAutomationAssignedProfile,
        verbose_name=_('Assigned Profile'),
        on_delete=models.CASCADE,
        related_name='jobs',
    )
    operation = models.CharField(
        verbose_name=_('Operation'),
        max_length=20,
        choices=AutomationOperation.choices,
    )
    status = models.CharField(
        verbose_name=_('Status'),
        max_length=30,
        choices=JobStatus.choices,
        default=JobStatus.QUEUED,
    )
    result = models.CharField(
        verbose_name=_('Result'),
        max_length=30,
        choices=JobResult.choices,
        default=JobResult.NONE,
    )
    verification_status = models.CharField(
        verbose_name=_('Verification Status'),
        max_length=30,
        choices=VerificationStatus.choices,
        default=VerificationStatus.NOT_CONFIGURED,
    )
    profile_snapshot = models.JSONField(verbose_name=_('Profile Snapshot'))
    profile_checksum = models.CharField(verbose_name=_('Profile Checksum'), max_length=64)
    candidate_certificate = models.ForeignKey(
        'pki.CertificateModel',
        verbose_name=_('Candidate Certificate'),
        on_delete=models.PROTECT,
        related_name='web_ui_automation_jobs',
        null=True,
        blank=True,
    )
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_('Initiated By'),
        on_delete=models.SET_NULL,
        related_name='web_ui_automation_jobs',
        null=True,
        blank=True,
    )
    is_automatic = models.BooleanField(verbose_name=_('Automatic Job'), default=False)
    failed_step_id = models.CharField(verbose_name=_('Failed Step ID'), max_length=120, blank=True)
    failure_category = models.CharField(verbose_name=_('Failure Category'), max_length=80, blank=True)
    error_message = models.TextField(verbose_name=_('Error Message'), blank=True)
    started_at = models.DateTimeField(verbose_name=_('Started At'), null=True, blank=True)
    finished_at = models.DateTimeField(verbose_name=_('Finished At'), null=True, blank=True)
    created_at = models.DateTimeField(verbose_name=_('Created At'), auto_now_add=True)

    if TYPE_CHECKING:
        initiated_by: AbstractBaseUser | None  # type: ignore[no-redef]
        step_logs: RelatedManager[WebUiAutomationStepLog]

    class Meta(TypedModelMeta):
        """Meta configuration for WebUiAutomationJob."""

        ordering: ClassVar[list[str]] = ['-created_at']
        verbose_name = _('Web UI Automation Job')
        verbose_name_plural = _('Web UI Automation Jobs')

    def __str__(self) -> str:
        """Return a readable job description."""
        return f'{self.assignment} - {self.operation} ({self.status})'


class WebUiAutomationStepLog(models.Model):
    """Sanitized log entry for one profile step."""

    job = models.ForeignKey(
        WebUiAutomationJob,
        verbose_name=_('Job'),
        on_delete=models.CASCADE,
        related_name='step_logs',
    )
    sequence = models.PositiveIntegerField(verbose_name=_('Sequence'))
    step_id = models.CharField(verbose_name=_('Step ID'), max_length=120)
    action = models.CharField(verbose_name=_('Action'), max_length=80)
    status = models.CharField(
        verbose_name=_('Status'),
        max_length=20,
        choices=StepStatus.choices,
        default=StepStatus.RUNNING,
    )
    message = models.TextField(verbose_name=_('Message'), blank=True)
    details = models.JSONField(verbose_name=_('Details'), default=dict, blank=True)
    started_at = models.DateTimeField(verbose_name=_('Started At'), auto_now_add=True)
    finished_at = models.DateTimeField(verbose_name=_('Finished At'), null=True, blank=True)

    class Meta(TypedModelMeta):
        """Meta configuration for WebUiAutomationStepLog."""

        ordering: ClassVar[list[str]] = ['sequence']
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=['job', 'sequence'], name='unique_webui_step_sequence')
        ]
        verbose_name = _('Web UI Automation Step Log')
        verbose_name_plural = _('Web UI Automation Step Logs')

    def __str__(self) -> str:
        """Return a readable step log description."""
        return f'{self.job_id}:{self.sequence} {self.step_id}'



