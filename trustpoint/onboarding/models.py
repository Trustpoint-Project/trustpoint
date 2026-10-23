# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""This module contains models related to onboarding configurations."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import TYPE_CHECKING, ClassVar, cast

from django.apps import apps
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from devices.secrets import assign_secret, guard_configuration_save
from onboarding.enums import (
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.models.truststore import TruststoreModel
from util.encrypted_fields import EncryptedCharField

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Any

SCEP_CHALLENGE_BYTES = 32


__all__ = [
    'AbstractPkiProtocolModel',
    'NoOnboardingConfigModel',
    'NoOnboardingPkiProtocol',
    'OnboardingConfigModel',
    'OnboardingPkiProtocol',
    'OnboardingProtocol',
    'OnboardingStatus',
]


class AbstractPkiProtocolModel[T: models.IntegerChoices]:
    """Extends a model for IntegerChoices stored as bitwise flags."""

    pki_protocol_class: type[T]

    def add_pki_protocol(self, pki_protocol: T) -> None:
        """Adds the provided PkiProtocol to the allowed protocols for onboarded devices.

        Args:
            pki_protocol: The PkiProtocol to allow.
        """
        self.pki_protocols |= pki_protocol.value

    def remove_pki_protocol(self, pki_protocol: T) -> None:
        """Removes the provided PkiProtocol from the allowed protocols if it is allowed..

        Args:
            pki_protocol: The PkiProtocol to forbid.
        """
        self.pki_protocols &= ~pki_protocol

    def clear_pki_protocols(self) -> None:
        """Clears all allowed PkiProtocols, that is, it deactivates application certificate issuance."""
        self.pki_protocols = 0

    def has_pki_protocol(self, pki_protocol: T) -> bool:
        """Checks if the provided PkiProtocol is allowed.

        Args:
            pki_protocol: The PkiProtocol that is checked against the allowed ones.

        Returns:
            Returns True if the provided PkiProtocol is allowed, False otherwise.
        """
        return (self.pki_protocols & pki_protocol) == pki_protocol

    def get_pki_protocols(self) -> list[T]:
        """Gets all allowed PkiProtocols.

        Returns:
            Retruns the allowed PkiProtocols as list.
        """
        return [pki_protocol for pki_protocol in self.pki_protocol_class if self.has_pki_protocol(pki_protocol)]

    def set_pki_protocols(self, pki_protocols: list[T]) -> None:
        """Sets all allowed PkiProtocols exactly matching the provided list."""
        self.clear_pki_protocols()
        for pki_protocol in pki_protocols:
            self.add_pki_protocol(pki_protocol)


class DeviceSecretAssignmentLock(models.Model):
    """One shared writer lock for challenge uniqueness across both configuration tables."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)

    def __str__(self) -> str:
        """Describe the shared serialization lock."""
        return 'Device secret assignment lock'


class DeviceSecretUse(models.Model):
    """Durable reservation preventing rotation while issuance, including remote issuance, runs.

    Abandoned reservations fail closed and require operator investigation before removal.
    """

    config_label = models.CharField(max_length=100)
    config_pk = models.PositiveBigIntegerField()
    credential = models.CharField(max_length=32)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        """Index the configuration lookup used while holding its row lock."""

        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=['config_label', 'config_pk', 'credential'],
                name='device_secret_use_config_idx',
            )
        ]

    def __str__(self) -> str:
        """Identify the reserved operation without credential material."""
        return f'{self.config_label}:{self.config_pk} ({self.credential})'


class DeviceSecretStateMixin(models.Model):
    """Shared CMP/EST/REST credential generations and assignment lifecycle guards."""

    cmp_secret_version = models.PositiveBigIntegerField(default=0, editable=False)
    est_password_version = models.PositiveBigIntegerField(default=0, editable=False)

    class Meta:
        """Keep credential state on the concrete configuration tables."""

        abstract = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Keep transient assignment audit metadata separate for each instance."""
        super().__init__(*args, **kwargs)
        self.secret_assignment_actions: dict[str, str] = {}

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Serialize secret changes and reject stale lifecycle writes."""
        with guard_configuration_save(cast('OnboardingConfigModel | NoOnboardingConfigModel', self), kwargs):
            super().save(*args, **kwargs)


class ScepEnrollmentModelMixin(DeviceSecretStateMixin):
    """SCEP (RFC 8894) enrollment state of a device, shared by both onboarding config models.

    The challenge serves two separate purposes: it authorizes exactly one initial PKCSReq (ends with
    ``scep_challenge_consumed_at``, expiry or reset), and it stays available as shared secret for
    CMS PasswordRecipientInfo response encryption towards ECDSA clients. It never authorizes issuance
    after consumption.

    Inherit the shared secret lifecycle so SCEP saves use the same assignment guards.
    """

    objects = models.Manager()

    scep_secret_version = models.PositiveBigIntegerField(default=0, editable=False)

    scep_challenge = EncryptedCharField(
        verbose_name=_('SCEP Challenge Password'), max_length=256, blank=True, default=''
    )
    scep_challenge_digest = models.CharField(
        verbose_name=_('SCEP Challenge Lookup Digest'),
        max_length=64,
        blank=True,
        default='',
        db_index=True,
        help_text=_('SHA-256 of the high-entropy challenge; used only to locate the device.'),
    )
    scep_challenge_expires_at = models.DateTimeField(verbose_name=_('SCEP Challenge Expiry'), null=True, blank=True)
    scep_challenge_consumed_at = models.DateTimeField(
        verbose_name=_('SCEP Enrollment Authorization Consumed'), null=True, blank=True
    )
    scep_transactions = models.JSONField(
        verbose_name=_('SCEP Transactions'),
        default=dict,
        blank=True,
        help_text=_('Issued SCEP transactions by transactionID: request digest, message type, certificate.'),
    )

    class Meta:
        """Abstract mixin."""

        abstract = True

    @staticmethod
    def scep_digest_for(challenge: str) -> str:
        """Return the lookup digest for a challenge."""
        return hashlib.sha256(challenge.encode('utf-8')).hexdigest()

    def set_scep_challenge(self, ttl: timedelta | None = None) -> str:
        """Set a fresh per-device challenge without saving; returns the plaintext (never log it).

        The lifetime defaults to ``SecurityConfig.credential_ttl_seconds`` like the other onboarding credentials.
        """
        if ttl is None:
            security_config = apps.get_model('management', 'SecurityConfig').objects.first()
            seconds = security_config.credential_ttl_seconds if security_config is not None else None
            ttl = timedelta(seconds=seconds) if seconds is not None else None
        challenge = secrets.token_urlsafe(SCEP_CHALLENGE_BYTES)
        self.scep_challenge = challenge
        self.scep_challenge_digest = self.scep_digest_for(challenge)
        self.scep_challenge_expires_at = timezone.now() + ttl if ttl is not None else None
        self.scep_challenge_consumed_at = None
        return challenge

    def provision_scep_challenge(self, ttl: timedelta | None = None) -> str:
        """Create and save a fresh per-device challenge (reset)."""
        if ttl is not None:
            msg = 'Per-device SCEP TTL overrides are not supported.'
            raise ValidationError(msg)
        return assign_secret(cast('OnboardingConfigModel | NoOnboardingConfigModel', self), 'scep_challenge')

    def scep_challenge_state(self, now: datetime | None = None) -> str:
        """Return 'none', 'active', 'expired' or 'consumed'."""
        if not self.scep_challenge_digest:
            return 'none'
        if self.scep_challenge_consumed_at is not None:
            return 'consumed'
        if self.scep_challenge_expires_at is not None and (now or timezone.now()) >= self.scep_challenge_expires_at:
            return 'expired'
        return 'active'

    def can_authorize_scep_enrollment(self, now: datetime | None = None) -> bool:
        """Return whether the challenge can still authorize an initial enrollment."""
        return self.scep_challenge_state(now) == 'active'

    def consume_scep_challenge(self, now: datetime | None = None) -> bool:
        """Atomically consume the enrollment authorization; False if it was no longer usable."""
        now = now or timezone.now()
        updated = (
            type(self).objects.filter(
                models.Q(scep_challenge_expires_at__gt=now) | models.Q(scep_challenge_expires_at__isnull=True),
                pk=self.pk,
                scep_challenge_digest=self.scep_challenge_digest,
                scep_secret_version=self.scep_secret_version,
                scep_challenge_consumed_at__isnull=True,
            )
            .exclude(scep_challenge_digest='')
            .update(scep_challenge_consumed_at=now)
        )
        if updated:
            self.scep_challenge_consumed_at = now
        return bool(updated)


class OnboardingConfigModel(
    AbstractPkiProtocolModel[OnboardingPkiProtocol], ScepEnrollmentModelMixin,
):
    """Onboarding Configuration Model."""

    pki_protocol_class = OnboardingPkiProtocol

    pki_protocols = models.PositiveIntegerField(
        verbose_name=_('Pki Protocol Bitwise Flag'), null=False, blank=True, default=0
    )

    onboarding_status = models.IntegerField(
        choices=OnboardingStatus,
        verbose_name=_('Onboarding Status'),
        null=False,
        blank=False,
        default=OnboardingStatus.PENDING,
    )

    onboarding_protocol = models.PositiveIntegerField(
        choices=OnboardingProtocol,
        verbose_name=_('Onboarding Protocol'),
        null=False,
        blank=False,
    )

    # these will be dropped after successfull onboarding
    est_password = EncryptedCharField(verbose_name=_('EST Password'), max_length=128, blank=True, default='')
    cmp_shared_secret = EncryptedCharField(verbose_name=_('CMP Shared Secret'), max_length=128, blank=True, default='')

    credential_expires_at = models.DateTimeField(
        verbose_name=_('Credential Expiry'),
        null=True,
        blank=True,
        default=None,
        help_text=_('Expiry for CMP shared-secret and EST/REST password authentication. Null means no expiry.'),
    )

    idevid_trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('IDevID Manufacturer Truststore'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='idevid_onboarding_configs',
    )

    trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('Trust Store'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='onboarding_configs',
        help_text=_('Trust store containing certificates to verify the remote server'),
    )

    class Meta:
        """Resolve the abstract mixins' model options for this concrete table."""

        abstract = False

    def __str__(self) -> str:
        """Gets the model instance as human-readable string."""
        return (
            'OnboardingConfigModel('
            f'onboarding_status:{OnboardingStatus(self.onboarding_status).label}, '
            f'onboarding_protocol:{OnboardingProtocol(self.onboarding_protocol).label}, '
            f'cmp_shared_secret:{bool(self.cmp_shared_secret)}, '
            f'est_password:{bool(self.est_password)})'
        )

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Executes full_clean() before saving.

        Args:
            *args: Positional arguments are passed to super().save().
            **kwargs: Keyword arguments are passed to super().save().
        """
        if (
            self._state.adding
            and self.credential_expires_at is None
            and self.onboarding_protocol in (
                OnboardingProtocol.CMP_SHARED_SECRET,
                OnboardingProtocol.EST_USERNAME_PASSWORD,
                OnboardingProtocol.REST_USERNAME_PASSWORD,
                OnboardingProtocol.AGENT,
            )
            and (self.cmp_shared_secret or self.est_password)
        ):
            security_config = apps.get_model('management', 'SecurityConfig').objects.filter(pk=1).first()
            if security_config is not None and security_config.credential_ttl_seconds is not None:
                self.credential_expires_at = timezone.now() + timedelta(seconds=security_config.credential_ttl_seconds)
        self.full_clean()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validation before saving the model."""
        if self.onboarding_status == OnboardingStatus.ONBOARDED and (self.est_password or self.cmp_shared_secret):
            msg = 'Completed onboarding credentials cannot be restored.'
            raise ValidationError(msg)
        error_messages = self._dispatch_protocol_validation()
        if error_messages:
            raise ValidationError(error_messages)

    def is_credential_expired(self) -> bool:
        """Checks whether the shared authentication credential has expired.

        Returns:
            True if an expiry is set and the current time is past it, False otherwise
            (including when no expiry is configured).
        """
        if self.credential_expires_at is None:
            return False
        return timezone.now() >= self.credential_expires_at

    def _dispatch_protocol_validation(self) -> dict[str, str]:
        """Dispatch validation to the appropriate handler based on the onboarding protocol."""
        match self.onboarding_protocol:
            case OnboardingProtocol.MANUAL:
                result = self._validate_case_manual_onboarding()
            case OnboardingProtocol.CMP_IDEVID:
                result = self._validate_case_cmp_idevid_onboarding()
            case OnboardingProtocol.CMP_SHARED_SECRET:
                result = self._validate_case_cmp_shared_secret_onboarding()
            case OnboardingProtocol.EST_IDEVID:
                result = self._validate_case_est_idevid_onboarding()
            case OnboardingProtocol.EST_USERNAME_PASSWORD | OnboardingProtocol.REST_USERNAME_PASSWORD:
                result = self._validate_case_est_username_password_onboarding()
            case OnboardingProtocol.OPC_GDS_PUSH:
                result = self._validate_case_opc_gds_push_onboarding()
            case OnboardingProtocol.AOKI:
                result = self._validate_case_aoki_onboarding()
            case OnboardingProtocol.AGENT:
                result = self._validate_case_agent_onboarding()
            case OnboardingProtocol.BRSKI:
                err_msg = 'BRSKI is not yet supported as onboarding protocol.'
                raise ValidationError(err_msg)
            case _:
                err_msg = f'Unknown onboarding protocol found: {self.onboarding_protocol}.'
                raise ValidationError(err_msg)
        return result

    def _validate_case_opc_gds_push_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.OPC_GDS_PUSH.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for OPC - GDS Push onboarding.'  # noqa: S105

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for OPC - GDS Push onboarding.'  # noqa: S105

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = 'IDevID truststore must not be set for OPC - GDS Push onboarding.'

        allowed_protocols = self.get_pki_protocols()
        if len(allowed_protocols) != 1 or OnboardingPkiProtocol.OPC_GDS_PUSH not in allowed_protocols:
            error_messages['pki_protocols'] = 'OPC - GDS Push onboarding must use only the OPC_GDS_PUSH PKI protocol.'

        return error_messages

    def _validate_case_manual_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.MANUAL.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for manual onboarding.'  # noqa: S105

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for manual onboarding.'  # noqa: S105

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = 'IDevID truststore must not be set for manual onboarding.'

        return error_messages

    def _validate_case_cmp_idevid_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.CMP_IDEVID.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        return {}

    def _validate_case_aoki_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.AOKI."""
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for AOKI onboarding.'  # noqa: S105

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for AOKI onboarding.'  # noqa: S105

        return error_messages

    def _validate_case_cmp_shared_secret_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.CMP_SHARED_SECRET.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for CMP shared-secret onboarding.'  # noqa: S105

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = 'IDevID truststore must not be set for CMP shared-secret onboarding.'

        return error_messages

    def _validate_case_est_idevid_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.EST_IDEVID.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for EST IDevID onboarding.'  # noqa: S105

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for EST IDevID onboarding.'  # noqa: S105

        # idevid_trust_store can be left blank while this would ofcourse mean no onboarding is possible.

        return error_messages

    def _validate_case_est_username_password_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.EST_USERNAME_PASSWORD.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = (
                'CMP shared-secret must not be set for EST username / password onboarding.'  # noqa: S105
            )

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = (
                'IDevID truststore must not be set for EST username / password onboarding.'
            )

        return error_messages

    def _validate_case_agent_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.AGENT.

        Agent-managed devices use REST as the PKI protocol with a generated
        password credential.  No CMP secret, IDevID trust store, or OPC
        credentials are expected.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for Agent onboarding.'  # noqa: S105

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = 'IDevID truststore must not be set for Agent onboarding.'

        allowed_protocols = self.get_pki_protocols()
        if OnboardingPkiProtocol.REST not in allowed_protocols:
            error_messages['pki_protocols'] = 'Agent onboarding must include the REST PKI protocol.'

        return error_messages


class NoOnboardingConfigModel(
    AbstractPkiProtocolModel[NoOnboardingPkiProtocol], ScepEnrollmentModelMixin,
):
    """No Onboarding Configuration Model."""

    pki_protocol_class = NoOnboardingPkiProtocol

    pki_protocols = models.PositiveIntegerField(
        verbose_name=_('Pki Protocol Bitwise Flag'), null=False, blank=True, default=0
    )
    est_password = models.CharField(verbose_name=_('EST Password'), max_length=128, blank=True, default='')
    cmp_shared_secret = models.CharField(verbose_name=_('CMP Shared Secret'), max_length=128, blank=True, default='')

    trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('Trust Store'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='no_onboarding_configs',
        help_text=_('Trust store containing certificates to verify the remote server'),
    )

    class Meta:
        """Resolve the abstract mixins' model options for this concrete table."""

        abstract = False

    def __str__(self) -> str:
        """Gets the model instance as human-readable string."""
        return (
            'NoOnboardingConfigModel('
            f'cmp_shared_secret:{bool(self.cmp_shared_secret)}, '
            f'est_password:{bool(self.est_password)})'
        )

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Executes full_clean() before saving.

        Args:
            *args: Positional arguments are passed to super().save().
            **kwargs: Keyword arguments are passed to super().save().
        """
        self.full_clean()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validation before saving the model."""
        error_messages = {}

        if self.cmp_shared_secret != '' and not self.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET):
            error_messages['cmp_shared_secret'] = (
                'CMP shared-secret must not be set if CMP_SHARED_SECRET is not enabled.'  # noqa: S105
            )

        if self.cmp_shared_secret == '' and self.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET):
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must be set if CMP_SHARED_SECRET is enabled.'  # noqa: S105

        est_enabled = self.has_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD)
        rest_enabled = self.has_pki_protocol(NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD)
        est_or_rest_enabled = est_enabled or rest_enabled

        if self.est_password != '' and not est_or_rest_enabled:
            error_messages['est_password'] = (
                'EST/REST password must not be set if neither EST_USERNAME_PASSWORD '  # noqa: S105
                'nor REST_USERNAME_PASSWORD is enabled.'
            )

        if self.est_password == '' and est_or_rest_enabled:
            error_messages['est_password'] = (
                'EST/REST password must be set if EST_USERNAME_PASSWORD '  # noqa: S105
                'or REST_USERNAME_PASSWORD is enabled.'
            )

        if error_messages:
            raise ValidationError(error_messages)
