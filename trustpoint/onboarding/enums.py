"""Onboarding protocol and status enumerations."""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _

__all__ = [
    'NoOnboardingPkiProtocol',
    'OnboardingPkiProtocol',
    'OnboardingProtocol',
    'OnboardingStatus',
]


class OnboardingStatus(models.IntegerChoices):
    """The onboarding status."""

    PENDING = 1, _('Pending')
    ONBOARDED = 2, _('Onboarded')


class OnboardingProtocol(models.IntegerChoices):
    """Choices of onboarding protocols."""

    MANUAL = 0, _('Manual Onboarding')
    CMP_IDEVID = 1, _('CMP - IDevID')
    CMP_SHARED_SECRET = 2, _('CMP - Shared Secret')
    EST_IDEVID = 3, _('EST - IDevID')
    EST_USERNAME_PASSWORD = 4, _('EST - Username & Password')
    AOKI = 5, _('AOKI')
    BRSKI = 6, _('BRSKI')
    OPC_GDS_PUSH = 7, _('OPC - GDS Push')
    REST_USERNAME_PASSWORD = 8, _('REST - Username & Password')
    AGENT = 9, _('Agent')


class OnboardingPkiProtocol(models.IntegerChoices):
    """Choices for onboarding pki protocols."""

    # Bitmask: Only use powers of 2: 1, 2, 4, 8, 16 ...
    CMP = 1, _('CMP')
    EST = 2, _('EST')
    OPC_GDS_PUSH = 4, _('OPC - GDS Push')
    REST = 8, _('REST')


class NoOnboardingPkiProtocol(models.IntegerChoices):
    """Choices for no onboarding pki protocols."""

    # Bitmask: Only use powers of 2: 1, 2, 4, 8, 16 ...
    CMP_SHARED_SECRET = 1, _('CMP - Shared Secret (HMAC)')
    # 2 reserved for CMP Client Certificate
    EST_USERNAME_PASSWORD = 4, _('EST - Username & Password')
    # 8 reserved for EST Client Certificate
    MANUAL = 16, _('Manual')
    REST_USERNAME_PASSWORD = 32, _('REST - Username & Password')
