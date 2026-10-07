# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Small ORM factories used by Behave tests.

These helpers intentionally avoid an additional factory dependency.
"""

from __future__ import annotations

from devices.models import DeviceModel
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import DomainModel


def create_no_onboarding_device(
    *,
    common_name: str,
    serial_number: str,
    domain: DomainModel,
    protocols: list[NoOnboardingPkiProtocol] | None = None,
) -> DeviceModel:
    """Create a generic no-onboarding device accepted by current model validation."""
    config = NoOnboardingConfigModel()
    config.set_pki_protocols(protocols or [NoOnboardingPkiProtocol.MANUAL])
    config.full_clean()
    config.save()

    device = DeviceModel(
        common_name=common_name,
        serial_number=serial_number,
        domain=domain,
        device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
        no_onboarding_config=config,
    )
    device.full_clean()
    device.save()
    return device
