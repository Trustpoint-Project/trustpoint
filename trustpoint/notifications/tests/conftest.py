"""Fixtures for the NotificationModel model and related functionality in the notifications app."""

import typing

import pytest
from devices.models import DeviceModel
from django.core.management import call_command
from pki.models import DomainModel, CaModel

from notifications.models import NotificationMessageModel, NotificationStatus


@pytest.fixture
def setup_test_issuing_ca() -> CaModel :
    """Use custom management command to create a test Issuing CA."""
    # Ensure crypto storage config exists for encrypted fields
    from management.models import KeyStorageConfig
    KeyStorageConfig.get_or_create_default()
    
    call_command('create_single_test_issuing_ca')
    issuing_ca = CaModel.objects.get(unique_name='issuing-ca-a-test-fixture')
    return typing.cast('CaModel', issuing_ca)



@pytest.fixture
def test_domain(setup_test_issuing_ca: CaModel) -> DomainModel:
    """Create a domain linked to the test issuing CA."""
    domain, _ = DomainModel.objects.get_or_create(
        unique_name='test-domain',
        defaults={'issuing_ca': setup_test_issuing_ca},
    )
    domain.issuing_ca = setup_test_issuing_ca
    domain.save()
    return domain

@pytest.fixture
def test_device(test_domain: DomainModel) -> DeviceModel:
    """Create a test device fixture."""
    device = DeviceModel.objects.create(
        common_name='test-device-1',
        serial_number='TEST123456',
        domain=test_domain,
    )
    return typing.cast('DeviceModel', device)


@pytest.fixture
def test_message() -> NotificationMessageModel:
    """Create a NotificationMessageModel used for custom notifications."""
    return NotificationMessageModel.objects.create(
        short_description='Test short',
        long_description='Test long description'
    )


@pytest.fixture
def test_status() -> NotificationStatus:
    """Create a notification status object."""
    return NotificationStatus.objects.create(status=NotificationStatus.StatusChoices.NEW)
