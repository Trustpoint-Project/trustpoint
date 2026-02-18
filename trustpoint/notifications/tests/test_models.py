"""Tests for the NotificationModel model and related functionality in the notifications app."""

import pytest
from devices.models import DeviceModel
from django.utils import timezone
from pki.models import DomainModel, CaModel

from notifications.models import (
    NotificationConfig,
    NotificationMessageModel,
    NotificationModel,
    NotificationStatus,
)

DEFAULT_EXPIRY_WARNING_DAYS = 30
DEFAULT_RSA_KEY_SIZE = 2048
EXPECTED_STATUS_COUNT = 2


@pytest.mark.django_db
def test_create_notification_with_issuing_ca(
    test_message: NotificationMessageModel, test_status: NotificationStatus, setup_test_issuing_ca: CaModel
) -> None:
    """Test creation of a NotificationModel linked to an Issuing CA."""
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.WARNING,
        notification_source=NotificationModel.NotificationSource.ISSUING_CA,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=test_message,
        issuing_ca=setup_test_issuing_ca,
    )
    notification.statuses.set([test_status])

    assert notification.issuing_ca == setup_test_issuing_ca
    assert notification.short_translated == 'Test short'
    assert notification.long_translated == 'Test long description'
    assert str(notification).startswith('WARNING - Test short')


@pytest.mark.django_db
def test_create_notification_with_domain(
    test_message: NotificationMessageModel, test_status: NotificationStatus, test_domain: DomainModel
) -> None:
    """Test creation of a NotificationModel linked to a domain."""
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.INFO,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=test_message,
        domain=test_domain,
    )
    notification.statuses.set([test_status])

    assert notification.domain == test_domain
    assert notification.short_translated == 'Test short'
    assert notification.long_translated == 'Test long description'


@pytest.mark.django_db
def test_notification_translations_for_builtins(test_status: NotificationStatus) -> None:
    """Test translated messages for built-in (non-CUSTOM) notification types."""
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
        notification_source=NotificationModel.NotificationSource.SYSTEM,
        message_type=NotificationModel.NotificationMessageType.SYSTEM_NOT_HEALTHY,
        message_data={},
    )
    notification.statuses.set([test_status])

    assert 'System health check failed' in notification.short_translated
    assert 'The system health check detected an issue' in notification.long_translated


@pytest.mark.django_db
def test_unknown_message_type_fallback(test_status: NotificationStatus) -> None:
    """Test fallback behavior when an unknown message_type is provided."""
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
        notification_source=NotificationModel.NotificationSource.SYSTEM,
        message_type='UNKNOWN_CODE',
        message_data={},
    )
    notification.statuses.set([test_status])

    assert 'Unknown Notification message type.' in notification.short_translated
    assert 'Guess we messed up' in notification.long_translated


@pytest.mark.django_db
def test_notification_with_multiple_statuses(test_message: NotificationMessageModel, test_domain: DomainModel) -> None:
    """Test that multiple statuses can be added to a NotificationModel."""
    status_new = NotificationStatus.objects.create(status=NotificationStatus.StatusChoices.NEW)
    status_ack = NotificationStatus.objects.create(status=NotificationStatus.StatusChoices.ACKNOWLEDGED)

    notif = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.INFO,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=test_message,
        domain=test_domain,
    )
    notif.statuses.set([status_new, status_ack])

    statuses = notif.statuses.all()
    assert statuses.count() == EXPECTED_STATUS_COUNT
    assert status_new in statuses
    assert status_ack in statuses


@pytest.mark.django_db
def test_notification_str_fallback_missing_message(test_domain: DomainModel) -> None:
    """Test that __str__ handles missing message (should not raise)."""
    notif = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        domain=test_domain,
        message=None,  # required=False on model level
    )
    assert str(notif) == f'{notif.get_notification_type_display()} - No message'


@pytest.mark.django_db
def test_notification_str_with_long_message(test_domain: DomainModel) -> None:
    """Test that __str__ properly truncates long messages to 20 characters."""
    message = NotificationMessageModel.objects.create(
        short_description='This is a very long message that should be truncated', long_description='Full description'
    )
    notif = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.INFO,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        domain=test_domain,
        message=message,
    )
    assert str(notif) == f'{notif.get_notification_type_display()} - This is a very long '


@pytest.mark.django_db
def test_notification_str_with_empty_message(test_domain: DomainModel) -> None:
    """Test that __str__ handles empty message description properly."""
    message = NotificationMessageModel.objects.create(short_description='', long_description='Some long description')
    notif = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.WARNING,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        domain=test_domain,
        message=message,
    )
    assert str(notif) == f'{notif.get_notification_type_display()} - '


@pytest.mark.django_db
def test_notification_str_with_special_characters(test_domain: DomainModel) -> None:
    """Test that __str__ handles messages with special characters properly."""
    message = NotificationMessageModel.objects.create(
        short_description='!@#$%^&*()_+-=[]{}', long_description='Test with special characters'
    )
    notif = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        domain=test_domain,
        message=message,
    )
    assert str(notif) == f'{notif.get_notification_type_display()} - !@#$%^&*()_+-=[]{{}}'


@pytest.mark.django_db
def test_notification_for_issuing_ca_creation(
    test_message: NotificationMessageModel, test_status: NotificationStatus, setup_test_issuing_ca: CaModel
) -> None:
    """Test notification creation when a new issuing CA is created."""
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.INFO,
        notification_source=NotificationModel.NotificationSource.ISSUING_CA,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=test_message,
        issuing_ca=setup_test_issuing_ca,
        message_data={
            'ca_name': setup_test_issuing_ca.unique_name,
            'ca_type': str(setup_test_issuing_ca.CaTypeChoice(setup_test_issuing_ca.ca_type).label),
            'common_name': setup_test_issuing_ca.common_name,
        },
    )
    notification.statuses.set([test_status])

    assert notification.issuing_ca == setup_test_issuing_ca
    assert notification.message_data['ca_name'] == setup_test_issuing_ca.unique_name


@pytest.mark.django_db
def test_create_notification_with_device(
    test_message: NotificationMessageModel, test_status: NotificationStatus, test_device: DeviceModel
) -> None:
    """Test creation of a NotificationModel linked to a device."""
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.WARNING,
        notification_source=NotificationModel.NotificationSource.DEVICE,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=test_message,
        device=test_device,
    )
    notification.statuses.set([test_status])

    assert notification.device == test_device
    assert notification.short_translated == 'Test short'
    assert notification.long_translated == 'Test long description'


@pytest.mark.django_db
def test_notification_config_defaults() -> None:
    """Test NotificationConfig default values and singleton behavior."""
    config = NotificationConfig.get()

    assert config.cert_expiry_warning_days == DEFAULT_EXPIRY_WARNING_DAYS
    assert config.issuing_ca_expiry_warning_days == DEFAULT_EXPIRY_WARNING_DAYS
    assert config.rsa_minimum_key_size == DEFAULT_RSA_KEY_SIZE

    config2 = NotificationConfig.get()
    assert config == config2


@pytest.mark.django_db
def test_notification_created_at_auto_now() -> None:
    """Test that created_at is automatically set when creating a notification."""
    before_creation = timezone.now()
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.INFO,
        notification_source=NotificationModel.NotificationSource.SYSTEM,
        message_type=NotificationModel.NotificationMessageType.SYSTEM_NOT_HEALTHY,
    )
    after_creation = timezone.now()

    assert before_creation <= notification.created_at <= after_creation


@pytest.mark.django_db
def test_notification_event_filtering() -> None:
    """Test that notifications can be filtered by event."""
    NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.WARNING,
        notification_source=NotificationModel.NotificationSource.SYSTEM,
        message_type=NotificationModel.NotificationMessageType.SYSTEM_NOT_HEALTHY,
        event='test_event',
    )

    found = NotificationModel.objects.filter(event='test_event').exists()
    assert found
    assert NotificationModel.objects.filter(event='non_existent').exists() is False


@pytest.mark.django_db
def test_custom_message_with_empty_descriptions() -> None:
    """Test custom notification message with empty descriptions."""
    message = NotificationMessageModel.objects.create(short_description='', long_description='')
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.INFO,
        notification_source=NotificationModel.NotificationSource.SYSTEM,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=message,
    )

    assert notification.short_translated == ''
    assert notification.long_translated == ''
