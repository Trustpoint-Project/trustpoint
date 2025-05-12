import pytest
from django.core.management import call_command
from django.utils import timezone

from notifications.models import (
    NotificationModel,
    NotificationStatus,
    NotificationMessageModel,
)
from pki.models import IssuingCaModel, DomainModel


@pytest.fixture
def setup_test_issuing_ca(db):
    """
    Use custom management command to create a test Issuing CA.
    """
    call_command("create_single_test_issuing_ca")
    return IssuingCaModel.objects.get(unique_name="issuing-ca-a-test-fixture")


@pytest.fixture
def test_domain(db, setup_test_issuing_ca):
    """
    Create a domain linked to the test issuing CA.
    """
    domain, _ = DomainModel.objects.get_or_create(
        unique_name="test-domain",
        defaults={"issuing_ca": setup_test_issuing_ca},
    )
    domain.issuing_ca = setup_test_issuing_ca
    domain.save()
    return domain


@pytest.fixture
def test_message(db):
    """
    Create a NotificationMessageModel used for custom notifications.
    """
    return NotificationMessageModel.objects.create(
        short_description="Test short",
        long_description="Test long description"
    )


@pytest.fixture
def test_status(db):
    """
    Create a notification status object.
    """
    return NotificationStatus.objects.create(status=NotificationStatus.StatusChoices.NEW)


@pytest.mark.django_db
def test_create_notification_with_issuing_ca(test_message, test_status, setup_test_issuing_ca):
    """
    Test creation of a NotificationModel linked to an Issuing CA.
    """
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.WARNING,
        notification_source=NotificationModel.NotificationSource.ISSUING_CA,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=test_message,
        issuing_ca=setup_test_issuing_ca,
    )
    notification.statuses.set([test_status])

    assert notification.issuing_ca == setup_test_issuing_ca
    assert notification.short_translated == "Test short"
    assert notification.long_translated == "Test long description"
    assert str(notification).startswith("WARNING - Test short")


@pytest.mark.django_db
def test_create_notification_with_domain(test_message, test_status, test_domain):
    """
    Test creation of a NotificationModel linked to a domain.
    """
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.INFO,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=test_message,
        domain=test_domain,
    )
    notification.statuses.set([test_status])

    assert notification.domain == test_domain
    assert notification.short_translated == "Test short"
    assert notification.long_translated == "Test long description"


@pytest.mark.django_db
def test_notification_translations_for_builtins(test_status):
    """
    Test translated messages for built-in (non-CUSTOM) notification types.
    """
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
        notification_source=NotificationModel.NotificationSource.SYSTEM,
        message_type=NotificationModel.NotificationMessageType.SYSTEM_NOT_HEALTHY,
        message_data={},
    )
    notification.statuses.set([test_status])

    assert "System health check failed" in notification.short_translated
    assert "The system health check detected an issue" in notification.long_translated


@pytest.mark.django_db
def test_unknown_message_type_fallback(test_status):
    """
    Test fallback behavior when an unknown message_type is provided.
    """
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
        notification_source=NotificationModel.NotificationSource.SYSTEM,
        message_type="UNKNOWN_CODE",
        message_data={},
    )
    notification.statuses.set([test_status])

    assert "Unknown Notification message type." in notification.short_translated
    assert "Guess we messed up" in notification.long_translated

@pytest.mark.django_db
def test_notification_with_multiple_statuses(test_message, test_domain):
    """
    Test that multiple statuses can be added to a NotificationModel.
    """
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
    assert statuses.count() == 2
    assert status_new in statuses
    assert status_ack in statuses

@pytest.mark.django_db
def test_notification_str_fallback_missing_message(test_domain):
    """
    Test that __str__ handles missing message (should not raise).
    """
    notif = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
        notification_source=NotificationModel.NotificationSource.DOMAIN,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        domain=test_domain,
        message=None,  # required=False on model level
    )
    assert isinstance(str(notif), str)
