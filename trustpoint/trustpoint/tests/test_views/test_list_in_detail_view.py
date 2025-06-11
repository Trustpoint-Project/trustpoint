"""Tests for the ListInDetailView class."""

from devices.models import DeviceModel
from django.http import Http404
from django.test import TestCase
from django.test.client import RequestFactory
from notifications.models import NotificationModel

from trustpoint.views.base import ListInDetailView


class TestListInDetailView(TestCase):
    """Test cases for ListInDetailView using existing models."""

    @classmethod
    def setUpTestData(cls) -> None:
        """Set up test data shared across all test methods."""
        cls.device = DeviceModel.objects.create(
            common_name='Test Device',
            serial_number='12345',
            domain_credential_onboarding=True
        )
        cls.notification1 = NotificationModel.objects.create(
            notification_type=NotificationModel.NotificationTypes.INFO,
            notification_source=NotificationModel.NotificationSource.DEVICE,
            message_type=NotificationModel.NotificationMessageType.DEVICE_TEST,
            device=cls.device
        )
        cls.notification2 = NotificationModel.objects.create(
            notification_type=NotificationModel.NotificationTypes.WARNING,
            notification_source=NotificationModel.NotificationSource.DEVICE,
            message_type=NotificationModel.NotificationMessageType.DEVICE_ONBOARDING_FAILED,
            device=cls.device
        )

    def setUp(self) -> None:
        """Set up instance-specific data."""
        self.factory = RequestFactory()
        self.view = ListInDetailView()

    def test_get_object_success(self) -> None:
        """Test that get_object retrieves the correct DeviceModel instance."""
        request = self.factory.get('/')
        self.view.request = request

        self.view.kwargs = {'pk': self.device.pk}
        self.view.detail_model = DeviceModel

        obj = self.view.get_object()
        assert obj == self.device, 'get_object() should return the correct DeviceModel instance.'

    def test_get_object_invalid_pk(self) -> None:
        """Test get_object raises Http404 for nonexistent DeviceModel instance (invalid pk)."""
        request = self.factory.get('/')
        self.view.request = request
        self.view.kwargs = {'pk': 9999}  # Nonexistent pk
        self.view.detail_model = DeviceModel

        try:
            self.view.get_object()
            error_message = 'Expected Http404 but no exception was raised.'
            raise AssertionError(error_message)
        except Http404:
            pass

    def test_get_context_data_with_children(self) -> None:
        """Test that context contains both the parent object and the child list."""
        request = self.factory.get('/')
        self.view.request = request

        # Mock required attributes
        self.view.kwargs = {'pk': self.device.pk}
        self.view.detail_model = DeviceModel
        self.view.model = NotificationModel
        self.view.object = self.device
        self.view.object_list = NotificationModel.objects.filter(device=self.device).order_by('id')

        context = self.view.get_context_data()
        assert 'object' in context, "Context should contain 'object'."
        assert context['object'] == self.device, "'object' should match the parent DeviceModel instance."
        assert 'notificationmodel_list' in context, \
            "Context should contain the child list under 'notificationmodel_list'."

        expected_notifications = [self.notification1, self.notification2]
        expected_notifications.sort(key=lambda x: x.id)  # Ensure ordering
        assert list(context['notificationmodel_list']) == expected_notifications, (
            "'notificationmodel_list' should contain all notifications for the parent device in the correct order."
        )

    def test_get_object_missing_pk(self) -> None:
        """Ensure get_object raises AttributeError when pk is missing."""
        request = self.factory.get('/')
        self.view.request = request
        self.view.kwargs = {}  # Missing pk
        self.view.detail_model = DeviceModel

        try:
            self.view.get_object()
            error_msg = 'Expected AttributeError but no exception was raised.'
            raise AssertionError(error_msg)
        except AttributeError:
            pass

    def test_context_data_without_children(self) -> None:
        """Test context when no children exist for the parent."""
        request = self.factory.get('/')
        self.view.request = request

        # Mock required attributes
        self.view.kwargs = {'pk': self.device.pk}
        self.view.detail_model = DeviceModel
        self.view.model = NotificationModel
        self.view.object = self.device
        self.view.object_list = NotificationModel.objects.none()  # No children

        context = self.view.get_context_data()
        assert 'object' in context, "Context should contain 'object'."
        assert context['object'] == self.device, "'object' should match the parent DeviceModel instance."
        assert 'notificationmodel_list' in context, \
            "Context should contain the child list under 'notificationmodel_list'."
        assert list(context['notificationmodel_list']) == [], (
            "'notificationmodel_list' should be empty if there are no children for the parent device."
        )
