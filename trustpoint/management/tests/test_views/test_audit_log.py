"""Tests for audit log views."""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import RequestFactory, TestCase
from django.utils import timezone

from management.models.audit_log import AuditLog
from management.views.audit_log import AuditLogListView

User = get_user_model()


class AuditLogListViewTest(TestCase):
    """Test suite for AuditLogListView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = AuditLogListView()
        self.view.request = self.factory.get('/management/audit-log/')

        self.actor = User.objects.create_user(
            username='actor_user',
            password='testpass123',
        )
        self.target = User.objects.create_user(
            username='target_user',
            password='testpass123',
        )
        self.target_content_type = ContentType.objects.get_for_model(self.target)

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/audit_log/list.html')

    def test_context_object_name(self):
        """Test correct context object name is used."""
        self.assertEqual(self.view.context_object_name, 'audit_log_entries')

    def test_get_context_data_adds_filter(self):
        """Test get_context_data adds filter to context."""
        self.view._filter = 'dummy-filter'
        self.view.object_list = []
        self.view.kwargs = {}

        context = self.view.get_context_data()

        self.assertIn('filter', context)
        self.assertEqual(context['filter'], 'dummy-filter')

    def test_get_queryset_orders_entries_by_timestamp_desc(self):
        """Test queryset is ordered by newest timestamp first."""
        older = AuditLog.objects.create(
            operation_type=AuditLog.OperationType.MODEL_CREATED,
            target_content_type=self.target_content_type,
            target_object_id=str(self.target.pk),
            target_display='Older entry',
            actor=self.actor,
        )
        newer = AuditLog.objects.create(
            operation_type=AuditLog.OperationType.MODEL_UPDATED,
            target_content_type=self.target_content_type,
            target_object_id=str(self.target.pk),
            target_display='Newer entry',
            actor=self.actor,
        )

        older.timestamp = timezone.now() - timedelta(days=1)
        older.save(update_fields=['timestamp'])

        newer.timestamp = timezone.now()
        newer.save(update_fields=['timestamp'])

        queryset = self.view.get_queryset()
        entries = list(queryset)

        self.assertLess(entries.index(newer), entries.index(older))

    def test_get_queryset_filters_by_operation_type(self):
        """Test queryset is filtered by operation type."""
        entry_created = AuditLog.objects.create(
            operation_type=AuditLog.OperationType.MODEL_CREATED,
            target_content_type=self.target_content_type,
            target_object_id=str(self.target.pk),
            target_display='Created entry',
            actor=self.actor,
        )
        entry_updated = AuditLog.objects.create(
            operation_type=AuditLog.OperationType.MODEL_UPDATED,
            target_content_type=self.target_content_type,
            target_object_id=str(self.target.pk),
            target_display='Updated entry',
            actor=self.actor,
        )

        self.view.request = self.factory.get(
            '/management/audit-log/',
            {'operation_type': AuditLog.OperationType.MODEL_CREATED},
        )

        queryset = self.view.get_queryset()

        self.assertIn(entry_created, queryset)
        self.assertNotIn(entry_updated, queryset)