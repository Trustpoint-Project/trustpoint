from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from management.filters.audit_log import AuditLogFilter
from management.models.audit_log import AuditLog

User = get_user_model()


class AuditLogFilterTest(TestCase):
    """Test Auditlog filter."""

    def setUp(self):
        """Set up test Fixtures."""
        self.actor_1 = User.objects.create_user(
            username='actor_1_user',
            password='testpass123',
        )
        self.actor_2 = User.objects.create_user(
            username='actor_2_user',
            password='testpass123',
        )
        self.target = User.objects.create_user(
            username='target_user',
            password='testpass123',
        )
        self.target_content_type = ContentType.objects.get_for_model(self.target)
        self.entry_1 = AuditLog.objects.create(
            operation_type=AuditLog.OperationType.MODEL_CREATED,
            target_content_type=self.target_content_type,
            target_object_id=str(self.target.pk),
            target_display='User: target_user',
            actor=self.actor_1
        )
        self.entry_2 = AuditLog.objects.create(
            operation_type=AuditLog.OperationType.MODEL_UPDATED,
            target_content_type=self.target_content_type,
            target_object_id=str(self.target.pk),
            target_display='User: target_user',
            actor=self.actor_2
        )

    def test_filter_by_operation_type(self):
        """Test filter returns only entries with selected operation type."""
        audit_filter=AuditLogFilter(
            data={'operation_type': AuditLog.OperationType.MODEL_CREATED},
            queryset=AuditLog.objects.all(),
        )

        queryset=audit_filter.qs

        self.assertIn(self.entry_1, queryset)
        self.assertNotIn(self.entry_2, queryset)

    def test_filter_by_actor(self):
        """Test filter returns only entries with selected actor."""
        audit_filter=AuditLogFilter(
            data={'actor': self.actor_1.pk},
            queryset=AuditLog.objects.all(),
        )

        queryset=audit_filter.qs

        self.assertIn(self.entry_1, queryset)
        self.assertNotIn(self.entry_2, queryset)