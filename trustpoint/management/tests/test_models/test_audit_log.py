from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from management.models.audit_log import AuditLog

User = get_user_model()


class AuditLogModelTest(TestCase):
    """Test Auditlog Model."""

    def setUp(self):
        """Set up test fixtures."""
        self.actor = User.objects.create_user(
            username='actor_user',
            password='testpass123'
        )
        self.target = User.objects.create_user(
            username='target_user',
            password='testpass123'
        )

    def test_create_entry_creates_audit_log_with_actor(self):
        entry = AuditLog.create_entry(
            operation_type=AuditLog.OperationType.USER_CREATED,
            target=self.target,
            target_display='User: target_user',
            actor=self.actor,
        )
        self.assertEqual(entry.operation_type, AuditLog.OperationType.USER_CREATED)
        self.assertEqual(entry.target_object_id, str(self.target.pk))
        self.assertEqual(entry.target_display, 'User: target_user')
        self.assertEqual(entry.actor, self.actor)
        self.assertEqual(
            entry.target_content_type, 
            ContentType.objects.get_for_model(self.target),       
        )

    def test_create_entry_creates_audit_log_without_actor(self):
        entry = AuditLog.create_entry(
            operation_type=AuditLog.OperationType.USER_CREATED,
            target=self.target,
            target_display='User: target_user',
            actor=None,
        )
        self.assertEqual(entry.operation_type, AuditLog.OperationType.USER_CREATED)
        self.assertEqual(entry.target_object_id, str(self.target.pk))
        self.assertEqual(entry.target_display, 'User: target_user')
        self.assertIsNone(entry.actor)
        self.assertEqual(
            entry.target_content_type,
            ContentType.objects.get_for_model(self.target),
        )