"""Audit log model for recording important changes to managed objects."""

from __future__ import annotations

from typing import ClassVar

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta

User = get_user_model()


class AuditLog(models.Model):
    """Generic audit log entry for important state changes to any managed object."""

    class OperationType(models.TextChoices):
        """Allowed operation types recorded in the audit log."""

        CREDENTIAL_ISSUED = 'CREDENTIAL_ISSUED', _('Credential Issued')
        CREDENTIAL_RENEWED = 'CREDENTIAL_RENEWED', _('Credential Renewed')
        CREDENTIAL_REVOKED = 'CREDENTIAL_REVOKED', _('Credential Revoked')
        CREDENTIAL_DELETED = 'CREDENTIAL_DELETED', _('Credential Deleted')
        MODEL_CREATED = 'MODEL_CREATED', _('Model Created')
        MODEL_UPDATED = 'MODEL_UPDATED', _('Model Updated')
        MODEL_DELETED = 'MODEL_DELETED', _('Model Deleted')
        SECURITY_CONFIG_CHANGED = 'SECURITY_CONFIG_CHANGED', _('Security Config Changed')
        DEVICE_ADDED = 'DEVICE_ADDED', _('Device Added')
        DEVICE_DELETED = 'DEVICE_DELETED', _('Device Deleted')
        CA_CREATED = 'CA_CREATED', _('CA Created')
        CA_DELETED = 'CA_DELETED', _('CA Deleted')
        DOMAIN_CREATED = 'DOMAIN_CREATED', _('Domain Created')
        DOMAIN_DELETED = 'DOMAIN_DELETED', _('Domain Deleted')
        TLS_CERTIFICATE_CHANGED = 'TLS_CERTIFICATE_CHANGED', _('TLS Certificate Changed')
        TLS_CERTIFICATE_DELETED = 'TLS_CERTIFICATE_DELETED', _('TLS Certificate Deleted')
        USER_CREATED = 'USER_CREATED', _('User Created')

    timestamp = models.DateTimeField(
        verbose_name=_('Timestamp'),
        auto_now_add=True,
        editable=False,
        db_index=True,
    )
    operation_type = models.CharField(
        verbose_name=_('Operation Type'),
        max_length=32,
        choices=OperationType,
        db_index=True,
    )

    target_content_type = models.ForeignKey(
        ContentType,
        verbose_name=_('Target Content Type'),
        on_delete=models.CASCADE,
        db_index=True,
    )
    target_object_id = models.CharField(
        verbose_name=_('Target Object ID'),
        max_length=255,
        db_index=True,
    )
    target = GenericForeignKey('target_content_type', 'target_object_id')

    target_display = models.CharField(
        verbose_name=_('Target Display'),
        max_length=255,
        help_text=_(
            'Human-readable label of the affected object at the time of the action, '
            'e.g. "DevOwnerID: my-device". Preserved even if the target is later deleted.'
        ),
    )

    actor = models.ForeignKey(
        User,
        verbose_name=_('Actor'),
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_log_entries',
        help_text=_('The user who triggered the action. Null for system-triggered actions.'),
    )

    class Meta(TypedModelMeta):
        """Meta options for AuditLog."""

        ordering: ClassVar[list[str]] = ['-timestamp']
        verbose_name = _('Audit Log Entry')
        verbose_name_plural = _('Audit Log Entries')
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=['target_content_type', 'target_object_id'],
                name='audit_log_target_idx',
            ),
        ]

    def __str__(self) -> str:
        """Return a human-readable summary of the audit log entry."""
        return f'[{self.timestamp}] {self.operation_type} - {self.target_display}'

    @classmethod
    def create_entry(
        cls,
        operation_type: str,
        target: models.Model,
        target_display: str,
        actor: models.Model | None = None,
    ) -> AuditLog:
        """Create and persist a new audit log entry.

        This is the preferred way to write audit log entries. It resolves the
        :class:`~django.contrib.contenttypes.models.ContentType` for *target*
        internally so callers never need to import ``ContentType`` themselves.

        :param operation_type: One of the :class:`OperationType` values.
        :param target: The model instance that was affected by the operation.
        :param target_display: Human-readable label captured at the time of the
            action, e.g. ``"Device: my-sensor"``.  Preserved even after the
            target is deleted.
        :param actor: The :class:`~django.contrib.auth.models.User` who
            triggered the action, or ``None`` for system-triggered actions.
        :returns: The newly created :class:`AuditLog` instance.
        """
        return cls.objects.create(
            operation_type=operation_type,
            target_content_type=ContentType.objects.get_for_model(target),
            target_object_id=str(target.pk),
            target_display=target_display,
            actor=actor,
        )

