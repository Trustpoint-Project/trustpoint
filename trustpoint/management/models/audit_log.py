# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

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
        MODEL_CREATED = 'MODEL_CREATED', _('Model Created (Legacy)')
        MODEL_UPDATED = 'MODEL_UPDATED', _('Model Updated (Legacy)')
        MODEL_DELETED = 'MODEL_DELETED', _('Model Deleted (Legacy)')
        # Generic model operations above are retained only for historical audit rows.
        APPSECRET_BACKEND_CREATED = 'APPSECRET_BACKEND_CREATED', _('Application Secret Backend Created')
        APPSECRET_BACKEND_UPDATED = 'APPSECRET_BACKEND_UPDATED', _('Application Secret Backend Updated')
        APPSECRET_BACKEND_DELETED = 'APPSECRET_BACKEND_DELETED', _('Application Secret Backend Deleted')
        APPSECRET_PKCS11_CREATED = 'APPSECRET_PKCS11_CREATED', _('Application Secret PKCS#11 Configuration Created')
        APPSECRET_PKCS11_UPDATED = 'APPSECRET_PKCS11_UPDATED', _('Application Secret PKCS#11 Configuration Updated')
        APPSECRET_PKCS11_DELETED = 'APPSECRET_PKCS11_DELETED', _('Application Secret PKCS#11 Configuration Deleted')
        APPSECRET_SOFTWARE_CREATED = (
            'APPSECRET_SOFTWARE_CREATED',
            _('Application Secret Software Configuration Created'),
        )
        APPSECRET_SOFTWARE_UPDATED = (
            'APPSECRET_SOFTWARE_UPDATED',
            _('Application Secret Software Configuration Updated'),
        )
        APPSECRET_SOFTWARE_DELETED = (
            'APPSECRET_SOFTWARE_DELETED',
            _('Application Secret Software Configuration Deleted'),
        )
        CRYPTO_PROVIDER_CREATED = 'CRYPTO_PROVIDER_CREATED', _('Crypto Provider Created')
        CRYPTO_PROVIDER_UPDATED = 'CRYPTO_PROVIDER_UPDATED', _('Crypto Provider Updated')
        CRYPTO_PROVIDER_DELETED = 'CRYPTO_PROVIDER_DELETED', _('Crypto Provider Deleted')
        CRYPTO_PKCS11_CONFIG_CREATED = 'CRYPTO_PKCS11_CONFIG_CREATED', _('Crypto PKCS#11 Configuration Created')
        CRYPTO_PKCS11_CONFIG_UPDATED = 'CRYPTO_PKCS11_CONFIG_UPDATED', _('Crypto PKCS#11 Configuration Updated')
        CRYPTO_PKCS11_CONFIG_DELETED = 'CRYPTO_PKCS11_CONFIG_DELETED', _('Crypto PKCS#11 Configuration Deleted')
        CRYPTO_SOFTWARE_CONFIG_CREATED = 'CRYPTO_SOFTWARE_CONFIG_CREATED', _('Crypto Software Configuration Created')
        CRYPTO_SOFTWARE_CONFIG_UPDATED = 'CRYPTO_SOFTWARE_CONFIG_UPDATED', _('Crypto Software Configuration Updated')
        CRYPTO_SOFTWARE_CONFIG_DELETED = 'CRYPTO_SOFTWARE_CONFIG_DELETED', _('Crypto Software Configuration Deleted')
        CRYPTO_REST_CONFIG_CREATED = 'CRYPTO_REST_CONFIG_CREATED', _('Crypto REST Configuration Created')
        CRYPTO_REST_CONFIG_UPDATED = 'CRYPTO_REST_CONFIG_UPDATED', _('Crypto REST Configuration Updated')
        CRYPTO_REST_CONFIG_DELETED = 'CRYPTO_REST_CONFIG_DELETED', _('Crypto REST Configuration Deleted')
        SECURITY_CONFIG_CREATED = 'SECURITY_CONFIG_CREATED', _('Security Configuration Created')
        SECURITY_CONFIG_DELETED = 'SECURITY_CONFIG_DELETED', _('Security Configuration Deleted')
        CA_UPDATED = 'CA_UPDATED', _('CA Updated')
        TRUSTSTORE_CREATED = 'TRUSTSTORE_CREATED', _('Truststore Created')
        TRUSTSTORE_UPDATED = 'TRUSTSTORE_UPDATED', _('Truststore Updated')
        TRUSTSTORE_DELETED = 'TRUSTSTORE_DELETED', _('Truststore Deleted')
        TRUSTSTORE_ENTRY_CREATED = 'TRUSTSTORE_ENTRY_CREATED', _('Truststore Certificate Created')
        TRUSTSTORE_ENTRY_UPDATED = 'TRUSTSTORE_ENTRY_UPDATED', _('Truststore Certificate Updated')
        TRUSTSTORE_ENTRY_DELETED = 'TRUSTSTORE_ENTRY_DELETED', _('Truststore Certificate Deleted')
        DOMAIN_UPDATED = 'DOMAIN_UPDATED', _('Domain Updated')
        DOMAIN_PROFILE_CREATED = 'DOMAIN_PROFILE_CREATED', _('Domain Certificate Profile Assignment Created')
        DOMAIN_PROFILE_UPDATED = 'DOMAIN_PROFILE_UPDATED', _('Domain Certificate Profile Assignment Updated')
        DOMAIN_PROFILE_DELETED = 'DOMAIN_PROFILE_DELETED', _('Domain Certificate Profile Assignment Deleted')
        CERT_PROFILE_CREATED = 'CERT_PROFILE_CREATED', _('Certificate Profile Created')
        CERT_PROFILE_UPDATED = 'CERT_PROFILE_UPDATED', _('Certificate Profile Updated')
        CERT_PROFILE_DELETED = 'CERT_PROFILE_DELETED', _('Certificate Profile Deleted')
        DEVID_REGISTRATION_CREATED = 'DEVID_REGISTRATION_CREATED', _('DevID Registration Created')
        DEVID_REGISTRATION_UPDATED = 'DEVID_REGISTRATION_UPDATED', _('DevID Registration Updated')
        DEVID_REGISTRATION_DELETED = 'DEVID_REGISTRATION_DELETED', _('DevID Registration Deleted')
        AGENT_PROFILE_CREATED = 'AGENT_PROFILE_CREATED', _('Agent Profile Created')
        AGENT_PROFILE_UPDATED = 'AGENT_PROFILE_UPDATED', _('Agent Profile Updated')
        AGENT_PROFILE_DELETED = 'AGENT_PROFILE_DELETED', _('Agent Profile Deleted')
        SECURITY_CONFIG_CHANGED = 'SECURITY_CONFIG_CHANGED', _('Security Config Changed')
        DEVICE_ADDED = 'DEVICE_ADDED', _('Device Added')
        DEVICE_DELETED = 'DEVICE_DELETED', _('Device Deleted')
        CA_CREATED = 'CA_CREATED', _('CA Created')
        CA_DELETED = 'CA_DELETED', _('CA Deleted')
        CA_ROLLOVER_PLANNED = 'CA_ROLLOVER_PLANNED', _('CA Rollover Planned')
        CA_ROLLOVER_STARTED = 'CA_ROLLOVER_STARTED', _('CA Rollover Started')
        CA_ROLLOVER_TRANSITIONED = 'CA_ROLLOVER_TRANSITIONED', _('CA Rollover Transitioned')
        CA_ROLLOVER_COMPLETED = 'CA_ROLLOVER_COMPLETED', _('CA Rollover Completed')
        CA_ROLLOVER_CANCELLED = 'CA_ROLLOVER_CANCELLED', _('CA Rollover Cancelled')
        DOMAIN_CREATED = 'DOMAIN_CREATED', _('Domain Created')
        DOMAIN_DELETED = 'DOMAIN_DELETED', _('Domain Deleted')
        TLS_CERTIFICATE_CHANGED = 'TLS_CERTIFICATE_CHANGED', _('TLS Certificate Changed')
        TLS_CERTIFICATE_DELETED = 'TLS_CERTIFICATE_DELETED', _('TLS Certificate Deleted')
        USER_CREATED = 'USER_CREATED', _('User Created')
        SIGNER_DELETED = 'SIGNER_DELETED', _('Signer Deleted')
        SIGNER_ADDED = 'SIGNER_ADDED', _('Signer Added')
        HASH_SIGNED = 'HASH_SIGNED', _('Hash Signed')
        ORGANIZATION_UPDATED = 'ORGANIZATION_UPDATED', _('Organization Changed')
        CRYPTO_VERIFY_PROVIDER = 'CRYPTO_VERIFY_PROVIDER', _('Crypto: Verify Provider')
        CRYPTO_GENERATE_MANAGED_KEY = 'CRYPTO_GENERATE_MANAGED_KEY', _('Crypto: Generate Managed Key')
        CRYPTO_IMPORT_MANAGED_KEY = 'CRYPTO_IMPORT_MANAGED_KEY', _('Crypto: Import Managed Key')
        CRYPTO_VERIFY_MANAGED_KEY = 'CRYPTO_VERIFY_MANAGED_KEY', _('Crypto: Verify Managed Key')
        CRYPTO_GET_PUBLIC_KEY = 'CRYPTO_GET_PUBLIC_KEY', _('Crypto: Get Public Key')
        CRYPTO_SIGN = 'CRYPTO_SIGN', _('Crypto: Sign')
        CRYPTO_DESTROY_MANAGED_KEY = 'CRYPTO_DESTROY_MANAGED_KEY', _('Crypto: Destroy Managed Key')
        SCEP_ENROLLMENT = 'SCEP_ENROLLMENT', _('SCEP: Enrollment')
        SCEP_RENEWAL = 'SCEP_RENEWAL', _('SCEP: Renewal')
        SCEP_RETRY = 'SCEP_RETRY', _('SCEP: Verified Retry')
        SCEP_REJECTED = 'SCEP_REJECTED', _('SCEP: Request Rejected')
        SCEP_SECRET_PROVISIONED = 'SCEP_SECRET_PROVISIONED', _('SCEP: Enrollment Secret Provisioned')

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
    details = models.JSONField(
        verbose_name=_('Details'),
        default=dict,
        blank=True,
        help_text=_('Structured non-secret metadata captured for this audit entry.'),
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
        details: dict[str, object] | None = None,
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
        :param details: Optional structured metadata. Do not include secrets,
            key material, PINs, raw payloads, signatures, or auth references.
        :returns: The newly created :class:`AuditLog` instance.
        """
        return cls.objects.create(
            operation_type=operation_type,
            target_content_type=ContentType.objects.get_for_model(target),
            target_object_id=str(target.pk),
            target_display=target_display,
            actor=actor,
            details=details or {},
        )
