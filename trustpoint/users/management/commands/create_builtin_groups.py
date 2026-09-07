# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create Trustpoint's built-in groups with their predefined permissions."""

from collections.abc import Iterable

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import BaseCommand
from django.db import transaction

from users.models import AppPermission, BuiltinRole, GroupProfile


ROLE_PERMISSION_CODENAMES: dict[BuiltinRole, frozenset[str] | None] = {
    BuiltinRole.ADMIN: None,
    BuiltinRole.SERVICE: frozenset({
        'manage_cas',
        'manage_ras',
        'manage_domains',
        'manage_truststores',
        'manage_certificate_profiles',
        'manage_devices',
    }),
    BuiltinRole.PKI_ADMIN: frozenset({
        'manage_crypto_backends',
        'issue_certificates',
        'revoke_certificates',
        'download_credentials',
        'view_help_pages',
    }),
    BuiltinRole.DEVICE_OPERATOR: frozenset({
        'manage_devices',
        'download_credentials',
        'view_help_pages',
    }),
    BuiltinRole.SYSTEM_ADMIN: frozenset({
        'manage_users',
        'manage_roles',
        'manage_organizations',
        'manage_service_accounts',
        'manage_system_configuration',
        'manage_security_configuration',
        'manage_backups',
        'manage_notifications',
        'manage_tls_webserver_configuration',
        'view_metrics',
    }),
    BuiltinRole.WORKFLOW_ADMIN: frozenset({'manage_workflows'}),
    BuiltinRole.WORKFLOW_APPROVER: frozenset({'approve_workflows'}),
    BuiltinRole.SECURITY_AUDITOR: frozenset({
        'view_audit_log',
        'view_system_logs',
        'view_metrics',
    }),
}


class Command(BaseCommand):
    """Create all built-in groups, profiles, and predefined permissions."""

    help = 'Creates all built-in role groups with their predefined permissions.'

    @transaction.atomic
    def handle(self, *_args: object, **_options: object) -> None:
        """Create or update every built-in role."""
        permission_content_type = ContentType.objects.get_for_model(AppPermission)
        available_permissions = Permission.objects.filter(content_type=permission_content_type)

        for role, codenames in ROLE_PERMISSION_CODENAMES.items():
            group, created = Group.objects.get_or_create(name=role.value)
            GroupProfile.objects.update_or_create(
                group=group,
                defaults={
                    'grants_staff': role is BuiltinRole.ADMIN,
                    'grants_superuser': role is BuiltinRole.ADMIN,
                    'is_builtin': True,
                    'is_protected': role is BuiltinRole.ADMIN,
                },
            )
            group.permissions.set(self._get_permissions(available_permissions, codenames))
            action = 'Created' if created else 'Updated'
            self.stdout.write(f'{action} {role.value} role.')

    @staticmethod
    def _get_permissions(
        available_permissions: Iterable[Permission],
        codenames: frozenset[str] | None,
    ) -> Iterable[Permission]:
        """Return all permissions for Admin or the configured subset for a role."""
        if codenames is None:
            return available_permissions
        return (permission for permission in available_permissions if permission.codename in codenames)