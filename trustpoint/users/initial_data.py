"""Migration helper that seeds the initial role-based permission groups and profiles."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from django.db.backends.base.schema import BaseDatabaseSchemaEditor

# Hard-coded group names matching the Role enum values.  We cannot import
# the live ``Role`` enum here because migration code must be decoupled from
# the current model state.
_BASIC_USER = 'Basic User'
_ADVANCED_USER = 'Advanced User'
_ADMIN = 'Admin'

# Standard Django model permissions for TrustpointUser.
_TRUSTPOINTUSER_PERMISSIONS = [
    ('add_trustpointuser', 'Can add trustpoint user'),
    ('change_trustpointuser', 'Can change trustpoint user'),
    ('delete_trustpointuser', 'Can delete trustpoint user'),
    ('view_trustpointuser', 'Can view trustpoint user'),
]


def populate_groups(apps: Any, schema_editor: BaseDatabaseSchemaEditor) -> None:
    """Create role-based Groups, GroupProfiles and assign permissions.

    Called by migration 0002 via RunPython.  Creates one Group per role,
    one GroupProfile per group, and manually creates the ContentType and
    Permission objects for TrustpointUser so they can be assigned
    immediately (Django normally creates these in ``post_migrate``).

    Args:
        apps: The app registry provided by Django during migrations.
        schema_editor: The database schema editor (unused but required by RunPython).
    """
    del schema_editor  # unused, required by RunPython signature

    Group = apps.get_model('auth', 'Group')
    ContentType = apps.get_model('contenttypes', 'ContentType')
    Permission = apps.get_model('auth', 'Permission')

    # Create one Group for each role (idempotent via get_or_create).
    group_basic_user, _ = Group.objects.get_or_create(name=_BASIC_USER)
    group_advanced_user, _ = Group.objects.get_or_create(name=_ADVANCED_USER)
    group_admin, _ = Group.objects.get_or_create(name=_ADMIN)

    # Manually create the ContentType for TrustpointUser so permissions
    # are available during migration (before post_migrate runs).
    ct, _ = ContentType.objects.get_or_create(app_label='users', model='trustpointuser')

    # Create the 4 standard permissions for TrustpointUser.
    permissions = []
    for codename, name in _TRUSTPOINTUSER_PERMISSIONS:
        perm, _ = Permission.objects.get_or_create(
            codename=codename,
            content_type=ct,
            defaults={'name': name},
        )
        permissions.append(perm)

    # Grant TrustpointUser permissions to Advanced User; Basic User gets none.
    # Admin gets no explicit permissions — is_superuser covers everything.
    group_advanced_user.permissions.add(*permissions)

    # Create GroupProfiles that control is_staff / is_superuser for each role.
    GroupProfile = apps.get_model('users', 'GroupProfile')
    for group, staff, superuser in [
        (group_basic_user, False, False),
        (group_advanced_user, True, False),
        (group_admin, True, True),
    ]:
        GroupProfile.objects.get_or_create(
            group=group,
            defaults={'grants_staff': staff, 'grants_superuser': superuser},
        )
