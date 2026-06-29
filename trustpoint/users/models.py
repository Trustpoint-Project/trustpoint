"""Custom user model with role-based access control.

Defines a ``Role`` enum whose values are human-readable group names
(e.g. ``'Admin'``) and a ``TrustpointUser`` model whose ``role`` field
is a foreign key to ``django.contrib.auth.models.Group``.
"""

from typing import Any

from django.apps import apps
from django.contrib.auth.models import AbstractUser, Group, UserManager
from django.db import models
from django.utils.translation import gettext_lazy as _


class Role(models.TextChoices):
    """Predefined roles that map to Django groups.

    The *value* is the canonical Group name stored in the database.
    Admin is the only protected group and cannot be deleted via the UI.
    """

    ADMIN = 'Admin', _('Admin')
    DEFAULT = 'Default', _('Default')

class GroupProfile(models.Model):
    """Extended attributes for a Django ``Group`` used as a role.

    Stores per-group flags that control which Django permission attributes
    (``is_staff``, ``is_superuser``) are granted to users assigned to
    the group.  Created automatically alongside each group via the
    ``GroupPermissionForm``.
    """

    group = models.OneToOneField(
        Group,
        on_delete=models.CASCADE,
        related_name='profile',
        verbose_name=_('group'),
    )
    grants_staff = models.BooleanField(
        default=False,
        verbose_name=_('staff status'),
        help_text=_('Users with this role can log into the admin site.'),
    )
    grants_superuser = models.BooleanField(
        default=False,
        verbose_name=_('superuser status'),
        help_text=_('Users with this role have all permissions without explicitly assigning them.'),
    )

    class Meta:
        """Metaclass for GroupProfile."""

        verbose_name = _('group profile')
        verbose_name_plural = _('group profiles')

    def __str__(self) -> str:
        """Return a human-readable representation of the profile."""
        return f'Profile for {self.group.name}'


class TrustpointUserManager(UserManager['TrustpointUser']):
    """Custom manager that handles the required ``role`` field for ``createsuperuser``."""

    def _get_default_org(self):
        """Create default organization."""
        org = apps.get_model('management', 'OrganizationModel')
        return org.objects.get_or_create(pk=1, name='trustpoint', organization='trustpoint')

    def create_superuser(
        self,
        username: str,
        email: str | None = None,
        password: str | None = None,
        **extra_fields: Any,
    ) -> 'TrustpointUser':
        """Create a superuser and assign the Admin role automatically.

        Args:
            username: The username for the new superuser.
            email: Optional email address.
            password: The password for the new superuser.
            **extra_fields: Additional fields passed to the model.

        Returns:
            The newly created superuser instance.
        """
        if 'role' not in extra_fields and 'role_id' not in extra_fields:
            admin_group, _ = Group.objects.get_or_create(name=Role.ADMIN.value)
            extra_fields['role'] = admin_group
        extra_fields.setdefault('organization', self._get_default_org())
        return super().create_superuser(username, email, password, **extra_fields)

    def create_user(
        self,
        username: str,
        email: str | None = None,
        password: str | None = None,
        **extra_fields: Any,
    ) -> 'TrustpointUser':
        """Create a user and assign the default role automatically.

        Args:
            username: The username for the new user.
            email: Optional email address.
            password: The password for the new user.
            **extra_fields: Additional fields passed to the model.

        Returns:
            The newly created TrustpointUser instance.
        """
        if 'role' not in extra_fields and 'role_id' not in extra_fields:
            default_group, _ = Group.objects.get_or_create(name=Role.DEFAULT.value)
            extra_fields['role'] = default_group
        extra_fields.setdefault('organization', self._get_default_org())
        return super().create_user(username, email, password, **extra_fields)


class TrustpointUser(AbstractUser):
    """Custom user model that adds a role field to the standard Django user.

    The ``role`` foreign key points to a ``Group`` instance.  On every
    save the model synchronises Django's ``is_staff`` / ``is_superuser``
    flags and the user's ``groups`` M2M relation so that the user belongs
    to exactly the group referenced by ``role``.
    """

    role = models.ForeignKey(
        Group,
        on_delete=models.PROTECT,
        related_name='trustpoint_users',
        verbose_name=_('role'),
    )

    organization = models.ForeignKey(
        'management.OrganizationModel',
        on_delete=models.PROTECT,
        related_name='org_users',
        verbose_name=_('organization')
    )

    objects = TrustpointUserManager()  # type: ignore[misc]

    def __str__(self) -> str:
        """Return a human-readable representation of the user."""
        return f'Username: {self.username}, Role: {self.role.name}'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Persist the user and synchronise Django permission flags and group membership.

        Reads ``grants_staff`` and ``grants_superuser`` from the role's
        :class:`GroupProfile` to set ``is_staff`` and ``is_superuser``.
        Groups without a profile default to both flags being ``False``.

        After saving, the user's ``groups`` M2M is set to contain
        *exactly* the group pointed to by ``role``.
        """
        # Sync Django permission flags from the role's GroupProfile.
        if self.role_id:
            profile: GroupProfile | None = getattr(self.role, 'profile', None)
            self.is_superuser = profile.grants_superuser if profile else False
            self.is_staff = profile.grants_staff if profile else False
        else:
            self.is_superuser = False
            self.is_staff = False

        super().save(*args, **kwargs)

        # Ensure the user belongs to exactly the role group.
        self.groups.set([self.role])

class AppPermission(models.Model):
    """Dummy model used only to host app-level permissions.

    No database usage beyond auth_permission table.
    """

    class Meta:
        """Define permissions."""

        default_permissions = ()  # disables add/change/delete/view
        permissions = (
            ('manage_workflow', 'Can manage workflow'),
            ('onboard_device', 'Can onboard device'),
            ('manage_ca', 'Can manage CA'),
            ('manage_role', 'Can manage role')
        )

    def __str__(self) -> str:
        """Return a string representation for the AppPermission."""
        return 'app_permission_model'
