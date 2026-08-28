# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Custom user model with role-based access control.

Defines a ``Role`` enum whose values are human-readable group names
(e.g. ``'Admin'``) and a ``TrustpointUser`` model whose ``role`` field
is a foreign key to ``django.contrib.auth.models.Group``.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any

from django.apps import apps
from django.contrib.auth.models import AbstractUser, Group, UserManager
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from management.models.organization import OrganizationModel


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

    def _get_default_org(self) -> OrganizationModel:
        """Create default organization."""
        org_model = apps.get_model('management', 'OrganizationModel')
        org, _created = org_model.objects.get_or_create(pk=1, name='trustpoint', organization='trustpoint')
        return org

    def create_superuser(
        self,
        username: str,
        email: str | None = None,
        password: str | None = None,
        **extra_fields: Any,
    ) -> TrustpointUser:
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
    ) -> TrustpointUser:
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

    class AccountType(models.TextChoices):
        """Account type choices."""

        HUMAN = 'HUMAN', _('Human')
        SERVICE = 'SERVICE', _('Service')

    account_type = models.CharField(
        max_length=10,
        choices=AccountType.choices,
        default=AccountType.HUMAN,
        verbose_name=_('account type'),
        help_text=_('Human accounts have interactive Web UI login; service accounts use API credentials or mTLS.'),
    )

    role = models.ForeignKey(
        Group,
        on_delete=models.PROTECT,
        related_name='trustpoint_users',
        verbose_name=_('role'),
    )

    organization = models.ForeignKey(
        'management.OrganizationModel',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='org_users',
        verbose_name=_('organization')
    )

    objects = TrustpointUserManager()  # type: ignore[misc]

    def __str__(self) -> str:
        """Return a human-readable representation of the user."""
        account_type = f' ({self.get_account_type_display()})' if self.account_type != self.AccountType.HUMAN else ''
        return f'Username: {self.username}, Role: {self.role.name}{account_type}'

    def clean(self) -> None:
        """Validate model constraints."""
        super().clean()

        # Service accounts cannot be staff or superusers
        if self.account_type == self.AccountType.SERVICE and (self.is_staff or self.is_superuser):
            msg = _('Service accounts cannot be staff or superusers.')
            raise ValidationError(msg)

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Persist the user and synchronise Django permission flags and group membership.

        Reads ``grants_staff`` and ``grants_superuser`` from the role's
        :class:`GroupProfile` to set ``is_staff`` and ``is_superuser``.
        Groups without a profile default to both flags being ``False``.

        After saving, the user's ``groups`` M2M is set to contain
        *exactly* the group pointed to by ``role``.

        Service accounts are never staff or superusers.
        """
        # Service accounts can never be staff or superusers
        if self.account_type == self.AccountType.SERVICE:
            self.is_staff = False
            self.is_superuser = False
        # Sync Django permission flags from the role's GroupProfile for human accounts
        elif self.role_id:
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


class ServiceAccountCredential(models.Model):
    """API Key credentials for service account authentication.

    Stores metadata for API key credentials (client ID/secret)
    used by service accounts for non-interactive API access.
    """

    service_account = models.ForeignKey(
        TrustpointUser,
        on_delete=models.CASCADE,
        related_name='service_credentials',
        verbose_name=_('service account'),
        limit_choices_to={'account_type': TrustpointUser.AccountType.SERVICE},
    )

    client_id = models.CharField(
        max_length=255,
        unique=True,
        verbose_name=_('client ID'),
        help_text=_('Unique identifier for API key authentication.'),
    )

    hashed_secret = models.CharField(
        max_length=255,
        verbose_name=_('hashed secret'),
        help_text=_('Hashed API secret for API key authentication.'),
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('created at'),
    )

    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('expires at'),
        help_text=_('Optional expiration date for the credential.'),
    )

    last_used = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('last used'),
    )

    usage_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_('usage count'),
        help_text=_('Number of times this credential has been used for authentication.'),
    )

    is_active = models.BooleanField(
        default=True,
        verbose_name=_('active'),
        help_text=_('Deactivate to revoke access without deleting the credential.'),
    )

    description = models.TextField(
        blank=True,
        verbose_name=_('description'),
        help_text=_('Optional description of this credential.'),
    )

    class Meta:
        """Metaclass for ServiceAccountCredential."""

        verbose_name = _('service account credential')
        verbose_name_plural = _('service account credentials')
        indexes = [  # noqa: RUF012
            models.Index(fields=['client_id']),
            models.Index(fields=['service_account', 'is_active']),
        ]

    def __str__(self) -> str:
        """Return a human-readable representation of the credential."""
        return f'{self.client_id} - {self.service_account.username}'

    def clean(self) -> None:
        """Validate credential constraints."""
        super().clean()

        # Verify service account type
        if self.service_account.account_type != TrustpointUser.AccountType.SERVICE:
            msg = _('Credentials can only be associated with service accounts.')
            raise ValidationError(msg)

    def is_expired(self) -> bool:
        """Check whether this credential has expired."""
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at

    def is_valid(self) -> bool:
        """Check if the credential is valid (active and not expired)."""
        if not self.is_active:
            return False

        return not self.is_expired()

    def record_usage(self) -> None:
        """Record the last usage time of this credential."""
        self.last_used = timezone.now()
        self.usage_count += 1
        self.save(update_fields=['last_used', 'usage_count'])

    @staticmethod
    def generate_client_id() -> str:
        """Generate a unique client ID."""
        return f'sa_{secrets.token_urlsafe(32)}'

    @staticmethod
    def generate_secret() -> str:
        """Generate a secure random API secret."""
        return secrets.token_urlsafe(48)
