# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Authentication helpers for Behave tests."""

from __future__ import annotations

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import Permission
from django.test import Client

from management.models import OrganizationModel
from users.models import BuiltinRole, ServiceAccountCredential, TrustpointUser

ADMIN_PASSWORD = 'testing321'  # noqa: S105


def _grant_all_trustpoint_permissions(user: TrustpointUser) -> None:
    """Grant the administrator every application-level Trustpoint permission.

    Trustpoint authorization is primarily role/group based. Merely creating a
    Django superuser is not sufficient for views that explicitly call
    ``has_perm(AppPermissions.*)`` when the role has not yet been populated by
    the test setup.
    """
    permissions = Permission.objects.filter(
        content_type__app_label='users',
        content_type__model='apppermission',
    )
    user.role.permissions.set(permissions)
    # Clear Django's permission caches if this user instance has already been
    # queried for permissions in the current scenario.
    for cache_name in ('_perm_cache', '_user_perm_cache', '_group_perm_cache'):
        if hasattr(user, cache_name):
            delattr(user, cache_name)


def create_admin_client() -> tuple[TrustpointUser, Client]:
    """Create an admin user with all Trustpoint permissions and log it in."""
    admin = TrustpointUser.objects.filter(username='admin').first()
    if admin is None:
        admin = TrustpointUser.objects.create_superuser(username='admin', password=ADMIN_PASSWORD)
    elif not admin.check_password(ADMIN_PASSWORD):
        admin.set_password(ADMIN_PASSWORD)
        admin.save()

    _grant_all_trustpoint_permissions(admin)

    client = Client()
    assert client.login(username='admin', password=ADMIN_PASSWORD), 'Admin login failed'
    return admin, client


def create_service_account(username: str = 'behave_service') -> tuple[TrustpointUser, ServiceAccountCredential, str]:
    """Create an API-only service account and one active credential."""
    organization, _ = OrganizationModel.objects.get_or_create(
        name='Behave',
        organization='behave',
    )
    role = BuiltinRole.get_service_group()
    permission = Permission.objects.get(
        content_type__app_label='users',
        content_type__model='apppermission',
        codename='use_rest_api',
    )
    role.permissions.add(permission)

    account = TrustpointUser.objects.create(
        username=username,
        account_type=TrustpointUser.AccountType.SERVICE,
        role=role,
        organization=organization,
    )
    account.set_unusable_password()
    account.save()

    client_id = ServiceAccountCredential.generate_client_id()
    secret = ServiceAccountCredential.generate_secret()
    credential = ServiceAccountCredential.objects.create(
        service_account=account,
        client_id=client_id,
        hashed_secret=make_password(secret),
        description='Behave test credential',
    )
    return account, credential, secret
