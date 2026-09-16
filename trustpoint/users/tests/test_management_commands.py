# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for user management commands."""

from io import StringIO

import pytest
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command

from users.management.commands.create_builtin_groups import ROLE_PERMISSION_CODENAMES
from users.models import AppPermission, BuiltinRole, GroupProfile


@pytest.mark.django_db
class TestCreateBuiltinGroupsCommand:
    """Tests for provisioning built-in groups."""

    def test_creates_builtin_groups_with_predefined_permissions(self) -> None:
        """Every built-in role has profile metadata and its configured permissions."""
        content_type = ContentType.objects.get_for_model(AppPermission)
        for codename in set().union(*(codenames or set() for codenames in ROLE_PERMISSION_CODENAMES.values())):
            Permission.objects.get_or_create(
                content_type=content_type,
                codename=codename,
                defaults={'name': codename},
            )

        output = StringIO()
        call_command('create_builtin_groups', stdout=output)

        assert Group.objects.filter(name__in=BuiltinRole.values).count() == len(BuiltinRole)
        for role, codenames in ROLE_PERMISSION_CODENAMES.items():
            group = Group.objects.get(name=role.value)
            profile = GroupProfile.objects.get(group=group)

            assert profile.is_builtin
            assert profile.is_modification_protected is (role is BuiltinRole.ADMIN)
            assert profile.is_deletion_protected is (role in (BuiltinRole.ADMIN, BuiltinRole.SERVICE))
            assert profile.grants_staff is (role is BuiltinRole.ADMIN)
            assert profile.grants_superuser is (role is BuiltinRole.ADMIN)
            if codenames is not None:
                assert set(group.permissions.values_list('codename', flat=True)) == codenames

        call_command('create_builtin_groups', stdout=output)
        assert Group.objects.filter(name__in=BuiltinRole.values).count() == len(BuiltinRole)