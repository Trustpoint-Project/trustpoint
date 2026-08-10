# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializers for the Role Management API."""

from typing import Any

from django.contrib.auth.models import Group, Permission
from rest_framework import serializers

from users.models import GroupProfile, Role


class PermissionSerializer(serializers.ModelSerializer[Permission]):
    """Read-only serializer exposing an assignable permission's id and name."""

    class Meta:
        """Permission model, scoped to AppPermission by the view's queryset."""

        model = Permission
        fields = ('id', 'name')


class RoleSerializer(serializers.ModelSerializer[Group]):
    """Serializer for role (Group) instances, including permissions and grants."""

    permissions = serializers.PrimaryKeyRelatedField(
        many=True,
        required=False,
        queryset=Permission.objects.filter(content_type__model='apppermission'),
    )
    grants_staff = serializers.BooleanField(required=False, default=False)
    grants_superuser = serializers.BooleanField(required=False, default=False)
    is_protected = serializers.SerializerMethodField()
    user_count = serializers.SerializerMethodField()

    class Meta:
        """Group model, used as roles."""

        model = Group
        fields = (
            'id',
            'name',
            'permissions',
            'grants_staff',
            'grants_superuser',
            'is_protected',
            'user_count',
        )

    def get_is_protected(self, obj: Group) -> bool:
        """Return whether this role is the built-in, non-deletable Admin role."""
        return obj.name == Role.ADMIN.value

    def get_user_count(self, obj: Group) -> int:
        """Return how many users are currently assigned to this role."""
        return obj.trustpoint_users.count()

    def to_representation(self, instance: Group) -> dict[str, Any]:
        """Inject the related GroupProfile's grant flags into the representation."""
        data = super().to_representation(instance)
        profile = getattr(instance, 'profile', None)
        data['grants_staff'] = bool(profile.grants_staff) if profile else False
        data['grants_superuser'] = bool(profile.grants_superuser) if profile else False
        return data

    def create(self, validated_data: dict[str, Any]) -> Group:
        """Create a new role, its permissions, and its GroupProfile grants."""
        grants_staff = validated_data.pop('grants_staff', False)
        grants_superuser = validated_data.pop('grants_superuser', False)
        permissions = validated_data.pop('permissions', [])

        group = Group.objects.create(name=validated_data['name'])
        group.permissions.set(permissions)
        GroupProfile.objects.update_or_create(
            group=group,
            defaults={'grants_staff': grants_staff, 'grants_superuser': grants_superuser},
        )
        return group

    def update(self, instance: Group, validated_data: dict[str, Any]) -> Group:
        """Update a role's name, permissions, and GroupProfile grants."""
        grants_staff = validated_data.pop('grants_staff', None)
        grants_superuser = validated_data.pop('grants_superuser', None)
        permissions = validated_data.pop('permissions', None)

        if 'name' in validated_data:
            instance.name = validated_data['name']
            instance.save()

        if permissions is not None:
            instance.permissions.set(permissions)

        if grants_staff is not None or grants_superuser is not None:
            profile, _created = GroupProfile.objects.get_or_create(group=instance)
            if grants_staff is not None:
                profile.grants_staff = grants_staff
            if grants_superuser is not None:
                profile.grants_superuser = grants_superuser
            profile.save()

        return instance
