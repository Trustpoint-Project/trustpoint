# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializers for the User Management API."""

from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from users.models import TrustpointUser


class UserSerializer(serializers.ModelSerializer[TrustpointUser]):
    """Serializer for user instances.

    Handles conversion between user model and JSON representations.
    """
    role_name = serializers.CharField(source='role.name', read_only=True)
    password = serializers.CharField(write_only=True, required=False)
    class Meta:
        """User Model."""
        model = get_user_model()
        fields = (
            'username',
            'first_name',
            'last_name',
            'role',
            'role_name',
            'email',
            'password'
            )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Validate password presence on create and password strength when provided."""
        password = attrs.get('password')

        if self.instance is None and not password:
            raise serializers.ValidationError(
                {'password': 'missing password'}
            )

        if password:
            try:
                validate_password(password, user=self.instance)
            except DjangoValidationError as exc:
                raise serializers.ValidationError({'password': exc.messages}) from exc

        return attrs

    def create(self, validated_data: dict[str, Any]) -> TrustpointUser:
        """Create a new TrustpointUser with the given validated data."""
        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance: TrustpointUser, validated_data: dict[str, Any]) -> TrustpointUser:
        """Update an existing TrustpointUser, hashing the password if it was changed."""
        password = validated_data.pop('password', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()
        return instance


