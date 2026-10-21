# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializers for Device-related API endpoints.

Defines classes that handle validation and transformation
of Device model instances to and from JSON.
"""

import secrets
from datetime import timedelta
from typing import Any, ClassVar

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers

from onboarding.models import OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol
from pki.models.truststore import TruststoreModel

from .models import DeviceModel, OpcUaGdsPushConfig


class PkiProtocolField(serializers.Field[int | str, int | str, int | str, Any]):
    """Custom field to accept PKI protocol as string name or integer value."""

    def to_internal_value(self, data: Any) -> int | str:
        """Accept either string or integer for PKI protocol."""
        if isinstance(data, (int, str)):
            return data
        msg = 'PKI protocol must be a string (name) or integer (value)'
        raise serializers.ValidationError(msg)

    def to_representation(self, value: Any) -> Any:
        """Return the value as-is for serialization."""
        return value


class OnboardingConfigSerializer(serializers.ModelSerializer[OnboardingConfigModel]):
    """Serializer for OnboardingConfig instances.

    Handles conversion between OnboardingConfigModel objects and JSON representations.
    Supports nested creation when creating a device with onboarding configuration.
    Auto-generates secure credentials if not provided for applicable protocols.
    Accepts both enum names (strings) and integer values for protocols.
    """

    # Accept legacy request locations; DeviceSerializer moves these into the OPC config.
    opc_user = serializers.CharField(required=False, allow_blank=True, write_only=True)
    opc_password = serializers.CharField(required=False, allow_blank=True, write_only=True)
    opc_trust_store = serializers.PrimaryKeyRelatedField(
        queryset=TruststoreModel.objects.filter(intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH),
        required=False, allow_null=True, write_only=True,
    )

    pki_protocols = serializers.ListField(
        child=PkiProtocolField(),
        required=False,
        allow_empty=True,
        write_only=True,
        help_text=(
            'List of PKI protocol names or values. '
            'Accepts: "CMP" (1), "EST" (2), "OPC_GDS_PUSH" (4), "REST" (8). '
            'Can use names ["CMP", "EST"] or values [1, 2] or mix both.'
        )
    )

    credential_ttl_seconds = serializers.IntegerField(
        required=False,
        write_only=True,
        min_value=1,
        help_text=(
            'Optional validity window (in seconds) for CMP, EST, and REST credentials. '
            'When provided, credential_expires_at is set to now + ttl. '
            'If omitted, new credentials use the TTL from Security Configuration '
            'unless an expiry is explicitly given.'
        ),
    )

    class Meta:
        """Metadata for OnboardingConfigSerializer."""

        model = OnboardingConfigModel
        fields: ClassVar[list[str]] = [
            'id',
            'onboarding_protocol',
            'onboarding_status',
            'pki_protocols',
            'est_password',
            'cmp_shared_secret',
            'credential_expires_at',
            'credential_ttl_seconds',
            'opc_user',
            'opc_password',
            'idevid_trust_store',
            'trust_store',
            'opc_trust_store',
        ]
        read_only_fields: ClassVar[list[str]] = ['id', 'onboarding_status']
        extra_kwargs: ClassVar[dict[str, dict[str, str]]] = {
            'onboarding_protocol': {
                'help_text': (
                    'Onboarding protocol: MANUAL (0), CMP_IDEVID (1), CMP_SHARED_SECRET (2), '
                    'EST_IDEVID (3), EST_USERNAME_PASSWORD (4), AOKI (5), BRSKI (6), '
                    'OPC_GDS_PUSH (7), REST_USERNAME_PASSWORD (8), AGENT (9)'
                )
            },
            'est_password': {
                'help_text': 'Password for EST. Auto-generated if omitted for EST protocols.'
            },
            'cmp_shared_secret': {
                'help_text': 'Shared secret for CMP. Auto-generated if omitted for CMP protocols.'
            },
        }

    def _apply_credential_expiry(
        self,
        data: dict[str, Any],
        ttl_seconds: int | None,
    ) -> None:
        """Resolve the credential expiry into data['credential_expires_at'].

        Precedence:
        1. An explicit credential_expires_at already in data is left untouched.
        2. An explicit ttl_seconds sets expiry to now + ttl.
        3. The model applies the security configuration default when saving a new credential.
        """
        if data.get('credential_expires_at') is not None:
            return

        if ttl_seconds is not None:
            data['credential_expires_at'] = timezone.now() + timedelta(seconds=ttl_seconds)
            return

    def _generate_secure_secret(self, length: int = 32) -> str:
        """Generate a cryptographically secure random secret.

        Args:
            length: The length of the secret in bytes (default 32 = 256 bits)

        Returns:
            A URL-safe base64-encoded secret string
        """
        return secrets.token_urlsafe(length)

    def _parse_pki_protocol(self, value: str | int | OnboardingPkiProtocol) -> OnboardingPkiProtocol:
        """Parse PKI protocol from string name, integer value, or enum instance.

        Args:
            value: Either enum name (e.g., "CMP"), integer value (e.g., 1), or OnboardingPkiProtocol enum

        Returns:
            OnboardingPkiProtocol enum instance

        Raises:
            serializers.ValidationError: If the value is invalid
        """
        # Already an enum instance
        if isinstance(value, OnboardingPkiProtocol):
            return value

        if isinstance(value, int):
            try:
                return OnboardingPkiProtocol(value)
            except ValueError:
                valid_values = [p.value for p in OnboardingPkiProtocol]
                msg = f'Invalid PKI protocol value: {value}. Valid values: {valid_values}'
                raise serializers.ValidationError(msg) from None

        # Try to parse as string (enum name)
        try:
            return OnboardingPkiProtocol[str(value).upper()]
        except KeyError:
            valid_names = [p.name for p in OnboardingPkiProtocol]
            msg = f'Invalid PKI protocol name: {value}. Valid names: {valid_names}'
            raise serializers.ValidationError(msg) from None

    def create(self, validated_data: dict[str, Any]) -> OnboardingConfigModel:
        """Create OnboardingConfigModel instance with proper PKI protocol handling.

        Auto-generates secure credentials for applicable protocols if not provided:
        - CMP_SHARED_SECRET: generates cmp_shared_secret
        - EST_USERNAME_PASSWORD or REST_USERNAME_PASSWORD: generates est_password
        """
        pki_protocol_values = validated_data.pop('pki_protocols', [])
        ttl_seconds = validated_data.pop('credential_ttl_seconds', None)
        onboarding_protocol = validated_data.get('onboarding_protocol')

        if onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET and not validated_data.get('cmp_shared_secret'):
            validated_data['cmp_shared_secret'] = self._generate_secure_secret()

        if (onboarding_protocol in (OnboardingProtocol.EST_USERNAME_PASSWORD, OnboardingProtocol.REST_USERNAME_PASSWORD)
            and not validated_data.get('est_password')):
            validated_data['est_password'] = self._generate_secure_secret()

        self._apply_credential_expiry(validated_data, ttl_seconds)

        instance = OnboardingConfigModel(**validated_data)

        if pki_protocol_values:
            protocol_enums = [self._parse_pki_protocol(val) for val in pki_protocol_values]
            instance.set_pki_protocols(protocol_enums)

        instance.save()
        return instance

    def update(self, instance: OnboardingConfigModel, validated_data: dict[str, Any]) -> OnboardingConfigModel:
        """Update OnboardingConfigModel instance with proper PKI protocol handling."""
        pki_protocol_values = validated_data.pop('pki_protocols', None)
        ttl_seconds = validated_data.pop('credential_ttl_seconds', None)

        # Resolve an explicit TTL into an expiry timestamp. A TTL always takes
        # precedence over any expiry already present in the update payload.
        if ttl_seconds is not None:
            validated_data['credential_expires_at'] = timezone.now() + timedelta(seconds=ttl_seconds)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if pki_protocol_values is not None:
            protocol_enums = [self._parse_pki_protocol(val) for val in pki_protocol_values]
            instance.set_pki_protocols(protocol_enums)

        instance.save()
        return instance


class OpcUaGdsPushConfigSerializer(serializers.ModelSerializer[OpcUaGdsPushConfig]):
    """Serialize the dedicated GDS Push configuration without exposing its password."""

    class Meta:
        """Fields editable through the nested device API."""

        model = OpcUaGdsPushConfig
        exclude = ('id', 'device')
        read_only_fields = ('opc_gds_push_last_update_scheduled_at', 'opc_gds_push_domain_credential_next_renewal_at')
        extra_kwargs: ClassVar[dict[str, dict[str, Any]]] = {
            'opc_password': {'write_only': True},
            'opc_gds_push_renewal_interval': {'min_value': 1},
            'opc_gds_push_domain_credential_renewal_interval': {'min_value': 1},
        }


class DeviceSerializer(serializers.ModelSerializer[DeviceModel]):
    """Serializer for Device instances.

    Handles conversion between Device model objects and JSON representations.
    Supports nested creation of onboarding_config when provided in the request.
    """

    onboarding_config = OnboardingConfigSerializer(required=False, allow_null=True)
    opc_ua_gds_push_config = OpcUaGdsPushConfigSerializer(required=False)
    opc_server_port = serializers.IntegerField(required=False, min_value=1, max_value=65535, write_only=True)

    def _extract_gds_push_config(self, data: dict[str, Any]) -> dict[str, Any]:
        """Accept both the dedicated config and legacy OPC request field locations."""
        config: dict[str, Any] = data.pop('opc_ua_gds_push_config', {})
        if 'opc_server_port' in data:
            config.setdefault('opc_server_port', data.pop('opc_server_port'))
        onboarding = data.get('onboarding_config') or {}
        for name in ('opc_user', 'opc_password', 'opc_trust_store'):
            if name in onboarding:
                value = onboarding.pop(name)
                config.setdefault(name, value)
        return config

    def _save_gds_push_config(self, device: DeviceModel, data: dict[str, Any]) -> None:
        """Validate and persist OPC settings while triggering renewal scheduling."""
        if not data:
            return
        config, _created = OpcUaGdsPushConfig.objects.get_or_create(device=device)
        for name, value in data.items():
            setattr(config, name, value)
        try:
            config.full_clean()
        except DjangoValidationError as exc:
            raise serializers.ValidationError({'opc_ua_gds_push_config': exc.message_dict}) from exc
        config.device = device
        device.opc_ua_gds_push_config = config
        config.save(update_fields=[name.removesuffix('_id') for name in data])

    class Meta:
        """Metadata for DeviceSerializer, defining model and serialized fields."""

        model = DeviceModel
        fields = '__all__'

    @transaction.atomic
    def create(self, validated_data: dict[str, Any]) -> DeviceModel:
        """Create DeviceModel instance with nested onboarding_config if provided."""
        config_data = self._extract_gds_push_config(validated_data)
        onboarding_config_data = validated_data.pop('onboarding_config', None)

        if onboarding_config_data:
            onboarding_config = OnboardingConfigSerializer().create(onboarding_config_data)
            validated_data['onboarding_config'] = onboarding_config

        device = super().create(validated_data)
        self._save_gds_push_config(device, config_data)
        return device

    @transaction.atomic
    def update(self, instance: DeviceModel, validated_data: dict[str, Any]) -> DeviceModel:
        """Update DeviceModel instance, handling nested onboarding_config updates."""
        config_data = self._extract_gds_push_config(validated_data)
        onboarding_config_data = validated_data.pop('onboarding_config', None)

        if onboarding_config_data is not None:
            if instance.onboarding_config:
                OnboardingConfigSerializer().update(instance.onboarding_config, onboarding_config_data)
            else:
                onboarding_config = OnboardingConfigSerializer().create(onboarding_config_data)
                validated_data['onboarding_config'] = onboarding_config

        device = super().update(instance, validated_data)
        self._save_gds_push_config(device, config_data)
        return device
