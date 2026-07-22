"""Serializers for Device-related API endpoints.

Defines classes that handle validation and transformation
of Device model instances to and from JSON.
"""

import secrets
from typing import Any, ClassVar

from rest_framework import serializers

from onboarding.models import OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol

from .models import DeviceModel


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
        onboarding_protocol = validated_data.get('onboarding_protocol')

        if onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET and not validated_data.get('cmp_shared_secret'):
            validated_data['cmp_shared_secret'] = self._generate_secure_secret()

        if (onboarding_protocol in (OnboardingProtocol.EST_USERNAME_PASSWORD, OnboardingProtocol.REST_USERNAME_PASSWORD)
            and not validated_data.get('est_password')):
            validated_data['est_password'] = self._generate_secure_secret()

        instance = OnboardingConfigModel(**validated_data)

        if pki_protocol_values:
            protocol_enums = [self._parse_pki_protocol(val) for val in pki_protocol_values]
            instance.set_pki_protocols(protocol_enums)

        instance.save()
        return instance

    def update(self, instance: OnboardingConfigModel, validated_data: dict[str, Any]) -> OnboardingConfigModel:
        """Update OnboardingConfigModel instance with proper PKI protocol handling."""
        pki_protocol_values = validated_data.pop('pki_protocols', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if pki_protocol_values is not None:
            protocol_enums = [self._parse_pki_protocol(val) for val in pki_protocol_values]
            instance.set_pki_protocols(protocol_enums)

        instance.save()
        return instance


class DeviceSerializer(serializers.ModelSerializer[DeviceModel]):
    """Serializer for Device instances.

    Handles conversion between Device model objects and JSON representations.
    Supports nested creation of onboarding_config when provided in the request.
    """

    onboarding_config = OnboardingConfigSerializer(required=False, allow_null=True)

    class Meta:
        """Metadata for DeviceSerializer, defining model and serialized fields."""

        model = DeviceModel
        fields = '__all__'

    def create(self, validated_data: dict[str, Any]) -> DeviceModel:
        """Create DeviceModel instance with nested onboarding_config if provided."""
        onboarding_config_data = validated_data.pop('onboarding_config', None)

        if onboarding_config_data:
            onboarding_config = OnboardingConfigSerializer().create(onboarding_config_data)
            validated_data['onboarding_config'] = onboarding_config

        return super().create(validated_data)

    def update(self, instance: DeviceModel, validated_data: dict[str, Any]) -> DeviceModel:
        """Update DeviceModel instance, handling nested onboarding_config updates."""
        onboarding_config_data = validated_data.pop('onboarding_config', None)

        if onboarding_config_data is not None:
            if instance.onboarding_config:
                OnboardingConfigSerializer().update(instance.onboarding_config, onboarding_config_data)
            else:
                onboarding_config = OnboardingConfigSerializer().create(onboarding_config_data)
                validated_data['onboarding_config'] = onboarding_config

        return super().update(instance, validated_data)
