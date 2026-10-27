# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializers for Device-related API endpoints.

Defines classes that handle validation and transformation
of Device model instances to and from JSON.
"""

from datetime import timedelta
from typing import Any, ClassVar, cast

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers

from devices.secrets import (
    VERSIONS,
    assignment_lock,
    audit_assignments,
    custom_secrets_allowed,
    ensure_eligible,
    prepare_secret,
    validate_custom_secret,
)
from onboarding.authorization import PermittedProtocolsAuthorization
from onboarding.models import NoOnboardingConfigModel, OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol
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


class ExactDeviceSecretField(serializers.CharField):
    """Require a string rather than coercing JSON numbers into chosen secrets."""

    def to_internal_value(self, data: Any) -> str:
        """Preserve the exact submitted string through validation."""
        if not isinstance(data, str):
            msg = 'A custom secret must be a string.'
            raise serializers.ValidationError(msg)
        return super().to_internal_value(data)


class OnboardingConfigSerializer(serializers.ModelSerializer[OnboardingConfigModel]):
    """Serializer for OnboardingConfig instances.

    Handles conversion between OnboardingConfigModel objects and JSON representations.
    Supports nested creation when creating a device with onboarding configuration.
    Auto-generates secure credentials if not provided for applicable protocols.
    Accepts both enum names (strings) and integer values for protocols.
    """

    est_password = ExactDeviceSecretField(required=False, trim_whitespace=False, max_length=128, write_only=True)
    cmp_shared_secret = ExactDeviceSecretField(required=False, trim_whitespace=False, max_length=128, write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Reject custom policy bypasses and preserve exact secret bytes."""
        custom = any(field in attrs for field in VERSIONS)
        if custom:
            if not custom_secrets_allowed():
                msg = 'Custom device secrets are disabled.'
                raise serializers.ValidationError(msg)
            if 'credential_ttl_seconds' in attrs or 'credential_expires_at' in attrs:
                msg = 'Custom assignments cannot include TTL or expiry overrides.'
                raise serializers.ValidationError(msg)
            for field in VERSIONS:
                if field in attrs:
                    try:
                        validate_custom_secret(attrs[field])
                    except DjangoValidationError as exc:
                        raise serializers.ValidationError({field: exc.messages}) from exc
        return attrs

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

    @transaction.atomic
    def create(self, validated_data: dict[str, Any]) -> OnboardingConfigModel:
        """Create credentials through the common policy service."""
        assignment_lock()
        values = validated_data.pop('pki_protocols', [])
        ttl = validated_data.pop('credential_ttl_seconds', None)
        supplied = {field: validated_data.pop(field) for field in VERSIONS if field in validated_data}
        expiry = validated_data.pop('credential_expires_at', serializers.empty)
        instance = OnboardingConfigModel(**validated_data)
        instance.set_pki_protocols([self._parse_pki_protocol(value) for value in values])
        fields = []
        if instance.onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET:
            fields = ['cmp_shared_secret']
        elif instance.onboarding_protocol in (
            OnboardingProtocol.EST_USERNAME_PASSWORD, OnboardingProtocol.REST_USERNAME_PASSWORD,
        ):
            fields = ['est_password']
        try:
            for field in set(fields) | supplied.keys():
                prepare_secret(instance, field, custom=field in supplied, value=supplied.get(field))
            if supplied and (expiry is not serializers.empty or ttl is not None):
                msg = 'Custom assignments cannot include TTL or expiry overrides.'
                raise DjangoValidationError(msg)  # noqa: TRY301
            if expiry is not serializers.empty:
                instance.credential_expires_at = expiry
            elif ttl is not None:
                instance.credential_expires_at = timezone.now() + timedelta(seconds=ttl)
            instance.save()
            if not self.context.get('defer_secret_audit'):
                audit_assignments(instance, actor=getattr(self.context.get('request'), 'user', None))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages) from exc
        return instance

    @transaction.atomic
    def update(self, instance: OnboardingConfigModel, validated_data: dict[str, Any]) -> OnboardingConfigModel:
        """Preserve omitted credentials and rotate explicitly supplied credentials atomically."""
        assignment_lock()
        instance = OnboardingConfigModel.objects.select_for_update().get(pk=instance.pk)
        values = validated_data.pop('pki_protocols', None)
        ttl = validated_data.pop('credential_ttl_seconds', None)
        supplied = {field: validated_data.pop(field) for field in VERSIONS if field in validated_data}
        if supplied and (ttl is not None or 'credential_expires_at' in validated_data):
            msg = 'Custom assignments cannot include TTL or expiry overrides.'
            raise serializers.ValidationError(msg)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if values is not None:
            instance.set_pki_protocols([self._parse_pki_protocol(value) for value in values])
        try:
            for field, value in supplied.items():
                prepare_secret(instance, field, custom=True, value=value)
            if ttl is not None:
                instance.credential_expires_at = timezone.now() + timedelta(seconds=ttl)
            instance.save()
            if not self.context.get('defer_secret_audit'):
                audit_assignments(instance, actor=getattr(self.context.get('request'), 'user', None))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages) from exc
        return instance


class NoOnboardingConfigSerializer(serializers.ModelSerializer[NoOnboardingConfigModel]):
    """Configure expiry-free CMP/EST/REST and one-use SCEP enrollment."""

    cmp_shared_secret = ExactDeviceSecretField(required=False, trim_whitespace=False, max_length=128, write_only=True)
    est_password = ExactDeviceSecretField(required=False, trim_whitespace=False, max_length=128, write_only=True)
    scep_challenge = ExactDeviceSecretField(required=False, trim_whitespace=False, max_length=128, write_only=True)

    class Meta:
        """Only expose supported configuration writes."""

        model = NoOnboardingConfigModel
        fields: ClassVar[list[str]] = [
            'id', 'pki_protocols', 'trust_store', 'cmp_shared_secret', 'est_password', 'scep_challenge',
        ]
        read_only_fields: ClassVar[list[str]] = ['id']

    def to_internal_value(self, data: Any) -> dict[str, Any]:
        """Reject expiry inputs even when this serializer is nested in a device request."""
        if isinstance(data, dict) and {
            'credential_ttl_seconds', 'credential_expires_at', 'scep_challenge_expires_at',
        } & data.keys():
            msg = 'Per-device expiry overrides are not supported here.'
            raise serializers.ValidationError(msg)
        return cast('dict[str, Any]', super().to_internal_value(data))

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Apply identical custom-input validation to both configuration types."""
        if any(field in attrs for field in VERSIONS):
            if not custom_secrets_allowed():
                msg = 'Custom device secrets are disabled.'
                raise serializers.ValidationError(msg)
            for field in VERSIONS:
                if field in attrs:
                    try:
                        validate_custom_secret(attrs[field])
                    except DjangoValidationError as exc:
                        raise serializers.ValidationError({field: exc.messages}) from exc
        return attrs

    @transaction.atomic
    def create(self, validated_data: dict[str, Any]) -> NoOnboardingConfigModel:
        """Generate selected credentials unless explicitly supplied."""
        assignment_lock()
        supplied = {field: validated_data.pop(field) for field in VERSIONS if field in validated_data}
        config = NoOnboardingConfigModel(**validated_data)
        try:
            for field in VERSIONS:
                try:
                    ensure_eligible(config, field)
                except DjangoValidationError:
                    if field in supplied:
                        raise
                    continue
                prepare_secret(config, field, custom=field in supplied, value=supplied.get(field))
            config.save()
            if not self.context.get('defer_secret_audit'):
                audit_assignments(config, actor=getattr(self.context.get('request'), 'user', None))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages) from exc
        return config

    @transaction.atomic
    def update(self, instance: NoOnboardingConfigModel, validated_data: dict[str, Any]) -> NoOnboardingConfigModel:
        """Preserve existing credentials on unrelated PATCH requests."""
        assignment_lock()
        instance = NoOnboardingConfigModel.objects.select_for_update().get(pk=instance.pk)
        supplied = {field: validated_data.pop(field) for field in VERSIONS if field in validated_data}
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        try:
            for field, value in supplied.items():
                prepare_secret(instance, field, custom=True, value=value)
            instance.save()
            if not self.context.get('defer_secret_audit'):
                audit_assignments(instance, actor=getattr(self.context.get('request'), 'user', None))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages) from exc
        return instance


class SecretReplacementSerializer(serializers.Serializer[dict[str, Any]]):
    """Explicit single-credential rotation contract."""

    credential = serializers.ChoiceField(choices=list(VERSIONS))
    action = serializers.ChoiceField(choices=['generate', 'custom'])
    value = ExactDeviceSecretField(required=False, trim_whitespace=False, max_length=128, write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Distinguish omitted values from explicit empty or conflicting values."""
        if set(self.initial_data) - {'credential', 'action', 'value'}:
            msg = 'Unexpected replacement fields. TTL and expiry overrides are forbidden.'
            raise serializers.ValidationError(msg)
        if attrs['action'] == 'custom':
            if 'value' not in attrs:
                msg = 'A custom value is required.'
                raise serializers.ValidationError(msg)
            try:
                validate_custom_secret(attrs['value'])
            except DjangoValidationError as exc:
                raise serializers.ValidationError(exc.messages) from exc
        elif 'value' in attrs:
            msg = 'A generated replacement must omit the custom value.'
            raise serializers.ValidationError(msg)
        return attrs


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
    no_onboarding_config = NoOnboardingConfigSerializer(required=False)
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

    @staticmethod
    def _check_protocol_policy(device: DeviceModel) -> None:
        """Apply the same protocol policy used by device creation forms."""
        try:
            PermittedProtocolsAuthorization().check(device)
        except ValueError:
            msg = 'The selected protocols are not permitted by the active security policy.'
            raise serializers.ValidationError(msg) from None

    class Meta:
        """Metadata for DeviceSerializer, defining model and serialized fields."""

        model = DeviceModel
        fields = '__all__'

    @transaction.atomic
    def create(self, validated_data: dict[str, Any]) -> DeviceModel:
        """Create DeviceModel instance with nested onboarding_config if provided."""
        config_data = self._extract_gds_push_config(validated_data)
        config_context = {**self.context, 'defer_secret_audit': True}
        onboarding_config_data = validated_data.pop('onboarding_config', None)
        no_onboarding_data = validated_data.pop('no_onboarding_config', None)

        if onboarding_config_data is not None and no_onboarding_data is not None:
            msg = 'Select one configuration type.'
            raise serializers.ValidationError(msg)
        if no_onboarding_data is not None:
            validated_data['no_onboarding_config'] = NoOnboardingConfigSerializer(context=config_context).create(
                no_onboarding_data,
            )

        if onboarding_config_data:
            onboarding_config = OnboardingConfigSerializer(context=config_context).create(onboarding_config_data)
            validated_data['onboarding_config'] = onboarding_config

        device = super().create(validated_data)
        self._check_protocol_policy(device)
        self._save_gds_push_config(device, config_data)
        for config in (device.onboarding_config, device.no_onboarding_config):
            if config is not None:
                audit_assignments(config, device=device, actor=getattr(self.context.get('request'), 'user', None))
        return device

    @transaction.atomic
    def update(self, instance: DeviceModel, validated_data: dict[str, Any]) -> DeviceModel:
        """Update DeviceModel instance, handling nested onboarding_config updates."""
        config_data = self._extract_gds_push_config(validated_data)
        config_context = {**self.context, 'defer_secret_audit': True}
        onboarding_config_data = validated_data.pop('onboarding_config', None)
        no_onboarding_data = validated_data.pop('no_onboarding_config', None)

        if ('onboarding_config' in self.initial_data and instance.no_onboarding_config_id) or (
            no_onboarding_data is not None and instance.onboarding_config_id
        ):
            msg = 'Configuration type cannot be changed through a device update.'
            raise serializers.ValidationError(msg)
        if 'onboarding_config' in self.initial_data and onboarding_config_data is None:
            msg = 'Onboarding configuration cannot be detached.'
            raise serializers.ValidationError(msg)
        if no_onboarding_data is not None:
            if instance.no_onboarding_config is not None:
                instance.no_onboarding_config = NoOnboardingConfigSerializer(context=config_context).update(
                    instance.no_onboarding_config,
                    no_onboarding_data,
                )
            else:
                validated_data['no_onboarding_config'] = NoOnboardingConfigSerializer(context=config_context).create(
                    no_onboarding_data,
                )

        if onboarding_config_data is not None:
            if instance.onboarding_config:
                instance.onboarding_config = OnboardingConfigSerializer(context=config_context).update(
                    instance.onboarding_config,
                    onboarding_config_data,
                )
            else:
                onboarding_config = OnboardingConfigSerializer(context=config_context).create(onboarding_config_data)
                validated_data['onboarding_config'] = onboarding_config

        device = super().update(instance, validated_data)
        if onboarding_config_data is not None or no_onboarding_data is not None:
            self._check_protocol_policy(device)
        self._save_gds_push_config(device, config_data)
        for config in (device.onboarding_config, device.no_onboarding_config):
            if config is not None:
                audit_assignments(config, device=device, actor=getattr(self.context.get('request'), 'user', None))
        return device
