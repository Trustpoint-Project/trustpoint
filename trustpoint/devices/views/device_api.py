"""REST API viewsets for device management."""

from typing import Any, ClassVar

from django.utils.translation import gettext_lazy
from drf_spectacular.utils import OpenApiExample, extend_schema
from rest_framework import viewsets
from rest_framework.request import Request
from rest_framework.response import Response

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from devices.serializers import DeviceSerializer

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

@extend_schema(tags=['Device'])
class DeviceViewSet(viewsets.ModelViewSet[DeviceModel]):
    """ViewSet for managing Device instances.

    Supports standard CRUD operations such as list, retrieve,
    create, update, and delete.

    When creating a device, you can optionally include an onboarding_config
    to set up automatic certificate enrollment. The API supports both
    enum names (e.g., "CMP", "EST") and integer values for protocols.
    """

    queryset = DeviceModel.objects.all()
    serializer_class = DeviceSerializer
    action_descriptions: ClassVar[dict[str, str]] = {
        'list': 'Retrieve a list of all devices.',
        'retrieve': 'Retrieve a single device by id.',
        'create': (
            'Create a new device with name, serial number, and status. '
            'Optionally include onboarding_config for automatic certificate enrollment.'
        ),
        'update': 'Update an existing device.',
        'partial_update': 'Partially update an existing device.',
        'destroy': 'Delete a device.',
    }

    @extend_schema(
        description=(
            'Create a new device with optional onboarding configuration.\n\n'
            '**Onboarding Protocol Values:**\n'
            '- `0` = MANUAL: Manual certificate issuance\n'
            '- `1` = CMP_IDEVID: CMP with manufacturer IDevID certificate\n'
            '- `2` = CMP_SHARED_SECRET: CMP with pre-shared secret\n'
            '- `3` = EST_IDEVID: EST with manufacturer IDevID certificate\n'
            '- `4` = EST_USERNAME_PASSWORD: EST with username/password\n'
            '- `5` = AOKI: Automated zero-touch onboarding\n'
            '- `6` = BRSKI: Bootstrapping protocol (future)\n'
            '- `7` = OPC_GDS_PUSH: OPC UA Global Discovery Server\n'
            '- `8` = REST_USERNAME_PASSWORD: REST API with credentials\n'
            '- `9` = AGENT: Trustpoint agent-managed\n\n'
            '**PKI Protocol Values** (supports both integers and string names):\n'
            '- `1` or `"CMP"`: Certificate Management Protocol\n'
            '- `2` or `"EST"`: Enrollment over Secure Transport\n'
            '- `4` or `"OPC_GDS_PUSH"`: OPC UA GDS Push\n'
            '- `8` or `"REST"`: REST API\n\n'
            '**Auto-Generated Credentials:**\n'
            '- CMP_SHARED_SECRET (2): Auto-generates `cmp_shared_secret` if omitted\n'
            '- EST_USERNAME_PASSWORD (4) or REST_USERNAME_PASSWORD (8): Auto-generates `est_password` if omitted\n'
            '- Generated secrets are cryptographically secure 256-bit values'
        ),
        examples=[
            OpenApiExample(
                'Basic Device without Onboarding',
                value={
                    'common_name': 'device-001',
                    'serial_number': 'SN123456789',
                },
                request_only=True,
                description='Minimal device creation without onboarding configuration',
            ),
            OpenApiExample(
                'CMP with Auto-Generated Shared Secret',
                value={
                    'common_name': 'cmp-device-auto',
                    'serial_number': 'SN-CMP-001',
                    'domain': 1,
                    'onboarding_config': {
                        'onboarding_protocol': 2,
                        'pki_protocols': ['CMP'],
                    },
                },
                request_only=True,
                description=(
                    'Uses CMP_SHARED_SECRET (2) protocol. '
                    'Shared secret is automatically generated and returned in response.'
                ),
            ),
            OpenApiExample(
                'CMP with Custom Shared Secret',
                value={
                    'common_name': 'cmp-device-custom',
                    'serial_number': 'SN-CMP-002',
                    'domain': 1,
                    'onboarding_config': {
                        'onboarding_protocol': 2,
                        'cmp_shared_secret': 'my-custom-secret-123',
                        'pki_protocols': [1],
                    },
                },
                request_only=True,
                description='CMP with user-provided shared secret. PKI protocol as integer (1=CMP).',
            ),
            OpenApiExample(
                'EST with Username & Password',
                value={
                    'common_name': 'est-device',
                    'serial_number': 'SN-EST-001',
                    'domain': 1,
                    'onboarding_config': {
                        'onboarding_protocol': 4,
                        'est_password': 'secure-password-456',
                        'pki_protocols': ['EST'],
                        'trust_store': 5,
                    },
                },
                request_only=True,
                description=(
                    'Uses EST_USERNAME_PASSWORD (4) protocol. '
                    'Password can be omitted for auto-generation.'
                ),
            ),
            OpenApiExample(
                'Multiple PKI Protocols (Mixed Format)',
                value={
                    'common_name': 'multi-protocol-device',
                    'serial_number': 'SN-MULTI-001',
                    'domain': 1,
                    'ip_address': '192.168.1.100',
                    'onboarding_config': {
                        'onboarding_protocol': 2,
                        'pki_protocols': ['CMP', 2, 'REST'],
                        'trust_store': 5,
                    },
                },
                request_only=True,
                description=(
                    'Device supporting multiple PKI protocols. '
                    'Shows mixed format: strings ("CMP", "REST") and integers (2=EST).'
                ),
            ),
            OpenApiExample(
                'OPC UA GDS Push Device',
                value={
                    'common_name': 'opc-server',
                    'serial_number': 'SN-OPC-001',
                    'domain': 1,
                    'ip_address': '192.168.1.50',
                    'opc_server_port': 4840,
                    'device_type': 2,
                    'onboarding_config': {
                        'onboarding_protocol': 7,
                        'opc_user': 'admin',
                        'opc_password': 'opc-secure-pass',
                        'pki_protocols': ['OPC_GDS_PUSH'],
                        'opc_trust_store': 10,
                    },
                },
                request_only=True,
                description='OPC UA GDS Push device with all required OPC-specific fields.',
            ),
        ]
    )
    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Create a new device, optionally with onboarding configuration."""
        return super().create(request, *args, **kwargs)

    def get_view_description(self, html: bool = False) -> str:  # noqa: FBT001, FBT002
        """Return a description for the given action."""
        if hasattr(self, 'action') and self.action in self.action_descriptions:
            return self.action_descriptions[self.action]
        return super().get_view_description(html)

