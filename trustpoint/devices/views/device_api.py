"""REST API viewsets for device management."""

from typing import ClassVar

from django.utils.translation import gettext_lazy
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets

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
    """

    queryset = DeviceModel.objects.all()
    serializer_class = DeviceSerializer
    action_descriptions: ClassVar[dict[str, str]] = {
        'list': 'Retrieve a list of all devices.',
        'retrieve': 'Retrieve a single device by id.',
        'create': 'Create a new device with name, serial number, and status.',
        'update': 'Update an existing device.',
        'partial_update': 'Partially update an existing device.',
        'destroy': 'Delete a device.',
    }

    def get_view_description(self, html: bool = False) -> str:  # noqa: FBT001, FBT002
        """Return a description for the given action."""
        if hasattr(self, 'action') and self.action in self.action_descriptions:
            return self.action_descriptions[self.action]
        return super().get_view_description(html)
