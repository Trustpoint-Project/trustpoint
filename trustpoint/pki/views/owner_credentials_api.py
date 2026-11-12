# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""REST API ViewSet for Owner Credential (DevOwnerID) management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from django.db.models import ProtectedError
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    extend_schema,
)
from rest_framework import filters, status, viewsets
from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.response import Response

from pki.models import RemoteIssuedCredentialModel
from pki.serializer.owner_credential import (
    OwnerCredentialFileImportSerializer,
    OwnerCredentialSerializer,
)
from trustpoint.logger import LoggerMixin
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from rest_framework.request import Request


class CanManageOwnerCredentials(BasePermission):
    """Keep reads authenticated and guard DevOwnerID management."""

    def has_permission(self, request: Request, _view: Any) -> bool:
        """Apply the existing device-management permission."""
        if not request.user or not request.user.is_authenticated:
            return False
        if request.method in SAFE_METHODS:
            return True
        return request.user.has_perm(AppPermissions.MANAGE_DEVICES)


@extend_schema(tags=['DevOwnerID'])
class DevOwnerIdViewSet(LoggerMixin, viewsets.GenericViewSet[RemoteIssuedCredentialModel]):
    """ViewSet for managing DevOwnerID credential rows via REST API.

    Endpoints
    ---------
    GET    /api/devownerid/                         - list all DevOwnerIDs
    POST   /api/devownerid/                         - import a DevOwnerID from files
    GET    /api/devownerid/{id}/                    - retrieve a single DevOwnerID
    DELETE /api/devownerid/{id}/                    - delete a DevOwnerID
    """

    queryset = RemoteIssuedCredentialModel.objects.filter(
        issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID
    ).order_by('-created_at')
    serializer_class = OwnerCredentialSerializer
    permission_classes = (CanManageOwnerCredentials,)
    filter_backends = (
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    )
    filterset_fields: ClassVar = ['common_name', 'ca']
    search_fields: ClassVar = ['common_name']
    ordering_fields: ClassVar = ['common_name', 'created_at']

    @extend_schema(
        summary='List DevOwnerIDs',
        description='Retrieve all DevOwnerID credential rows.',
        responses={200: OwnerCredentialSerializer(many=True)},
    )
    def list(self, _request: Request) -> Response:
        """Return all DevOwnerID instances."""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary='Retrieve DevOwnerID',
        description='Retrieve details of a single DevOwnerID by ID.',
        responses={200: OwnerCredentialSerializer},
    )
    def retrieve(self, _request: Request, pk: int | None = None, **_kwargs: Any) -> Response:
        """Return a single DevOwnerID instance."""
        del pk
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary='Create DevOwnerID',
        description='Import a DevOwnerID from PEM certificate and private-key files.',
        request=OwnerCredentialFileImportSerializer,
        responses={
            201: OwnerCredentialSerializer,
            400: OpenApiTypes.OBJECT,
        },
    )
    def create(self, request: Request) -> Response:
        """Import a DevOwnerID from files."""
        serializer = OwnerCredentialFileImportSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(OwnerCredentialSerializer(instance).data, status=status.HTTP_201_CREATED)

    @extend_schema(
        summary='Delete DevOwnerID',
        description='Delete a DevOwnerID and all its associated issued credentials.',
        responses={
            204: None,
            404: OpenApiTypes.OBJECT,
            409: OpenApiTypes.OBJECT,
        },
    )
    def destroy(self, _request: Request, pk: int | None = None, **_kwargs: Any) -> Response:
        """Delete a DevOwnerID instance."""
        del pk
        instance = self.get_object()
        try:
            instance.delete()
        except ProtectedError:
            return Response(
                {'detail': 'Cannot delete DevOwnerID: it is referenced by other objects.'},
                status=status.HTTP_409_CONFLICT,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)
