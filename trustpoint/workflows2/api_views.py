"""DRF API views for Workflow 2 definitions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiExample, extend_schema
from rest_framework import status, viewsets
from rest_framework.response import Response

from workflows2.models import Workflow2Definition
from workflows2.serializers import Workflow2DefinitionSerializer
from workflows2.services.definitions import WorkflowDefinitionService

if TYPE_CHECKING:
    from rest_framework.request import Request


MINIMAL_WORKFLOW_YAML_EXAMPLE = """\
schema: trustpoint.workflow.v2
name: Minimal workflow
enabled: true

trigger:
    on: certificate.issued
    sources:
        trustpoint: true

apply: []

workflow:
    start: done
    steps:
        done:
            type: set
            vars: {}
    flow: []
"""

YAML_REQUEST_EXAMPLE = OpenApiExample(
        name='Example workflow v2 YAML',
        value=MINIMAL_WORKFLOW_YAML_EXAMPLE,
        request_only=True,
        media_type='application/yaml',
)


@extend_schema(tags=['Workflows2'])
class Workflow2DefinitionViewSet(viewsets.ModelViewSet[Workflow2Definition]):
    """CRUD API for Workflow 2 definitions.

    Create and update operations accept the entire request body as YAML text.
    """

    queryset = Workflow2Definition.objects.order_by('-created_at')
    serializer_class = Workflow2DefinitionSerializer

    @staticmethod
    def _request_yaml_text(request: Request) -> str:
        """Return UTF-8 YAML text from the raw request body."""
        try:
            yaml_text = request.body.decode('utf-8')
        except UnicodeDecodeError as exc:
            msg = f'Request body must be UTF-8 encoded YAML: {exc!s}'
            raise ValueError(msg) from exc

        if not yaml_text.strip():
            msg = 'Request body must contain YAML text.'
            raise ValueError(msg)
        return yaml_text

    @extend_schema(
        request={'application/yaml': OpenApiTypes.STR},
        examples=[YAML_REQUEST_EXAMPLE],
    )
    def create(self, request: Request, *_args: object, **_kwargs: object) -> Response:
        """Create a definition from YAML text in the request body."""
        try:
            yaml_text = self._request_yaml_text(request)
        except ValueError as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        svc = WorkflowDefinitionService()
        obj, res = svc.create_definition(name=None, enabled=None, yaml_text=yaml_text)

        if not res.ok:
            return Response({'detail': res.error or 'Workflow compilation failed.'}, status=status.HTTP_400_BAD_REQUEST)
        if obj is None:
            return Response({'detail': 'Workflow save succeeded without returning a definition.'}, status=500)

        serializer = self.get_serializer(obj)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @extend_schema(
        request={'application/yaml': OpenApiTypes.STR},
        examples=[YAML_REQUEST_EXAMPLE],
    )
    def update(self, request: Request, *_args: object, **_kwargs: object) -> Response:
        """Update a definition from YAML text in the request body."""
        try:
            yaml_text = self._request_yaml_text(request)
        except ValueError as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        definition = self.get_object()
        svc = WorkflowDefinitionService()
        updated, res = svc.update_definition(
            definition=definition,
            name=None,
            enabled=None,
            yaml_text=yaml_text,
        )

        if not res.ok:
            return Response({'detail': res.error or 'Workflow compilation failed.'}, status=status.HTTP_400_BAD_REQUEST)
        if updated is None:
            return Response({'detail': 'Workflow update succeeded without returning a definition.'}, status=500)

        serializer = self.get_serializer(updated)
        return Response(serializer.data)

    @extend_schema(
        request={'application/yaml': OpenApiTypes.STR},
        examples=[YAML_REQUEST_EXAMPLE],
    )
    def partial_update(self, request: Request, *_args: object, **_kwargs: object) -> Response:
        """Treat PATCH like PUT because updates are YAML document replacements."""
        return self.update(request, *_args, **_kwargs)
