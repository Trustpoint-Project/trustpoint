"""Compile draft YAML and return the corresponding graph payload."""

from __future__ import annotations

import json
import logging
from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.translation import gettext as _
from django.views import View

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.compiler.errors import CompileError
from workflows2.services.graph import WorkflowGraphService

logger = logging.getLogger(__name__)


def _compile_error_payload(exc: CompileError) -> dict[str, Any]:
    """Build a safe client-facing compile error payload."""
    public_message = str(exc.args[0]) if exc.args else _('Invalid workflow draft')
    payload: dict[str, Any] = {'error': public_message}

    path = getattr(exc, 'path', None)
    if path:
        payload['path'] = str(path)

    return payload


class Workflow2GraphFromYamlView(LoginRequiredMixin, View):
    """Compile draft YAML and return the same graph structure as saved definitions.

    The editor uses this endpoint to keep the graph usable while the YAML is
    still being edited.
    """

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Return graph JSON for the posted YAML draft."""
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': _('Invalid JSON body')}, status=400)

        yaml_text = payload.get('yaml_text', '')
        if not isinstance(yaml_text, str) or not yaml_text.strip():
            return JsonResponse({'error': _('yaml_text missing')}, status=400)

        try:
            ir = compile_workflow_yaml(yaml_text, compiler_version='workflows2-graph-api')
            graph = WorkflowGraphService().graph_from_ir(ir=ir)
            return JsonResponse(graph)

        except CompileError as exc:
            return JsonResponse(_compile_error_payload(exc), status=400)

        except (ValueError, TypeError, KeyError):
            logger.warning('Invalid workflow draft payload during graph preview.', exc_info=True)
            return JsonResponse({'error': _('Invalid workflow draft')}, status=400)

        except Exception:
            logger.exception('Unexpected graph preview failure.')
            return JsonResponse({'error': _('Unable to build graph preview')}, status=500)
