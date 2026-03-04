# workflows2/views/format_yaml.py
from __future__ import annotations

import json
from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, JsonResponse
from django.views import View

from workflows2.compiler.yaml_format import format_yaml_text


class FormatYamlView(LoginRequiredMixin, View):
    """
    POST {"yaml": "<text>"} -> {"ok": true, "yaml": "<formatted>"}
    """

    def post(self, request: HttpRequest) -> JsonResponse:
        try:
            data: dict[str, Any] = json.loads(request.body.decode("utf-8") or "{}")
        except Exception:
            return JsonResponse({"ok": False, "error": "Invalid JSON body."}, status=400)

        yaml_text = data.get("yaml")
        if not isinstance(yaml_text, str):
            return JsonResponse({"ok": False, "error": "Missing 'yaml' string."}, status=400)

        try:
            formatted = format_yaml_text(yaml_text)
            return JsonResponse({"ok": True, "yaml": formatted})
        except Exception as e:  # noqa: BLE001
            return JsonResponse({"ok": False, "error": f"YAML format failed: {e}"}, status=400)