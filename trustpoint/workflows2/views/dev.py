# workflows2/views.py
from __future__ import annotations

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views import View

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.compiler.errors import CompileError


class Workflow2DevView(LoginRequiredMixin, View):
    """
    Dev-only YAML → IR compiler playground.

    GET  renders a textarea
    POST compiles YAML and shows IR or errors
    """

    template_name = "workflows2/dev.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        if not settings.DEBUG:
            return HttpResponse("Not available.", status=404)

        return render(
            request,
            self.template_name,
            {
                "yaml_text": DEFAULT_SAMPLE_YAML,
                "ir_json": None,
                "error": None,
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        if not settings.DEBUG:
            return HttpResponse("Not available.", status=404)

        yaml_text = request.POST.get("yaml_text", "") or ""
        ir_json = None
        error = None

        try:
            ir_json = compile_workflow_yaml(yaml_text, compiler_version="workflows2-dev")
        except CompileError as e:
            error = str(e)
        except Exception as e:  # noqa: BLE001 (dev page)
            error = f"Unexpected error: {e!s}"

        return render(
            request,
            self.template_name,
            {
                "yaml_text": yaml_text,
                "ir_json": ir_json,
                "error": error,
            },
        )


DEFAULT_SAMPLE_YAML = """\
schema: trustpoint.workflow.v2
name: Example v2
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true
    ca_ids: []
    domain_ids: []
    device_ids: []

apply:
  - exists: ${event.device}

workflow:
  start: notify

  steps:
    notify:
      type: email
      title: Send email
      to: [test.test@gmx.de]
      subject: "New device: ${event.device.common_name}"
      body: |
        Common Name: ${event.device.common_name}
        Full event: ${json(event)}

    call_status:
      type: webhook
      method: POST
      url: https://example.com/status
      capture:
        status_code: vars.http_status

    route_by_status:
      type: logic
      cases:
        - when:
            compare:
              left: ${vars.http_status}
              op: "=="
              right: 200
          outcome: ok
      default: fail

    stop_ok:
      type: set
      vars: {}

    stop_fail:
      type: stop
      reason: Done (fail)

  flow:
    - from: notify
      to: call_status
    - from: call_status
      to: route_by_status
    - from: route_by_status
      on: ok
      to: stop_ok
    - from: route_by_status
      on: fail
      to: stop_fail
"""
