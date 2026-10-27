# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for REST PKI certificate enrollment and re-enrollment."""

from typing import Any, Literal, cast

from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from request.enrollment import rest_enrollment
from request.message_responder import RestErrorMessageResponder
from request.request_context import RestCertificateRequestContext
from trustpoint.logger import LoggerMixin
from workflows2.events.request_events import Events


@method_decorator(csrf_exempt, name='dispatch')
class RestCertificateEnrollmentView(LoggerMixin, View):
    """Run the shared REST certificate enrollment pipeline."""

    operation: Literal['enroll', 'reenroll'] = 'enroll'
    EVENT = Events.rest_enroll

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for REST certificate enrollment."""
        del args
        self.logger.info('REST %s request received: method=%s path=%s', self.operation, request.method, request.path)

        domain_name = cast('str', kwargs.get('domain'))
        cert_profile = cast('str | None', kwargs.get('cert_profile'))

        try:
            ctx = RestCertificateRequestContext(
                raw_message=request,
                protocol='rest',
                operation=self.operation,
                domain_str=domain_name,
                cert_profile_str=cert_profile,
                event=self.EVENT,
            )
        except Exception:
            err_msg = 'Failed to set up REST request context.'
            self.logger.exception(err_msg)
            return HttpResponse(err_msg, status=500, content_type='application/json')

        orchestrator = rest_enrollment(ctx, operation=self.operation)
        try:
            orchestrator.run()
        except Exception:
            self.logger.exception('Error processing REST %s request', self.operation)
            RestErrorMessageResponder.build_response(orchestrator.context)

        return orchestrator.context.to_http_response()


class RestEnrollView(RestCertificateEnrollmentView):
    """Handle initial REST certificate enrollment."""


class RestReEnrollView(RestCertificateEnrollmentView):
    """Handles REST certificate re-enrollment requests.

    Request body (JSON)::

        {
            "csr": "<PEM or Base64-DER encoded PKCS#10 CSR>"
        }

    Response (JSON, HTTP 200)::

        {
            "certificate": "<PEM certificate>",
            "certificate_chain": ["<PEM ca cert>", ...]
        }
    """

    operation = 'reenroll'
    EVENT = Events.rest_reenroll
