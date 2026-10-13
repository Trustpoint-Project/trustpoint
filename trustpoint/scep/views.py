# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""SCEP protocol endpoint (RFC 8894): GetCACaps, GetCACert and POST PKIOperation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from pki.models.domain import DomainModel
from scep.handler import ScepPkiOperationHandler
from scep.protocol.cms import build_degenerate_certificates_only
from scep.protocol.oids import (
    CA_CAPABILITIES,
    CONTENT_TYPE_CA_RA_CERT,
    MAX_REQUEST_BYTES,
)
from scep.services import get_serving_credential
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pki.models import CredentialModel


def _text(message: str, status: int) -> HttpResponse:
    return HttpResponse(message, status=status, content_type='text/plain')


@method_decorator(csrf_exempt, name='dispatch')
class ScepView(LoggerMixin, View):
    """Single SCEP endpoint; the operation is selected with the ``operation`` query parameter."""

    http_method_names = ('get', 'post')

    def _resolve(self, request: HttpRequest, domain_name: str) -> tuple[DomainModel, CredentialModel] | HttpResponse:
        if not (request.is_secure() or settings.DEBUG):
            return _text('SCEP requires HTTPS.', 403)
        domain = DomainModel.objects.filter(unique_name=domain_name).first()
        credential = get_serving_credential(domain) if domain else None
        if domain is None or credential is None:
            return _text('SCEP is not available for this domain.', 404)
        return domain, credential

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GetCACaps and GetCACert; everything else is rejected explicitly."""
        del args
        resolved = self._resolve(request, kwargs['domain'])
        if isinstance(resolved, HttpResponse):
            return resolved
        _, credential = resolved
        operation = request.GET.get('operation', '')

        if operation == 'GetCACaps':
            return HttpResponse('\n'.join(CA_CAPABILITIES) + '\n', content_type='text/plain')
        if operation == 'GetCACert':
            certificates = [credential.get_certificate(), *credential.get_certificate_chain()]
            return HttpResponse(
                build_degenerate_certificates_only(certificates), content_type=CONTENT_TYPE_CA_RA_CERT
            )
        if operation == 'PKIOperation':
            response = _text('PKIOperation must be sent with HTTP POST.', 405)
            response['Allow'] = 'POST'
            return response
        if operation in {'GetNextCACert', 'GetCert', 'GetCRL', 'CertPoll'}:
            return _text(f'{operation} is not supported.', 501)
        return _text('Unknown SCEP operation.', 400)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST PKIOperation."""
        del args
        resolved = self._resolve(request, kwargs['domain'])
        if isinstance(resolved, HttpResponse):
            return resolved
        domain, credential = resolved
        if request.GET.get('operation', 'PKIOperation') != 'PKIOperation':
            return _text('Unsupported operation for POST.', 400)

        declared = request.META.get('CONTENT_LENGTH', '')
        if declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
            return _text('Request too large.', 413)
        body = request.read(MAX_REQUEST_BYTES + 1)
        if len(body) > MAX_REQUEST_BYTES:
            return _text('Request too large.', 413)

        try:
            result = ScepPkiOperationHandler(domain, credential, request, kwargs.get('cert_profile')).handle(body)
        except Exception:
            self.logger.exception('SCEP: server error')
            return _text('Internal server error.', 500)
        return HttpResponse(result.body, status=result.status, content_type=result.content_type)
