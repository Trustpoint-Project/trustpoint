
"""OCSP Responder endpoint for Trustpoint (RFC 6960 compliant)."""
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from trustpoint.request.message_responder.ocsp import OcspMessageResponder

@csrf_exempt
class OcspResponderView(View):
    """OCSP Responder endpoint (RFC 6960 compliant)."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle OCSP POST requests as per RFC 6960.

        Returns a DER-encoded OCSP response or error.
        """
        if request.content_type != 'application/ocsp-request':
            return HttpResponseBadRequest('Invalid content type')
        responder = OcspMessageResponder()
        try:
            response_bytes = responder.handle(request.body)
        except ValueError:
            return HttpResponse(status=400, content=b'')
        # Only catch ValueError, let other exceptions propagate for debugging
        return HttpResponse(response_bytes, content_type='application/ocsp-response')
