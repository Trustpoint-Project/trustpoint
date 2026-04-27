"""OCSP Responder endpoint for Trustpoint (RFC 6960 compliant)."""
from django.views import View
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from trustpoint.request.message_responder.ocsp import OcspMessageResponder

@csrf_exempt
class OcspResponderView(View):
    """OCSP Responder endpoint (RFC 6960 compliant)."""
    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if request.content_type != 'application/ocsp-request':
            return HttpResponseBadRequest('Invalid content type')
        responder = OcspMessageResponder()
        try:
            response_bytes = responder.handle(request.body)
        except Exception:
            return HttpResponse(status=500, content=b'')
        return HttpResponse(response_bytes, content_type='application/ocsp-response')
