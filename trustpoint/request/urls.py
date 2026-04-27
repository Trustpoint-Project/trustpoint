"""URL configuration for the request app."""
from django.urls import path
from trustpoint.request.message_responder.ocsp import OcspMessageResponder
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest

class OcspResponderView(csrf_exempt):
    """Django view for OCSP endpoint."""
    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method != 'POST' or request.content_type != 'application/ocsp-request':
            return HttpResponseBadRequest('Invalid OCSP request')
        responder = OcspMessageResponder()
        try:
            response_bytes = responder.handle(request.body)
        except Exception:
            return HttpResponse(status=500, content=b'')
        return HttpResponse(response_bytes, content_type='application/ocsp-response')

urlpatterns = [
    path('ocsp/', OcspResponderView()),
]

