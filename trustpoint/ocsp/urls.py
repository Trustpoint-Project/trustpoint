"""URL configuration for OCSP app."""
from django.urls import path
from .views import OcspResponderView

urlpatterns = [
    path('ocsp/', OcspResponderView.as_view(), name='ocsp-responder'),
]
