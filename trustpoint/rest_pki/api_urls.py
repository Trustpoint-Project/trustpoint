"""URL configuration for the REST PKI API endpoints."""

from django.urls import path

from .api_views import ApplicationCertificateEnrollView

urlpatterns = [
    path(
        'rest-pki/enroll/',
        ApplicationCertificateEnrollView.as_view(),
        name='rest-pki-enroll',
    ),
]
