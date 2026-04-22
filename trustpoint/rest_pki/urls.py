"""URL configuration for the 'rest_pki' app."""

from django.urls import re_path

from rest_pki import views

app_name = 'rest_pki'

urlpatterns = [
    # Enroll: domain + optional cert_profile
    re_path(
        r'^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/enroll/?$',
        views.RestEnrollView.as_view(),
        name='enroll',
    ),
    # Enroll: domain only (cert_profile defaults to domain_credential)
    re_path(
        r'^(?P<domain>[^/]+)/enroll/?$',
        views.RestEnrollView.as_view(),
        name='enroll-default-profile',
    ),
    # Re-enroll: domain + cert_profile
    re_path(
        r'^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/reenroll/?$',
        views.RestReEnrollView.as_view(),
        name='reenroll',
    ),
]
