# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL configuration for the REST PKI API endpoints."""

from django.urls import path

from .api_views import ApplicationCertificateEnrollView, CertificateRevokeView

urlpatterns = [
    path(
        'rest-pki/enroll/',
        ApplicationCertificateEnrollView.as_view(),
        name='rest-pki-enroll',
    ),
    path(
        'rest-pki/revoke/',
        CertificateRevokeView.as_view(),
        name='rest-pki-revoke',
    ),
]
