# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL configuration for the SCEP protocol endpoint."""

from django.urls import re_path

from scep import views

app_name = 'scep'

urlpatterns = [
    re_path(r'^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/$', views.ScepView.as_view(), name='endpoint-profile'),
    re_path(r'^(?P<domain>[^/]+)/$', views.ScepView.as_view(), name='endpoint'),
]
