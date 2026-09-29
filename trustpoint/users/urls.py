# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL configuration for the users application."""

from django.conf import settings
from django.contrib.auth import views as auth_views
from django.urls import path

from users.views import OTPLoginView, TrustpointLoginView

app_name = 'users'
urlpatterns = [
    path('login/', TrustpointLoginView.as_view(template_name='users/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),
]

if settings.TRUSTPOINT_IS_OPERATIONAL and not settings.TRUSTPOINT_IS_BOOTSTRAP:
    urlpatterns.append(path('login/otp/', OTPLoginView.as_view(), name='otp'))
