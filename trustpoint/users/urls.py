# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL configuration for the users application."""

from django.contrib.auth import views as auth_views
from django.urls import path

from users.views import PasswordChangeRequiredView, TrustpointLoginView, TrustpointProfileView

app_name = 'users'
urlpatterns = [
    path('login/', TrustpointLoginView.as_view(template_name='users/login.html'), name='login'),
    path('profile/', TrustpointProfileView.as_view(), name='profile'),
    path('profile/<int:pk>/', TrustpointProfileView.as_view(), name='user-profile'),
    path('password-change-required/', PasswordChangeRequiredView.as_view(), name='password-change-required'),
    path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),
]

