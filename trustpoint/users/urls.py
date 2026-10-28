# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL configuration for the users application."""

from django.conf import settings
from django.contrib.auth import views as auth_views
from django.urls import path

from users.views import (
    ManagedUserPasswordChangeView,
    OTPLoginView,
    PasswordChangeRequiredView,
    TrustpointLoginView,
    TrustpointProfileView,
    UserProfileCertificateAuthenticationView,
    UserProfileClientCertificateActionView,
    UserProfileDeleteView,
    UserProfileDetailsView,
    UserProfilePasswordChangeView,
    UserProfileResetOTPView,
    UserProfileRoleView,
)

app_name = 'users'
urlpatterns = [
    path('profile/', TrustpointProfileView.as_view(), name='profile'),
    path('profile/details/', UserProfileDetailsView.as_view(), name='profile_details'),
    path('profile/role/', UserProfileRoleView.as_view(), name='profile_role'),
    path('profile/password/', UserProfilePasswordChangeView.as_view(), name='profile_password'),
    path('profile/delete/', UserProfileDeleteView.as_view(), name='profile_delete'),
    path('profile/<int:pk>/delete/', UserProfileDeleteView.as_view(), name='user-profile-delete'),
    path(
        'profile/<int:pk>/password/',
        ManagedUserPasswordChangeView.as_view(),
        name='user-profile-password',
    ),
    path('profile/reset-otp/', UserProfileResetOTPView.as_view(), name='profile_reset_otp'),
    path(
        'profile/certificate-authentication/',
        UserProfileCertificateAuthenticationView.as_view(),
        name='profile_certificate_authentication',
    ),
    path(
        'profile/certificate-authentication/<int:pk>/<str:action>/',
        UserProfileClientCertificateActionView.as_view(),
        name='profile_client_certificate_action',
    ),
    path('login/', TrustpointLoginView.as_view(template_name='users/login.html'), name='login'),
    path('profile/<int:pk>/', TrustpointProfileView.as_view(), name='user-profile'),
    path('password-change-required/', PasswordChangeRequiredView.as_view(), name='password-change-required'),
    path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),
]

if settings.TRUSTPOINT_IS_OPERATIONAL and not settings.TRUSTPOINT_IS_BOOTSTRAP:
    urlpatterns.append(path('login/otp/', OTPLoginView.as_view(), name='otp'))
