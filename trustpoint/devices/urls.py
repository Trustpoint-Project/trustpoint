"""URL configuration for the devices' application."""

from django.urls import path  # type: ignore[import-untyped]

from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.DeviceTableView.as_view(), name='devices'),
    path('add/', views.CreateDeviceView.as_view(), name='add'),
    path('details/<int:pk>/', views.DeviceDetailsView.as_view(), name='details'),
    path('configure/<int:pk>/', views.DeviceConfigureView.as_view(), name='config'),
    path('browser/', views.DeviceOnboardingBrowserLoginView.as_view(), name='browser_login'),
    path('browser/credential-download/<int:pk>/',
         views.DeviceBrowserCredentialDownloadView.as_view(),
         name='browser_domain_credential_download'),
    path(
        'credential-download/browser/<int:pk>/',
        views.DeviceBrowserOnboardingOTPView.as_view(),
        name='browser_otp_view'),
    path(
        'credential-download/browser/<int:pk>/cancel',
        views.DeviceBrowserOnboardingCancelView.as_view(),
        name='browser_cancel'),
    path(
        'download/<int:pk>/',
        views.DownloadPageDispatcherView.as_view(),
        name='download'
    ),
    path(
        'credential/download/<int:pk>/',
        views.DeviceManualCredentialDownloadView.as_view(),
        name='credential-download'
    ),
    path(
        'certificate/download/<int:pk>/',
        views.CertificateDownloadView.as_view(),
        name='certificate-download'
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/',
        views.DeviceCertificateLifecycleManagementSummaryView.as_view(),
        name='certificate_lifecycle_management'),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-client-credential/',
        views.DeviceIssueTlsClientCredential.as_view(),
        name='certificate_lifecycle_management-issue_tls_client_credential'),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-server-credential/',
        views.DeviceIssueTlsServerCredential.as_view(),
        name='certificate_lifecycle_management-issue_tls_server_credential'),
    path('certificate-lifecycle-management/<int:pk>/revoke/<int:credential_pk>/',
         views.DeviceCredentialRevocationView.as_view(),
         name='credential_revocation'),
    path('revoke/<int:pk>/',
         views.DeviceRevocationView.as_view(),
         name='device_revocation'),
    path(
        'help/dispatchDomain/<int:pk>/',
        views.HelpDispatchDomainView.as_view(),
        name='help_dispatch_domain'
    ),
    path(
        'help/dispatchApplication/<int:pk>/',
        views.HelpDispatchApplicationView.as_view(),
        name='help_dispatch_application'
    ),
    path(
        'help/no-onboarding/cmp-shared-secret/<int:pk>/',
        views.NoOnboardingCmpSharedSecretHelpView.as_view(),
        name='help_no-onboarding_cmp-shared-secret'),
    path(
        'help/onboarding/cmp-shared-secret-domain/<int:pk>/',
        views.OnboardingCmpSharedSecretDomainHelpView.as_view(),
        name='help-onboarding_cmp-shared-secret-domain'),
    path(
        'help/onboarding/cmp-idevid-domain/<int:pk>/',
        views.OnboardingCmpIdevidDomainHelpView.as_view(),
        name='help-onboarding_cmp-idevid-domain'),
    path(
        'help/onboarding/cmp-shared-secret-application/<int:pk>/',
        views.OnboardingCmpSharedSecretApplicationHelpView.as_view(),
        name='help-onboarding_cmp-shared-secret-application'),
    path(
        'help/onboarding/cmp-idevid-application/<int:pk>/',
        views.OnboardingCmpIdevidApplicationHelpView.as_view(),
        name='help-onboarding_cmp-idevid-application'),
    path(
        'help/onboarding/cmp-idevid-registration/<int:pk>/',
        views.OnboardingIdevidRegistrationHelpView.as_view(),
        name='help-onboarding_cmp-idevid-registration')
]
