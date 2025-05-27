"""URL configuration for the devices' application."""

from django.urls import path, re_path

from . import views

app_name = 'devices'

urlpatterns = [
    # Main Pages
    path('', views.DeviceTableView.as_view(), name='devices'),
    path('add/', views.CreateDeviceView.as_view(), name='add'),
    path('details/<int:pk>/', views.DeviceDetailsView.as_view(), name='details'),
    # Certificate Lifecycle Management
    path(
        'certificate-lifecycle-management/<int:pk>/',
        views.DeviceCertificateLifecycleManagementSummaryView.as_view(),
        name='certificate_lifecycle_management',
    ),
    # OPC UA GDS
    path(
        'opc-ua-gds/',
        views.OpcUaGdsTableView.as_view(),
        name='opc_ua_gds',
    ),
    path(
        'opc-ua-gds/add/',
        views.CreateOpcUaGdsView.as_view(),
        name='opc_ua_gds-add',
    ),
    # Certificate Lifecycle Management - Credential Issuance
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-client-credential/',
        views.DeviceIssueTlsClientCredential.as_view(),
        name='certificate_lifecycle_management-issue_tls_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-server-credential/',
        views.DeviceIssueTlsServerCredential.as_view(),
        name='certificate_lifecycle_management-issue_tls_server_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-opcua-client-credential/',
        views.DeviceIssueOpcUaClientCredential.as_view(),
        name='certificate_lifecycle_management-issue_opcua_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-opcua-server-credential/',
        views.DeviceIssueOpcUaServerCredential.as_view(),
        name='certificate_lifecycle_management-issue_opcua_server_credential',
    ),
    # Certificate Lifecycle Management - Help Pages
    path(
        'help/dispatchDomain/<int:pk>/', views.HelpDispatchDomainCredentialView.as_view(), name='help_dispatch_domain'
    ),
    path(
        'help/dispatchApplication/<int:pk>/',
        views.HelpDispatchApplicationCredentialView.as_view(),
        name='help_dispatch_application',
    ),
    path(
        'help/dispatchApplication/<int:pk>/<str:certificate_template>/',
        views.HelpDispatchApplicationCredentialTemplateView.as_view(),
        name='help_dispatch_application_template',
    ),
    path(
        'help/no-onboarding/cmp-shared-secret/<int:pk>/<str:certificate_template>/',
        views.NoOnboardingCmpSharedSecretHelpView.as_view(),
        name='help_no-onboarding_cmp-shared-secret',
    ),
    path(
        'help/onboarding/cmp-shared-secret/<int:pk>/',
        views.OnboardingCmpSharedSecretHelpView.as_view(),
        name='help-onboarding_cmp-shared-secret',
    ),
    path(
        'help/onboarding/cmp-idevid/<int:pk>/',
        views.OnboardingCmpIdevidHelpView.as_view(),
        name='help-onboarding_cmp-idevid',
    ),
    path(
        'help/onboarding/cmp-idevid-registration/<int:pk>/',
        views.OnboardingIdevidRegistrationHelpView.as_view(),
        name='help-onboarding_cmp-idevid-registration',
    ),
    path(
        'help/onboarding/cmp-application-credentials/<int:pk>/<str:certificate_template>/',
        views.OnboardingCmpApplicationCredentialsHelpView.as_view(),
        name='help-onboarding_cmp-application-credentials',
    ),
    path(
        'help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
        views.NoOnboardingEstUsernamePasswordHelpView.as_view(),
        name='help-no-onboarding_est-username-password',
    ),
    path(
        'help/onboarding/est-username-password/<int:pk>/',
        views.OnboardingEstUsernamePasswordHelpView.as_view(),
        name='help-onboarding_est-username-password',
    ),
    path(
        'help/onboarding/est-application-credentials/<int:pk>/<str:certificate_template>/',
        views.OnboardingEstApplicationCredentialsHelpView.as_view(),
        name='help-onboarding_est-application-credentials',
    ),
    path(
        'help/onboarding/ldevid/<int:pk>/',
        views.OnboardingEstApplicationCredentialsHelpView.as_view(),
        name='help-onboarding_est-ldevid',
    ),
    path(
        'help/no-onboarding/opc-ua-gds/est-username-password/<int:pk>/',
        views.NoOnboardingEstOpcUaGdsUsernamePasswordHelpView.as_view(),
        name='help-no-onboarding_est-opcua-gds-username-password',
    ),
    # Certificate Lifecycle Management - Downloads
    path('download/<int:pk>/', views.DownloadPageDispatcherView.as_view(), name='download'),
    path('certificate/download/<int:pk>/', views.CertificateDownloadView.as_view(), name='certificate-download'),
    path(
        'credential/download/<int:pk>/', views.DeviceManualCredentialDownloadView.as_view(), name='credential-download'
    ),
    path(
        'credential-download/browser/<int:pk>/', views.DeviceBrowserOnboardingOTPView.as_view(), name='browser_otp_view'
    ),
    path('browser/', views.DeviceOnboardingBrowserLoginView.as_view(), name='browser_login'),
    # Revoke Views
    path('browser/', views.DeviceOnboardingBrowserLoginView.as_view(), name='browser_login'),
    path(
        'browser/credential-download/<int:pk>/',
        views.DeviceBrowserCredentialDownloadView.as_view(),
        name='browser_domain_credential_download',
    ),
    path(
        'credential-download/browser/<int:pk>/cancel',
        views.DeviceBrowserOnboardingCancelView.as_view(),
        name='browser_cancel',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/revoke/<int:credential_pk>/',
        views.DeviceCredentialRevocationView.as_view(),
        name='credential_revocation',
    ),
    path('revoke/<int:pk>/', views.DeviceRevocationView.as_view(), name='device_revocation'),
    re_path(
        r'^delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        views.DeviceBulkDeleteView.as_view(),
        name='device_delete',
    ),
]
