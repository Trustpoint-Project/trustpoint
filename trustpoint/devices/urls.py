"""URL configuration for the devices' application."""

from django.urls import path, re_path
from help_pages import devices_help_views

from trustpoint.page_context import DEVICES_PAGE_DEVICES_SUBCATEGORY, DEVICES_PAGE_OPC_UA_SUBCATEGORY

from . import views

app_name = 'devices'

urlpatterns = [
    # Main Pages
    path('', views.DeviceTableView.as_view(), name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}'),
    path('opc-ua-gds/', views.OpcUaGdsTableView.as_view(), name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}'),

    # Details Views
    path('details/<int:pk>/', views.DeviceDetailsView.as_view(), name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_details'),
    path(
        'opc-ua-gds/details/<int:pk>/',
        views.OpcUaDeviceDetailsView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_details'
    ),

    # Create Views
    path('create/', views.CreateDeviceView.as_view(), name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_create'),
    path('opc-ua-gds/create/', views.CreateOpcUaGdsView.as_view(), name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_create'),

    # Certificate Lifecycle Management Views
    path(
        'certificate-lifecycle-management/<int:pk>/',
        views.DeviceCertificateLifecycleManagementSummaryView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management',
    ),
    path(
        'opc-us-gds/certificate-lifecycle-management/<int:pk>/',
        views.OpcUaGdsCertificateLifecycleManagementSummaryView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management'
    ),


    # Certificate Lifecycle Management - Credential Issuance
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-client-credential/',
        views.DeviceIssueTlsClientCredential.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-server-credential/',
        views.DeviceIssueTlsServerCredential.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_server_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-opcua-client-credential/',
        views.DeviceIssueOpcUaClientCredential.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-opcua-server-credential/',
        views.DeviceIssueOpcUaServerCredential.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_server_credential',
    ),

    path(
        'opc-us-gds/certificate-lifecycle-management/<int:pk>/issue-tls-client-credential/',
        views.DeviceIssueTlsClientCredential.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_client_credential',
    ),
    path(
        'opc-us-gds/certificate-lifecycle-management/<int:pk>/issue-tls-server-credential/',
        views.DeviceIssueTlsServerCredential.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_server_credential',
    ),
    path(
        'opc-us-gds/certificate-lifecycle-management/<int:pk>/issue-opcua-client-credential/',
        views.DeviceIssueOpcUaClientCredential.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_client_credential',
    ),
    path(
        'opc-us-gds/certificate-lifecycle-management/<int:pk>/issue-opcua-server-credential/',
        views.DeviceIssueOpcUaServerCredential.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_server_credential',
    ),


    # Certificate Lifecycle Management - Help Pages
    path(
        'help/dispatch-domain/<int:pk>/',
        devices_help_views.HelpDispatchDomainCredentialView.as_view(),
        name='help_dispatch_domain',
    ),
    path(
        'help/dispatch-device-type-redirect/<int:pk>/',
        devices_help_views.HelpDispatchDeviceTypeRedirectView.as_view(),
        name='help_dispatch_device_type_redirect',
    ),
    path(
        'help/dispatch-opcua_gds/<int:pk>/',
        devices_help_views.HelpDispatchOpcUaGdsView.as_view(),
        name='help_dispatch_opcua_gds',
    ),
    path(
        'help/dispatch-application/<int:pk>/',
        devices_help_views.HelpDispatchApplicationCredentialView.as_view(),
        name='help_dispatch_application',
    ),
    path(
        'help/dispatch-application/<int:pk>/<str:certificate_template>/',
        devices_help_views.HelpDispatchApplicationCredentialTemplateView.as_view(),
        name='help_dispatch_application_template',
    ),
    path(
        'help/no-onboarding/cmp-shared-secret/<int:pk>/<str:certificate_template>/',
        devices_help_views.NoOnboardingCmpSharedSecretHelpView.as_view(),
        name='help_no-onboarding_cmp-shared-secret',
    ),
    path(
        'help/onboarding/cmp-shared-secret/<int:pk>/',
        devices_help_views.OnboardingCmpSharedSecretHelpView.as_view(),
        name='help-onboarding_cmp-shared-secret',
    ),
    path(
        'help/onboarding/cmp-idevid/<int:pk>/',
        devices_help_views.OnboardingCmpIdevidHelpView.as_view(),
        name='help-onboarding_cmp-idevid',
    ),
    path(
        'help/onboarding/cmp-idevid-registration/<int:pk>/',
        devices_help_views.OnboardingCmpIdevidRegistrationHelpView.as_view(),
        name='help-onboarding_cmp-idevid-registration',
    ),
    path(
        'help/onboarding/cmp-application-credentials/<int:pk>/<str:certificate_template>/',
        devices_help_views.OnboardingCmpApplicationCredentialsHelpView.as_view(),
        name='help-onboarding_cmp-application-credentials',
    ),
    path(
        'help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
        devices_help_views.NoOnboardingEstUsernamePasswordHelpView.as_view(),
        name='help-no-onboarding_est-username-password',
    ),
    path(
        'help/onboarding/est-username-password/<int:pk>/',
        devices_help_views.OnboardingEstUsernamePasswordHelpView.as_view(),
        name='help-onboarding_est-username-password',
    ),
    path(
        'help/onboarding/est-application-credentials/<int:pk>/<str:certificate_template>/',
        devices_help_views.OnboardingEstApplicationCredentialsHelpView.as_view(),
        name='help-onboarding_est-application-credentials',
    ),
    path(
        'help/onboarding/ldevid/<int:pk>/',
        devices_help_views.OnboardingEstApplicationCredentialsHelpView.as_view(),
        name='help-onboarding_est-ldevid',
    ),
    path(
        'help/onboarding/est-idevid/<int:pk>/',
        devices_help_views.OnboardingEstIdevidHelpView.as_view(),
        name='help-onboarding_est-idevid',
    ),
    path(
        'help/onboarding/est-idevid-registration/<int:pk>/',
        devices_help_views.OnboardingEstIdevidRegistrationHelpView.as_view(),
        name='help-onboarding_est-idevid-registration',
    ),
    path(
        'help/onboarding/method-select-idevid/<int:pk>/',
        devices_help_views.OnboardingMethodSelectIdevidHelpView.as_view(),
        name='help-onboarding_method_select-idevid',
    ),
    path(
        'help/no-onboarding/opc-ua-gds/est-username-password/<int:pk>/',
        devices_help_views.NoOnboardingEstOpcUaGdsUsernamePasswordHelpView.as_view(),
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
        'revoke/<int:pk>/',
        views.IssuedCredentialRevocationView.as_view(),
        name='credential_revocation',
    ),
    re_path(
        r'^revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        views.DeviceBulkRevokeView.as_view(),
        name='device_revocation',
    ),
    re_path(
        r'^delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        views.DeviceBulkDeleteView.as_view(),
        name='device_delete',
    ),
]
