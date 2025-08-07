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
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_details',
    ),
    # Create Views
    path(
        'create/', views.DeviceCreateChooseOnboardingView.as_view(), name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_create'
    ),
    path(
        'opc-ua-gds/create/',
        views.OpcUaGdsCreateChooseOnboardingView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_create',
    ),
    path(
        'create/onboarding/',
        views.DeviceCreateOnboardingView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_create_onboarding',
    ),
    path(
        'opc-ua-gds/create/onboarding',
        views.OpcUaGdsCreateOnboardingView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_create_onboarding',
    ),
    path(
        'create/no-onboarding/',
        views.DeviceCreateNoOnboardingView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_create_no_onboarding',
    ),
    path(
        'opc-ua-gds/create/no-onboarding',
        views.OpcUaGdsCreateNoOnboardingView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_create_no_onboarding',
    ),
    # Certificate Lifecycle Management Views
    path(
        'certificate-lifecycle-management/<int:pk>/',
        views.DeviceCertificateLifecycleManagementSummaryView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management',
    ),
    path(
        'opc-us-gds/certificate-lifecycle-management/<int:pk>/',
        views.OpcUaGdsCertificateLifecycleManagementSummaryView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management',
    ),
    # Certificate Lifecycle Management - Credential Issuance
    path(
        'certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/',
        views.DeviceNoOnboardingIssueNewApplicationCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_no_onboarding_clm_issue_application_credential'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/',
        views.OpcUaGdsNoOnboardingIssueNewApplicationCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_no_onboarding_clm_issue_application_credential'
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cert-profile-select/<str:protocol>/',
        views.DeviceNoOnboardingProfileSelectView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_no_onboarding_clm_issue_application_credential_profile_select'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cert-profile-select/<str:protocol>/',
        views.OpcUaGdsNoOnboardingProfileSelectView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_no_onboarding_clm_issue_application_credential_profile_select'
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/cert-profile-select/<str:protocol>/',
        views.DeviceOnboardingProfileSelectView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_onboarding_clm_issue_application_credential_profile_select'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/cert-profile-select/<str:protocol>/',
        views.OpcUaGdsOnboardingProfileSelectView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_onboarding_clm_issue_application_credential_profile_select'
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/',
        views.DeviceOnboardingIssueNewApplicationCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_onboarding_clm_issue_application_credential'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/',
        views.OpcUaGdsOnboardingIssueNewApplicationCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_onboarding_clm_issue_application_credential'
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-client-credential/',
        views.DeviceIssueTlsClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_client_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/issue-tls-client-credential/',
        views.OpcUaGdsIssueTlsClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-server-credential/',
        views.DeviceIssueTlsServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_server_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/issue-tls-server-credential/',
        views.OpcUaGdsIssueTlsServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_tls_server_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-opcua-client-credential/',
        views.DeviceIssueOpcUaClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_client_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/issue-opcua-client-credential/',
        views.OpcUaGdsIssueOpcUaClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-opcua-server-credential/',
        views.DeviceIssueOpcUaServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_server_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/issue-opcua-server-credential/',
        views.OpcUaGdsIssueOpcUaServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management-issue_opc_ua_server_credential',
    ),

    # path(
    #     'certificate-lifecycle-management/<int:pk>/oboarding/issue-application-credential/',
    #     pass,
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_onboarding_clm_issue_domain_credential'
    # ),
    # path(
    #     'certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/',
    #     pass,
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_no_onboarding_clm_issue_domain_credential'
    # ),
    # path(
    #     'certificate-lifecycle-management/<int:pk>/issue-domain-credential/',
    #     views.DeviceIssueDomainCredentialView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management-issue_domain_credential',
    # ),
    # # Certificate Lifecycle Management - Downloads
    path(
        'download/<int:pk>/',
        views.DeviceDownloadPageDispatcherView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_download',
    ),
    path(
        'opc-us-gds/download/<int:pk>/',
        views.OpcUaGdsDownloadPageDispatcherView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_download',
    ),
        path(
        'credential/download/<int:pk>/',
        views.DeviceManualCredentialDownloadView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_credential-download',
    ),
    path(
        'opc-ua-gds/credential/download/<int:pk>/',
        views.DeviceManualCredentialDownloadView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_credential-download',
    ),
    path(
        'credential-download/browser/<int:pk>/',
        views.DeviceBrowserOnboardingOTPView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_browser_otp_view',
    ),
    path(
        'opc-ua-gds/credential-download/browser/<int:pk>/',
        views.OpcUaGdsBrowserOnboardingOTPView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_browser_otp_view',
    ),
    path(
        'certificate/download/<int:pk>/',
        views.DeviceCertificateDownloadView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate-download',
    ),
    path(
        'opc-us-gds/certificate/download/<int:pk>/',
        views.OpcUaGdsCertificateDownloadView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate-download',
    ),
    path(
        'credential-download/browser/<int:pk>/cancel',
        views.DeviceBrowserOnboardingCancelView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_browser_cancel',
    ),
    path(
        'credential-download/browser/<int:pk>/cancel',
        views.OpcUaGdsBrowserOnboardingCancelView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_browser_cancel',
    ),
    # browser login and download views
    path('browser/', views.DeviceOnboardingBrowserLoginView.as_view(), name='browser_login'),
    path(
        'browser/credential-download/<int:pk>/',
        views.DeviceBrowserCredentialDownloadView.as_view(),
        name='browser_domain_credential_download',
    ),
    # Revokation views
    path(
        'revoke/<int:pk>/',
        views.DeviceIssuedCredentialRevocationView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_credential_revoke',
    ),
    path(
        'opc-ua-gds/revoke/<int:pk>/',
        views.OpcUaGdsIssuedCredentialRevocationView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_credential_revoke',
    ),
    re_path(
        r'^revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        views.DeviceBulkRevokeView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_device_revoke',
    ),
    re_path(
        r'^opc-ua-gds/revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        views.DeviceBulkRevokeView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_device_revoke',
    ),
    re_path(
        r'^delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        views.DeviceBulkDeleteView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_device_delete',
    ),
    re_path(
        r'^opc-ua-gds/delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        views.DeviceBulkDeleteView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_device_delete',
    ),
    # # Certificate Lifecycle Management - Help Pages
    path(
        'help/no-onboarding/cmp-shared-secret/<int:pk>/<str:certificate_template>/',
        devices_help_views.DeviceNoOnboardingCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_no_onboarding_cmp_shared_secret',
    ),
    path(
        'opc-ua-gds/help/no-onboarding/cmp-shared-secret/<int:pk>/<str:certificate_template>/',
        devices_help_views.OpcUaGdsNoOnboardingCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_no_onboarding_cmp_shared_secret',
    ),
    path(
        'help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
        devices_help_views.DeviceNoOnboardingEstUsernamePasswordHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_no_onboarding_est_username_password',
    ),
    path(
        'opc-ua-gds/help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
        devices_help_views.OpcUaGdsNoOnboardingEstUsernamePasswordHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_no_onboarding_est_username_password',
    ),
    path(
        'help/onboarding/cmp-shared-secret/<int:pk>/',
        devices_help_views.DeviceOnboardingCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_cmp-shared-secret',
    ),
    path(
        'opc-ua-gds/help/onboarding/cmp-shared-secret/<int:pk>/',
        devices_help_views.OpcUaGdsOnboardingCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-onboarding_cmp-shared-secret',
    ),
    path(
        'help/onboarding/est-username-password/<int:pk>/',
        devices_help_views.DeviceOnboardingEstUsernamePasswordHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_est-username-password',
    ),
    path(
        'opc-ua-gds/help/onboarding/est-username-password/<int:pk>/',
        devices_help_views.OpcUaGdsOnboardingEstUsernamePasswordHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_est-username-password',
    ),
    path(
        'help/onboarding/cmp-shared-secret/<int:pk>/<str:certificate_template>/',
        devices_help_views.DeviceOnboardingCmpHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_onboarding_cmp',
    ),
    path(
        'opc-ua-gds/help/onboarding/cmp-shared-secret/<int:pk>/<str:certificate_template>/',
        devices_help_views.OpcUaGdsOnboardingCmpHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_onboarding_cmp',
    ),
    path(
        'help/onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
        devices_help_views.DeviceOnboardingEstHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_no_onboarding_est',
    ),
    path(
        'opc-ua-gds/help/onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
        devices_help_views.OpcUaGdsOnboardingEstHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_onboarding_est',
    ),



    # path(
    #     'help/onboarding/cmp-idevid/<int:pk>/',
    #     devices_help_views.DeviceOnboardingCmpIdevidHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_cmp-idevid',
    # ),
    # path(
    #     'opc-ua-gds/help/onboarding/cmp-idevid/<int:pk>/',
    #     devices_help_views.OpcUaGdsOnboardingCmpIdevidHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-onboarding_cmp-idevid',
    # ),


    #  path(
    #     'help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.DeviceNoOnboardingEstUsernamePasswordHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-no-onboarding_est-username-password',
    # ),
    # path(
    #     'opc-ua-gds/help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.OpcUaGdsNoOnboardingEstUsernamePasswordHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-no-onboarding_est-username-password',
    # ),
    # # Domain Credential Help Dispatcher
    # path(
    #     'help/dispatch-domain/<int:pk>/',
    #     devices_help_views.DeviceHelpDispatchDomainCredentialView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_dispatch_domain',
    # ),
    # path(
    #     'opc-ua-gds/help/dispatch-domain/<int:pk>/',
    #     devices_help_views.DeviceHelpDispatchDomainCredentialView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_dispatch_domain',
    # ),
    # # Application Credential Help Dispatcher
    # path(
    #     'help/application-credential-selection/<int:pk>/<str:protocol>/',
    #     devices_help_views.HelpDispatchApplicationCredentialView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_application_credential_selection',
    # ),
    # path(
    #     'opc-ua-gds/help/application-credential-selection/<int:pk>/<str:protocol>/',
    #     devices_help_views.HelpDispatchApplicationCredentialView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_application_credential_selection',
    # ),
    # # Application Credential Template Dispatcher
    # path(
    #     'help/dispatch-application-template/<int:pk>/<str:protocol>/<str:certificate_template>/',
    #     devices_help_views.DeviceHelpDispatchApplicationCredentialTemplateView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_dispatch_application_template',
    # ),
    # path(
    #     'opc-ua-gds/help/dispatch-application-template/<int:pk>/<str:protocol>/<str:certificate_template>/',
    #     devices_help_views.OpcUaGdsHelpDispatchApplicationCredentialTemplateView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_dispatch_application_template',
    # ),
    # path(
    #     'help/dispatch-device-type-redirect/<int:pk>/',
    #     devices_help_views.HelpDispatchDeviceTypeRedirectView.as_view(),
    #     name='help_dispatch_device_type_redirect',
    # ),
    # path(
    #     'help/dispatch-opcua_gds/<int:pk>/',
    #     devices_help_views.HelpDispatchOpcUaGdsView.as_view(),
    #     name='help_dispatch_opcua_gds',
    # ),
    # path(
    #     'help/dispatch-application/<int:pk>/',
    #     devices_help_views.HelpDispatchApplicationCredentialView.as_view(),
    #     name='help_dispatch_application',
    # ),
    # path(
    #     'help/dispatch-application/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.HelpDispatchApplicationCredentialTemplateView.as_view(),
    #     name='help_dispatch_application_template',
    # ),

    #

    # path(
    #     'help/onboarding/manual/<int:pk>/',
    #     views.DeviceIssueDomainCredentialView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_manual',
    # ),
    # path(
    #     'opc-ua-gds/help/onboarding/manual/<int:pk>/',
    #     views.OpcUaGdsIssueDomainCredentialView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-onboarding_manual',
    # ),
    # path(
    #     'help/onboarding/est-application-credentials/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.DeviceOnboardingEstApplicationCredentialsHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_est-application-credentials',
    # ),
    # path(
    #     'help/onboarding/cmp-application-credentials/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.OnboardingCmpApplicationCredentialsHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_cmp-application-credentials',
    # ),
    # path(
    #     'opc-ua-gds/help/onboarding/cmp-application-credentials/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.OnboardingCmpApplicationCredentialsHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-onboarding_cmp-application-credentials',
    # ),

    # path(
    #     'help/onboarding/ldevid/<int:pk>/',
    #     devices_help_views.OnboardingEstApplicationCredentialsHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_est-ldevid',
    # ),
    # path(
    #     'opc-ua-gds/help/onboarding/ldevid/<int:pk>/',
    #     devices_help_views.OnboardingEstApplicationCredentialsHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-onboarding_est-ldevid',
    # ),
    # path(
    #     'help/onboarding/est-idevid/<int:pk>/',
    #     devices_help_views.DeviceOnboardingEstIdevidHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_est-idevid',
    # ),
    # path(
    #     'opc-ua-gds/help/onboarding/est-idevid/<int:pk>/',
    #     devices_help_views.OpcUaGdsOnboardingEstIdevidHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-onboarding_est-idevid',
    # ),
    # path(
    #     'help/onboarding/method-select-idevid/<int:pk>/',
    #     devices_help_views.OnboardingMethodSelectIdevidHelpView.as_view(),
    #     name='help-onboarding_method_select-idevid',
    # ),
    # path(
    #     'help/onboarding/est-idevid-registration/<int:pk>/',
    #     devices_help_views.OnboardingEstIdevidRegistrationHelpView.as_view(),
    #     name='help-onboarding_est-idevid-registration',
    # ),
    # path(
    #     'help/onboarding/cmp-idevid-registration/<int:pk>/',
    #     devices_help_views.OnboardingCmpIdevidRegistrationHelpView.as_view(),
    #     name='help-onboarding_cmp-idevid-registration',
    # ),
]
