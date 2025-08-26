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

    # Create Views
    path(
        'create/', views.DeviceCreateChooseOnboardingView.as_view(), name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_create'
    ),
    path(
        'opc-ua-gds/create/',
        views.OpcUaGdsCreateChooseOnboardingView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_create',
    ),

    # Create views using no onboarding
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

    # Create views using onboarding
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
        'certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cmp-shared-secret/',
        devices_help_views.DeviceNoOnboardingCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_no_onboarding_cmp_shared_secret_help'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cmp-shared-secret/',
        devices_help_views.OpcUaGdsNoOnboardingCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_no_onboarding_cmp_shared_secret_help'
    ),

    path(
        'certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/est-username-password/',
        devices_help_views.DeviceNoOnboardingEstUsernamePasswordHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_no_onboarding_est_username_password_help'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/est-username-password/',
        devices_help_views.OpcUaGdsNoOnboardingEstUsernamePasswordHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_no_onboarding_est_username_password_help'
    ),

    path(
        'certificate-lifecycle-management/<int:pk>/manual/select-certificate-profile',
        views.DeviceSelectCertificateProfileNewApplicationCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_no_onboarding_select_certificate_profile'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/manual/select-certificate-profile',
        views.OpcUaGdsSelectCertificateProfileNewApplicationCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_no_onboarding_select_certificate_profile'
    ),


    path(
        'certificate-lifecycle-management/<int:pk>/manual/issue-tls-client-credential/',
        views.DeviceIssueTlsClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management_issue_tls_client_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/manual/issue-tls-client-credential/',
        views.OpcUaGdsIssueTlsClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management_issue_tls_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/manual/issue-tls-server-credential/',
        views.DeviceIssueTlsServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management_issue_tls_server_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/manual/issue-tls-server-credential/',
        views.OpcUaGdsIssueTlsServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management_issue_tls_server_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/manual/issue-opc-ua-client-credential/',
        views.DeviceIssueOpcUaClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management_issue_opc_ua_client_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/manual/issue-opc-ua-client-credential/',
        views.OpcUaGdsIssueOpcUaClientCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management_issue_opc_ua_client_credential',
    ),
    path(
        'certificate-lifecycle-management/<int:pk>/manual/issue-opc-ua-server-credential/',
        views.DeviceIssueOpcUaServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management_issue_opc_ua_server_credential',
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/manual/issue-opc-ua-server-credential/',
        views.OpcUaGdsIssueOpcUaServerCredentialView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management_issue_opc_ua_server_credential',
    ),

    path(
        'certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/cmp-shared-secret/',
        devices_help_views.DeviceOnboardingDomainCredentialCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management_issue_domain_credential_cmp_shared_secret'
    ),
    path(
        'opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/cmp-shared-secret/',
        devices_help_views.DeviceOnboardingDomainCredentialCmpSharedSecretHelpView.as_view(),
        name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_certificate_lifecycle_management_issue_domain_credential_cmp_shared_secret'
    ),

    # ^^^^^ DONE DONE DONE ^^^^^
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
    
    # Certificate Lifecycle Management - Downloads
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
    # path(
    #     'help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.DeviceNoOnboardingEstUsernamePasswordHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help_no_onboarding_est_username_password',
    # ),
    # path(
    #     'opc-ua-gds/help/no-onboarding/est-username-password/<int:pk>/<str:certificate_template>/',
    #     devices_help_views.OpcUaGdsNoOnboardingEstUsernamePasswordHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help_no_onboarding_est_username_password',
    # ),
    # path(
    #     'help/onboarding/cmp-shared-secret/<int:pk>/',
    #     devices_help_views.DeviceOnboardingCmpSharedSecretHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_cmp-shared-secret',
    # ),
    # path(
    #     'opc-ua-gds/help/onboarding/cmp-shared-secret/<int:pk>/',
    #     devices_help_views.OpcUaGdsOnboardingCmpSharedSecretHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_OPC_UA_SUBCATEGORY}_help-onboarding_cmp-shared-secret',
    # ),
    # path(
    #     'help/onboarding/est-username-password/<int:pk>/',
    #     devices_help_views.DeviceOnboardingEstUsernamePasswordHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_est-username-password',
    # ),
    # path(
    #     'opc-ua-gds/help/onboarding/est-username-password/<int:pk>/',
    #     devices_help_views.OpcUaGdsOnboardingEstUsernamePasswordHelpView.as_view(),
    #     name=f'{DEVICES_PAGE_DEVICES_SUBCATEGORY}_help-onboarding_est-username-password',
    # ),
]
