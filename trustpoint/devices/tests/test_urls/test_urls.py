"""Tests for the devices urls."""

import pytest
from django.urls import resolve, reverse

from devices import views


@pytest.mark.parametrize(('url_name', 'kwargs', 'view_class'), [
    # Main Pages
    ('devices:devices', {}, views.DeviceTableView),
    ('devices:add', {}, views.CreateDeviceView),
    ('devices:details', {'pk': 1}, views.DeviceDetailsView),

    # Certificate Lifecycle Management
    ('devices:certificate_lifecycle_management', {'pk': 1}, views.DeviceCertificateLifecycleManagementSummaryView),

    # OPC UA GDS
    ('devices:opc_ua_gds', {}, views.OpcUaGdsTableView),
    ('devices:opc_ua_gds-add', {}, views.CreateOpcUaGdsView),

    # Certificate Lifecycle Management - Credential Issuance
    ('devices:certificate_lifecycle_management-issue_tls_client_credential', {'pk': 1},
     views.DeviceIssueTlsClientCredential),
    ('devices:certificate_lifecycle_management-issue_tls_server_credential', {'pk': 1},
     views.DeviceIssueTlsServerCredential),
    ('devices:certificate_lifecycle_management-issue_opcua_client_credential', {'pk': 1},
     views.DeviceIssueOpcUaClientCredential),
    ('devices:certificate_lifecycle_management-issue_opcua_server_credential', {'pk': 1},
     views.DeviceIssueOpcUaServerCredential),

    # Help Pages
    ('devices:help_dispatch_domain', {'pk': 1}, views.HelpDispatchDomainCredentialView),
    ('devices:help_dispatch_device_type_redirect', {'pk': 1}, views.HelpDispatchDeviceTypeRedirectView),
    ('devices:help_dispatch_opcua_gds', {'pk': 1}, views.HelpDispatchOpcUaGdsView),
    ('devices:help_dispatch_application', {'pk': 1}, views.HelpDispatchApplicationCredentialView),
    ('devices:help_dispatch_application_template', {'pk': 1, 'certificate_template': 'template'},
     views.HelpDispatchApplicationCredentialTemplateView),
    ('devices:help_no-onboarding_cmp-shared-secret', {'pk': 1, 'certificate_template': 'template'},
     views.NoOnboardingCmpSharedSecretHelpView),
    ('devices:help-onboarding_cmp-shared-secret', {'pk': 1}, views.OnboardingCmpSharedSecretHelpView),
    ('devices:help-onboarding_cmp-idevid', {'pk': 1}, views.OnboardingCmpIdevidHelpView),
    ('devices:help-onboarding_cmp-idevid-registration', {'pk': 1},
     views.OnboardingCmpIdevidRegistrationHelpView),
    ('devices:help-onboarding_cmp-application-credentials', {'pk': 1, 'certificate_template': 'template'},
     views.OnboardingCmpApplicationCredentialsHelpView),
    ('devices:help-no-onboarding_est-username-password', {'pk': 1, 'certificate_template': 'template'},
     views.NoOnboardingEstUsernamePasswordHelpView),
    ('devices:help-onboarding_est-username-password', {'pk': 1},
     views.OnboardingEstUsernamePasswordHelpView),
    ('devices:help-onboarding_est-application-credentials', {'pk': 1, 'certificate_template': 'template'},
     views.OnboardingEstApplicationCredentialsHelpView),
    ('devices:help-onboarding_est-ldevid', {'pk': 1}, views.OnboardingEstApplicationCredentialsHelpView),
    ('devices:help-onboarding_est-idevid', {'pk': 1}, views.OnboardingEstIdevidHelpView),
    ('devices:help-onboarding_est-idevid-registration', {'pk': 1}, views.OnboardingEstIdevidRegistrationHelpView),
    ('devices:help-onboarding_method_select-idevid', {'pk': 1}, views.OnboardingMethodSelectIdevidHelpView),
    ('devices:help-no-onboarding_est-opcua-gds-username-password', {'pk': 1},
     views.NoOnboardingEstOpcUaGdsUsernamePasswordHelpView),

    # Downloads
    ('devices:download', {'pk': 1}, views.DownloadPageDispatcherView),
    ('devices:certificate-download', {'pk': 1}, views.CertificateDownloadView),
    ('devices:credential-download', {'pk': 1}, views.DeviceManualCredentialDownloadView),
    ('devices:browser_otp_view', {'pk': 1}, views.DeviceBrowserOnboardingOTPView),
    ('devices:browser_login', {}, views.DeviceOnboardingBrowserLoginView),
    ('devices:browser_domain_credential_download', {'pk': 1}, views.DeviceBrowserCredentialDownloadView),
    ('devices:browser_cancel', {'pk': 1}, views.DeviceBrowserOnboardingCancelView),

    # Revoke Views
    ('devices:credential_revocation', {'pk': 1, 'credential_pk': 1}, views.DeviceCredentialRevocationView),
    ('devices:device_revocation', {'pk': 1}, views.DeviceRevocationView),
    ('devices:device_delete', {'pks': '1/2/3'}, views.DeviceBulkDeleteView),
])
def test_url_resolves(
    url_name: str,
    kwargs: dict[str, str],
    view_class: type
) -> None:
    """Test that each URL resolves to the correct view."""
    url = reverse(url_name, kwargs=kwargs)
    resolver = resolve(url)

    assert resolver.func.view_class == view_class, f'Failed on {url_name}'  # type: ignore[attr-defined]




