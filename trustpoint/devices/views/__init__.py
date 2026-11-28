# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for the devices application."""

from .agents import (
    AgentCreateOneToOneOnboardingView,
    AgentTableView,
)
from .browser_onboarding import (
    DeviceBrowserOnboardingCancelView,
    DeviceBrowserOnboardingOTPView,
    DeviceOnboardingBrowserLoginView,
)
from .clm import (
    DeviceCertificateLifecycleManagementSummaryView,
    OpcUaGdsPushCertificateLifecycleManagementSummaryView,
)
from .credential_issuance import (
    DeviceChooseIssuanceMethodView,
    DeviceIssueCsrCredentialView,
    DeviceIssueProfileCredentialView,
    DeviceNoOnboardingIssueNewApplicationCredentialView,
    DeviceOnboardingIssueNewApplicationCredentialView,
    DeviceSelectCertificateProfileNewApplicationCredentialView,
    OpcUaGdsPushDiscoveredCertificateView,
    OpcUaGdsPushDiscoverServerView,
    OpcUaGdsPushIssueDomainCredentialView,
    OpcUaGdsPushOnboardingIssueNewApplicationCredentialView,
    OpcUaGdsPushTruststoreAssociationView,
)
from .delete import (
    AgentsBulkDeleteView,
    DeviceBulkDeleteView,
    OpcUaGdsPushBulkDeleteView,
)
from .device_api import DeviceViewSet
from .device_create import (
    DeviceCreateAddOnboardingTypeView,
    DeviceCreateChooseOnboardingView,
    DeviceCreateNoOnboardingView,
    DeviceCreateOnboardingView,
    DeviceCreateOpcUaGdsPushView,
    NamedCurveMissingForEccErrorMsg,
    OpcUaGdsPushCreateChooseOnboardingView,
    OpcUaGdsPushCreateOnboardingView,
    PublicKeyInfoMissingErrorMsg,
)
from .device_secrets import DeviceSecretChangeView
from .download import (
    DeviceBrowserCredentialDownloadView,
    DeviceCertificateDownloadView,
    DeviceDownloadPageDispatcherView,
    DeviceManualCredentialDownloadView,
)
from .gds_push import (
    OpcUaGdsPushCertRenewalSettingsView,
    OpcUaGdsPushDomainCredentialRenewalSettingsView,
    OpcUaGdsPushRefreshInventoryView,
    OpcUaGdsPushTrustlistAuthoritativePreviewView,
    OpcUaGdsPushTrustlistModeView,
    OpcUaGdsPushUpdateServerCertificateView,
    OpcUaGdsPushUpdateTrustlistView,
    TrustBundleDownloadView,
)
from .revoke import (
    DeviceBulkRevokeView,
    DeviceIssuedCredentialRevocationView,
    OpcUaGdsPushBulkRevokeView,
    OpcUaGdsPushIssuedCredentialRevocationView,
)
from .tables import (
    DeviceTableView,
)

__all__ = [
    'AgentCreateOneToOneOnboardingView',
    'AgentTableView',
    'AgentsBulkDeleteView',
    'DeviceBrowserCredentialDownloadView',
    'DeviceBrowserOnboardingCancelView',
    'DeviceBrowserOnboardingOTPView',
    'DeviceBulkDeleteView',
    'DeviceBulkRevokeView',
    'DeviceCertificateDownloadView',
    'DeviceCertificateLifecycleManagementSummaryView',
    'DeviceChooseIssuanceMethodView',
    'DeviceCreateAddOnboardingTypeView',
    'DeviceCreateChooseOnboardingView',
    'DeviceCreateNoOnboardingView',
    'DeviceCreateOnboardingView',
    'DeviceCreateOpcUaGdsPushView',
    'DeviceDownloadPageDispatcherView',
    'DeviceIssueCsrCredentialView',
    'DeviceIssueProfileCredentialView',
    'DeviceIssuedCredentialRevocationView',
    'DeviceManualCredentialDownloadView',
    'DeviceNoOnboardingIssueNewApplicationCredentialView',
    'DeviceOnboardingBrowserLoginView',
    'DeviceOnboardingIssueNewApplicationCredentialView',
    'DeviceSecretChangeView',
    'DeviceSelectCertificateProfileNewApplicationCredentialView',
    'DeviceTableView',
    'DeviceViewSet',
    'NamedCurveMissingForEccErrorMsg',
    'OpcUaGdsPushBulkDeleteView',
    'OpcUaGdsPushBulkRevokeView',
    'OpcUaGdsPushCertRenewalSettingsView',
    'OpcUaGdsPushCertificateLifecycleManagementSummaryView',
    'OpcUaGdsPushCreateChooseOnboardingView',
    'OpcUaGdsPushCreateOnboardingView',
    'OpcUaGdsPushDiscoverServerView',
    'OpcUaGdsPushDiscoveredCertificateView',
    'OpcUaGdsPushDomainCredentialRenewalSettingsView',
    'OpcUaGdsPushIssueDomainCredentialView',
    'OpcUaGdsPushIssuedCredentialRevocationView',
    'OpcUaGdsPushOnboardingIssueNewApplicationCredentialView',
    'OpcUaGdsPushRefreshInventoryView',
    'OpcUaGdsPushTrustlistAuthoritativePreviewView',
    'OpcUaGdsPushTrustlistModeView',
    'OpcUaGdsPushTruststoreAssociationView',
    'OpcUaGdsPushUpdateServerCertificateView',
    'OpcUaGdsPushUpdateTrustlistView',
    'PublicKeyInfoMissingErrorMsg',
    'TrustBundleDownloadView',
]
