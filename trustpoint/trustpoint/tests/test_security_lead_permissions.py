# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Operation permissions must reject requests before reaching mutation handlers."""

from unittest.mock import Mock, patch

import pytest
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.test import RequestFactory
from rest_framework.exceptions import PermissionDenied as ApiPermissionDenied
from rest_framework.test import APIRequestFactory, force_authenticate

from agents.web_views import AgentProfileDefinitionConfigView
from devices.views import owner_credentials as owners
from devices.views.browser_onboarding import DeviceBrowserOnboardingCancelView
from devices.views.credential_issuance import OpcUaGdsPushTruststoreAssociationView
from devices.views.gds_push import OpcUaGdsPushCertRenewalSettingsView
from pki.views.certificates import CertificateViewSet
from pki.views.issuing_cas import IssuingCaCrlGenerationView
from rest_pki.api_views import ApplicationCertificateEnrollView
from signer.views import SignHashView
from users.permissions import AppPermissions
from workflows2.views.instances import (
    Workflow2InstanceCancelView,
    Workflow2InstanceResumeView,
    Workflow2InstanceRunInlineView,
    Workflow2InstanceStopView,
)
from workflows2.views.runs import (
    Workflow2RunCancelView,
    Workflow2RunReleaseIdempotencyView,
    Workflow2RunRunInlineView,
)


@pytest.mark.parametrize('view_class', [
    SignHashView,
    AgentProfileDefinitionConfigView,
    OpcUaGdsPushTruststoreAssociationView,
    OpcUaGdsPushCertRenewalSettingsView,
    IssuingCaCrlGenerationView,
    owners.OwnerCredentialFileImportView,
    owners.OwnerCredentialAddRequestEstNoOnboardingView,
    owners.OwnerCredentialAddRequestEstOnboardingView,
    owners.OwnerCredentialTruststoreAssociationView,
    owners.OwnerCredentialOnboardingSetupView,
    owners.OwnerCredentialBulkDeleteConfirmView,
    owners.IssuedCredentialDeleteView,
    owners.OwnerCredentialDefineCertContentEstView,
    owners.OwnerCredentialRequestCertEstView,
    owners.OwnerCredentialDefineCertContentDomainCredentialEstView,
    owners.OwnerCredentialRequestDomainCredentialEstView,
    Workflow2RunCancelView,
    Workflow2RunReleaseIdempotencyView,
    Workflow2RunRunInlineView,
    Workflow2InstanceCancelView,
    Workflow2InstanceStopView,
    Workflow2InstanceResumeView,
    Workflow2InstanceRunInlineView,
])
@pytest.mark.parametrize('method', ['get', 'post'])
def test_unprivileged_browser_requests_never_reach_handlers(view_class, method):
    request = getattr(RequestFactory(), method)('/protected/')
    request.user = Mock(is_authenticated=True, has_perm=Mock(return_value=False))
    with (
        patch.object(view_class, method, create=True) as handler,
        patch.object(owners, 'get_object_or_404'),
    ):
        with pytest.raises(PermissionDenied):
            view_class.as_view()(request, pk=1, owner_pk=1)
        handler.assert_not_called()


@pytest.mark.parametrize('view_class', [
    SignHashView, OpcUaGdsPushTruststoreAssociationView, OpcUaGdsPushCertRenewalSettingsView,
    AgentProfileDefinitionConfigView, owners.OwnerCredentialTruststoreAssociationView,
    Workflow2RunCancelView, Workflow2InstanceStopView, IssuingCaCrlGenerationView,
])
def test_permitted_browser_requests_reach_handlers(view_class):
    request = RequestFactory().post('/protected/')
    request.user = Mock(is_authenticated=True, has_perm=Mock(return_value=True))
    with (
        patch.object(view_class, 'post', return_value=HttpResponse(status=204)) as handler,
        patch('agents.security.AgentSecurity.is_agent_protocol_permitted', return_value=True),
    ):
        assert view_class.as_view()(request).status_code == 204
        handler.assert_called_once()


@pytest.mark.parametrize('permitted', [False, True])
def test_rest_management_issuance_checks_permission_before_parsing(permitted):
    request = APIRequestFactory().post('/api/enroll/', {}, format='json')
    force_authenticate(request, user=Mock(is_authenticated=True, has_perm=Mock(return_value=permitted)))
    with patch('rest_pki.api_views.CertificateEnrollRequestSerializer') as serializer:
        serializer.return_value.is_valid.return_value = False
        serializer.return_value.errors = {'csr': ['required']}
        response = ApplicationCertificateEnrollView.as_view()(request)
    assert response.status_code == (400 if permitted else 403)
    assert serializer.called is permitted


@pytest.mark.parametrize('view_class', [OpcUaGdsPushTruststoreAssociationView, owners.OwnerCredentialTruststoreAssociationView])
def test_truststore_upload_requires_its_own_management_permission(view_class):
    request = RequestFactory().post('/import/')
    request.user = Mock(has_perm=Mock(return_value=False))
    with (
        patch('pki.forms.TruststoreAddForm') as owner_form,
        patch('devices.views.credential_issuance.TruststoreAddForm') as gds_form,
    ):
        with pytest.raises(PermissionDenied):
            view_class()._handle_import(request)
        owner_form.assert_not_called()
        gds_form.assert_not_called()


@pytest.mark.parametrize('permissions,member,allowed', [
    (set(), False, False),
    ({AppPermissions.MANAGE_TRUSTSTORES}, True, False),
    ({AppPermissions.MANAGE_CAS}, True, False),
    ({AppPermissions.MANAGE_CAS}, False, True),
    ({AppPermissions.MANAGE_CAS, AppPermissions.MANAGE_TRUSTSTORES}, True, True),
])
def test_certificate_deletion_preserves_unauthorized_truststore_memberships(permissions, member, allowed):
    view = CertificateViewSet()
    view.request = Mock(user=Mock(has_perm=lambda permission: permission in permissions))
    certificate = Mock()
    certificate.trust_store_components.exists.return_value = member
    with patch('pki.views.certificates.get_object_or_404', return_value=certificate):
        if allowed:
            view.perform_destroy(certificate)
            certificate.delete.assert_called_once()
        else:
            with pytest.raises(ApiPermissionDenied):
                view.perform_destroy(certificate)
            certificate.delete.assert_not_called()


@pytest.mark.parametrize('view_class', [IssuingCaCrlGenerationView, DeviceBrowserOnboardingCancelView])
def test_get_cannot_generate_a_crl_or_cancel_a_download(view_class):
    request = RequestFactory().get('/mutation/')
    request.user = Mock(is_authenticated=True, has_perm=Mock(return_value=True))
    with patch.object(view_class, 'get_object') as lookup:
        assert view_class.as_view()(request).status_code == 405
        lookup.assert_not_called()
