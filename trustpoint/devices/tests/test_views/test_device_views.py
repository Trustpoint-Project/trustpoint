# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for device views."""
import json
from datetime import timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Any
from unittest.mock import patch, Mock

import pytest
from cryptography import x509
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.messages import WARNING
from django.test import Client
from django.urls import reverse

from devices.models import DeviceModel
from management.models import OrganizationModel
from onboarding.models import OnboardingPkiProtocol, OnboardingProtocol, OnboardingStatus
from pki.models import CertificateModel, IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.models.domain import DomainAllowedCertificateProfileModel


@pytest.fixture
def opc_ua_domain_device(device_instance_onboarding: dict[str, Any]) -> DeviceModel:
    """Use a custom domain profile to verify that issuance resolves the domain's choice."""
    device = device_instance_onboarding['device']
    device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
    device.onboarding_config.set_pki_protocols([OnboardingPkiProtocol.OPC_GDS_PUSH])
    device.onboarding_config.save()
    device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
    device.ip_address = '127.0.0.1'
    device.save()
    profile_json = json.loads((
        Path(__file__).resolve().parents[3] / 'pki/default_certificate_profiles/opc_ua_domain_credential.json'
    ).read_text())
    profile_json['subj']['common_name'] = {'value': 'Custom Domain Credential', 'mutable': False}
    profile_json['ext']['subject_alternative_name']['dns_names'] = {'default': ['device.example.com']}
    profile_json['validity']['mutable'] = True
    profile = CertificateProfileModel.objects.create(
        unique_name='custom_opcua_domain',
        display_name='Custom OPC UA Domain',
        credential_type=CertificateProfileModel.ProfileCredentialType.DOMAIN,
        profile_json=profile_json,
    )
    device.domain.domain_credential_profile = profile
    device.domain.save()
    return device


@pytest.mark.django_db
@pytest.mark.parametrize('opc_ua_profile_selected', [False, True])
def test_opc_ua_domain_credential_warns_about_profile_selection(
    admin_client: Client, opc_ua_domain_device: DeviceModel, opc_ua_profile_selected: bool,
) -> None:
    """Show a warning with a settings link unless the OPC UA domain profile is selected."""
    device = opc_ua_domain_device
    profile = device.domain.domain_credential_profile
    if opc_ua_profile_selected:
        profile.unique_name = 'opc_ua_domain_credential'
        profile.save()
    else:
        profile.profile_json = (
            Path(__file__).resolve().parents[3] / 'pki/default_certificate_profiles/domain_credential.json'
        ).read_text()
        profile.save()

    response = admin_client.get(reverse(
        'devices:devices_onboarding_clm_issue_domain_credential', kwargs={'pk': device.pk},
    ))

    assert response.status_code == HTTPStatus.OK
    warnings = [str(message) for message in response.context['messages'] if message.level == WARNING]
    if opc_ua_profile_selected:
        assert not warnings
    else:
        assert len(warnings) == 1
        assert 'not using the OPC UA Domain Credential profile' in warnings[0]
        settings_url = reverse('pki:domains-config', kwargs={'pk': device.domain_id})
        assert f'href="{settings_url}"' in warnings[0]
        assert warnings[0].encode() in response.content


@pytest.mark.django_db
@pytest.mark.parametrize('route', ['opc_ua', 'manual'])
def test_domain_profile_prefills_shared_issuance_form(
    admin_client: Client, opc_ua_domain_device: DeviceModel, route: str,
) -> None:
    """Both routes render the domain profile's values and resolved template defaults."""
    device = opc_ua_domain_device
    profile = device.domain.domain_credential_profile
    profile.profile_json = (
        Path(__file__).resolve().parents[3] / 'pki/default_certificate_profiles/domain_credential.json'
    ).read_text()
    profile.save()
    domain_defaults = {
        'organization': 'Example Organization',
        'organization_unit': 'Device Operations',
        'country': 'DE',
        'state': 'Berlin',
        'locality': 'Berlin',
    }
    device.domain.organization = OrganizationModel.objects.create(**domain_defaults)
    device.domain.save()
    if route == 'opc_ua':
        url = reverse('devices:devices_onboarding_clm_issue_domain_credential', kwargs={'pk': device.pk})
    else:
        url = reverse('devices:devices_certificate_lifecycle_management_issue_profile_credential',
                      kwargs={'pk': device.pk, 'profile_id': profile.pk})

    response = admin_client.get(url)

    assert response.status_code == HTTPStatus.OK
    form = response.context['form']
    expected = {
        'common_name': 'Trustpoint Domain Credential',
        'organization_name': domain_defaults['organization'],
        'organizational_unit_name': domain_defaults['organization_unit'],
        'country_name': domain_defaults['country'],
        'state_or_province_name': domain_defaults['state'],
        'locality_name': domain_defaults['locality'],
        'days': 30,
    }
    assert not form.is_bound
    for field_name, value in expected.items():
        assert form[field_name].value() == value
        assert f'value="{form[field_name].value()}"'.encode() in response.content
    assert not form.fields['common_name'].disabled


@pytest.mark.django_db
@pytest.mark.parametrize('method', ['get', 'post'])
def test_opc_ua_gds_push_domain_credential_form_renders(
    admin_client: Client, opc_ua_domain_device: DeviceModel, method: str,
) -> None:
    """Use the shared profile template on GET and after invalid submission."""
    device = opc_ua_domain_device
    url = reverse('devices:devices_onboarding_clm_issue_domain_credential', kwargs={'pk': device.pk})
    response = admin_client.get(url) if method == 'get' else admin_client.post(url, data={'days': 7})

    assert response.status_code == HTTPStatus.OK
    assert 'pki/cert_profiles/issuance.html' in [t.name for t in response.templates]
    assert response.context['profile'] == device.domain.domain_credential_profile
    assert b'name="uris"' in response.content
    assert type(response.context['form']) is CertificateIssuanceForm
    if method == 'get':
        assert response.context['form']['uris'].value() == f'urn:trustpoint:opcua:{device.rfc_4122_uuid}'
    assert b'name="csrfmiddlewaretoken"' in response.content
    clm_url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
    assert f'href="{clm_url}"'.encode() in response.content
    if method == 'post':
        assert response.context['form'].errors['uris']
        assert b'This field is required.' in response.content
        assert not IssuedCredentialModel.objects.filter(device=device).exists()


@pytest.mark.django_db
def test_opc_ua_domain_credential_issuance_uses_profile(admin_client: Client, opc_ua_domain_device: DeviceModel) -> None:
    """Sign a domain credential with profile subject/validity and required OPC UA extensions."""
    device = opc_ua_domain_device
    url = reverse('devices:devices_onboarding_clm_issue_domain_credential', kwargs={'pk': device.pk})
    response = admin_client.post(url, data={'uris': 'urn:trustpoint:test-device', 'days': 7})
    assert response.status_code == HTTPStatus.FOUND
    assert response.url == reverse('devices:devices_truststore_association', kwargs={'pk': device.pk})
    issued = IssuedCredentialModel.objects.get(device=device)
    assert issued.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
    assert issued.is_valid_domain_credential()[0]
    assert issued.common_name == 'Custom Domain Credential'
    cert = issued.credential.get_certificate()
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=7, hours=1)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == ['urn:trustpoint:test-device']
    assert san.get_values_for_type(x509.DNSName) == ['device.example.com']
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical
    assert usage.value.digital_signature and usage.value.content_commitment
    assert usage.value.key_encipherment and usage.value.data_encipherment
    assert not usage.value.key_cert_sign and not usage.value.crl_sign
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
    ]
    device.onboarding_config.refresh_from_db()
    assert device.onboarding_config.onboarding_status == OnboardingStatus.PENDING


@pytest.mark.django_db
def test_opc_ua_domain_credential_default_profile_fallback(
    admin_client: Client, opc_ua_domain_device: DeviceModel,
) -> None:
    """Use the standard domain profile when no custom profile is configured."""
    device = opc_ua_domain_device
    profile, _ = CertificateProfileModel.objects.get_or_create(
        unique_name='domain_credential',
        defaults={
            'credential_type': CertificateProfileModel.ProfileCredentialType.DOMAIN,
            'profile_json': device.domain.domain_credential_profile.profile,
        },
    )
    DomainAllowedCertificateProfileModel.objects.get_or_create(domain=device.domain, certificate_profile=profile)
    device.domain.domain_credential_profile = None
    device.domain.save()
    url = reverse('devices:devices_onboarding_clm_issue_domain_credential', kwargs={'pk': device.pk})
    response = admin_client.get(url)
    assert response.status_code == HTTPStatus.OK
    assert response.context['profile'] == profile
    response = admin_client.post(url, data={'uris': 'urn:trustpoint:default-profile', 'days': 7})
    assert response.status_code == HTTPStatus.FOUND
    assert response.url == reverse('devices:devices_truststore_association', kwargs={'pk': device.pk})
    assert IssuedCredentialModel.objects.get(device=device).is_valid_domain_credential()[0]


@pytest.mark.django_db
def test_opc_ua_domain_credential_failure_returns_to_device(
    admin_client: Client, opc_ua_domain_device: DeviceModel,
) -> None:
    """Do not advance to truststore association when credential issuance fails."""
    device = opc_ua_domain_device
    url = reverse('devices:devices_onboarding_clm_issue_domain_credential', kwargs={'pk': device.pk})
    with patch('devices.views.credential_issuance.CredentialIssueProcessor.process_operation',
               side_effect=ValueError('Signing failed')):
        response = admin_client.post(url, data={'uris': 'urn:trustpoint:test-device', 'days': 7})
    assert response.status_code == HTTPStatus.FOUND
    assert response.url == reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
    assert not IssuedCredentialModel.objects.filter(device=device).exists()


@pytest.mark.django_db
def test_manual_profile_issuance_still_issues_application_credential(
    admin_client: Client, device_instance: dict[str, Any],
) -> None:
    """The shared hooks preserve manual application issuance and device navigation."""
    device = device_instance['device']
    profile = CertificateProfileModel.objects.create(
        unique_name='manual_application_test',
        profile_json={
            'type': 'cert_profile',
            'subj': {'common_name': {'value': 'Manual Application'}},
            'validity': {'days': 7},
        },
    )
    DomainAllowedCertificateProfileModel.objects.create(domain=device.domain, certificate_profile=profile)
    url = reverse('devices:devices_certificate_lifecycle_management_issue_profile_credential',
                  kwargs={'pk': device.pk, 'profile_id': profile.pk})
    response = admin_client.get(url)
    assert response.status_code == HTTPStatus.OK
    assert 'pki/cert_profiles/issuance.html' in [t.name for t in response.templates]
    response = admin_client.post(url, data={})
    assert response.status_code == HTTPStatus.FOUND
    assert response.url == reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
    issued = IssuedCredentialModel.objects.get(device=device)
    assert issued.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued.common_name == 'Manual Application'


@pytest.fixture(autouse=True)
def grant_manage_devices_to_admin_client(admin_client: Client) -> None:
    """Grant the shared web-test user access to protected device operations."""
    user_id = admin_client.session['_auth_user_id']
    user = get_user_model().objects.get(pk=user_id)
    manage_devices_perm = Permission.objects.get(codename='manage_devices')
    revoke_certificates_perm = Permission.objects.get(codename='revoke_certificates')
    user.role.permissions.add(manage_devices_perm, revoke_certificates_perm)


@pytest.mark.django_db
class TestDeviceTableView:
    """Test DeviceTableView."""

    def test_device_table_view_get(self, admin_client: Client) -> None:
        """Test GET request to device table view."""
        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/devices.html' in [t.name for t in response.templates]

    def test_device_table_view_filters_generic_devices(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that device table view only shows generic devices."""
        device = device_instance['device']
        assert device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE

        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        devices = response.context['object_list']
        assert device in devices

    def test_device_table_view_pagination(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test pagination in device table view."""
        # Create multiple devices
        domain = device_instance['domain']
        for i in range(15):
            DeviceModel.objects.create(
                common_name=f'test-device-pagination-{i}',
                serial_number=f'SN-PAGINATE-{i:05d}',
                domain=domain,
                device_type=DeviceModel.DeviceType.GENERIC_DEVICE
            )

        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'is_paginated' in response.context or 'page_obj' in response.context


@pytest.mark.django_db
class TestOpcUaGdsPushTableView:
    """Test OpcUaGdsPushTableView."""

    def test_opcua_gds_push_table_view_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS Push table view."""
        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/devices.html' in [t.name for t in response.templates]

    def test_opcua_gds_push_table_view_filters_opcua_gds_push_devices(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that devices table shows OPC UA GDS Push devices."""
        domain = device_instance['domain']

        # Create an OPC UA GDS Push device
        opcua_gds_push_device = DeviceModel.objects.create(
            common_name='opcua-gds-push-device',
            serial_number='SN67890',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        )

        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        devices = response.context['object_list']
        assert opcua_gds_push_device in devices


@pytest.mark.django_db
class TestDeviceCreateChooseOnboardingView:
    """Test DeviceCreateChooseOnboardingView."""

    def test_device_create_choose_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to device create choose onboarding view."""
        url = reverse('devices:devices_create')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/create_choose_onboarding.html' in [t.name for t in response.templates]

    def test_device_create_choose_onboarding_context(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test that view provides correct context."""
        url = reverse('devices:devices_create')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'page_category' in response.context
        assert 'page_name' in response.context
        assert response.context['page_category'] == 'devices'
        assert response.context['page_name'] == 'devices'


@pytest.mark.django_db
class TestOpcUaGdsPushCreateChooseOnboardingView:
    """Test OpcUaGdsPushCreateChooseOnboardingView."""

    def test_opcua_gds_push_create_choose_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS Push create choose onboarding view."""
        url = reverse('devices:opc_ua_gds_push_create_redirect')
        response = admin_client.get(url, follow=True)

        assert response.status_code == 200
        assert 'devices/create_choose_onboarding.html' in [t.name for t in response.templates]


@pytest.mark.django_db
class TestDeviceCreateNoOnboardingView:
    """Test DeviceCreateNoOnboardingView."""

    def test_device_create_no_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to device create no onboarding view."""
        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]

    def test_device_create_no_onboarding_post_valid(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test POST request with valid data creates device."""
        domain = domain_instance['domain']

        post_data = {
            'common_name': 'new-test-device',
            'serial_number': 'SN99999',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': ['1'],  # CMP_SHARED_SECRET
        }

        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.post(url, data=post_data)

        # Should redirect on success
        assert response.status_code == 302

        # Check device was created
        device = DeviceModel.objects.get(common_name='new-test-device')
        assert device.serial_number == 'SN99999'
        assert device.domain == domain
        assert device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE

    def test_device_create_no_onboarding_post_invalid(
        self,
        admin_client: Client
    ) -> None:
        """Test POST request with invalid data shows errors."""
        post_data = {
            'common_name': '',  # Invalid: empty name
            'serial_number': 'SN12345',
        }

        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.post(url, data=post_data)

        # Should not redirect, should show form with errors
        assert response.status_code == 200
        assert 'form' in response.context
        assert response.context['form'].errors


@pytest.mark.django_db
class TestDeviceCreateOnboardingView:
    """Test DeviceCreateOnboardingView."""

    def test_device_create_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to device create onboarding view."""
        url = reverse('devices:devices_create_onboarding')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]

    def test_device_create_onboarding_post_valid(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test POST request with valid data creates device with onboarding."""
        domain = domain_instance['domain']

        post_data = {
            'common_name': 'onboarding-device',
            'serial_number': 'SN77777',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.CMP_SHARED_SECRET.value),
            'onboarding_pki_protocols': ['1'],  # CMP
        }

        url = reverse('devices:devices_create_onboarding')
        response = admin_client.post(url, data=post_data)

        assert response.status_code == 302

        device = DeviceModel.objects.get(common_name='onboarding-device')
        assert device.onboarding_config is not None
        assert device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE


@pytest.mark.django_db
class TestOpcUaGdsPushCreateOnboardingView:
    """Test OpcUaGdsPushCreateOnboardingView."""

    def test_opcua_gds_push_create_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS Push create onboarding view."""
        url = reverse('devices:opc_ua_gds_push_create_onboarding_redirect')
        response = admin_client.get(url, follow=True)

        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]

    def test_opcua_gds_push_create_onboarding_creates_opcua_gds_push_device(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS Push view creates OPC UA GDS Push device with onboarding."""
        domain = domain_instance['domain']

        post_data = {
            'common_name': 'opcua-gds-push-onboarding-device',
            'serial_number': 'SN88888',
            'domain': domain.pk,
            'ip_address': '192.168.1.100',
            'opc_server_port': 4840,
            'opc_user': 'admin',
            'opc_password': 'password123',
        }

        url = reverse('devices:devices_create_opc_ua_gds_push')
        response = admin_client.post(url, data=post_data, follow=True)

        assert response.status_code == 200

        device = DeviceModel.objects.get(common_name='opcua-gds-push-onboarding-device')
        assert device.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        assert device.onboarding_config is not None
        assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.OPC_GDS_PUSH
        assert device.ip_address == '192.168.1.100'
        assert device.opc_ua_gds_push_config.opc_server_port == 4840


@pytest.mark.django_db
class TestDeviceCertificateLifecycleManagementSummaryView:
    """Test DeviceCertificateLifecycleManagementSummaryView."""

    def test_clm_summary_view_get(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test GET request to CLM summary view."""
        device = device_instance['device']

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/credentials/certificate_lifecycle_management.html' in [t.name for t in response.templates]
        assert response.context['object'] == device

    def test_clm_summary_view_invalid_device(self, admin_client: Client) -> None:
        """Test GET request with invalid device ID returns 404."""
        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': 99999})
        response = admin_client.get(url)

        assert response.status_code == 404


@pytest.mark.django_db
class TestDeviceCreateAddOnboardingTypeView:
    """Test DeviceCreateAddOnboardingTypeView."""

    def test_device_create_add_onboarding_type_get(self, admin_client: Client) -> None:
        """Test GET request to device create add onboarding type view."""
        url = reverse('devices:devices_new_onboarding')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/add_onboarding_type.html' in [t.name for t in response.templates]

    def test_device_create_add_onboarding_type_context(self, admin_client: Client) -> None:
        """Test that view provides correct context urls."""
        url = reverse('devices:devices_new_onboarding')
        response = admin_client.get(url)

        assert response.status_code == 200
        context = response.context


        assert context.get('page_category') == 'devices'
        assert context.get('page_name') == 'devices'


        assert 'cancel_create_url' in context
        assert context['cancel_create_url'] == 'devices:devices'


        assert 'use_onboarding_url_name' in context
        assert context['use_onboarding_url_name'] == 'pki:devid_registration-method_select'


        assert 'use_no_onboarding_url' in context
        assert context['use_no_onboarding_url'] == 'devices:devices_create_no_onboarding'


@pytest.mark.django_db
class TestOpcUaGdsPushCertificateLifecycleManagementSummaryView:
    """Test OpcUaGdsPushCertificateLifecycleManagementSummaryView."""

    def test_opcua_gds_push_clm_summary_view_get(
        self,
        admin_client: Client,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test GET request to OPC UA GDS Push CLM summary view."""
        device = device_instance_onboarding['device']
        # Change device type to GDS Push
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.save()

        url = reverse('devices:opc_ua_gds_push_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'devices/credentials/certificate_lifecycle_management.html' in [t.name for t in response.templates]
        assert response.context['object'] == device


@pytest.mark.django_db
class TestIssuedCredentialRevocationView:
    """Test the revocation error messages if tried to revoke revoked cert."""

    def test_revoke_already_revoked_certificate_coverage(
            self,
            admin_client: Client,
            device_instance: dict[str, Any]
    ) -> None:
        """Mocks the certificate status to REVOKED to hit the error message."""
        device = device_instance['device']

        url = reverse('devices:devices_credential_revoke', kwargs={'pk': 1})


        with patch('devices.views.revoke.AbstractIssuedCredentialRevocationView.get_object') as mock_get:
            mock_issued_cred = Mock()
            mock_cert = Mock()


            mock_cert.certificate_status = CertificateModel.CertificateStatus.REVOKED
            mock_issued_cred.credential.certificate_or_error = mock_cert
            mock_issued_cred.device = device
            mock_issued_cred.id = 1

            mock_get.return_value = mock_issued_cred

            response = admin_client.post(url, data={'revocation_reason': 'unspecified'}, follow=True)


        assert response.status_code == HTTPStatus.OK
        messages_list = [str(m) for m in list(response.context['messages'])]


        assert any('already revoked' in m for m in messages_list)
