# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Periodic GDS Push client credential renewal tests."""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.urls import reverse
from django.utils import timezone
from django_q.models import Schedule

from devices.domain_credential_renewal import renew_gds_push_domain_credential
from devices.models import DeviceModel, OpcUaGdsPushConfig
from devices.tasks import perform_gds_push_domain_credential_renewal
from pki.models.cert_profile import CertificateProfileModel
from pki.models.certificate import RevokedCertificateModel


@pytest.fixture
def renewal_device(device_instance_onboarding, admin_client):
    from onboarding.models import OnboardingPkiProtocol, OnboardingProtocol

    user = get_user_model().objects.get(pk=admin_client.session['_auth_user_id'])
    user.role.permissions.add(*Permission.objects.filter(codename__in=['manage_devices', 'view_help_pages']))
    device = device_instance_onboarding['device']
    device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
    device.ip_address = '127.0.0.1'
    device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
    device.onboarding_config.set_pki_protocols([OnboardingPkiProtocol.OPC_GDS_PUSH])
    device.onboarding_config.save()
    device.save()
    profile_json = json.loads(
        (
            Path(__file__).resolve().parents[2] / 'pki/default_certificate_profiles/opc_ua_domain_credential.json'
        ).read_text()
    )
    profile = CertificateProfileModel.objects.create(
        unique_name='test_gds_domain',
        credential_type=CertificateProfileModel.ProfileCredentialType.DOMAIN,
        profile_json=profile_json,
    )
    device.domain.domain_credential_profile = profile
    device.domain.save()
    url = reverse('devices:devices_onboarding_clm_issue_domain_credential', kwargs={'pk': device.pk})
    response = admin_client.post(
        url,
        {
            'common_name': 'Trustpoint Domain Credential',
            'days': 30,
            'uris': 'urn:custom:keep-this-identity',
        },
    )
    assert response.status_code == 302, response.context['form'].errors
    assert device.issued_credentials.count() == 1
    return device


def settings_url(device):
    return reverse('devices:devices_domain_credential_renewal_settings', kwargs={'pk': device.pk})


def enable_renewal(client, device, hours=12):
    return client.post(
        settings_url(device),
        {
            'opc_gds_push_enable_domain_credential_renewal': 'on',
            'opc_gds_push_domain_credential_renewal_interval': hours,
        },
    )


def test_settings_schedule_reschedule_and_disable(admin_client, renewal_device):
    device = renewal_device
    assert enable_renewal(admin_client, device).status_code == 302
    device.refresh_from_db()
    assert device.opc_ua_gds_push_config.opc_gds_push_enable_domain_credential_renewal
    assert not device.opc_ua_gds_push_config.opc_gds_push_enable_periodic_update
    task_name = f'gds_push_domain_credential_renewal_{device.pk}'
    task = Schedule.objects.get(name=task_name)
    assert task.func == 'devices.tasks.perform_gds_push_domain_credential_renewal'
    assert task.next_run == device.opc_ua_gds_push_config.opc_gds_push_domain_credential_next_renewal_at
    assert timezone.now() + timedelta(hours=11) < task.next_run < timezone.now() + timedelta(hours=13)
    first_id = task.pk
    enable_renewal(admin_client, device, hours=24)
    task = Schedule.objects.get(name=task_name)
    assert task.pk != first_id
    assert timezone.now() + timedelta(hours=23) < task.next_run < timezone.now() + timedelta(hours=25)
    admin_client.post(settings_url(device), {'opc_gds_push_domain_credential_renewal_interval': 24})
    device.refresh_from_db()
    assert not device.opc_ua_gds_push_config.opc_gds_push_enable_domain_credential_renewal
    assert device.opc_ua_gds_push_config.opc_gds_push_domain_credential_next_renewal_at is None
    assert not Schedule.objects.filter(name=task_name).exists()


@pytest.mark.parametrize('interval', ['', 'x', '0', '-1'])
def test_invalid_settings_do_not_schedule(admin_client, renewal_device, interval):
    enable_renewal(admin_client, renewal_device, interval)
    renewal_device.refresh_from_db()
    assert not renewal_device.opc_ua_gds_push_config.opc_gds_push_enable_domain_credential_renewal
    assert not Schedule.objects.filter(name=f'gds_push_domain_credential_renewal_{renewal_device.pk}').exists()


def test_real_renewal_preserves_identity_and_revokes_previous(renewal_device):
    device = renewal_device
    previous = device.issued_credentials.get()
    old_cert = previous.credential.get_certificate()
    replacement = renew_gds_push_domain_credential(device)
    new_cert = replacement.credential.get_certificate()
    assert replacement.pk != previous.pk
    assert replacement.is_valid_domain_credential()[0]
    assert new_cert.subject == old_cert.subject
    assert new_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName) == (
        old_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    )
    spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert new_cert.public_key().public_bytes(*spki) != old_cert.public_key().public_bytes(*spki)
    revoked = RevokedCertificateModel.objects.get(certificate=previous.credential.certificate)
    assert revoked.revocation_reason == RevokedCertificateModel.ReasonCode.SUPERSEDED


def test_issuance_failure_retains_previous_identity(renewal_device):
    previous = renewal_device.issued_credentials.get()
    with patch(
        'devices.domain_credential_renewal.CredentialIssueProcessor.process_operation', side_effect=ValueError('failed')
    ):
        with pytest.raises(ValueError, match='failed'):
            renew_gds_push_domain_credential(renewal_device)
    assert previous.is_valid_domain_credential()[0]
    assert renewal_device.issued_credentials.count() == 1


def test_revocation_failure_rolls_back_replacement(renewal_device):
    previous = renewal_device.issued_credentials.get()
    with patch(
        'devices.domain_credential_renewal.DeviceCredentialRevocation.revoke_certificate',
        return_value=(False, 'failed'),
    ):
        with pytest.raises(ValueError, match='failed'):
            renew_gds_push_domain_credential(renewal_device)
    assert previous.is_valid_domain_credential()[0]
    assert renewal_device.issued_credentials.count() == 1


def test_task_renews_and_schedules_next_run(admin_client, renewal_device):
    device = renewal_device
    enable_renewal(admin_client, device)
    OpcUaGdsPushConfig.objects.filter(device=device).update(
        opc_gds_push_domain_credential_next_renewal_at=timezone.now() - timedelta(seconds=1)
    )
    previous = device.issued_credentials.get()
    perform_gds_push_domain_credential_renewal(device.pk)
    device.refresh_from_db()
    assert device.issued_credentials.count() == 2
    assert not previous.is_valid_domain_credential()[0]
    assert device.opc_ua_gds_push_config.opc_gds_push_domain_credential_next_renewal_at > timezone.now()
    assert Schedule.objects.filter(name=f'gds_push_domain_credential_renewal_{device.pk}').count() == 1
    # A duplicate queued execution must not rotate the identity a second time.
    perform_gds_push_domain_credential_renewal(device.pk)
    assert device.issued_credentials.count() == 2


def test_disabled_task_does_not_issue(renewal_device):
    perform_gds_push_domain_credential_renewal(renewal_device.pk)
    assert renewal_device.issued_credentials.count() == 1


def test_onboarding_page_shows_domain_renewal_form(admin_client, renewal_device):
    url = reverse('devices:devices_onboarding_truststore_associated_help', kwargs={'pk': renewal_device.pk})
    response = admin_client.get(url)
    assert response.status_code == 200
    assert b'Periodic Domain Credential Renewal' in response.content
    assert b'name="opc_gds_push_domain_credential_renewal_interval"' in response.content
    assert settings_url(renewal_device).encode() in response.content


def test_task_failure_keeps_old_identity_and_schedules_retry(admin_client, renewal_device):
    device = renewal_device
    enable_renewal(admin_client, device)
    OpcUaGdsPushConfig.objects.filter(device=device).update(
        opc_gds_push_domain_credential_next_renewal_at=timezone.now() - timedelta(seconds=1)
    )
    previous = device.issued_credentials.get()
    with patch(
        'devices.domain_credential_renewal.CredentialIssueProcessor.process_operation', side_effect=ValueError('failed')
    ):
        perform_gds_push_domain_credential_renewal(device.pk)
    device.refresh_from_db()
    assert previous.is_valid_domain_credential()[0]
    assert device.issued_credentials.count() == 1
    assert device.opc_ua_gds_push_config.opc_gds_push_domain_credential_next_renewal_at > timezone.now()
    assert Schedule.objects.filter(name=f'gds_push_domain_credential_renewal_{device.pk}').count() == 1


def test_enabling_requires_initial_credential(admin_client, renewal_device):
    renewal_device.issued_credentials.all().delete()
    enable_renewal(admin_client, renewal_device)
    renewal_device.refresh_from_db()
    assert not renewal_device.opc_ua_gds_push_config.opc_gds_push_enable_domain_credential_renewal
    assert renewal_device.opc_ua_gds_push_config.opc_gds_push_domain_credential_next_renewal_at is None


def test_settings_require_device_management_permission(admin_client, renewal_device):
    user = get_user_model().objects.get(pk=admin_client.session['_auth_user_id'])
    user.role.permissions.remove(Permission.objects.get(codename='manage_devices'))
    response = enable_renewal(admin_client, renewal_device)
    assert response.status_code == 403
    renewal_device.refresh_from_db()
    assert not renewal_device.opc_ua_gds_push_config.opc_gds_push_enable_domain_credential_renewal
