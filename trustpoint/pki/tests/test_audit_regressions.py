# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression checks for PKI permission and lifecycle failures."""

from ast import literal_eval
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.utils import timezone
from django_q.models import Schedule
from rest_framework.test import APIRequestFactory, force_authenticate

from pki.models import CaModel, CredentialModel, OwnerCredentialModel, RemoteIssuedCredentialModel
from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainModel
from pki.rollover.import_ca import ImportCaRolloverStrategy
from pki.services.ca_enrollment import CmpCaEnrollmentService, EstCaEnrollmentService
from pki.services.ca_rollover import CaRolloverError, CaRolloverService
from pki.tasks import generate_crl_for_ca
from pki.util.x509 import CertificateGenerator, CertificateVerifier
from pki.views.owner_credentials_api import DevOwnerIdViewSet


def test_owner_creation_requires_management_permission():
    user = get_user_model().objects.create_user(username='reader')
    payload = {
        'method': 'est_basic_auth',
        'unique_name': 'owner',
        'remote_host': 'ca.example',
        'est_username': 'enroll',
        'est_password': 'test',
    }
    view = DevOwnerIdViewSet.as_view({'post': 'create'})
    request = APIRequestFactory().post('/api/devownerid/', payload, format='json')
    force_authenticate(request, user=user)
    assert view(request).status_code == 403
    assert not OwnerCredentialModel.objects.exists()

    user.user_permissions.add(Permission.objects.get(content_type__app_label='users', codename='manage_devices'))
    user = get_user_model().objects.get(pk=user.pk)
    request = APIRequestFactory().post('/api/devownerid/', payload, format='json')
    force_authenticate(request, user=user)
    assert view(request).status_code == 201


@pytest.mark.parametrize('action', ['request_domain_credential', 'request_devownerid'])
def test_owner_enrollment_requires_issuance_permission(action):
    user = get_user_model().objects.create_user(username='manager')
    user.user_permissions.add(Permission.objects.get(content_type__app_label='users', codename='manage_devices'))
    owner = OwnerCredentialModel.objects.create(unique_name='owner')
    view = DevOwnerIdViewSet.as_view({'post': action})
    request = APIRequestFactory().post('/api/devownerid/request/', {}, format='json')
    force_authenticate(request, user=user)
    assert view(request, pk=owner.pk).status_code == 403

    user.user_permissions.add(Permission.objects.get(content_type__app_label='users', codename='issue_certificates'))
    user = get_user_model().objects.get(pk=user.pk)
    request = APIRequestFactory().post('/api/devownerid/request/', {}, format='json')
    force_authenticate(request, user=user)
    # The local owner fails enrollment validation after passing authorization.
    assert view(request, pk=owner.pk).status_code == 400


@pytest.mark.parametrize('with_credential', [False, True])
def test_owner_deletion_cleans_up_protected_credentials(with_credential):
    owner = OwnerCredentialModel.objects.create(unique_name='owner')
    owner_pk = owner.pk
    if with_credential:
        credential = CredentialModel.objects.create(credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID)
        RemoteIssuedCredentialModel.objects.create(
            common_name='owner',
            owner_credential=owner,
            credential=credential,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
        )
    owner.delete()
    assert not OwnerCredentialModel.objects.filter(pk=owner_pk).exists()
    assert not RemoteIssuedCredentialModel.objects.exists()
    if with_credential:
        assert not CredentialModel.objects.filter(pk=credential.pk).exists()


def test_generated_rollover_clears_remote_fields(issuing_ca_model, second_issuing_ca_model):
    ca = second_issuing_ca_model
    CaModel.objects.filter(pk=ca.pk).update(
        ca_type=CaModel.CaTypeChoice.REMOTE_ISSUING_EST,
        remote_host='ca.example',
        remote_port=443,
        remote_path='/enroll',
        est_username='enroll',
        cmp_sender_kid=4,
    )
    ca.refresh_from_db()
    rollover = CaRolloverModel.objects.create(
        old_issuing_ca=issuing_ca_model,
        new_issuing_ca=ca,
        state=CaRolloverState.AWAITING_NEW_CA,
        strategy_type=CaRolloverStrategyType.GENERATE_KEYPAIR,
    )
    CaRolloverService.complete_awaiting_rollover_for_ca(ca)
    rollover.refresh_from_db()
    ca.refresh_from_db()
    assert rollover.state == CaRolloverState.PLANNED
    assert ca.ca_type == CaModel.CaTypeChoice.LOCAL_PKCS11
    assert (ca.remote_host, ca.remote_port, ca.remote_path, ca.est_username, ca.cmp_sender_kid) == (
        '',
        None,
        '',
        '',
        None,
    )


def test_crl_schedule_preserves_other_ca_and_replaces_legacy_job(issuing_ca_model, second_issuing_ca_model):
    a, b = issuing_ca_model, second_issuing_ca_model
    a.unique_name, b.unique_name = 'ca', 'ca-backup'
    a.crl_cycle_enabled = b.crl_cycle_enabled = True
    a.save()
    b.save()
    legacy = Schedule.objects.create(
        name='crl_gen_ca_legacy',
        func='pki.tasks.generate_crl_for_ca',
        args=str((a.pk,)),
        schedule_type='O',
        next_run=timezone.now(),
    )
    b.schedule_next_crl_generation()
    other_job = Schedule.objects.get(func='pki.tasks.generate_crl_for_ca', args=str((b.pk,)))
    a.schedule_next_crl_generation()
    a.schedule_next_crl_generation()
    assert Schedule.objects.filter(pk=other_job.pk).exists()
    assert not Schedule.objects.filter(pk=legacy.pk).exists()
    assert Schedule.objects.filter(func='pki.tasks.generate_crl_for_ca', args=str((a.pk,))).count() == 1


def test_failed_crl_is_reported_and_retried_at_most_three_times(issuing_ca_model):
    with patch.object(CaModel, 'issue_crl', return_value=False):
        for attempt in range(1, 4):
            Schedule.objects.all().delete()
            with pytest.raises(RuntimeError, match=f'attempt {attempt}/3'):
                generate_crl_for_ca(issuing_ca_model.pk, attempt=attempt)
            if attempt < 3:
                retry = Schedule.objects.get(func='pki.tasks.generate_crl_for_ca')
                assert literal_eval(retry.args) == (issuing_ca_model.pk,)
                assert literal_eval(retry.kwargs) == {'attempt': attempt + 1, 'q_options': {'ack_failure': True}}
                assert retry.next_run > timezone.now()
            else:
                assert not Schedule.objects.exists()


def test_crl_worker_preserves_fractional_validity(issuing_ca_model):
    issuing_ca_model.crl_validity_hours = 1.5
    issuing_ca_model.save()
    with patch.object(CaModel, 'issue_crl', return_value=True) as issue:
        generate_crl_for_ca(issuing_ca_model.pk)
    issue.assert_called_once_with(crl_validity_hours=1.5)


def test_rollover_completion_rolls_back_hook_failure(issuing_ca_model, second_issuing_ca_model):
    rollover = CaRolloverModel.objects.create(
        old_issuing_ca=issuing_ca_model,
        new_issuing_ca=second_issuing_ca_model,
        state=CaRolloverState.TRANSITION,
        strategy_type=CaRolloverStrategyType.IMPORT_CA,
    )
    domain = DomainModel.objects.create(unique_name='domain', issuing_ca=issuing_ca_model)
    complete = ImportCaRolloverStrategy().on_complete

    def fail_after_updates(rollover):
        complete(rollover)
        raise RuntimeError('failure')

    with patch.object(ImportCaRolloverStrategy, 'on_complete', side_effect=fail_after_updates):
        with pytest.raises(RuntimeError):
            CaRolloverService.finalize_rollover(rollover)
    rollover.refresh_from_db()
    issuing_ca_model.refresh_from_db()
    assert rollover.state == CaRolloverState.TRANSITION
    assert issuing_ca_model.is_active
    domain.refresh_from_db()
    assert domain.issuing_ca == issuing_ca_model


def test_stale_rollover_cannot_cancel_completed_rollover(issuing_ca_model, second_issuing_ca_model):
    rollover = CaRolloverModel.objects.create(
        old_issuing_ca=issuing_ca_model,
        new_issuing_ca=second_issuing_ca_model,
        state=CaRolloverState.TRANSITION,
        strategy_type=CaRolloverStrategyType.IMPORT_CA,
    )
    stale = CaRolloverModel.objects.get(pk=rollover.pk)
    CaRolloverService.finalize_rollover(rollover)
    with pytest.raises(CaRolloverError, match='Cannot cancel'):
        CaRolloverService.cancel_rollover(stale)
    rollover.refresh_from_db()
    assert rollover.state == CaRolloverState.COMPLETED


def test_pss_ca_signature_uses_encoded_parameters():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'PSS')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(key, hashes.SHA256(), rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32))
    )
    CertificateVerifier._verify_cert_signature(cert, cert)


def test_cmp_ca_lookup_distinguishes_replacement_key(issuing_ca_model):
    replacement, _ = CertificateGenerator.create_root_ca('Old Issuing CA')
    assert issuing_ca_model.get_certificate().subject == replacement.subject
    service = CmpCaEnrollmentService()
    assert service._find_existing_ca_for_certificate(replacement) is None
    assert service._find_existing_ca_for_certificate(issuing_ca_model.get_certificate()) == issuing_ca_model


def test_cmp_parent_selection_verifies_signature(issuing_ca_model, second_issuing_ca_model):
    # Same subject but wrong signing key must not match a valid candidate name.
    leaf, _ = CertificateGenerator.create_issuing_ca(
        second_issuing_ca_model.credential.get_private_key(),
        'Old Issuing CA',
        'Leaf',
    )
    assert CmpCaEnrollmentService()._find_issuer_ca(leaf, [issuing_ca_model]) is None


@pytest.mark.parametrize('protocol', ['est', 'cmp'])
@pytest.mark.parametrize('invalid_ca', [False, True])
def test_enrollment_rejects_invalid_material_before_saving(
    issuing_ca_model,
    second_issuing_ca_model,
    protocol,
    invalid_ca,
):
    ca = issuing_ca_model
    profile = CertificateProfileModel.objects.create(unique_name='profile', profile_json={})
    if invalid_ca:
        wrong_cert, _ = CertificateGenerator.create_ee(
            ca.credential.get_private_key(), ca.get_certificate().subject, 'leaf'
        )
    else:
        wrong_cert = second_issuing_ca_model.get_certificate()
    original_certificate = ca.credential.certificate_id
    with pytest.raises((ValueError, ValidationError)):
        if protocol == 'est':
            with (
                patch('pki.services.ca_enrollment.ProfileAwareCsrBuilder'),
                patch('pki.services.ca_enrollment.EstDeviceCsrSignProcessor'),
                patch('pki.services.ca_enrollment.EstClient') as client,
                patch.object(EstCaEnrollmentService, '_build_request_data_from_form', return_value={}),
            ):
                client.return_value.simple_enroll.return_value = (wrong_cert, [])
                EstCaEnrollmentService().enroll(ca, {}, profile)
        else:
            CmpCaEnrollmentService()._save_cmp_certificates(ca, wrong_cert, [], profile)
    ca.credential.refresh_from_db()
    assert ca.credential.certificate_id == original_certificate
    assert not RemoteIssuedCredentialModel.objects.filter(ca=ca).exists()


def test_cmp_parent_selection_skips_wrong_key_with_same_subject(issuing_ca_model):
    cert, key = CertificateGenerator.create_root_ca('Old Issuing CA')
    replacement = CaModel.create_keyless_ca(unique_name='replacement', certificate_obj=cert)
    leaf, _ = CertificateGenerator.create_issuing_ca(key, 'Old Issuing CA', 'Leaf')
    assert CmpCaEnrollmentService()._find_issuer_ca(leaf, [issuing_ca_model, replacement]) == replacement


def test_cmp_enrollment_keeps_same_named_replacement_ca_distinct(issuing_ca_model):
    old_root, _ = CertificateGenerator.create_root_ca('Shared Root')
    old_ca = CaModel.create_keyless_ca(unique_name='Shared Root', certificate_obj=old_root)
    new_root, new_key = CertificateGenerator.create_root_ca('Shared Root')
    cert, _ = CertificateGenerator.create_issuing_ca(
        new_key,
        'Shared Root',
        'Replacement',
        private_key=issuing_ca_model.credential.get_private_key(),
    )
    profile = CertificateProfileModel.objects.create(unique_name='profile', profile_json={})
    CmpCaEnrollmentService()._save_cmp_certificates(issuing_ca_model, cert, [new_root], profile)
    issuing_ca_model.refresh_from_db()
    assert issuing_ca_model.parent_ca != old_ca
    assert issuing_ca_model.parent_ca.get_certificate() == new_root
    assert old_ca.get_certificate() == old_root
