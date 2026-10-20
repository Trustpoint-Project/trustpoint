# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for persisted CMP registration-authority permissions."""

import pytest
from pyasn1_modules import rfc4210

from devices.forms import ClmDeviceModelNoOnboardingForm, ClmDeviceModelOnboardingForm
from devices.models import DeviceModel, OnboardingProtocol
from request.request_context import CmpCertificateRequestContext
from request.security_hardening import validate_cmp_proof_of_possession


@pytest.mark.django_db
def test_ra_permission_survives_rename_and_can_be_revoked(device_instance):
    device = device_instance['device']
    original_name = device.common_name
    message = rfc4210.PKIMessage()
    message['body']['cr'][0]['pop']['raVerified'] = ''
    context = CmpCertificateRequestContext(parsed_message=message, cmp_body_type='cr', device=device)
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)

    device.allow_cmp_ra_verified = True
    device.save(update_fields=['allow_cmp_ra_verified'])
    device.common_name = 'renamed-trusted-ra'
    device.save(update_fields=['common_name'])
    context.device = DeviceModel.objects.get(pk=device.pk)
    validate_cmp_proof_of_possession(context)

    device.allow_cmp_ra_verified = False
    device.save(update_fields=['allow_cmp_ra_verified'])
    context.device = DeviceModel.objects.get(pk=device.pk)
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)

    # Reusing the former name does not grant the old device's permission.
    context.device = DeviceModel(common_name=original_name)
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)


@pytest.mark.django_db
@pytest.mark.parametrize('initial_permission', [False, True])
@pytest.mark.parametrize('uses_onboarding', [False, True])
def test_clm_forms_do_not_expose_or_change_ra_permission(request, initial_permission, uses_onboarding):
    fixture_name = 'device_instance_onboarding' if uses_onboarding else 'device_instance'
    device = request.getfixturevalue(fixture_name)['device']
    device.allow_cmp_ra_verified = initial_permission
    device.save(update_fields=['allow_cmp_ra_verified'])
    form_type = ClmDeviceModelOnboardingForm if uses_onboarding else ClmDeviceModelNoOnboardingForm
    form = form_type(
        instance=device,
        data={
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': device.domain_id,
            'onboarding_status': 'pending',
            'pki_protocol_cmp': True,
            'allow_cmp_ra_verified': not initial_permission,
        },
    )
    assert 'allow_cmp_ra_verified' not in form.fields
    assert form.is_valid(), form.errors
    if uses_onboarding:
        form.save(OnboardingProtocol.CMP_SHARED_SECRET)
    else:
        form.save()
    device.refresh_from_db()
    assert device.allow_cmp_ra_verified is initial_permission


@pytest.mark.parametrize('ca_type', ['remote_cmp_ra', 'remote_est_ra', 'local', None])
def test_ra_verified_follows_the_devices_linked_ca(ca_type):
    from pki.models import CaModel, DomainModel

    device = DeviceModel(common_name='linked-device')
    message = rfc4210.PKIMessage()
    message['body']['cr'][0]['pop']['raVerified'] = ''
    context = CmpCertificateRequestContext(parsed_message=message, cmp_body_type='cr', device=device)
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)

    ca_types = {
        'remote_cmp_ra': CaModel.CaTypeChoice.REMOTE_CMP_RA,
        'remote_est_ra': CaModel.CaTypeChoice.REMOTE_EST_RA,
        'local': CaModel.CaTypeChoice.LOCAL_UNPROTECTED,
    }
    ca = CaModel(unique_name='linked-ca', ca_type=ca_types[ca_type]) if ca_type else None
    device.domain = DomainModel(unique_name='linked-domain', issuing_ca=ca)
    if ca_type == 'remote_cmp_ra':
        validate_cmp_proof_of_possession(context)
        device.common_name = 'renamed-linked-device'
        validate_cmp_proof_of_possession(context)
        device.domain = None
        with pytest.raises(ValueError, match='not permitted'):
            validate_cmp_proof_of_possession(context)
        assert device.allow_cmp_ra_verified is False
    else:
        with pytest.raises(ValueError, match='not permitted'):
            validate_cmp_proof_of_possession(context)
