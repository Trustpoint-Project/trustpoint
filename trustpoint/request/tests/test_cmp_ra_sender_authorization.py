# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Authorization of the authenticated upstream identity used by a configured CMP RA."""

import pytest
from django.urls import reverse
from pyasn1_modules import rfc4210

from management.models import SecurityConfig
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import CaModel
from request.clients.cmp_client import CmpClient
from request.message_builder.cmp import CmpPkiHeaderBuilding
from request.request_context import CmpCertificateRequestContext
from request.security_hardening import authenticate_cmp_request, validate_cmp_proof_of_possession

pytestmark = pytest.mark.django_db


@pytest.fixture
def ra_sender(cmp_device_without_onboarding):
    SecurityConfig.objects.create()
    device = cmp_device_without_onboarding['device']
    secret = device.no_onboarding_config.cmp_shared_secret
    config = NoOnboardingConfigModel.objects.create(
        pki_protocols=NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
        cmp_shared_secret=secret,
    )
    ra = CaModel.objects.create(
        unique_name='configured-cmp-ra',
        ca_type=CaModel.CaTypeChoice.REMOTE_CMP_RA,
        certificate=device.domain.issuing_ca.ca_certificate_model,
        remote_host='127.0.0.1',
        remote_port=8443,
        remote_path=reverse(
            'cmp:req_domain_profile_op',
            kwargs={
                'domain': device.domain.unique_name,
                'cert_profile': 'tls_server',
                'operation': 'certification',
            },
        ),
        cmp_sender_kid=device.pk,
        no_onboarding_config=config,
    )
    return device, ra


def _request(device, secret=None):
    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 2
    header['sender']['rfc822Name'] = 'ra@example.test'
    header['recipient']['rfc822Name'] = 'ca@example.test'
    header['senderKID'] = str(device.pk).encode()
    message['header'] = CmpPkiHeaderBuilding._prepare_protection_algorithm_pbm(header)
    entry = message['body']['cr'][0]
    entry['certReq']['certReqId'] = 0
    entry['certReq']['certTemplate']['version'] = 2
    entry['pop']['raVerified'] = ''
    context = CmpCertificateRequestContext(
        protocol='cmp',
        operation='certification',
        cmp_body_type='cr',
        parsed_message=message,
        domain=device.domain,
        cmp_server_host='example.test',
        cmp_shared_secret=secret if secret is not None else device.no_onboarding_config.cmp_shared_secret,
    )
    CmpClient(context)._add_protection_shared_secret(message)
    # Only authentication may populate the credential used to protect replies.
    context.cmp_shared_secret = None
    return context


def test_configured_upstream_sender_is_allowed_and_loses_permission_when_ra_is_disabled(ra_sender):
    device, ra = ra_sender
    assert not device.can_assert_cmp_ra_verified  # The upstream account belongs to a local CA domain.
    context = _request(device)
    authenticate_cmp_request(context)
    validate_cmp_proof_of_possession(context)

    ra.is_active = False
    ra.save(update_fields=['is_active'])
    context = _request(device)
    authenticate_cmp_request(context)
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)


@pytest.mark.parametrize('mismatch', ['sender_id', 'secret', 'domain', 'endpoint', 'ca_type'])
def test_unrelated_ra_configuration_does_not_authorize_the_upstream_sender(ra_sender, mismatch):
    device, ra = ra_sender
    if mismatch == 'sender_id':
        ra.cmp_sender_kid = device.pk + 1
    elif mismatch == 'secret':
        ra.no_onboarding_config.cmp_shared_secret = 'unrelated-ra-secret'
        ra.no_onboarding_config.save()
    elif mismatch == 'domain':
        ra.remote_path = '/.well-known/cmp/p/another-domain/tls_server/certification'
    elif mismatch == 'endpoint':
        ra.remote_path = '/.well-known/est/local/tls_server/simpleenroll'
    else:
        ra.ca_type = CaModel.CaTypeChoice.REMOTE_EST_RA
    ra.save()
    context = _request(device)
    authenticate_cmp_request(context)
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)


def test_configured_sender_requires_successful_authentication(ra_sender):
    device, _ = ra_sender
    context = _request(device)
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)

    with pytest.raises(ValueError, match='authentication failed'):
        authenticate_cmp_request(_request(device, secret='incorrect-secret'))
