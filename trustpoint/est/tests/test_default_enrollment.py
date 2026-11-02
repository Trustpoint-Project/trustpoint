# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise default EST routes through authentication, authorization and issuance."""

import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from django.urls import resolve

from management.models import SecurityConfig
from pki.models import CertificateModel, CertificateProfileModel, DomainModel


@pytest.fixture(params=['simpleenroll', 'simplereenroll'])
def enrollment_request(request, rf, rsa_private_key, settings):
    settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING = False
    config = SecurityConfig.objects.create(security_mode=SecurityConfig.SecurityModeChoices.LAB)
    config.apply_security_settings()
    operation = request.param
    environment = request.getfixturevalue(
        'est_device_with_onboarding' if operation == 'simpleenroll' else 'domain_credential_est_onboarding'
    )
    device = environment['device']
    headers = {}
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, device.common_name)])
    if operation == 'simpleenroll':
        credentials = f'{device.common_name}:{device.onboarding_config.est_password}'.encode()
        headers['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(credentials).decode()
    else:
        certificate = environment['domain_credential'].credential.get_certificate()
        subject = certificate.subject
        headers['HTTP_SSL_CLIENT_CERT'] = certificate.public_bytes(Encoding.PEM).decode()
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(rsa_private_key, hashes.SHA256())

    def post(prefix='', *, authenticated=True):
        path = f'/.well-known/est/{prefix}{operation}'
        http_request = rf.post(
            path, data=base64.b64encode(csr.public_bytes(Encoding.DER)),
            content_type='application/pkcs10', **(headers if authenticated else {}),
        )
        match = resolve(path)
        return match.func(http_request, *match.args, **match.kwargs)

    return device, post


@pytest.mark.parametrize('custom_default', [False, True])
@pytest.mark.parametrize('explicit_domain', [False, True])
def test_default_route_issues_using_authenticated_domain(enrollment_request, custom_default, explicit_domain):
    device, post = enrollment_request
    if custom_default:
        profile = CertificateProfileModel.objects.create(
            unique_name='custom-default',
            profile_json={'type': 'cert_profile', 'subj': {'allow': '*'}, 'validity': {'days': 7}},
        )
        device.domain.domain_credential_profile = profile
        device.domain.save()
    before = CertificateModel.objects.count()
    response = post(f'{device.domain.unique_name}/' if explicit_domain else '')
    assert response.status_code == 200, response.content
    certificates = load_der_pkcs7_certificates(base64.b64decode(response.content))
    assert certificates
    assert CertificateModel.objects.count() == before + 1
    issued = CertificateModel.objects.latest('pk').get_certificate_serializer().as_crypto()
    assert issued in certificates
    if custom_default:
        assert (issued.not_valid_after_utc - issued.not_valid_before_utc).days == 7


def test_explicit_cross_domain_request_is_rejected(enrollment_request, caplog):
    device, post = enrollment_request
    other = DomainModel.objects.create(unique_name='other-domain', issuing_ca=device.domain.issuing_ca)
    before = CertificateModel.objects.count()
    assert post(f'{other.unique_name}/').status_code >= 400
    assert "doesn't match requested domain" in caplog.text
    assert CertificateModel.objects.count() == before


def test_default_route_still_requires_authentication(enrollment_request):
    _, post = enrollment_request
    before = CertificateModel.objects.count()
    assert post(authenticated=False).status_code >= 400
    assert CertificateModel.objects.count() == before
