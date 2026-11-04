# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for EST credential scope, approval retries and HTTP responses."""

import base64
from copy import copy
from dataclasses import replace
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import AttributeOID
from django.urls import resolve
from trustpoint_core.serializer import CertificateCollectionSerializer

from est.channel_binding import verify_est_channel_binding
from est.tests.client import ESTClient
from management.models import SecurityConfig
from pki.models import IssuedCredentialModel
from pki.models.domain import DomainAllowedCertificateProfileModel
from pki.tests.credential_helpers import issue_test_credential
from request.message_responder.est import EstCertificateMessageResponder
from request.request_context import EstCertificateRequestContext
from request.request_validator.http_req import EstHttpRequestValidator
from request.workflow2_issuance import Workflow2IssuanceDecision
from request.workflows2_handler import _build_est_simpleenroll_dispatch
from workflows2.models import Workflow2Run
from workflows2.services.dispatch import WorkflowDispatchService


@pytest.fixture
def lab_policy():
    config = SecurityConfig.objects.create(security_mode=SecurityConfig.SecurityModeChoices.LAB)
    config.apply_security_settings()


def post_est(rf, device, csr, operation='simpleenroll', profile='domain_credential', **headers):
    path = f'/.well-known/est/{device.domain.unique_name}/{profile}/{operation}'
    request = rf.post(
        path,
        data=base64.b64encode(csr.public_bytes(Encoding.DER)),
        content_type='application/pkcs10',
        **headers,
    )
    match = resolve(path)
    return match.func(request, **match.kwargs)


@pytest.mark.parametrize('profile', ['tls_client', 'client-alias', 'domain_credential', 'tls_server'])
def test_application_renewal_preserves_profile(
    domain_credential_est_onboarding,
    rsa_private_key,
    rf,
    lab_policy,
    profile,
):
    device = domain_credential_est_onboarding['device']
    app = issue_test_credential(device, 'tls_client', common_name='app', public_key=rsa_private_key.public_key())
    DomainAllowedCertificateProfileModel.objects.create(
        domain=device.domain,
        certificate_profile=app.certificate_profile,
        alias='client-alias',
    )
    certificate = app.credential.get_certificate()
    csr = (
        x509.CertificateSigningRequestBuilder().subject_name(certificate.subject).sign(rsa_private_key, hashes.SHA256())
    )
    before = IssuedCredentialModel.objects.count()

    response = post_est(
        rf,
        device,
        csr,
        'simplereenroll',
        profile,
        HTTP_SSL_CLIENT_CERT=certificate.public_bytes(Encoding.PEM).decode(),
    )

    if profile in {'tls_client', 'client-alias'}:
        assert response.status_code == 200, response.content
        issued = IssuedCredentialModel.objects.latest('pk')
        assert issued.certificate_profile == app.certificate_profile
        assert issued.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    else:
        assert response.status_code == 403
        assert IssuedCredentialModel.objects.count() == before


@pytest.mark.parametrize('auth', ['missing', 'wrong-password', 'malformed', 'unsupported'])
def test_authentication_failure_challenges_client(est_device_with_onboarding, rsa_private_key, rf, lab_policy, auth):
    device = est_device_with_onboarding['device']
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'device')]))
        .sign(rsa_private_key, hashes.SHA256())
    )
    headers = {
        'missing': {},
        'wrong-password': {
            'HTTP_AUTHORIZATION': 'Basic ' + base64.b64encode(f'{device.common_name}:wrong'.encode()).decode(),
        },
        'malformed': {'HTTP_AUTHORIZATION': 'Basic !!!'},
        'unsupported': {'HTTP_AUTHORIZATION': 'Bearer token'},
    }
    before = IssuedCredentialModel.objects.count()

    response = post_est(rf, device, csr, **headers[auth])

    assert response.status_code == 401
    assert response['WWW-Authenticate'] == 'Basic realm="est", charset="UTF-8"'
    assert IssuedCredentialModel.objects.count() == before


@pytest.mark.parametrize(
    'accept',
    [
        'application/pkcs7-mime;q=1',
        'application/*',
        '*/*',
        'application/pkcs7-mime; smime-type=certs-only',
    ],
)
def test_est_accepts_http_media_ranges(rf, accept):
    context = EstCertificateRequestContext(
        raw_message=rf.post(
            '/',
            data=b'csr',
            content_type='application/pkcs10',
            HTTP_ACCEPT=accept,
        )
    )
    EstHttpRequestValidator().validate(context)


@pytest.mark.parametrize(
    'accept',
    [
        'text/plain',
        'application/pkcs7-mime;q=0',
        'application/pkcs7-mime; smime-type=enveloped-data',
    ],
)
def test_est_rejects_unacceptable_response_formats(rf, accept):
    context = EstCertificateRequestContext(
        raw_message=rf.post(
            '/',
            data=b'csr',
            content_type='application/pkcs10',
            HTTP_ACCEPT=accept,
        )
    )
    with pytest.raises(ValueError, match='Accept'):
        EstHttpRequestValidator().validate(context)


def test_pending_enrollment_supplies_retry_delay():
    context = EstCertificateRequestContext()
    with (
        patch(
            'request.message_responder.est.get_workflow2_dispatch_outcome',
            return_value=Mock(run=Mock(status='awaiting')),
        ),
        patch(
            'request.message_responder.est.get_workflow2_issuance_decision', return_value=Workflow2IssuanceDecision.WAIT
        ),
    ):
        EstCertificateMessageResponder.build_response(context)
    response = context.to_http_response()
    assert response.status_code == 202
    assert int(response['Retry-After']) > 0


@pytest.fixture
def enrollment_context(est_device_with_onboarding, rsa_private_key):
    device = est_device_with_onboarding['device']
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'device')]))
        .sign(rsa_private_key, hashes.SHA256())
    )
    return EstCertificateRequestContext(
        protocol='est',
        operation='simpleenroll',
        device=device,
        domain=device.domain,
        cert_requested=csr,
        cert_profile_str='tls_server',
        certificate_profile_model=device.domain.get_allowed_cert_profile('tls_server'),
    )


@pytest.mark.parametrize('change', ['profile', 'domain', 'device', 'csr'])
def test_approval_does_not_transfer_to_another_request(enrollment_context, rsa_private_key, change):
    original = enrollment_context
    changed = replace(original)
    if change == 'profile':
        changed.cert_profile_str = 'domain_credential'
        changed.certificate_profile_model = original.domain.get_allowed_cert_profile('domain_credential')
    elif change == 'csr':
        changed.cert_requested = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'different')]))
            .sign(rsa_private_key, hashes.SHA256())
        )
    else:
        model = copy(getattr(original, change))
        model.pk += 1
        setattr(changed, change, model)
    service = WorkflowDispatchService()
    runs = []
    for context in (original, changed):
        dispatch = _build_est_simpleenroll_dispatch(context)
        run = service.get_or_create_run(
            on=dispatch.on,
            event=dispatch.event,
            source=dispatch.source,
            idempotency_key=dispatch.idempotency_key,
        )
        runs.append(run)
        if len(runs) == 1:
            run.status = Workflow2Run.STATUS_APPROVED
            run.save()
    assert runs[0].pk != runs[1].pk
    assert runs[1].status == Workflow2Run.STATUS_QUEUED


def test_profile_alias_reuses_approval(enrollment_context):
    original = _build_est_simpleenroll_dispatch(enrollment_context)
    alias = _build_est_simpleenroll_dispatch(replace(enrollment_context, cert_profile_str='client-alias'))
    assert alias.idempotency_key == original.idempotency_key


def test_verified_new_tls_binding_reuses_approval(enrollment_context, rsa_private_key, rf, settings):
    settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING = True
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    settings.TRUSTPOINT_TRUSTED_PROXY_IPS = ['127.0.0.1']
    runs = []
    for binding in [b'0123456789ab', b'abcdefghijkl']:
        encoded = base64.b64encode(binding)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(enrollment_context.cert_requested.subject)
            .add_attribute(
                AttributeOID.CHALLENGE_PASSWORD,
                encoded,
            )
            .sign(rsa_private_key, hashes.SHA256())
        )
        request = rf.post(
            '/',
            data=b'csr',
            content_type='application/pkcs10',
            HTTP_X_EST_TLS_UNIQUE=encoded.decode(),
            HTTP_X_EST_TLS_UNIQUE_SUPPORTED='1',
            HTTP_X_EST_TLS_PROTOCOL='TLSv1.2',
        )
        context = replace(enrollment_context, cert_requested=csr, raw_message=request)
        verify_est_channel_binding(context)
        dispatch = _build_est_simpleenroll_dispatch(context)
        run = WorkflowDispatchService().get_or_create_run(
            on=dispatch.on,
            event=dispatch.event,
            source=dispatch.source,
            idempotency_key=dispatch.idempotency_key,
        )
        runs.append(run)
        if len(runs) == 1:
            run.status = Workflow2Run.STATUS_APPROVED
            run.save()
    assert runs[0].pk == runs[1].pk
    assert runs[1].status == Workflow2Run.STATUS_APPROVED


@pytest.mark.parametrize('operation', ['enroll', 'reenroll'])
def test_example_client_reads_server_certificate_collection(
    domain_credential_est_onboarding,
    rsa_private_key,
    tmp_path,
    monkeypatch,
    operation,
):
    monkeypatch.chdir(tmp_path)
    issued = domain_credential_est_onboarding['domain_credential']
    certificate = issued.credential.get_certificate()
    chain = [*issued.credential.get_certificate_chain(), certificate]
    body = base64.b64encode(CertificateCollectionSerializer(chain).as_pkcs7_der())
    client = ESTClient('https://example.invalid/.well-known/est', 'basic', out_cert_path='issued.pem')
    client.session.post = Mock(return_value=Mock(status_code=200, content=body))
    if operation == 'enroll':
        monkeypatch.setattr('est.tests.client.rsa.generate_private_key', lambda **kwargs: rsa_private_key)
        client.enroll('device', 'serial', save_key=False)
        output = tmp_path / 'issued.pem'
    else:
        cert_path = tmp_path / 'existing.pem'
        cert_path.write_bytes(certificate.public_bytes(Encoding.PEM))
        key_path = tmp_path / 'existing.key'
        key_path.write_bytes(rsa_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        client.reenroll(str(cert_path), str(key_path))
        output = tmp_path / 'reenrolled_issued.pem'
    assert x509.load_pem_x509_certificate(output.read_bytes()) == certificate
