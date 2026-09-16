# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Focused branch tests for request authentication components."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from pyasn1_modules import rfc4210
from trustpoint_core.oid import HashAlgorithm

from devices.models import DeviceModel
from pki.models import IssuedCredentialModel
from request.authentication.base import (
    ClientCertificateAuthentication,
    CompositeAuthentication,
    IDevIDAuthentication,
    ReenrollmentAuthentication,
)
from request.authentication.cmp import (
    CmpCertConfAuthentication,
    CmpSharedSecretAuthentication,
    CmpSignatureBasedCertificationAuthentication,
    CmpSignatureBasedInitializationAuthentication,
    CmpSignatureBasedPollAuthentication,
)
from request.authentication.est import UsernamePasswordAuthentication
from request.authentication.rest import RestUsernamePasswordAuthentication
from request.request_context import (
    BaseCertificateRequestContext,
    BaseRequestContext,
    CmpBaseRequestContext,
    CmpCertificateRequestContext,
    CmpCertConfRequestContext,
    CmpPollRequestContext,
    EstBaseRequestContext,
    HttpBaseRequestContext,
    RestBaseRequestContext,
)
from onboarding.models import OnboardingProtocol


def _certificate_and_csr() -> tuple[x509.Certificate, x509.CertificateSigningRequest]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device')])
    san = x509.SubjectAlternativeName([x509.DNSName('device.example')])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate, csr


def _cmp_pbm_message(parameters: object, protection: bytes) -> MagicMock:
    protection_algorithm = MagicMock()
    protection_algorithm.__getitem__.side_effect = lambda key: parameters if key == 'parameters' else Mock()
    header = MagicMock()
    header.__getitem__.side_effect = lambda key: protection_algorithm if key == 'protectionAlg' else Mock()
    message = MagicMock()
    message.__getitem__.side_effect = lambda key: (
        header if key == 'header' else (Mock(asOctets=Mock(return_value=protection)) if key == 'protection' else Mock())
    )
    return message


def test_client_certificate_authentication_accepts_non_domain_credential() -> None:
    issued = Mock(device=Mock())
    issued.credential.is_valid_issued_credential.return_value = (True, '')
    with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=issued):
        context = BaseRequestContext(client_certificate=Mock())
        ClientCertificateAuthentication(domain_credential_only=False).authenticate(context)
    issued.credential.is_valid_issued_credential.assert_called_once_with()
    assert context.device is issued.device


def test_client_certificate_authentication_unexpected_error_is_normalized() -> None:
    with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', side_effect=RuntimeError('database')):
        with pytest.raises(ValueError, match='Certificate authentication failed'):
            ClientCertificateAuthentication().authenticate(BaseRequestContext(client_certificate=Mock()))


def test_reenrollment_validates_real_subject_and_san() -> None:
    certificate, csr = _certificate_and_csr()
    credential_certificate = Mock()
    credential_certificate.subjects_match.side_effect = lambda subject: subject == certificate.subject
    credential_certificate.get_certificate_serializer.return_value.as_crypto.return_value = certificate
    credential = Mock(certificate_or_error=credential_certificate)
    credential.is_valid_issued_credential.return_value = (True, '')
    issued = Mock(credential=credential, device=Mock())
    context = BaseCertificateRequestContext(client_certificate=certificate, cert_requested=csr)
    with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=issued):
        ReenrollmentAuthentication().authenticate(context)
    assert context.device is issued.device


@pytest.mark.parametrize(
    ('context', 'error'),
    [
        (BaseRequestContext(), None),
        (
            BaseCertificateRequestContext(client_certificate='bad', cert_requested=Mock()),
            'Invalid client certificate type',
        ),
    ],
)
def test_reenrollment_context_validation(context: BaseRequestContext, error: str | None) -> None:
    if error:
        with pytest.raises((TypeError, ValueError), match=error):
            ReenrollmentAuthentication().authenticate(context)
    else:
        assert ReenrollmentAuthentication().authenticate(context) is None


def test_reenrollment_rejects_missing_csr() -> None:
    certificate, _ = _certificate_and_csr()
    with pytest.raises(ValueError, match='CSR is missing'):
        ReenrollmentAuthentication().authenticate(BaseCertificateRequestContext(client_certificate=certificate))


def test_reenrollment_missing_credential_and_invalid_subject_are_rejected() -> None:
    certificate, csr = _certificate_and_csr()
    context = BaseCertificateRequestContext(client_certificate=certificate, cert_requested=csr)
    with patch.object(
        IssuedCredentialModel, 'get_credential_for_certificate', side_effect=IssuedCredentialModel.DoesNotExist
    ):
        with pytest.raises(ValueError, match='Issued credential not found'):
            ReenrollmentAuthentication().authenticate(context)

    credential_certificate = Mock()
    credential_certificate.subjects_match.return_value = False
    credential = Mock(certificate_or_error=credential_certificate)
    credential.is_valid_issued_credential.return_value = (True, '')
    issued = Mock(credential=credential, device=Mock())
    with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=issued):
        with pytest.raises(ValueError, match='subject does not match'):
            ReenrollmentAuthentication().authenticate(context)


def test_idevid_unexpected_error_is_normalized() -> None:
    context = HttpBaseRequestContext(raw_message=Mock())
    with patch('request.authentication.base.IDevIDAuthenticator.authenticate_idevid', side_effect=RuntimeError('boom')):
        with pytest.raises(ValueError, match='unexpected error'):
            IDevIDAuthentication().authenticate(context)


def test_composite_rejects_invalid_ips_and_sets_http_error() -> None:
    auth = CompositeAuthentication()
    context = HttpBaseRequestContext(raw_message=Mock(META={'HTTP_X_FORWARDED_FOR': 'bad', 'REMOTE_ADDR': 'also-bad'}))
    assert auth._resolve_request_ip(context) is None
    auth.add(Mock(authenticate=Mock(side_effect=ValueError('no'))))
    with pytest.raises(ValueError, match='All authentication methods'):
        auth.authenticate(context)
    assert context.http_response_status == 403
    assert context.http_response_content == 'Authentication failed.'


def test_composite_keeps_unchanged_ip_and_removes_component() -> None:
    component = Mock()
    auth = CompositeAuthentication()
    auth.add(component)
    auth.remove(component)
    device = Mock(ip_address='127.0.0.1', common_name='device')
    context = HttpBaseRequestContext(raw_message=Mock(META={'REMOTE_ADDR': '127.0.0.1'}), device=device)
    auth._update_device_ip_from_request(context)
    device.save.assert_not_called()


@pytest.mark.parametrize('exception', [ValueError('bad'), RuntimeError('boom')])
def test_composite_continues_after_component_errors(exception: Exception) -> None:
    auth = CompositeAuthentication()
    auth.add(Mock(authenticate=Mock(side_effect=exception)))
    auth.add(Mock(authenticate=Mock(side_effect=ValueError('second'))))
    with pytest.raises(ValueError, match='All authentication methods'):
        auth.authenticate(BaseRequestContext())


def test_cmp_shared_secret_hmac_success_stores_secret_and_context() -> None:
    auth = CmpSharedSecretAuthentication()
    device = Mock(domain=Mock())
    config = Mock(cmp_shared_secret='secret')
    context = CmpBaseRequestContext(protocol='cmp', parsed_message=Mock())
    with (
        patch.object(auth, '_validate_context', return_value=True),
        patch.object(auth, '_extract_sender_kid', return_value=1),
        patch.object(auth, '_get_device', return_value=device),
        patch.object(auth, '_validate_device_configuration', return_value=config),
        patch.object(auth, '_verify_hmac_protection'),
    ):
        auth.authenticate(context)
    assert context.device is device
    assert context.domain is device.domain


@pytest.mark.parametrize('failure', [ValueError('invalid PBM'), TypeError('invalid HMAC'), RuntimeError('invalid OWF')])
def test_cmp_shared_secret_protection_errors_are_rejected(failure: Exception) -> None:
    auth = CmpSharedSecretAuthentication()
    with (
        patch.object(auth, '_validate_context', return_value=True),
        patch.object(auth, '_extract_sender_kid', return_value=1),
        patch.object(auth, '_get_device', side_effect=failure),
    ):
        with pytest.raises(ValueError, match='CMP shared secret authentication'):
            auth.authenticate(CmpBaseRequestContext(protocol='cmp', parsed_message=Mock()))


def test_cmp_shared_secret_missing_device_and_wrong_configuration() -> None:
    auth = CmpSharedSecretAuthentication()
    with patch.object(DeviceModel.objects, 'get', side_effect=DeviceModel.DoesNotExist):
        with pytest.raises(ValueError, match='Device with ID'):
            auth._get_device(99)
    with pytest.raises(ValueError, match='no shared secret'):
        auth._validate_device_configuration(
            Mock(common_name='device', onboarding_config=None, no_onboarding_config=None), 1
        )


def test_cmp_shared_secret_verifies_real_pbm_hmac() -> None:
    salt = b'salt'
    protected_part = b'protected-part'
    secret = b'secret'
    key = hashes.Hash(hashes.SHA256())
    key.update(secret + salt)
    hmac_key = key.finalize()
    protection = hmac.HMAC(hmac_key, hashes.SHA256())
    protection.update(protected_part)
    decoded = MagicMock(
        salt=Mock(asOctets=Mock(return_value=salt)),
        owf=MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='2.16.840.1.101.3.4.2.1'))),
        iterationCount=1,
        mac=MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='1.3.6.1.5.5.8.1.5'))),
    )
    decoded.__getitem__.side_effect = lambda key: {
        'salt': decoded.salt,
        'owf': decoded.owf,
        'iterationCount': decoded.iterationCount,
        'mac': decoded.mac,
    }[key]
    decoded.owf.__getitem__.side_effect = lambda key: decoded.owf.algorithm
    decoded.mac.__getitem__.side_effect = lambda key: decoded.mac.algorithm
    message = _cmp_pbm_message(Mock(), protection.finalize())
    message['header']['protectionAlg'].__getitem__.side_effect = lambda key: decoded if key == 'parameters' else Mock()
    with (
        patch('request.authentication.cmp.decoder.decode', return_value=(decoded, b'')),
        patch('request.authentication.cmp.encoder.encode', return_value=protected_part),
        patch('request.authentication.cmp.rfc4210.ProtectedPart', return_value=MagicMock()),
    ):
        result = CmpSharedSecretAuthentication._verify_protection_shared_secret(message, 'secret')
    assert result is not None


def test_cmp_shared_secret_verifies_pbm_with_multiple_iterations_and_sha512_hmac() -> None:
    salt = b'branch-salt'
    hmac_key = b'secret' + salt
    for _ in range(2):
        digest = hashes.Hash(hashes.SHA384())
        digest.update(hmac_key)
        hmac_key = digest.finalize()

    protection = hmac.HMAC(hmac_key, hashes.SHA512())
    protection.update(b'protected-part')
    decoded = MagicMock(
        salt=Mock(asOctets=Mock(return_value=salt)),
        owf=MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='2.16.840.1.101.3.4.2.2'))),
        iterationCount=2,
        mac=MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='1.3.6.1.5.5.8.1.7'))),
    )
    decoded.__getitem__.side_effect = lambda key: {
        'salt': decoded.salt, 'owf': decoded.owf,
        'iterationCount': decoded.iterationCount, 'mac': decoded.mac,
    }[key]
    decoded.owf.__getitem__.side_effect = lambda key: decoded.owf.algorithm
    decoded.mac.__getitem__.side_effect = lambda key: decoded.mac.algorithm
    message = _cmp_pbm_message(decoded, protection.finalize())
    with (
        patch('request.authentication.cmp.decoder.decode', return_value=(decoded, b'')),
        patch('request.authentication.cmp.encoder.encode', return_value=b'protected-part'),
        patch('request.authentication.cmp.rfc4210.ProtectedPart', return_value=MagicMock()),
    ):
        assert CmpSharedSecretAuthentication._verify_protection_shared_secret(message, 'secret')


def test_cmp_shared_secret_rejects_invalid_hmac_and_owf() -> None:
    decoded = MagicMock(
        salt=Mock(asOctets=Mock(return_value=b'salt')),
        owf=MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='unsupported'))),
    )
    decoded.__getitem__.side_effect = lambda key: {
        'salt': decoded.salt,
        'owf': decoded.owf,
        'iterationCount': decoded.iterationCount,
        'mac': decoded.mac,
    }[key]
    decoded.owf.__getitem__.side_effect = lambda key: decoded.owf.algorithm
    with patch('request.authentication.cmp.decoder.decode', return_value=(decoded, b'')):
        with pytest.raises(ValueError, match='owf algorithm not supported'):
            CmpSharedSecretAuthentication._verify_protection_shared_secret(_cmp_pbm_message(Mock(), b'bad'), 'secret')

    decoded.owf.algorithm.prettyPrint.return_value = '2.16.840.1.101.3.4.2.1'
    decoded.iterationCount = 1
    decoded.mac = MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='1.3.6.1.5.5.8.1.5')))
    decoded.mac.__getitem__.side_effect = lambda key: decoded.mac.algorithm
    message = _cmp_pbm_message(decoded, b'bad')
    with (
        patch('request.authentication.cmp.decoder.decode', return_value=(decoded, b'')),
        patch('request.authentication.cmp.encoder.encode', return_value=b'protected-part'),
        patch('request.authentication.cmp.rfc4210.ProtectedPart', return_value=MagicMock()),
    ):
        with pytest.raises(ValueError, match='hmac verification failed'):
            CmpSharedSecretAuthentication._verify_protection_shared_secret(message, 'secret')


def test_cmp_signature_initialization_rejects_wrong_protocol() -> None:
    with pytest.raises(ValueError):
        CmpSignatureBasedInitializationAuthentication()._should_authenticate(
            Mock(protocol='est', operation='initialization')
        )


def test_cmp_signature_certification_skips_wrong_protocol() -> None:
    assert (
        CmpSignatureBasedCertificationAuthentication()._should_authenticate(
            Mock(protocol='est', operation='certification')
        )
        is False
    )


def test_cmp_signature_initialization_wraps_authenticator_error() -> None:
    auth = CmpSignatureBasedInitializationAuthentication()
    with pytest.raises(ValueError, match='signature-based initialization'):
        auth._authenticate_and_verify_device(Mock(), Mock(), [])


def test_cmp_signature_certification_rejects_unknown_device() -> None:
    auth = CmpSignatureBasedCertificationAuthentication()
    with patch.object(DeviceModel.objects, 'get', side_effect=DeviceModel.DoesNotExist):
        with pytest.raises(ValueError, match='Device not found'):
            auth._lookup_device({'device_id': 3})


def test_cmp_signature_poll_domain_credential_is_accepted() -> None:
    auth = CmpSignatureBasedPollAuthentication()
    device = Mock()
    context = Mock()
    with (
        patch.object(auth, '_authenticate_with_domain_credential', return_value=device),
        patch.object(auth, '_extract_extra_certs', return_value=(Mock(), [])),
        patch.object(auth, '_should_authenticate', return_value=True),
        patch.object(auth, '_verify_protection_and_finalize'),
    ):
        auth.authenticate(context)


def test_cmp_signature_poll_rejects_failed_idevid_authentication() -> None:
    auth = CmpSignatureBasedPollAuthentication()
    with patch(
        'request.authentication.cmp.IDevIDAuthenticator.authenticate_idevid_from_x509', side_effect=ValueError('bad')
    ):
        assert auth._authenticate_with_idevid(Mock(), Mock(), []) is None
    context = CmpPollRequestContext(protocol='cmp', cmp_body_type='pollReq', parsed_message=Mock())
    with (
        patch.object(auth, '_should_authenticate', return_value=True),
        patch.object(auth, '_extract_extra_certs', return_value=(Mock(), [])),
        patch.object(auth, '_authenticate_with_domain_credential', return_value=None),
        patch.object(auth, '_authenticate_with_idevid', return_value=None),
    ):
        with pytest.raises(ValueError, match='pollReq authentication failed'):
            auth.authenticate(context)


@pytest.mark.parametrize(
    'auth_class, context_class, fields',
    [
        (UsernamePasswordAuthentication, EstBaseRequestContext, {'est_username': 1, 'est_password': 'x'}),
        (RestUsernamePasswordAuthentication, RestBaseRequestContext, {'rest_username': 1, 'rest_password': 'x'}),
    ],
)
def test_username_password_rejects_unknown_or_wrong_type(
    auth_class: type, context_class: type, fields: dict[str, object]
) -> None:
    auth = auth_class()
    with pytest.raises(ValueError, match='Invalid username or password'):
        auth.authenticate(context_class(**fields))
    with pytest.raises(TypeError):
        auth.authenticate(BaseRequestContext())


def test_rest_username_password_invalid_config_and_lookup_error() -> None:
    auth = RestUsernamePasswordAuthentication()
    context = RestBaseRequestContext(rest_username='device', rest_password='secret')
    with patch('request.authentication.rest.DeviceModel.objects') as objects:
        objects.select_related.return_value.filter.return_value.first.return_value = Mock(
            onboarding_config=None, no_onboarding_config=None
        )
        with pytest.raises(ValueError, match='Invalid username or password'):
            auth.authenticate(context)
    with patch('request.authentication.rest.DeviceModel.objects') as objects:
        objects.select_related.side_effect = RuntimeError('db')
        with pytest.raises(ValueError, match='Invalid username or password'):
            auth.authenticate(context)


def test_cmp_shared_secret_rejects_unsupported_hmac_algorithm() -> None:
    decoded = MagicMock(
        salt=Mock(asOctets=Mock(return_value=b'salt')),
        owf=MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='2.16.840.1.101.3.4.2.1'))),
        iterationCount=1,
        mac=MagicMock(algorithm=Mock(prettyPrint=Mock(return_value='unsupported'))),
    )
    decoded.__getitem__.side_effect = lambda key: {
        'salt': decoded.salt, 'owf': decoded.owf,
        'iterationCount': decoded.iterationCount, 'mac': decoded.mac,
    }[key]
    decoded.owf.__getitem__.side_effect = lambda key: decoded.owf.algorithm
    decoded.mac.__getitem__.side_effect = lambda key: decoded.mac.algorithm

    with patch('request.authentication.cmp.decoder.decode', return_value=(decoded, b'')):
        with pytest.raises(ValueError, match='hmac algorithm not supported'):
            CmpSharedSecretAuthentication._verify_protection_shared_secret(
                _cmp_pbm_message(decoded, b'bad'), 'secret'
            )


def test_cmp_signature_base_rejects_missing_or_empty_extra_certs() -> None:
    auth = CmpSignatureBasedInitializationAuthentication()
    with pytest.raises(ValueError, match='Missing parsed message'):
        auth._extract_extra_certs(CmpBaseRequestContext())

    message = MagicMock(spec=rfc4210.PKIMessage)
    message.__getitem__.return_value = []
    with pytest.raises(ValueError, match='No extra certificates'):
        auth._extract_extra_certs(CmpBaseRequestContext(parsed_message=message))


def test_cmp_signature_initialization_success_sets_device_and_certificate() -> None:
    auth = CmpSignatureBasedInitializationAuthentication()
    signer = Mock()
    device = Mock(common_name='device')
    context = CmpCertificateRequestContext(protocol='cmp', operation='initialization')
    with (
        patch.object(auth, '_should_authenticate', return_value=True),
        patch.object(auth, '_extract_extra_certs', return_value=(signer, [])),
        patch.object(auth, '_authenticate_and_verify_device', return_value=device),
    ):
        auth.authenticate(context)

    assert context.client_certificate is signer
    assert context.device is device


def test_cmp_signature_initialization_rejects_missing_domain_and_config() -> None:
    auth = CmpSignatureBasedInitializationAuthentication()
    device = Mock(domain=None)
    with patch('request.authentication.cmp.IDevIDAuthenticator.authenticate_idevid_from_x509', return_value=device):
        with pytest.raises(ValueError, match='Device domain is not set'):
            auth._authenticate_device(CmpCertificateRequestContext(), Mock(), [])

    with pytest.raises(ValueError, match='not configured'):
        auth._verify_device_configuration(Mock(domain=Mock(), onboarding_config=None))


def test_cmp_signature_initialization_passes_aoki_parameters() -> None:
    auth = CmpSignatureBasedInitializationAuthentication()
    device = Mock(domain=Mock())
    context = CmpCertificateRequestContext(
        protocol='cmp', operation='initialization', domain_str='.aoki',
        raw_message=Mock(path='/p/.aoki/initialization'),
    )
    with patch(
        'request.authentication.cmp.IDevIDAuthenticator.authenticate_idevid_from_x509', return_value=device
    ) as authenticate:
        assert auth._authenticate_device(context, Mock(), []) is device
    assert authenticate.call_args.kwargs['domain'] is None
    assert authenticate.call_args.kwargs['onboarding_protocol'].name == 'AOKI'


def test_cmp_signature_initialization_rejects_wrong_onboarding_protocol_and_pki() -> None:
    auth = CmpSignatureBasedInitializationAuthentication()
    device = Mock(domain=Mock(), onboarding_config=Mock(onboarding_protocol='wrong'))
    with pytest.raises(ValueError, match='Wrong onboarding protocol'):
        auth._verify_device_configuration(device)
    device.onboarding_config.onboarding_protocol = OnboardingProtocol.CMP_IDEVID
    device.onboarding_config.has_pki_protocol.return_value = False
    with pytest.raises(ValueError, match='PKI protocol CMP expected'):
        auth._verify_device_configuration(device)


def test_cmp_signature_certification_falls_back_to_fingerprint_lookup() -> None:
    auth = CmpSignatureBasedCertificationAuthentication()
    certificate, _ = _certificate_and_csr()
    context = CmpCertificateRequestContext(client_certificate=certificate)
    device = Mock()
    with patch.object(ClientCertificateAuthentication, 'authenticate', side_effect=lambda ctx: setattr(ctx, 'device', device)):
        assert auth._authenticate_device(context) is device


def test_cmp_signature_certification_wraps_protection_failure() -> None:
    auth = CmpSignatureBasedCertificationAuthentication()
    context = CmpCertificateRequestContext(protocol='cmp', operation='certification')
    with (
        patch.object(auth, '_should_authenticate', return_value=True),
        patch.object(auth, '_extract_extra_certs', return_value=(Mock(), [])),
        patch.object(auth, '_authenticate_device', return_value=Mock()),
        patch.object(auth, '_verify_protection_and_finalize', side_effect=TypeError('bad signature')),
    ):
        with pytest.raises(ValueError, match='bad signature'):
            auth.authenticate(context)


def test_cmp_signature_certification_requires_profile_and_signer() -> None:
    auth = CmpSignatureBasedCertificationAuthentication()
    context = CmpCertificateRequestContext(
        protocol='cmp', operation='certification', parsed_message=MagicMock(spec=rfc4210.PKIMessage),
        cert_profile_str=None,
    )
    with patch('request.authentication.cmp.AlgorithmIdentifier.from_dotted_string', return_value=Mock()):
        with pytest.raises(ValueError, match='Missing application certificate template'):
            auth._should_authenticate(context)

    context.client_certificate = None
    with pytest.raises(ValueError, match='signer certificate is missing'):
        auth._authenticate_device(context)


def test_cmp_signature_certification_rejects_domain_and_wrong_config() -> None:
    auth = CmpSignatureBasedCertificationAuthentication()
    device_info = {'serial_number': None, 'domain_name': None, 'device_id': None, 'common_name': None}
    with pytest.raises(ValueError, match='not part of any domain'):
        auth._validate_device(Mock(domain=None), device_info, Mock())

    no_config = Mock(domain=Mock(unique_name='domain'), onboarding_config=None)
    with pytest.raises(ValueError, match='not configured'):
        auth._validate_device(no_config, device_info, Mock())


def test_cmp_signature_poll_falls_back_after_domain_credential_error() -> None:
    auth = CmpSignatureBasedPollAuthentication()
    context = CmpPollRequestContext()
    with patch.object(ClientCertificateAuthentication, 'authenticate', side_effect=ValueError('unknown')):
        assert auth._authenticate_with_domain_credential(context) is None
    assert context.device is None

    with patch(
        'request.authentication.cmp.IDevIDAuthenticator.authenticate_idevid_from_x509',
        return_value=Mock(domain=None),
    ):
        with pytest.raises(ValueError, match='Device domain is not set'):
            auth._authenticate_with_idevid(context, Mock(), [])


def test_cmp_signature_poll_checks_protocol_body_and_signature_protection() -> None:
    auth = CmpSignatureBasedPollAuthentication()
    assert not auth._should_authenticate(CmpPollRequestContext(protocol='est', cmp_body_type='pollReq'))
    assert not auth._should_authenticate(CmpPollRequestContext(protocol='cmp', cmp_body_type='certRep'))
    context = CmpPollRequestContext(
        protocol='cmp', cmp_body_type='pollReq', parsed_message=MagicMock(spec=rfc4210.PKIMessage)
    )
    with patch('request.authentication.cmp.AlgorithmIdentifier.from_dotted_string', return_value=HashAlgorithm.SHA256):
        assert auth._should_authenticate(context)


def test_cmp_signature_poll_wraps_certificate_extraction_error() -> None:
    auth = CmpSignatureBasedPollAuthentication()
    context = CmpPollRequestContext(protocol='cmp', cmp_body_type='pollReq')
    with (
        patch.object(auth, '_should_authenticate', return_value=True),
        patch.object(auth, '_extract_extra_certs', side_effect=ValueError('no signer')),
    ):
        with pytest.raises(ValueError, match='pollReq authentication failed: no signer'):
            auth.authenticate(context)


def test_cmp_certconf_hash_resolution_and_missing_credential() -> None:
    auth = CmpCertConfAuthentication()
    assert isinstance(auth._resolve_certconf_hash_algorithm(CmpCertConfRequestContext()), hashes.SHA256)

    unsupported = CmpCertConfRequestContext(cert_hash_algorithm_oid='1.2.3')
    with pytest.raises(ValueError, match='unsupported'):
        auth._resolve_certconf_hash_algorithm(unsupported)

    context = CmpCertConfRequestContext(operation='certconf', cert_hash=b'unknown')
    queryset = Mock()
    queryset.select_related.return_value.first.return_value = None
    with patch.object(IssuedCredentialModel.objects, 'filter', return_value=queryset):
        with pytest.raises(ValueError, match='no issued credential'):
            auth.authenticate(context)


def test_cmp_certconf_resolves_allowed_hash_and_der_certificate() -> None:
    auth = CmpCertConfAuthentication()
    certificate, _ = _certificate_and_csr()
    digest = hashes.Hash(hashes.SHA384())
    digest.update(certificate.public_bytes(Encoding.DER))
    issued = Mock(credential=Mock(get_certificate=Mock(return_value=certificate)))
    queryset = Mock()
    queryset.iterator.return_value = iter([issued])
    context = CmpCertConfRequestContext(cert_hash=digest.finalize(), cert_hash_algorithm_oid='2.16.840.1.101.3.4.2.2')
    with patch.object(IssuedCredentialModel.objects, 'select_related', return_value=queryset):
        assert auth._resolve_issued_credential_by_cert_hash(context=context, hash_algorithm=hashes.SHA384()) is issued


def test_cmp_certconf_rejects_disallowed_hash_and_missing_implicit_signature_hash() -> None:
    auth = CmpCertConfAuthentication()
    with pytest.raises(TypeError, match='not permitted'):
        auth._resolve_certconf_hash_algorithm(CmpCertConfRequestContext(cert_hash_algorithm_oid='1.2.840.113549.2.5'))
    certificate, _ = _certificate_and_csr()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate.public_bytes(Encoding.DER))
    issued = Mock(credential=Mock(get_certificate=Mock(return_value=certificate)))
    queryset = Mock()
    queryset.select_related.return_value.first.return_value = issued
    context = CmpCertConfRequestContext(cert_hash=digest.finalize())
    with (
        patch.object(IssuedCredentialModel.objects, 'filter', return_value=queryset),
        patch('request.authentication.cmp.SignatureSuite.from_certificate', return_value=Mock(
            algorithm_identifier=Mock(hash_algorithm=None)
        )),
    ):
        with pytest.raises(ValueError, match='hashAlg is required'):
            auth._resolve_issued_credential_by_cert_hash(context=context, hash_algorithm=hashes.SHA256())


def test_est_username_password_skips_missing_credentials_and_accepts_valid_device() -> None:
    auth = UsernamePasswordAuthentication()
    assert auth.authenticate(EstBaseRequestContext(est_username='user')) is None

    device = Mock(spec=DeviceModel)
    device.onboarding_config = Mock(est_password='secret')
    queryset = Mock()
    queryset.filter.return_value.first.return_value = device
    context = EstBaseRequestContext(est_username='user', est_password='secret')
    with patch.object(DeviceModel.objects, 'select_related', return_value=queryset):
        auth.authenticate(context)
    assert context.device is device
