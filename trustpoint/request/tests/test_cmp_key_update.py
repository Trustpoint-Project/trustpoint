# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise signed key updates through the HTTP pipeline with real certificates and PoP."""

import os
import uuid
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.test import RequestFactory
from django.urls import resolve
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc4210, rfc4211

from cmp.models import CmpTransactionModel
from management.models import SecurityConfig
from request.cmp_key_update import validate_key_update_followup
from request.message_builder.cmp import CmpMessageBuilder, CmpPkiHeaderBuilding
from request.message_parser.cmp import CmpMessageParser
from request.request_context import CmpCertificateRequestContext
from request.security_hardening import authenticate_cmp_request, validate_cmp_proof_of_possession
from workflows2.events.request_events import Events


@pytest.fixture
def update_material(domain_credential_cmp_onboarding, rsa_private_key):
    SecurityConfig.objects.get_or_create()
    issued = domain_credential_cmp_onboarding['domain_credential']
    return issued, issued.credential.get_certificate(), rsa_private_key


def _sign(message, certificate, private_key):
    message['header']['sender'] = CmpPkiHeaderBuilding._build_general_name_from_dn(
        certificate.subject.rfc4514_string(),
    )
    message['header']['protectionAlg']['algorithm'] = '1.2.840.113549.1.1.11'
    message['header']['senderNonce'] = os.urandom(16)
    protected = rfc4210.ProtectedPart()
    protected['header'] = message['header']
    protected['infoValue'] = message['body']
    signature = private_key.sign(encoder.encode(protected), padding.PKCS1v15(), hashes.SHA256())
    message['protection'] = message['protection'].clone(value=univ.BitString.fromOctetString(signature))
    cert, _ = decoder.decode(certificate.public_bytes(serialization.Encoding.DER), asn1Spec=rfc4210.CMPCertificate())
    message['extraCerts'].clear()
    message['extraCerts'].append(cert)
    return message


def _kur(certificate, old_key, *, implicit=True, subject=None, bad_pop=False, old_id=None, extensions=None):
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    context = CmpCertificateRequestContext(
        protocol='cmp', operation='keyupdate',
        request_data={
            'subject': subject if subject is not None else certificate.subject,
            'public_key': new_key.public_key(), 'private_key': new_key, 'extensions': extensions,
            'recipient_name': certificate.issuer.rfc4514_string(),
        },
    )
    CmpMessageBuilder().build(context)
    message = context.parsed_message
    if not implicit:
        message['header']['generalInfo'].clear()
    if old_id is not None:
        identifier = rfc4211.CertId()
        identifier['issuer'] = message['header']['recipient']
        identifier['serialNumber'] = old_id
        control = message['body']['kur'][0]['certReq']['controls'][0]
        control['type'] = '1.3.6.1.5.5.7.5.1.5'
        control['value'] = encoder.encode(identifier)
        # Controls are part of the PoP's signed CertRequest.
        signed = encoder.encode(message['body']['kur'][0]['certReq'])
        pop = new_key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        message['body']['kur'][0]['popo']['signature']['signature'] = univ.BitString.fromOctetString(pop)
    if bad_pop:
        message['body']['kur'][0]['popo']['signature']['signature'] = univ.BitString.fromOctetString(b'bad-pop')
    return _sign(message, certificate, old_key), new_key


def _post(message, issued, *, operation='keyupdate', path=None):
    if path is None:
        path = (
            f'/.well-known/cmp/p/{issued.domain.unique_name}~'
            f'{issued.issued_using_cert_profile}/{operation}'
        )
    request = RequestFactory().post(path, encoder.encode(message), content_type='application/pkixcmp')
    match = resolve(path)
    response = match.func(request, *match.args, **match.kwargs)
    assert response.status_code == 200, response.content
    parsed, remainder = decoder.decode(response.content, asn1Spec=rfc4210.PKIMessage())
    assert not remainder
    return parsed


def _assert_signature(message, certificate):
    protected = rfc4210.ProtectedPart()
    protected['header'] = message['header']
    protected['infoValue'] = message['body']
    certificate.public_key().verify(
        message['protection'].asOctets(), encoder.encode(protected), padding.PKCS1v15(), hashes.SHA256(),
    )


@pytest.mark.parametrize('implicit', [True, False])
@pytest.mark.parametrize('old_id', [False, True])
def test_key_update_issues_kup_and_confirms(update_material, implicit, old_id):
    issued, certificate, key = update_material
    message, new_key = _kur(certificate, key, implicit=implicit, old_id=certificate.serial_number if old_id else None)
    response = _post(message, issued)
    assert response['body'].getName() == 'kup'
    assert int(response['body']['kup']['response'][0]['status']['status']) == 0
    assert not response['body']['kup']['caPubs'].hasValue()
    cert_value = response['body']['kup']['response'][0]['certifiedKeyPair']['certOrEncCert']['certificate']
    new_cert = x509.load_der_x509_certificate(encoder.encode(
        cert_value.clone(tagSet=rfc4210.CMPCertificate().tagSet, cloneValueFlag=True),
    ))
    assert new_cert.subject == certificate.subject
    assert new_cert.public_key().public_numbers() == new_key.public_key().public_numbers()
    assert new_cert.serial_number != certificate.serial_number
    _assert_signature(response, issued.domain.issuing_ca.credential.get_certificate())
    tx = CmpTransactionModel.objects.get(transaction_id=message['header']['transactionID'].asOctets().hex())
    assert tx.operation == 'keyupdate'
    assert tx.request_body_type == 'kur'
    assert tx.implicit_confirm == implicit
    if implicit:
        return
    confirmation = rfc4210.PKIMessage()
    confirmation['header'] = decoder.decode(encoder.encode(message['header']), asn1Spec=rfc4210.PKIHeader())[0]
    confirmation['header']['generalInfo'].clear()
    confirmation['header']['recipNonce'] = response['header']['senderNonce'].asOctets()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(new_cert.public_bytes(serialization.Encoding.DER))
    confirmation['body']['certConf'][0]['certHash'] = digest.finalize()
    confirmation['body']['certConf'][0]['certReqId'] = 0
    confirmation = _sign(confirmation, certificate, key)
    result = _post(confirmation, issued)
    assert result['body'].getName() == 'pkiconf'
    _assert_signature(result, issued.domain.issuing_ca.credential.get_certificate())
    tx.refresh_from_db()
    assert tx.confirmed_at is not None


@pytest.mark.parametrize('failure', ['subject', 'old_id', 'pop', 'signature'])
def test_key_update_rejects_invalid_request_without_issuance(update_material, failure):
    issued, certificate, key = update_material
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'different')]) if failure == 'subject' else None
    message, _ = _kur(certificate, key, subject=subject, bad_pop=failure == 'pop', old_id=1 if failure == 'old_id' else None)
    if failure == 'signature':
        message['protection'] = message['protection'].clone(value=univ.BitString.fromOctetString(b'invalid'))
    with patch('request.operation_processor.cmp_certificate_request.CertificateIssueProcessor') as issuer:
        response = _post(message, issued)
    issuer.assert_not_called()
    assert response['body'].getName() == ('error' if failure == 'signature' else 'kup')
    assert not CmpTransactionModel.objects.filter(transaction_id=message['header']['transactionID'].asOctets().hex()).exists()


def test_key_update_parser_infers_operation_and_verifies_pop(update_material):
    issued, certificate, key = update_material
    message, _ = _kur(certificate, key)
    context = CmpCertificateRequestContext(
        protocol='cmp', raw_message=Mock(body=encoder.encode(message)),
        domain_str=issued.domain.unique_name, cert_profile_str='domain_credential',
    )
    context = CmpMessageParser().parse(context)
    assert context.operation == 'keyupdate'
    assert context.event == Events.cmp_keyupdate
    authenticate_cmp_request(context)
    validate_cmp_proof_of_possession(context)


def test_key_update_followup_rejects_changed_signer(update_material):
    issued, certificate, key = update_material
    message, _ = _kur(certificate, key)
    context = CmpCertificateRequestContext(client_certificate=issued.domain.issuing_ca.credential.get_certificate())
    with pytest.raises(ValueError, match='original protection certificate'):
        validate_key_update_followup(context, Mock(request_der=encoder.encode(message)))


@pytest.mark.parametrize('implicit', [True, False])
def test_key_update_delayed_delivery_returns_kup(update_material, implicit):
    issued, certificate, key = update_material
    message, new_key = _kur(certificate, key, implicit=implicit)

    def wait(context, process):
        context.workflow2_outcome = Mock(run=Mock(id=uuid.uuid4(), status='awaiting'))
        from request.workflow2_issuance import Workflow2IssuanceDecision
        with patch('request.operation_processor.cmp_certificate_request.get_workflow2_issuance_decision',
                   return_value=Workflow2IssuanceDecision.WAIT):
            process(context)

    with patch('cmp.views.process_workflow_operation', side_effect=wait):
        waiting = _post(message, issued)
    assert waiting['body'].getName() == 'kup'
    assert int(waiting['body']['kup']['response'][0]['status']['status']) == 3
    tx = CmpTransactionModel.objects.get(transaction_id=message['header']['transactionID'].asOctets().hex())
    tx.backend = CmpTransactionModel.Backend.NONE
    tx.save()
    poll = rfc4210.PKIMessage()
    poll['header'] = decoder.decode(encoder.encode(message['header']), asn1Spec=rfc4210.PKIHeader())[0]
    poll['header']['generalInfo'].clear()
    poll['header']['recipNonce'] = waiting['header']['senderNonce'].asOctets()
    poll['body']['pollReq'][0]['certReqId'] = 0
    interim = _post(_sign(poll, certificate, key), issued)
    assert interim['body'].getName() == 'pollRep'
    tx.refresh_from_db()
    tx.status = CmpTransactionModel.Status.PROCESSING
    tx.save()
    poll['header']['recipNonce'] = interim['header']['senderNonce'].asOctets()
    result = _post(_sign(poll, certificate, key), issued)
    assert result['body'].getName() == 'kup'
    assert int(result['body']['kup']['response'][0]['status']['status']) == 0
    assert result['header']['recipNonce'].asOctets() == message['header']['senderNonce'].asOctets()
    _assert_signature(result, issued.domain.issuing_ca.credential.get_certificate())
    info = {str(entry['infoType']) for entry in result['header']['generalInfo']}
    assert ('1.3.6.1.5.5.7.4.13' in info) == implicit
    assert ('1.3.6.1.5.5.7.4.14' in info) == (not implicit)


@pytest.mark.parametrize('invalid', ['revoked', 'expired', 'pbm', 'san', 'profile'])
def test_key_update_rejects_inactive_signers_and_identity_changes(update_material, invalid):
    issued, certificate, key = update_material
    extensions = None
    if invalid == 'san':
        extensions = [x509.Extension(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, False,
                                     x509.SubjectAlternativeName([x509.DNSName('new.example')]))]
    message, _ = _kur(certificate, key, extensions=extensions)
    context = CmpCertificateRequestContext(
        protocol='cmp', raw_message=Mock(body=encoder.encode(message)),
        domain_str=issued.domain.unique_name, cert_profile_str='domain_credential',
    )
    context = CmpMessageParser().parse(context)
    if invalid in ('revoked', 'expired'):
        with patch('pki.models.credential.CredentialModel.is_valid_issued_credential',
                   return_value=(False, invalid)), pytest.raises(ValueError, match=invalid):
            authenticate_cmp_request(context)
    elif invalid == 'pbm':
        context.parsed_message['header']['protectionAlg']['algorithm'] = '1.2.840.113533.7.66.13'
        # Exercise the operation-specific check independently of PBM parameter parsing.
        from request.security_hardening import _authenticate_key_update_signer
        with pytest.raises(ValueError, match='signature-based'):
            _authenticate_key_update_signer(context)
    elif invalid == 'profile':
        authenticate_cmp_request(context)
        context.cert_requested_profile_validated = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'changed-by-profile')]),
        )
        from request.cmp_key_update import validate_key_update_identity
        with pytest.raises(ValueError, match='subject'):
            validate_key_update_identity(context, profile_validated=True)
    else:
        with pytest.raises(ValueError, match='subjectAltName'):
            authenticate_cmp_request(context)


def test_application_certificate_can_update_itself(cmp_device_without_onboarding, rsa_private_key):
    from pki.tests.credential_helpers import issue_test_credential
    SecurityConfig.objects.get_or_create()
    device = cmp_device_without_onboarding['device']
    device.serial_number = 'SN-CMP-NO'
    device.save(update_fields=['serial_number'])
    issued = issue_test_credential(
        device, 'tls_server', common_name='server.example',
        public_key=rsa_private_key.public_key(),
        extensions=[(x509.SubjectAlternativeName([x509.DNSName('server.example')]), False)],
        profile_data={
            'type': 'cert_profile', 'subj': {'allow': '*'},
            'ext': {'san': {'dns_names': ['server.example']}}, 'validity': {'days': 10},
        },
    )
    certificate = issued.credential.get_certificate()
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    message, _ = _kur(certificate, rsa_private_key, extensions=[san])
    response = _post(message, issued)
    assert response['body'].getName() == 'kup'
    assert int(response['body']['kup']['response'][0]['status']['status']) == 0
    # Certificate extraction also understands KUP's body tag.
    from request.clients.cmp_client import CmpClient
    client = CmpClient(CmpCertificateRequestContext(cmp_server_host='unused.example'))
    replacement, _ = client._extract_issued_certificate(response, encoder.encode(response))
    assert replacement.subject == certificate.subject
    assert replacement.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == san.value


def test_key_update_cannot_cross_domains(update_material, domain_instance):
    issued, certificate, key = update_material
    message, _ = _kur(certificate, key)
    context = CmpCertificateRequestContext(
        protocol='cmp', raw_message=Mock(body=encoder.encode(message)),
        domain_str=issued.domain.unique_name, cert_profile_str='domain_credential',
    )
    context = CmpMessageParser().parse(context)
    # An unrelated domain cannot become the target of an update signed by this credential.
    from pki.models.domain import DomainModel
    context.domain = DomainModel.objects.create(unique_name='unrelated-update-domain', issuing_ca=issued.domain.issuing_ca)
    with pytest.raises(ValueError, match='different domain'):
        authenticate_cmp_request(context)


@pytest.mark.parametrize('layout', [
    '/.well-known/cmp/p/{domain}/{profile}/keyupdate',
    '/.well-known/cmp/p/{domain}/{profile}/keyupdate/',
    '/.well-known/cmp/p/{domain}~{profile}/keyupdate',
    '/.well-known/cmp/p/{domain}/keyupdate',
    '/.well-known/cmp/p/~{profile}/keyupdate',
    '/.well-known/cmp/p/{domain}/{profile}',
])
def test_key_update_http_paths(update_material, layout):
    """Resolve actual URLs, including the RFC 9483 HTTP keyupdate operation label."""
    issued, certificate, key = update_material
    message, _ = _kur(certificate, key)
    path = layout.format(domain=issued.domain.unique_name, profile=issued.issued_using_cert_profile)
    response = _post(message, issued, path=path)
    assert response['body'].getName() == 'kup'
    assert int(response['body']['kup']['response'][0]['status']['status']) == 0

