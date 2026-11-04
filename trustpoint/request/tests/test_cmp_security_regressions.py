# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Real message and endpoint regressions for CMP authentication and nonce state."""

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from django.test import RequestFactory
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc4210
from trustpoint_core.oid import AlgorithmIdentifier, SignatureSuite

from cmp.models import CmpTransactionModel
from cmp.views import CmpRequestView
from devices.models import DeviceModel
from management.models import SecurityConfig
from pki.models import CertificateModel, DevIdRegistration, IssuedCredentialModel, TruststoreModel
from pki.models.truststore import TruststoreOrderModel
from pki.util.x509 import CertificateGenerator
from request.authentication.cmp import CmpSignatureBasedInitializationAuthentication
from request.message_builder.cmp import CmpMessageBuilder, CmpPkiHeaderBuilding
from request.message_responder.cmp import CmpMessageResponder
from request.request_context import CmpBaseRequestContext, CmpCertificateRequestContext
from request.tests.test_cmp_response_security import _exchange, _protect

pytestmark = pytest.mark.django_db


def _sign(message, certificate, key, algorithm=AlgorithmIdentifier.RSA_SHA256):
    header = message['header']
    header['sender'] = CmpPkiHeaderBuilding._build_general_name_from_dn(certificate.subject.rfc4514_string())
    header['senderNonce'] = os.urandom(16)
    header['protectionAlg']['algorithm'] = algorithm.dotted_string
    header['protectionAlg']['parameters'] = univ.noValue
    data = CmpMessageResponder._get_encoded_protected_part(message)
    digest = algorithm.hash_algorithm.hash_algorithm()
    signature = (
        key.sign(data, padding.PKCS1v15(), digest) if isinstance(key, rsa.RSAPrivateKey)
        else key.sign(data, ec.ECDSA(digest))
    )
    message['protection'] = message['protection'].clone(value=univ.BitString.fromOctetString(signature))
    certificate_asn1, _ = decoder.decode(
        certificate.public_bytes(serialization.Encoding.DER), asn1Spec=rfc4210.CMPCertificate(),
    )
    message['extraCerts'].clear()
    message['extraCerts'].append(certificate_asn1)
    return message


def _post(message, domain, operation):
    request = RequestFactory().post('/', encoder.encode(message), content_type='application/pkixcmp')
    response = CmpRequestView().post(request, domain=domain.unique_name, operation=operation)
    assert response.status_code == 200, response.content
    reply, remainder = decoder.decode(response.content, asn1Spec=rfc4210.PKIMessage())
    assert not remainder
    return reply


@pytest.fixture(params=['rsa', 'ec'])
def signer(request):
    key = rsa.generate_private_key(65537, 2048) if request.param == 'rsa' else ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'CMP signer')])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA384())
    )
    algorithm = AlgorithmIdentifier.RSA_SHA256 if request.param == 'rsa' else AlgorithmIdentifier.ECDSA_SHA256
    return key, certificate, algorithm


def test_signature_uses_declared_hash_independently_of_certificate_hash(signer):
    key, certificate, algorithm = signer
    message, _ = _exchange()
    _sign(message, certificate, key, algorithm)
    auth = CmpSignatureBasedInitializationAuthentication()
    auth._verify_protection_signature(message, certificate)
    message['header']['senderNonce'] = os.urandom(16)
    with pytest.raises(InvalidSignature):
        auth._verify_protection_signature(message, certificate)


@pytest.mark.parametrize('invalid', ['unknown', 'wrong_key', 'weak_hash', 'parameters'])
def test_signature_rejects_incompatible_or_unsafe_declarations(signer, invalid):
    key, certificate, algorithm = signer
    message, _ = _exchange()
    _sign(message, certificate, key, algorithm)
    if invalid == 'unknown':
        message['header']['protectionAlg']['algorithm'] = '1.2.3.4'
    elif invalid == 'wrong_key':
        wrong = AlgorithmIdentifier.ECDSA_SHA256 if isinstance(key, rsa.RSAPrivateKey) else AlgorithmIdentifier.RSA_SHA256
        message['header']['protectionAlg']['algorithm'] = wrong.dotted_string
    elif invalid == 'weak_hash':
        weak = AlgorithmIdentifier.RSA_SHA1 if isinstance(key, rsa.RSAPrivateKey) else AlgorithmIdentifier.ECDSA_SHA1
        message['header']['protectionAlg']['algorithm'] = weak.dotted_string
    else:
        message['header']['protectionAlg']['parameters'] = b'\x04\x00'
    with pytest.raises((ValueError, TypeError)):
        CmpSignatureBasedInitializationAuthentication()._verify_protection_signature(message, certificate)


@pytest.mark.parametrize('outcome', ['nonce', 'hmac', 'authorization', 'valid'])
def test_rejected_followups_preserve_transaction_nonces(cmp_device_without_onboarding, outcome):
    SecurityConfig.objects.get_or_create()
    device = cmp_device_without_onboarding['device']
    message, _ = _exchange('pollReq', 'pollRep')
    message['body']['pollReq'][0]['certReqId'] = 0
    message['header']['senderNonce'] = os.urandom(16)
    message['header']['senderKID'] = str(device.pk).encode()
    server_nonce, client_nonce = os.urandom(16), os.urandom(16)
    message['header']['recipNonce'] = os.urandom(16) if outcome == 'nonce' else server_nonce
    owner = DeviceModel.objects.create(common_name='another-device', domain=device.domain) if outcome == 'authorization' else device
    record = CmpTransactionModel.objects.create(
        transaction_id=message['header']['transactionID'].asOctets().hex(), operation='certification',
        request_body_type='cr', request_der=b'original', device=owner, domain=device.domain,
        status=CmpTransactionModel.Status.WAITING, last_server_nonce=server_nonce, last_client_nonce=client_nonce,
    )
    secret = device.no_onboarding_config.cmp_shared_secret
    _protect(message, secret='wrong-secret' if outcome == 'hmac' else secret)
    response = _post(message, device.domain, 'certification')
    record.refresh_from_db()
    if outcome == 'valid':
        assert response['body'].getName() == 'pollRep'
        assert bytes(record.last_server_nonce) == response['header']['senderNonce'].asOctets()
        assert bytes(record.last_client_nonce) == message['header']['senderNonce'].asOctets()
    else:
        assert response['body'].getName() == 'error'
        assert bytes(record.last_server_nonce) == server_nonce
        assert bytes(record.last_client_nonce) == client_nonce


@pytest.mark.parametrize('operation', ['initialization', 'certification', 'revocation', 'certconf', 'keyupdate', 'getcacerts'])
def test_signed_response_declares_the_server_algorithm(domain_instance, signer, operation):
    key, certificate, _ = signer
    algorithm = AlgorithmIdentifier.RSA_SHA384 if isinstance(key, rsa.RSAPrivateKey) else AlgorithmIdentifier.ECDSA_SHA384
    request, _ = _exchange()
    _sign(request, certificate, key, algorithm)
    domain = domain_instance['domain']
    credential = domain.issuing_ca.get_credential()
    response = rfc4210.PKIMessage()
    response['header'] = CmpMessageResponder._build_response_message_header(
        request, request['header']['senderKID'], credential.get_certificate(),
    )
    response['body']['pkiconf'] = response['body']['pkiconf'].clone('')
    context = CmpBaseRequestContext(operation=operation, domain=domain, issuer_credential=credential)
    CmpMessageResponder._sign_pki_message(response, context)
    expected = SignatureSuite.from_certificate(credential.get_certificate()).algorithm_identifier
    assert str(response['header']['protectionAlg']['algorithm']) == expected.dotted_string
    assert not response['header']['protectionAlg']['parameters'].hasValue()
    CmpSignatureBasedInitializationAuthentication()._verify_protection_signature(response, credential.get_certificate())


def test_response_algorithm_and_signature_prefer_owner_credential(domain_instance, signer):
    key, certificate, _ = signer
    _, response = _exchange()
    context = CmpBaseRequestContext(
        operation='initialization', domain=domain_instance['domain'],
        owner_credential=Mock(get_certificate=lambda: certificate, get_private_key=lambda: key),
    )
    CmpMessageResponder._sign_pki_message(response, context)
    assert str(response['header']['protectionAlg']['algorithm']) == certificate.signature_algorithm_oid.dotted_string
    CmpSignatureBasedInitializationAuthentication()._verify_protection_signature(response, certificate)


@pytest.fixture
def idevid_transaction(cmp_device_with_onboarding):
    device = cmp_device_with_onboarding['device']
    root, root_key = CertificateGenerator.create_root_ca('Manufacturer')
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, 'IDevID'),
        x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, device.serial_number),
    ])
    certificate, key = CertificateGenerator.create_ee(root_key, root.subject, subject)
    truststore = TruststoreModel.objects.create(unique_name='cmp-manufacturer', intended_usage=TruststoreModel.IntendedUsage.IDEVID)
    TruststoreOrderModel.objects.create(trust_store=truststore, certificate=CertificateModel.save_certificate(root), order=0)
    DevIdRegistration.objects.create(
        unique_name='cmp-idevid', truststore=truststore, domain=device.domain, serial_number_pattern=device.serial_number,
    )
    context = CmpCertificateRequestContext(
        protocol='cmp', operation='initialization', request_data={
            'subject': subject, 'public_key': key.public_key(), 'private_key': key, 'use_ir': True,
            'recipient_name': device.domain.issuing_ca.get_credential().get_certificate().subject.rfc4514_string(),
        },
    )
    CmpMessageBuilder().build(context)
    original = _sign(context.parsed_message, certificate, key)
    transaction = CmpTransactionModel.objects.create(
        transaction_id=original['header']['transactionID'].asOctets().hex(), operation='initialization',
        request_body_type='ir', request_der=encoder.encode(original), device=device, domain=device.domain,
        status=CmpTransactionModel.Status.WAITING, last_server_nonce=os.urandom(16), last_client_nonce=os.urandom(16),
    )
    return transaction, certificate, key, root, root_key


@pytest.mark.parametrize(
    'invalid', [None, 'another_certificate', 'untrusted', 'signature', 'device', 'domain', 'operation', 'missing_original']
)
def test_idevid_polling_keeps_original_signer_and_transaction_scope(idevid_transaction, invalid):
    transaction, certificate, key, root, root_key = idevid_transaction
    domain = transaction.domain
    message, _ = _exchange('pollReq', 'pollRep')
    message['header']['transactionID'] = bytes.fromhex(transaction.transaction_id)
    message['header']['recipNonce'] = bytes(transaction.last_server_nonce)
    message['body']['pollReq'][0]['certReqId'] = 0
    if invalid == 'another_certificate':
        certificate, key = CertificateGenerator.create_ee(root_key, root.subject, certificate.subject)
    elif invalid == 'untrusted':
        rogue_root, rogue_key = CertificateGenerator.create_root_ca('Untrusted Manufacturer')
        certificate, key = CertificateGenerator.create_ee(rogue_key, rogue_root.subject, certificate.subject)
    elif invalid == 'device':
        transaction.device = DeviceModel.objects.create(common_name='wrong-device', domain=domain)
        transaction.save(update_fields=['device'])
    elif invalid == 'domain':
        from pki.models import DomainModel
        transaction.domain = DomainModel.objects.create(unique_name='wrong-domain', issuing_ca=domain.issuing_ca)
        transaction.save(update_fields=['domain'])
    elif invalid == 'operation':
        transaction.operation = 'certification'
        transaction.save(update_fields=['operation'])
    elif invalid == 'missing_original':
        original, _ = decoder.decode(bytes(transaction.request_der), asn1Spec=rfc4210.PKIMessage())
        original['extraCerts'].clear()
        transaction.request_der = encoder.encode(original)
        transaction.save(update_fields=['request_der'])
    _sign(message, certificate, key)
    if invalid == 'signature':
        message['protection'] = message['protection'].clone(value=univ.BitString.fromOctetString(b'invalid'))
    response = _post(message, domain, 'initialization')
    assert response['body'].getName() == ('pollRep' if invalid is None else 'error')
    assert not IssuedCredentialModel.objects.filter(device=transaction.device).exists()
    transaction.refresh_from_db()
    if invalid is None:
        assert bytes(transaction.last_server_nonce) == response['header']['senderNonce'].asOctets()
