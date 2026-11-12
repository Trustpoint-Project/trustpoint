# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression checks for owner selection and the bundled onboarding clients."""

import base64
import datetime
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from trustpoint_core.serializer import CredentialSerializer

from aoki.tests.client import AokiClient, AokiClientOwnerIdCertVerificationError
from aoki.views import AokiServiceMixin
from est.tests.client import ESTClient
from pki.models import RemoteIssuedCredentialModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel
from pki.util.x509 import CertificateGenerator
from request.message_responder.est import EstCertificateMessageResponder
from request.request_context import EstCertificateRequestContext


def owner_certificate(ca, key, references):
    return CertificateGenerator.create_ee(
        issuer_private_key=key,
        issuer_name=ca.subject,
        subject_name='Owner',
        extensions=[(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ref) for ref in references]), False)],
    )


@pytest.mark.parametrize('reference_kind', ['cert', 'uri', 'ca'])
def test_owner_lookup_skips_pending_and_unrelated_credentials(reference_kind, domain_instance):
    ca, key = domain_instance['cert'], domain_instance['priv_key']
    idevid, _ = owner_certificate(ca, key, ['urn:uuid:device-one'])
    references = {
        'cert': AokiServiceMixin.get_idevid_owner_san_uri(idevid),
        'uri': AokiServiceMixin.get_idevid_owner_san_uris_from_san(idevid)[0],
        'ca': f'dev-owner:ca:{ca.fingerprint(hashes.SHA256()).hex()}',
    }
    reference = references[reference_kind]
    cert, private_key = owner_certificate(ca, key, [reference])
    owner = RemoteIssuedCredentialModel.create_imported_dev_owner_id(
        common_name='owner',
        credential_serializer=CredentialSerializer(private_key=private_key, certificate=cert),
    )
    original = owner.credential

    def lookup():
        if reference_kind == 'ca':
            return AokiServiceMixin.get_domain_based_owner_credential(domain_instance['domain'])
        return AokiServiceMixin.get_owner_credential(idevid)

    def add_credential(certificate, private_key, stored_ref: str | None = reference):
        credential = CredentialModel.save_credential_serializer(
            CredentialSerializer(private_key=private_key, certificate=certificate),
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        record = RemoteIssuedCredentialModel.objects.create(
            credential=credential,
            common_name='new-owner',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
        )
        if stored_ref is not None:
            IDevIDReferenceModel.objects.create(
                dev_owner_id=record,
                idevid_ref=stored_ref,
                dev_owner_id_certificate=credential.certificate,
            )
        return credential

    add_credential(None, private_key)
    assert lookup() == original
    unrelated, unrelated_key = owner_certificate(ca, key, ['dev-owner:uri:other-device'])
    add_credential(unrelated, unrelated_key, stored_ref=None)
    assert lookup() == original
    expired = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(ca.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=2))
        .not_valid_after(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(reference)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    add_credential(expired, private_key)
    no_san, no_san_key = CertificateGenerator.create_ee(
        issuer_private_key=key, issuer_name=ca.subject, subject_name='No reference'
    )
    add_credential(no_san, no_san_key, stored_ref=None)
    keyless = CredentialModel.objects.create(
        credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID, certificate=original.certificate
    )
    keyless_record = RemoteIssuedCredentialModel.objects.create(
        credential=keyless,
        common_name='keyless',
        issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
    )
    IDevIDReferenceModel.objects.create(
        dev_owner_id=keyless_record,
        idevid_ref=reference,
        dev_owner_id_certificate=original.certificate,
    )
    assert lookup() == original
    renewed, renewed_key = owner_certificate(ca, key, [reference])
    latest = add_credential(renewed, renewed_key)
    assert lookup() == latest
    # The stored reference still points to the original certificate, so validate the SAN itself.
    assert owner.idevid_ref_set.get().dev_owner_id_certificate_id == original.certificate_id
    original.delete()
    latest.delete()
    assert lookup() is None


def test_est_client_accepts_matching_uri_and_rejects_another_device(issuing_ca_instance):
    ca, key = issuing_ca_instance['cert'], issuing_ca_instance['priv_key']
    idevid, _ = owner_certificate(ca, key, ['urn:uuid:device-one'])
    client = AokiClient('https://localhost', 'device.pem', 'device.key', 'owner-ca.pem')
    matching, _ = owner_certificate(ca, key, ['dev-owner:uri:urn:uuid:device-one'])
    client._verify_matches_idevid_cert(matching, idevid)
    unrelated, _ = owner_certificate(ca, key, ['dev-owner:uri:urn:uuid:device-two'])
    with pytest.raises(AokiClientOwnerIdCertVerificationError):
        client._verify_matches_idevid_cert(unrelated, idevid)


def test_aoki_enrollment_keeps_configured_identity(tmp_path, issuing_ca_instance):
    ca = issuing_ca_instance['cert']
    pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    response = Mock(
        status_code=200,
        headers={'AOKI-Signature': base64.b64encode(b'signature').decode(), 'AOKI-Signature-Algorithm': 'ignored'},
    )
    response.json.return_value = {
        'aoki-init': {
            'owner-id-cert': pem,
            'tls-truststore': pem,
            'enrollment-info': {'protocols': [{'protocol': 'EST', 'url': '/est/'}]},
        }
    }
    (tmp_path / 'custom.pem').write_text(pem)
    (tmp_path / 'owner-ca.pem').write_text(pem)
    client = AokiClient('https://localhost', 'custom.pem', 'custom.key', 'owner-ca.pem')
    with (
        patch('aoki.tests.client.CERTS_DIR', tmp_path),
        patch('aoki.tests.client.requests.get', return_value=response) as get,
        patch.object(client, '_verify_owner_id_cert'),
        patch.object(client, '_verify_owner_signature'),
        patch('aoki.tests.client.ESTClient') as est,
    ):
        client.onboard()
    expected = (tmp_path / 'custom.pem', tmp_path / 'custom.key')
    assert get.call_args.kwargs['cert'] == expected
    assert (est.call_args.kwargs['cert_path'], est.call_args.kwargs['key_path']) == expected


@pytest.mark.parametrize('operation', ['enroll', 'reenroll'])
def test_est_client_reads_server_pkcs7_and_selects_requested_key(operation, tmp_path, monkeypatch, issuing_ca_instance):
    ca, ca_key = issuing_ca_instance['cert'], issuing_ca_instance['priv_key']
    initial, key = owner_certificate(ca, ca_key, ['urn:uuid:device-one'])
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'existing.pem').write_bytes(initial.public_bytes(serialization.Encoding.PEM))
    (tmp_path / 'existing.key').write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    client = ESTClient('https://localhost/est', 'mutual_tls', out_cert_path='issued.pem', out_key_path='issued.key')
    issued = []

    def post(url, *, data, **kwargs):
        csr = x509.load_der_x509_csr(data)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ca.not_valid_before_utc)
            .not_valid_after(ca.not_valid_after_utc)
            .sign(ca_key, hashes.SHA256())
        )
        issued.append(certificate)
        context = EstCertificateRequestContext(
            est_encoding='pkcs7', issued_certificate=certificate, issued_certificate_chain=[ca]
        )
        body, content_type = EstCertificateMessageResponder._prepare_certificate_data(context)
        return Mock(
            status_code=200,
            content=body.encode(),
            headers={'Content-Type': content_type, 'Content-Transfer-Encoding': 'base64'},
        )

    with patch.object(client.session, 'post', side_effect=post):
        if operation == 'enroll':
            client.enroll('device', '123')
            output = tmp_path / 'issued.pem'
        else:
            client.reenroll('existing.pem', 'existing.key')
            output = tmp_path / 'reenrolled_issued.pem'
    assert x509.load_pem_x509_certificate(output.read_bytes()) == issued[0]
    with pytest.raises(ValueError, match='no certificate for the requested key'):
        ESTClient._issued_certificate(
            Mock(content=ca.public_bytes(serialization.Encoding.DER), headers={}), key.public_key()
        )
