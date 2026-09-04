"""Behavioral tests for the EST client at its HTTP boundary."""

import base64
import datetime
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from request.clients.est_client import EstClient, EstClientError
from request.request_context import EstBaseRequestContext


def certificate_and_csr() -> tuple[rsa.RSAPrivateKey, x509.Certificate, x509.CertificateSigningRequest]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'est-test')])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    return key, certificate, csr


def truststore() -> Mock:
    store = Mock()
    store.get_certificate_collection_serializer.return_value.as_pem.return_value = (
        b'-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n'
    )
    return store


def client_context(**kwargs: object) -> EstBaseRequestContext:
    values: dict[str, object] = {
        'est_server_host': 'est.example.test',
        'est_server_truststore': truststore(),
        'est_server_path': '/.well-known/est/simpleenroll',
        **kwargs,
    }
    return EstBaseRequestContext(**values)


class TestEstClient:
    def test_constructor_requires_host_and_truststore(self) -> None:
        with pytest.raises(EstClientError, match='est_server_host is required'):
            EstClient(EstBaseRequestContext(est_server_truststore=truststore()))
        with pytest.raises(EstClientError, match='est_server_truststore is required'):
            EstClient(EstBaseRequestContext(est_server_host='est.example.test'))

    def test_url_uses_default_and_custom_ports(self) -> None:
        assert EstClient(client_context())._build_url() == 'https://est.example.test/.well-known/est/simpleenroll'
        custom = EstClient(client_context(est_server_port=8443, est_server_path='/enroll'))
        assert custom._build_url() == 'https://est.example.test:8443/enroll'
        assert custom._build_url('/.well-known/est/cacerts') == 'https://est.example.test:8443/.well-known/est/cacerts'

    def test_prepare_csr_data_returns_base64_der(self) -> None:
        _, _, csr = certificate_and_csr()
        encoded, content_type = EstClient(client_context())._prepare_csr_data(csr)
        assert content_type == 'application/pkcs10'
        assert base64.b64decode(encoded) == csr.public_bytes(serialization.Encoding.DER)

    def test_parse_response_rejects_content_type_and_empty_pkcs7(self) -> None:
        client = EstClient(client_context())
        with pytest.raises(EstClientError, match='Unexpected content type'):
            client._parse_response(b'', 'text/plain')
        with patch('request.clients.est_client.pkcs7.load_der_pkcs7_certificates', return_value=[]):
            with pytest.raises(EstClientError, match='No certificates found'):
                client._parse_response(base64.b64encode(b'valid-pkcs7'), 'application/pkcs7-mime')

    def test_parse_response_returns_first_certificate(self) -> None:
        key, certificate, _ = certificate_and_csr()
        data = pkcs7.PKCS7SignatureBuilder().set_data(b'issued').add_signer(
            certificate, key, hashes.SHA256()
        ).sign(serialization.Encoding.DER, [])
        result = EstClient(client_context())._parse_response(base64.b64encode(data), 'application/pkcs7-mime')
        assert result.subject == certificate.subject

    def test_prepare_auth_prefers_mtls_then_basic_then_none(self) -> None:
        mtls = EstClient(client_context(est_client_cert_pem='CERT', est_client_key_pem='KEY'))
        with patch.object(mtls, '_write_temp_pem', side_effect=['cert.pem', 'key.pem']):
            basic, cert, files = mtls._prepare_auth()
        assert basic is None and cert == ('cert.pem', 'key.pem') and files == ['cert.pem', 'key.pem']

        basic_client = EstClient(client_context(est_username='alice', est_password='synthetic-password'))
        assert basic_client._prepare_auth() == (('alice', 'synthetic-password'), None, [])
        assert EstClient(client_context())._prepare_auth() == (None, None, [])

    def test_write_temp_pem_writes_text_and_bytes(self) -> None:
        client = EstClient(client_context())
        text_path = client._write_temp_pem('CERT')
        bytes_path = client._write_temp_pem(b'KEY')
        try:
            assert Path(text_path).read_text() == 'CERT'
            assert Path(bytes_path).read_text() == 'KEY'
        finally:
            Path(text_path).unlink()
            Path(bytes_path).unlink()

    def test_prepare_ca_bundle_requires_truststore(self) -> None:
        client = EstClient(client_context())
        path = client._prepare_ca_bundle()
        try:
            assert Path(path).read_bytes().startswith(b'-----BEGIN CERTIFICATE-----')
        finally:
            Path(path).unlink()
        client.context.est_server_truststore = None
        with pytest.raises(EstClientError, match='truststore is not configured'):
            client._prepare_ca_bundle()

    @patch('request.clients.est_client.requests.post')
    def test_simple_enroll_success_and_cleanup(self, post: Mock) -> None:
        key, certificate, csr = certificate_and_csr()
        response_data = pkcs7.PKCS7SignatureBuilder().set_data(b'issued').add_signer(
            certificate, key, hashes.SHA256()
        ).sign(serialization.Encoding.DER, [])
        response = Mock(status_code=200, content=base64.b64encode(response_data), headers={'Content-Type': 'application/pkcs7-mime'})
        post.return_value = response
        ca_path = tempfile.NamedTemporaryFile(delete=False).name
        auth_path = tempfile.NamedTemporaryFile(delete=False).name
        context = client_context(est_username='alice', est_password='synthetic-password')
        client = EstClient(context, timeout=7)
        with patch.object(client, '_prepare_ca_bundle', return_value=ca_path), patch.object(
            client, '_prepare_auth', return_value=(('alice', 'synthetic-password'), None, [auth_path])
        ):
            result = client.simple_enroll(csr)
        assert result.subject == certificate.subject
        post.assert_called_once()
        assert post.call_args.kwargs['timeout'] == 7
        assert not Path(ca_path).exists() and not Path(auth_path).exists()

    @patch('request.clients.est_client.requests.post')
    def test_simple_enroll_translates_http_and_network_errors(self, post: Mock) -> None:
        _, _, csr = certificate_and_csr()
        for response in [Mock(status_code=500, text='server failure')]:
            post.return_value = response
            client = EstClient(client_context())
            with patch.object(client, '_prepare_ca_bundle', side_effect=lambda: tempfile.NamedTemporaryFile(delete=False).name):
                with pytest.raises(EstClientError, match='returned error status 500'):
                    client.simple_enroll(csr)
        post.side_effect = __import__('requests').exceptions.Timeout('timed out')
        client = EstClient(client_context())
        with patch.object(client, '_prepare_ca_bundle', side_effect=lambda: tempfile.NamedTemporaryFile(delete=False).name):
            with pytest.raises(EstClientError, match='Failed to communicate'):
                client.simple_enroll(csr)

    @patch('request.clients.est_client.requests.get')
    def test_get_ca_certs_success_and_http_error(self, get: Mock) -> None:
        key, certificate, _ = certificate_and_csr()
        response_data = pkcs7.PKCS7SignatureBuilder().set_data(b'cas').add_signer(
            certificate, key, hashes.SHA256()
        ).sign(serialization.Encoding.DER, [])
        get.return_value = Mock(status_code=200, content=base64.b64encode(response_data), text='')
        result = EstClient(client_context()).get_ca_certs()
        assert len(result) == 1 and result[0].subject == certificate.subject
        get.return_value = Mock(status_code=503, content=b'', text='unavailable')
        with pytest.raises(EstClientError, match='returned error status 503'):
            EstClient(client_context()).get_ca_certs()
