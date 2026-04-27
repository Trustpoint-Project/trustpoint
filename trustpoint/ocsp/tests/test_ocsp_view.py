"""Tests for OCSP Responder endpoint."""
import pytest
from django.urls import reverse
from django.test import Client
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.ocsp import OCSPRequestBuilder

@pytest.mark.django_db
def test_ocsp_endpoint_success():
    client = Client()
    # Build a dummy OCSP request
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'Test CA'),
    ])
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'Test Cert'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(123456789)
        .not_valid_before(x509.datetime.datetime.utcnow())
        .not_valid_after(x509.datetime.datetime.utcnow())
        .sign(issuer_key, hashes.SHA256())
    )
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, cert, hashes.SHA1())
    ocsp_req = builder.build()
    data = ocsp_req.public_bytes(encoding=x509.Encoding.DER)
    url = reverse('ocsp-responder')
    response = client.post(url, data, content_type='application/ocsp-request')
    assert response.status_code == 200
    assert response['Content-Type'] == 'application/ocsp-response'

@pytest.mark.django_db
def test_ocsp_endpoint_bad_content_type():
    client = Client()
    url = reverse('ocsp-responder')
    response = client.post(url, b'invalid', content_type='application/octet-stream')
    assert response.status_code == 400

@pytest.mark.django_db
def test_ocsp_endpoint_malformed_request():
    client = Client()
    url = reverse('ocsp-responder')
    response = client.post(url, b'invalid', content_type='application/ocsp-request')
    assert response.status_code in (400, 500)
