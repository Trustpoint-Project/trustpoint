import pytest
from trustpoint_core.serializer.certificate import CertificateSerializer
from cryptography.hazmat.primitives import serialization
from pki.models.certificate import CertificateModel
from pki.tests.fixtures import self_signed_cert_with_ext  # noqa: F401


@pytest.mark.django_db
def test_save_certificate_method(self_signed_cert_with_ext) -> None:
    """Test that save_certificate method creates and stores a certificate model instance."""
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    assert isinstance(cert_model, CertificateModel)
    assert CertificateModel.objects.get(pk=cert_model.pk) == cert_model


@pytest.mark.django_db
def test_save_certificate_with_serializer(self_signed_cert_with_ext) -> None:
    """Test saving a certificate using a CertificateSerializer instead of a raw x509.Certificate."""
    cert_pem = self_signed_cert_with_ext.public_bytes(serialization.Encoding.PEM)
    serializer = CertificateSerializer(cert_pem)
    cert_model = CertificateModel.save_certificate(serializer)
    assert cert_model
