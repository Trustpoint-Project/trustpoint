import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from django.core.exceptions import ValidationError
from django.utils import timezone
from trustpoint_core import oid

from pki.models import DomainModel, IssuingCaModel
from pki.util.x509 import CertificateGenerator

COMMON_NAME = 'Root CA'
UNIQUE_NAME = COMMON_NAME.replace(' ','_').lower()
CA_TYPE = IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED

DOMAIN_UNIQUE_NAME = 'domain_name'


@pytest.fixture
def issuing_ca_instance() -> dict[str, Any]:
    cert, priv_key = CertificateGenerator.create_root_ca(cn=COMMON_NAME)
    issuing_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=priv_key,
        chain=[],
        unique_name=UNIQUE_NAME,
        ca_type= CA_TYPE
    )
    return {
        'issuing_ca': issuing_ca,
        'cert': cert,
        'priv_key': priv_key
    }

@pytest.fixture
def domain_instance(issuing_ca_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture for a DomainModel instance using a valid issuing CA."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    cert = issuing_ca_instance.get('cert')
    if not isinstance(issuing_ca, IssuingCaModel) or not isinstance(cert, x509.Certificate) or not isinstance(priv_key, RSAPrivateKey):
        msg = 'Issuig CA not created properly'
        raise TypeError(msg)
    domain = DomainModel.objects.create(unique_name=DOMAIN_UNIQUE_NAME, issuing_ca=issuing_ca, is_active=True)
    issuing_ca_instance.update({'domain': domain})
    return issuing_ca_instance

def test_attributes_and_properties(domain_instance: dict[str, Any]) -> None:
    """Test that the common_name property returns the certificate's common name."""
    tz = timezone.get_current_timezone()
    current_time = datetime.datetime.now(tz)
    domain = domain_instance.get('domain')
    issuing_ca = domain_instance.get('issuing_ca')
    cert = domain_instance.get('cert')
    if not isinstance(domain, DomainModel) or not isinstance(issuing_ca, IssuingCaModel) or not isinstance(cert, x509.Certificate):
        msg = 'Domain or IssuingCA not created properly'
        raise TypeError(msg)
    assert domain.unique_name == DOMAIN_UNIQUE_NAME
    assert domain.issuing_ca == issuing_ca
    assert domain.is_active
    time_difference = (current_time - domain.created_at).total_seconds()
    assert time_difference <= 20
    assert domain.signature_suite == oid.SignatureSuite.from_certificate(cert)
