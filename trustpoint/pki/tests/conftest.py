"""pytest configuration for the tests in the PKI app."""

from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from pki.models.domain import DomainModel
from pki.models import CaModel
from management.models import KeyStorageConfig
from pki.util.x509 import CertificateGenerator


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db: None) -> None:
    """Fixture to enable database access for all tests."""


# ----------------------------
# RSA Private Key Fixture
# ----------------------------


@pytest.fixture
def rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a reusable RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


# ----------------------------
# EC Private Key Fixture
# ----------------------------


@pytest.fixture
def ec_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a reusable EC private key."""
    return ec.generate_private_key(ec.SECP256R1())


# ----------------------------
# Test model instance Fixtures
# ----------------------------

CA_COMMON_NAME = 'Root CA'
UNIQUE_NAME = CA_COMMON_NAME.replace(' ', '_').lower()
CA_TYPE = CaModel.CaTypeChoice.LOCAL_UNPROTECTED

DOMAIN_UNIQUE_NAME = 'domain_name'


@pytest.fixture
def issuing_ca_instance() -> dict[str, Any]:
    """Fixture for a testing CaModel instance."""
    # Ensure crypto storage config exists for encrypted fields
    KeyStorageConfig.get_or_create_default()

    cert, priv_key = CertificateGenerator.create_root_ca(cn=CA_COMMON_NAME)
    issuing_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert, private_key=priv_key, chain=[], unique_name=UNIQUE_NAME, ca_type=CA_TYPE
    )
    return {'issuing_ca': issuing_ca, 'cert': cert, 'priv_key': priv_key}


@pytest.fixture
def domain_instance(issuing_ca_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture for a DomainModel instance using a valid issuing CA."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    cert = issuing_ca_instance.get('cert')
    if (
        not isinstance(issuing_ca, CaModel)
        or not isinstance(cert, x509.Certificate)
        or not isinstance(priv_key, RSAPrivateKey)
    ):
        msg = 'Issuing CA not created properly'
        raise TypeError(msg)
    domain = DomainModel.objects.create(unique_name=DOMAIN_UNIQUE_NAME, issuing_ca=issuing_ca, is_active=True)
    issuing_ca_instance.update({'domain': domain})
    return issuing_ca_instance
