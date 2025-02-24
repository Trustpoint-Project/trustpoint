"""pytest configuration for the tests in the PKI app."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db: None) -> None:
    """Fixture to enable database access for all tests."""


# ----------------------------
# RSA Private Key Fixture
# ----------------------------

@pytest.fixture(scope='function')
def rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a reusable RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# ----------------------------
# EC Private Key Fixture
# ----------------------------

@pytest.fixture(scope='function')
def ec_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a reusable EC private key."""
    return ec.generate_private_key(ec.SECP256R1())
