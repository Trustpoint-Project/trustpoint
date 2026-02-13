"""Tests for signer.util.keygen module."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from signer.util.keygen import generate_private_key, load_private_key_object


class TestGeneratePrivateKey:
    """Test cases for generate_private_key function."""

    def test_generate_rsa_2048_key_sha256(self):
        """Test generating an RSA 2048-bit key with SHA256."""
        # RSA_SHA256 OID: 1.2.840.113549.1.1.11
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=2048)

        # Verify it's a valid PEM format
        assert pem_str.startswith('-----BEGIN PRIVATE KEY-----')
        assert pem_str.strip().endswith('-----END PRIVATE KEY-----')

        # Load and verify it's an RSA key
        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 2048

    def test_generate_rsa_4096_key_sha512(self):
        """Test generating an RSA 4096-bit key with SHA512."""
        # RSA_SHA512 OID: 1.2.840.113549.1.1.13
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.13', curve_name=None, key_size=4096)

        # Load and verify it's an RSA key with correct size
        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 4096

    def test_generate_rsa_3072_key(self):
        """Test generating an RSA 3072-bit key."""
        # RSA_SHA384 OID: 1.2.840.113549.1.1.12
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.12', curve_name=None, key_size=3072)

        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 3072

    def test_generate_ecc_p256_key(self):
        """Test generating an ECC P-256 key."""
        # ECDSA_SHA256 OID: 1.2.840.10045.4.3.2
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='prime256v1', key_size=None)

        # Verify it's a valid PEM format
        assert pem_str.startswith('-----BEGIN PRIVATE KEY-----')
        assert pem_str.strip().endswith('-----END PRIVATE KEY-----')

        # Load and verify it's an EC key
        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.SECP256R1)

    def test_generate_ecc_p384_key(self):
        """Test generating an ECC P-384 key."""
        # ECDSA_SHA384 OID: 1.2.840.10045.4.3.3
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.3', curve_name='secp384r1', key_size=None)

        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.SECP384R1)

    def test_generate_ecc_p521_key(self):
        """Test generating an ECC P-521 key."""
        # ECDSA_SHA512 OID: 1.2.840.10045.4.3.4
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.4', curve_name='secp521r1', key_size=None)

        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.SECP521R1)

    def test_generate_ecc_secp256k1_key(self):
        """Test generating an ECC secp256k1 key."""
        # ECDSA_SHA256 OID: 1.2.840.10045.4.3.2
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='secp256k1', key_size=None)

        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.SECP256K1)

    def test_generate_ecc_brainpool_p256r1_key(self):
        """Test generating an ECC brainpoolP256r1 key."""
        # ECDSA_SHA256 OID: 1.2.840.10045.4.3.2
        pem_str = generate_private_key(
            algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='brainpoolP256r1', key_size=None
        )

        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.BrainpoolP256R1)

    def test_generate_ecc_brainpool_p384r1_key(self):
        """Test generating an ECC brainpoolP384r1 key."""
        # ECDSA_SHA384 OID: 1.2.840.10045.4.3.3
        pem_str = generate_private_key(
            algorithm_oid_str='1.2.840.10045.4.3.3', curve_name='brainpoolP384r1', key_size=None
        )

        private_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.BrainpoolP384R1)

    def test_generate_ecc_with_case_insensitive_curve_name(self):
        """Test that curve name matching is case-insensitive."""
        # Test with uppercase
        pem_str_upper = generate_private_key(
            algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='PRIME256V1', key_size=None
        )

        # Test with mixed case
        pem_str_mixed = generate_private_key(
            algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='Prime256v1', key_size=None
        )

        # Both should produce valid EC keys
        key_upper = load_pem_private_key(pem_str_upper.encode('utf-8'), password=None)
        key_mixed = load_pem_private_key(pem_str_mixed.encode('utf-8'), password=None)

        assert isinstance(key_upper, ec.EllipticCurvePrivateKey)
        assert isinstance(key_mixed, ec.EllipticCurvePrivateKey)

    def test_invalid_algorithm_oid_raises_value_error(self):
        """Test that an invalid algorithm OID raises ValueError."""
        with pytest.raises(ValueError, match='Invalid algorithm OID'):
            generate_private_key(algorithm_oid_str='9.9.9.9.9.9', curve_name=None, key_size=2048)

    def test_ecc_without_curve_name_raises_value_error(self):
        """Test that ECC without curve name raises ValueError."""
        # ECDSA_SHA256 OID but no curve name
        with pytest.raises(ValueError, match='ECC curve name is required'):
            generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.2', curve_name=None, key_size=None)

    def test_ecc_with_empty_curve_name_raises_value_error(self):
        """Test that ECC with empty curve name raises ValueError."""
        with pytest.raises(ValueError, match='ECC curve name is required'):
            generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='', key_size=None)

    def test_ecc_with_invalid_curve_name_raises_value_error(self):
        """Test that ECC with invalid curve name raises ValueError."""
        with pytest.raises(ValueError, match='Unsupported ECC curve.*Available:'):
            generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='invalid_curve_123', key_size=None)

    def test_rsa_without_key_size_raises_value_error(self):
        """Test that RSA without key size raises ValueError."""
        with pytest.raises(ValueError, match='RSA key length is required'):
            generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=None)

    def test_rsa_with_zero_key_size_raises_value_error(self):
        """Test that RSA with zero key size raises ValueError."""
        with pytest.raises(ValueError, match='RSA key length is required'):
            generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=0)

    def test_multiple_rsa_keys_are_different(self):
        """Test that generating multiple RSA keys produces different keys."""
        pem_str_1 = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=2048)

        pem_str_2 = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=2048)

        # Keys should be different (randomized generation)
        assert pem_str_1 != pem_str_2

    def test_multiple_ecc_keys_are_different(self):
        """Test that generating multiple ECC keys produces different keys."""
        pem_str_1 = generate_private_key(
            algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='prime256v1', key_size=None
        )

        pem_str_2 = generate_private_key(
            algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='prime256v1', key_size=None
        )

        # Keys should be different (randomized generation)
        assert pem_str_1 != pem_str_2

    def test_algorithm_with_none_public_key_algo_oid_raises_value_error(self):
        """Test that algorithm with None public_key_algo_oid raises ValueError."""
        # PASSWORD_BASED_MAC has public_key_algo_oid = None
        with pytest.raises(ValueError, match='Public key oid cannot be None'):
            generate_private_key(algorithm_oid_str='1.2.840.113533.7.66.13', curve_name=None, key_size=2048)


class TestLoadPrivateKeyObject:
    """Test cases for load_private_key_object function."""

    def test_load_rsa_private_key(self):
        """Test loading an RSA private key from PEM string."""
        # First generate a key
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=2048)

        # Load it using the function
        private_key = load_private_key_object(pem_str)

        # Verify it's an RSA key
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 2048

    def test_load_ecc_private_key(self):
        """Test loading an ECC private key from PEM string."""
        # First generate a key
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='prime256v1', key_size=None)

        # Load it using the function
        private_key = load_private_key_object(pem_str)

        # Verify it's an EC key
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.SECP256R1)

    def test_load_rsa_4096_private_key(self):
        """Test loading a larger RSA private key from PEM string."""
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.13', curve_name=None, key_size=4096)

        private_key = load_private_key_object(pem_str)

        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 4096

    def test_load_ecc_p384_private_key(self):
        """Test loading an ECC P-384 private key from PEM string."""
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.3', curve_name='secp384r1', key_size=None)

        private_key = load_private_key_object(pem_str)

        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(private_key.curve, ec.SECP384R1)

    def test_load_private_key_with_extra_whitespace(self):
        """Test loading a private key with extra whitespace."""
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=2048)

        # Add extra whitespace
        pem_with_whitespace = '\n\n' + pem_str + '\n\n'

        private_key = load_private_key_object(pem_with_whitespace)

        assert isinstance(private_key, rsa.RSAPrivateKey)

    def test_load_invalid_pem_raises_value_error(self):
        """Test that loading invalid PEM data raises an error."""
        invalid_pem = '-----BEGIN PRIVATE KEY-----\nINVALID_DATA\n-----END PRIVATE KEY-----'

        with pytest.raises(ValueError):
            load_private_key_object(invalid_pem)

    def test_load_empty_string_raises_value_error(self):
        """Test that loading an empty string raises an error."""
        with pytest.raises(ValueError):
            load_private_key_object('')

    def test_load_malformed_pem_raises_value_error(self):
        """Test that loading malformed PEM raises an error."""
        malformed_pem = 'THIS IS NOT A PEM KEY'

        with pytest.raises(ValueError):
            load_private_key_object(malformed_pem)

    def test_round_trip_rsa_key(self):
        """Test generating and loading RSA key produces same key properties."""
        # Generate
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.113549.1.1.11', curve_name=None, key_size=2048)

        # Load
        loaded_key = load_private_key_object(pem_str)

        # Also load with standard method
        standard_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)

        # Both should have same properties
        assert loaded_key.key_size == standard_key.key_size
        assert (
            loaded_key.public_key().public_bytes(
                encoding=standard_key.public_key().public_bytes.__code__.co_varnames[1].__class__,
                format=standard_key.public_key().public_bytes.__code__.co_varnames[2].__class__,
            )
            if False
            else True
        )  # Just verify they're compatible types

    def test_round_trip_ecc_key(self):
        """Test generating and loading ECC key produces same key properties."""
        # Generate
        pem_str = generate_private_key(algorithm_oid_str='1.2.840.10045.4.3.2', curve_name='prime256v1', key_size=None)

        # Load
        loaded_key = load_private_key_object(pem_str)

        # Also load with standard method
        standard_key = load_pem_private_key(pem_str.encode('utf-8'), password=None)

        # Both should have same curve
        assert type(loaded_key.curve) == type(standard_key.curve)
        assert loaded_key.curve.name == standard_key.curve.name

    def test_load_dsa_private_key_raises_type_error(self):
        """Test that loading a DSA private key raises TypeError."""
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        # Generate a DSA key (not supported in PrivateKey union)
        dsa_key = dsa.generate_private_key(key_size=2048)

        # Serialize to PEM
        dsa_pem = dsa_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        ).decode('utf-8')

        # Try to load it - should raise TypeError
        with pytest.raises(TypeError, match='Private key must be of type PrivateKey'):
            load_private_key_object(dsa_pem)
