"""Utility methods for private key generation and hash algorithm retrieval."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.db import models
from trustpoint_core.oid import KeyPairGenerator, NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import PrivateKeySerializer

if TYPE_CHECKING:
    from trustpoint_core.key_types import PrivateKey

    from pki.models.domain import DomainModel


class AutoGenPkiKeyAlgorithm(models.TextChoices):
    """The key algorithms supported by the AutoGenPKI."""

    RSA2048 = 'RSA2048SHA256', 'RSA2048'
    RSA4096 = 'RSA4096SHA256', 'RSA4096'
    SECP256R1 = 'SECP256R1SHA256', 'SECP256R1'
    # omitting the rest of the choices as an example that Auto Gen PKI doesn't have to support all key algorithms

    def to_public_key_info(self) -> PublicKeyInfo:
        """Gets the corresponding public key info for the key algorithm."""
        if self.value == AutoGenPkiKeyAlgorithm.RSA2048:
            return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=2048)
        if self.value == AutoGenPkiKeyAlgorithm.RSA4096:
            return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=4096)
        if self.value == AutoGenPkiKeyAlgorithm.SECP256R1:
            return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC, named_curve=NamedCurve.SECP256R1)
        exc_msg = f'Unsupported key algorithm type for AutoGenPKI: {self.value}'
        raise ValueError(exc_msg)


class KeyGenerator:
    """Utility class for generating private keys."""

    @staticmethod
    def generate_private_key_for_public_key_info(key_info: PublicKeyInfo) -> PrivateKeySerializer:
        """Generates a private key for a public key info.

        Returns:
            The generated private key.
        """
        return KeyPairGenerator.generate_key_pair_for_public_key_info(key_info)

    @staticmethod
    def generate_private_key(domain: DomainModel) -> PrivateKeySerializer:
        """Generates a key pair of the type corresponding to the domain model.

        Args:
            domain: The domain to consider.

        Returns:
            The generated private key / key pair serializer.
        """
        issuing_ca_cert = domain.issuing_ca.credential.get_certificate_serializer().as_crypto()
        return PrivateKeySerializer(KeyPairGenerator.generate_key_pair_for_certificate(issuing_ca_cert))


class CryptographyUtils:
    """Utilities methods for cryptography corresponding to Trustpoint models."""

    @staticmethod
    def get_hash_algorithm_for_private_key(private_key: PrivateKey) -> hashes.HashAlgorithm:
        """Gets a suitable hash algorithm for a given private key.

        Args:
            private_key: The private key to consider.

        Returns:
            The hash algorithm to use.
        """
        if isinstance(private_key, rsa.RSAPrivateKey):
            return hashes.SHA256()
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            if isinstance(private_key.curve, ec.SECP256R1):
                return hashes.SHA256()
            if isinstance(private_key.curve, ec.SECP384R1):
                return hashes.SHA384()

        err_msg = 'A suitable hash algorithm is not yet specified for the given private key type.'
        raise ValueError(err_msg)
