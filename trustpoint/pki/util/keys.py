"""Utility methods for private key generation and hash algorithm retrieval."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast, get_args

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.db import models
from trustpoint_core.crypto_types import PublicKey
from trustpoint_core.oid import KeyPairGenerator, NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import PrivateKeySerializer

if TYPE_CHECKING:
    from typing import Any, TypeGuard

    from trustpoint_core.crypto_types import PrivateKey

    from pki.models.credential import CredentialModel
    from pki.models.domain import DomainModel

logger = logging.getLogger(__name__)


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


def supported_auto_gen_pki_key_algorithms() -> tuple[AutoGenPkiKeyAlgorithm, ...]:
    """Return AutoGenPKI algorithms supported by the active crypto backend."""
    from crypto.adapters.pkcs11.backend import Pkcs11Backend  # noqa: PLC0415
    from crypto.runtime import is_hsm_backend_configured, require_active_pkcs11_config  # noqa: PLC0415
    from pkcs11 import Mechanism  # noqa: PLC0415

    all_algorithms = (
        AutoGenPkiKeyAlgorithm.RSA2048,
        AutoGenPkiKeyAlgorithm.RSA4096,
        AutoGenPkiKeyAlgorithm.SECP256R1,
    )
    if not is_hsm_backend_configured():
        return all_algorithms

    try:
        pkcs11_config = require_active_pkcs11_config()
        backend = Pkcs11Backend(profile=pkcs11_config.build_provider_profile())
    except Exception as exc:  # noqa: BLE001
        logger.warning('Could not load PKCS#11 backend config for AutoGenPKI capability filtering: %s', exc)
        return ()

    try:
        capabilities = backend.refresh_capabilities()
    except Exception as exc:  # noqa: BLE001
        logger.warning('Could not probe PKCS#11 backend for AutoGenPKI capability filtering: %s', exc)
        return ()
    finally:
        backend.close()

    supported: list[AutoGenPkiKeyAlgorithm] = []
    rsa_generation = capabilities.mechanism(Mechanism.RSA_PKCS_KEY_PAIR_GEN)
    if rsa_generation is not None:
        min_rsa = rsa_generation.min_key_size or 0
        max_rsa = rsa_generation.max_key_size or 100_000
        if min_rsa <= 2048 <= max_rsa:
            supported.append(AutoGenPkiKeyAlgorithm.RSA2048)
        if min_rsa <= 4096 <= max_rsa:
            supported.append(AutoGenPkiKeyAlgorithm.RSA4096)

    ec_generation = capabilities.mechanism(Mechanism.EC_KEY_PAIR_GEN)
    if ec_generation is not None:
        min_ec = ec_generation.min_key_size or 0
        max_ec = ec_generation.max_key_size or 100_000
        if min_ec <= 256 <= max_ec:
            supported.append(AutoGenPkiKeyAlgorithm.SECP256R1)

    return tuple(supported)


class KeyGenerator:
    """Utility class for generating private keys."""

    @staticmethod
    def generate_private_key_for_public_key_info(key_info: PublicKeyInfo) -> PrivateKey:
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
        if not domain.issuing_ca:
            exc_msg = 'Domain does not have an issuing CA associated.'
            raise ValueError(exc_msg)
        issuing_ca_cert = cast('CredentialModel', domain.issuing_ca.credential).get_certificate_serializer().as_crypto()
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
            if isinstance(private_key.curve, (ec.SECP192R1, ec.SECP224R1, ec.SECP256R1, ec.SECP256K1)):
                return hashes.SHA256()
            if isinstance(private_key.curve, ec.SECP384R1):
                return hashes.SHA384()
            if isinstance(private_key.curve, ec.SECP521R1):
                return hashes.SHA512()

        err_msg = 'A suitable hash algorithm is not yet specified for the given private key type.'
        raise ValueError(err_msg)


def is_supported_public_key(public_key: Any) -> TypeGuard[PublicKey]:
    """TypeGuard function that narrows down the public key type.

    Args:
        public_key: The loaded public key to check if it is supported.

    Returns:
        True if it is supported, False otherwise.
    """
    return isinstance(public_key, get_args(PublicKey))
