# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for ML-DSA managed private keys."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa

from crypto.application.private_keys import ManagedMLDSAPrivateKey
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import KeyPolicy
from crypto.domain.specs import MlDsaKeySpec, MlDsaVariant


@pytest.mark.django_db
class TestManagedMLDSAPrivateKey:
    """Tests for the ManagedMLDSAPrivateKey class."""

    def test_create_managed_mldsa_key(self, settings: object) -> None:
        """Test creating a managed ML-DSA private key."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa44',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        assert key_ref.algorithm is KeyAlgorithm.MLDSA

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
        assert private_key.managed_key_ref == key_ref

    def test_mldsa_key_sign(self, settings: object) -> None:
        """Test signing with a managed ML-DSA key."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-sign',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
        data = b'test data to sign'
        signature = private_key.sign(data)

        assert signature
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_mldsa_key_public_key(self, settings: object) -> None:
        """Test retrieving the public key from a managed ML-DSA key."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-pubkey',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
        public_key = private_key.public_key()

        assert isinstance(public_key, mldsa.MLDSA44PublicKey)

    def test_mldsa_key_size_returns_zero(self, settings: object) -> None:
        """Test that ML-DSA key_size returns 0 (not applicable)."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-keysize',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
        assert private_key.key_size == 0

    def test_mldsa_private_bytes_raises_not_implemented(self, settings: object) -> None:
        """Test that exporting ML-DSA private key material raises NotImplementedError."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-export',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)

        with pytest.raises(NotImplementedError, match='cannot be exported'):
            private_key.private_bytes(encoding=None, fmt=None, encryption_algorithm=None)

    def test_mldsa_key_copy_returns_self(self, settings: object) -> None:
        """Test that copying an ML-DSA key returns itself (immutable facade)."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-copy',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
        copied_key = private_key.__copy__()

        assert copied_key is private_key

    def test_mldsa_wrong_algorithm_raises_type_error(self, settings: object) -> None:
        """Test that creating ManagedMLDSAPrivateKey with non-ML-DSA key raises TypeError."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        from crypto.domain.specs import RsaKeySpec

        backend = TrustpointCryptoBackend()
        # Generate an RSA key
        rsa_key_ref = backend.generate_managed_key(
            alias='test-rsa-wrong',
            key_spec=RsaKeySpec(key_size=2048),
            policy=KeyPolicy.managed_signing_key(),
        )

        assert rsa_key_ref.algorithm is KeyAlgorithm.RSA

        # Try to create ManagedMLDSAPrivateKey with RSA key
        with pytest.raises(TypeError, match='is not an ML-DSA key'):
            ManagedMLDSAPrivateKey(key_ref=rsa_key_ref)

    def test_mldsa_all_variants(self, settings: object) -> None:
        """Test that all ML-DSA variants work with ManagedMLDSAPrivateKey."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()

        variants = [
            (MlDsaVariant.MLDSA44, mldsa.MLDSA44PublicKey),
            (MlDsaVariant.MLDSA65, mldsa.MLDSA65PublicKey),
            (MlDsaVariant.MLDSA87, mldsa.MLDSA87PublicKey),
        ]

        for variant, expected_pub_key_type in variants:
            key_ref = backend.generate_managed_key(
                alias=f'test-{variant.value}',
                key_spec=MlDsaKeySpec(variant=variant),
                policy=KeyPolicy.managed_signing_key(),
            )

            private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
            public_key = private_key.public_key()

            assert isinstance(public_key, expected_pub_key_type)

            # Test signing with each variant
            signature = private_key.sign(b'test data')
            assert signature
