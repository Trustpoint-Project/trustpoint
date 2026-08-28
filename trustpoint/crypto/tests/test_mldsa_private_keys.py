# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for ML-DSA managed private keys."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa, rsa

from crypto.application.private_keys import (
    ManagedMLDSA44PrivateKey,
    ManagedMLDSAPrivateKey,
    managed_private_key_for_ref,
)
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import KeyPolicy
from crypto.domain.specs import MlDsaKeySpec, MlDsaVariant, RsaKeySpec, SignRequest


@pytest.mark.django_db
class TestManagedMLDSAPrivateKey:
    """Tests for the ManagedMLDSAPrivateKey class."""

    def test_sign_forwards_bytes_and_pure_request(self) -> None:
        """Signing converts buffer inputs and sends the pure ML-DSA request."""
        backend = Mock()
        backend.sign.return_value = b'signature'
        key_ref = Mock()
        key_ref.algorithm = KeyAlgorithm.MLDSA
        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref, crypto_backend=backend)

        assert private_key.sign(memoryview(b'data')) == b'signature'
        backend.sign.assert_called_once_with(
            key=key_ref,
            data=b'data',
            request=SignRequest.mldsa_pure(),
        )

    def test_public_key_is_loaded_only_once(self) -> None:
        """Repeated public-key access uses the facade's cached key."""
        backend = Mock()
        public_key = mldsa.MLDSA44PrivateKey.generate().public_key()
        backend.get_public_key.return_value = public_key
        key_ref = Mock()
        key_ref.algorithm = KeyAlgorithm.MLDSA
        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref, crypto_backend=backend)

        assert private_key.public_key() is public_key
        assert private_key.public_key() is public_key
        backend.get_public_key.assert_called_once_with(key_ref)

    def test_public_key_rejects_non_mldsa_key(self) -> None:
        """A managed ML-DSA reference cannot resolve to another key type."""
        backend = Mock()
        backend.get_public_key.return_value = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        ).public_key()
        key_ref = Mock()
        key_ref.algorithm = KeyAlgorithm.MLDSA
        key_ref.alias = 'wrong-public-key'
        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref, crypto_backend=backend)

        with pytest.raises(TypeError, match='non-ML-DSA public key'):
            private_key.public_key()

    def test_concrete_facade_rejects_mismatched_variant(self) -> None:
        """A concrete ML-DSA facade enforces its parameter-set type."""
        public_key = mldsa.MLDSA65PrivateKey.generate().public_key()
        key_ref = Mock()
        key_ref.algorithm = KeyAlgorithm.MLDSA
        key_ref.alias = 'mismatched-variant'
        private_key = ManagedMLDSA44PrivateKey(
            key_ref=key_ref,
            crypto_backend=Mock(),
            public_key=public_key,
        )

        with pytest.raises(TypeError, match='non-ML-DSA-44 public key'):
            private_key.public_key()

    def test_deepcopy_returns_self(self) -> None:
        """Deep-copying the immutable facade preserves object identity."""
        key_ref = Mock()
        key_ref.algorithm = KeyAlgorithm.MLDSA
        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref, crypto_backend=Mock())

        assert private_key.__deepcopy__({}) is private_key

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

        with pytest.raises(NotImplementedError, match='cannot be exported'):
            private_key.private_bytes_raw()

    def test_mldsa_sign_rejects_non_empty_context(self, settings: object) -> None:
        """Non-empty ML-DSA signing contexts are rejected explicitly."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-context',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )
        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)

        with pytest.raises(NotImplementedError, match='non-empty signing contexts'):
            private_key.sign(b'data', context=b'context')

    def test_mldsa_sign_mu_raises_not_implemented(self, settings: object) -> None:
        """Pre-hashed ML-DSA signing is not exposed by the managed facade."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-sign-mu',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )
        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)

        with pytest.raises(NotImplementedError, match='do not expose sign_mu'):
            private_key.sign_mu(b'mu')

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

    def test_factory_returns_variant_specific_mldsa_facade(self, settings: object) -> None:
        """The managed-key factory returns the matching cryptography facade."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-factory',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA65),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = managed_private_key_for_ref(key_ref)

        assert isinstance(private_key, mldsa.MLDSA65PrivateKey)
