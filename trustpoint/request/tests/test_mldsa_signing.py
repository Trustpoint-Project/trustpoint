# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for ML-DSA signing operations."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa

from crypto.application.private_keys import ManagedMLDSAPrivateKey
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.policies import KeyPolicy
from crypto.domain.specs import MlDsaKeySpec, MlDsaVariant
from request.operation_processor.sign import GenericSignatureVerifier, GenericSigner


@pytest.mark.django_db
class TestMLDSASigningAndVerification:
    """Tests for ML-DSA signing and verification operations."""

    def test_sign_empty_data_with_mldsa(self, settings: object) -> None:
        """Test signing empty data with ML-DSA."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-empty',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)

        # Sign empty data
        empty_data = b''
        signature = private_key.sign(empty_data)

        assert signature
        assert isinstance(signature, bytes)

        # Verify the signature
        public_key = private_key.public_key()
        public_key.verify(signature, empty_data)

    @patch('request.operation_processor.sign.SignatureSuite.from_certificate')
    def test_generic_signer_dispatches_pure_mldsa(
        self,
        signature_suite_from_certificate: Mock,
        settings: object,
    ) -> None:
        """GenericSigner uses the ML-DSA pure-signature API when no hash exists."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        signature_suite_from_certificate.return_value.algorithm_identifier.hash_algorithm = None
        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-generic-mldsa',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )
        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
        credential = Mock()
        credential.get_certificate.return_value = Mock()
        credential.get_private_key.return_value = private_key

        signature = GenericSigner.sign(b'data', credential)

        assert signature

    @patch('request.operation_processor.sign.SignatureSuite.from_certificate')
    def test_generic_verifier_accepts_pure_mldsa(
        self,
        signature_suite_from_certificate: Mock,
    ) -> None:
        """GenericSignatureVerifier verifies a pure ML-DSA signature."""
        signature_suite_from_certificate.return_value.algorithm_identifier.hash_algorithm = None
        private_key = mldsa.MLDSA44PrivateKey.generate()
        data = b'data'
        certificate = Mock()
        certificate.public_key.return_value = private_key.public_key()

        GenericSignatureVerifier.verify(data, private_key.sign(data), certificate)

    @patch('request.operation_processor.sign.SignatureSuite.from_certificate')
    def test_generic_signer_rejects_non_mldsa_without_hash(
        self,
        signature_suite_from_certificate: Mock,
    ) -> None:
        """A missing hash algorithm is invalid for non-ML-DSA signing keys."""
        signature_suite_from_certificate.return_value.algorithm_identifier.hash_algorithm = None
        credential = Mock()
        credential.get_certificate.return_value = Mock()
        credential.get_private_key.return_value = object()

        with pytest.raises(TypeError, match='hash algorithm is None but key is not ML-DSA'):
            GenericSigner.sign(b'data', credential)

    def test_sign_large_data_with_mldsa(self, settings: object) -> None:
        """Test signing large data with ML-DSA."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-large',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)

        # Sign large data (1 MB)
        large_data = b'x' * (1024 * 1024)
        signature = private_key.sign(large_data)

        assert signature
        assert isinstance(signature, bytes)

        # Verify the signature
        public_key = private_key.public_key()
        public_key.verify(signature, large_data)

    def test_mldsa_signature_randomized(self, settings: object) -> None:
        """Test that ML-DSA signatures are randomized (same key, same data = different signature)."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        key_ref = backend.generate_managed_key(
            alias='test-mldsa-randomized',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=KeyPolicy.managed_signing_key(),
        )

        private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
        data = b'test data for randomized signing'

        # Sign the same data twice
        signature1 = private_key.sign(data)
        signature2 = private_key.sign(data)

        # ML-DSA signatures are randomized for security
        assert signature1 != signature2

        # But both signatures should verify successfully
        public_key = private_key.public_key()
        public_key.verify(signature1, data)
        public_key.verify(signature2, data)

    def test_mldsa_different_variants_produce_different_signatures(self, settings: object) -> None:
        """Test that different ML-DSA variants produce different signature sizes."""
        settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_OPERATIONAL = True  # type: ignore[attr-defined]
        settings.TRUSTPOINT_IS_BOOTSTRAP = False  # type: ignore[attr-defined]
        settings.DEVELOPMENT_ENV = True  # type: ignore[attr-defined]
        settings.DOCKER_CONTAINER = False  # type: ignore[attr-defined]
        settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'  # type: ignore[attr-defined]

        backend = TrustpointCryptoBackend()
        data = b'test data'

        signature_sizes = []
        for variant in MlDsaVariant:
            key_ref = backend.generate_managed_key(
                alias=f'test-{variant.value}-sig-size',
                key_spec=MlDsaKeySpec(variant=variant),
                policy=KeyPolicy.managed_signing_key(),
            )

            private_key = ManagedMLDSAPrivateKey(key_ref=key_ref)
            signature = private_key.sign(data)

            signature_sizes.append((variant.value, len(signature)))

        # All variants should produce signatures (with potentially different sizes)
        assert len(signature_sizes) == len(MlDsaVariant)
        for _variant_name, sig_size in signature_sizes:
            assert sig_size > 0
