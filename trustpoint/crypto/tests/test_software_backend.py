# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the software backend including ML-DSA support."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa

from crypto.adapters.software.backend import SoftwareBackend
from crypto.adapters.software.config import SoftwareProviderProfile
from crypto.domain.algorithms import EllipticCurveName, KeyAlgorithm
from crypto.domain.errors import MechanismUnsupportedError, UnsupportedKeySpecError
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.domain.refs import ManagedKeyVerificationStatus
from crypto.domain.specs import EcKeySpec, MlDsaKeySpec, MlDsaVariant, RsaKeySpec, SignRequest


@pytest.fixture
def software_profile() -> SoftwareProviderProfile:
    """Create a software provider profile with test encryption material."""
    return SoftwareProviderProfile(
        name='test-software-backend',
        encryption_source='dev_plaintext',
    )


@pytest.fixture
def software_backend(software_profile: SoftwareProviderProfile) -> SoftwareBackend:
    """Create a software backend instance."""
    return SoftwareBackend(profile=software_profile)


class TestMLDSAKeyGeneration:
    """Tests for ML-DSA key generation in the software backend."""

    def test_generate_mldsa44_key(self, software_backend: SoftwareBackend) -> None:
        """Test generating an ML-DSA-44 key pair."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-mldsa44',
            key_spec=key_spec,
            policy=policy,
        )

        assert binding.algorithm is KeyAlgorithm.MLDSA
        assert binding.provider_label == 'test-mldsa44'
        assert binding.encrypted_private_key_pkcs8_der
        assert binding.public_key_fingerprint_sha256
        assert binding.signing_execution_mode == SigningExecutionMode.COMPLETE_BACKEND

        # Verify the public key can be loaded and is the correct type
        public_key = software_backend.get_public_key(binding)
        assert isinstance(public_key, mldsa.MLDSA44PublicKey)

    def test_generate_mldsa65_key(self, software_backend: SoftwareBackend) -> None:
        """Test generating an ML-DSA-65 key pair."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA65)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-mldsa65',
            key_spec=key_spec,
            policy=policy,
        )

        assert binding.algorithm is KeyAlgorithm.MLDSA
        public_key = software_backend.get_public_key(binding)
        assert isinstance(public_key, mldsa.MLDSA65PublicKey)

    def test_generate_mldsa87_key(self, software_backend: SoftwareBackend) -> None:
        """Test generating an ML-DSA-87 key pair."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA87)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-mldsa87',
            key_spec=key_spec,
            policy=policy,
        )

        assert binding.algorithm is KeyAlgorithm.MLDSA
        public_key = software_backend.get_public_key(binding)
        assert isinstance(public_key, mldsa.MLDSA87PublicKey)

    def test_mldsa_key_encrypted_properly(self, software_backend: SoftwareBackend) -> None:
        """Test that ML-DSA keys are properly encrypted in their PKCS#8 DER encoding."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-encrypted',
            key_spec=key_spec,
            policy=policy,
        )

        # The key should be encrypted and decryptable
        assert binding.encrypted_private_key_pkcs8_der
        assert binding.encryption_metadata == {'format': 'pkcs8-der', 'encryption': 'best_available'}

        # Should be able to load the key successfully
        public_key = software_backend.get_public_key(binding)
        assert isinstance(public_key, mldsa.MLDSA44PublicKey)


class TestMLDSASigning:
    """Tests for ML-DSA signing operations in the software backend."""

    def test_sign_with_mldsa44(self, software_backend: SoftwareBackend) -> None:
        """Test signing data with an ML-DSA-44 key."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-sign-mldsa44',
            key_spec=key_spec,
            policy=policy,
        )

        data = b'test message to sign'
        request = SignRequest.mldsa_pure()

        signature = software_backend.sign(
            key=binding,
            data=data,
            request=request,
        )

        assert signature
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_sign_with_mldsa65(self, software_backend: SoftwareBackend) -> None:
        """Test signing data with an ML-DSA-65 key."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA65)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-sign-mldsa65',
            key_spec=key_spec,
            policy=policy,
        )

        data = b'test message to sign'
        request = SignRequest.mldsa_pure()

        signature = software_backend.sign(
            key=binding,
            data=data,
            request=request,
        )

        assert signature
        assert isinstance(signature, bytes)

    def test_sign_with_mldsa87(self, software_backend: SoftwareBackend) -> None:
        """Test signing data with an ML-DSA-87 key."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA87)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-sign-mldsa87',
            key_spec=key_spec,
            policy=policy,
        )

        data = b'test message to sign'
        request = SignRequest.mldsa_pure()

        signature = software_backend.sign(
            key=binding,
            data=data,
            request=request,
        )

        assert signature
        assert isinstance(signature, bytes)

    def test_mldsa_signature_verification(self, software_backend: SoftwareBackend) -> None:
        """Test that ML-DSA signatures can be verified with the public key."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-verify',
            key_spec=key_spec,
            policy=policy,
        )

        data = b'test message to sign and verify'
        request = SignRequest.mldsa_pure()

        signature = software_backend.sign(
            key=binding,
            data=data,
            request=request,
        )

        # Get the public key and verify the signature
        public_key = software_backend.get_public_key(binding)
        assert isinstance(public_key, mldsa.MLDSA44PublicKey)

        # ML-DSA verification should not raise an exception for valid signatures
        public_key.verify(signature, data)

    def test_mldsa_signature_invalid_verification_fails(self, software_backend: SoftwareBackend) -> None:
        """Test that ML-DSA signatures fail verification with tampered data."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-invalid-verify',
            key_spec=key_spec,
            policy=policy,
        )

        data = b'original message'
        request = SignRequest.mldsa_pure()

        signature = software_backend.sign(
            key=binding,
            data=data,
            request=request,
        )

        # Get the public key and try to verify with tampered data
        public_key = software_backend.get_public_key(binding)
        tampered_data = b'tampered message'

        # Verification should fail (raise InvalidSignature exception)
        with pytest.raises(Exception):  # cryptography raises InvalidSignature
            public_key.verify(signature, tampered_data)

    def test_mldsa_different_keys_produce_different_signatures(
        self,
        software_backend: SoftwareBackend,
    ) -> None:
        """Test that different ML-DSA keys produce different signatures for the same data."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding1 = software_backend.generate_managed_key(
            alias='test-key1',
            key_spec=key_spec,
            policy=policy,
        )

        binding2 = software_backend.generate_managed_key(
            alias='test-key2',
            key_spec=key_spec,
            policy=policy,
        )

        data = b'same message'
        request = SignRequest.mldsa_pure()

        signature1 = software_backend.sign(key=binding1, data=data, request=request)
        signature2 = software_backend.sign(key=binding2, data=data, request=request)

        # Different keys should produce different signatures
        assert signature1 != signature2

    def test_mldsa_reject_wrong_signature_algorithm(self, software_backend: SoftwareBackend) -> None:
        """Test that using non-ML-DSA signature algorithm with ML-DSA key fails."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-wrong-algo',
            key_spec=key_spec,
            policy=policy,
        )

        data = b'test message'
        # Try to use ECDSA algorithm with ML-DSA key
        request = SignRequest.ecdsa_sha256()

        with pytest.raises(MechanismUnsupportedError, match='Unsupported ML-DSA signature algorithm'):
            software_backend.sign(key=binding, data=data, request=request)


class TestMLDSAKeyVerification:
    """Tests for ML-DSA key verification in the software backend."""

    def test_verify_mldsa_key_present(self, software_backend: SoftwareBackend) -> None:
        """Test that ML-DSA key verification reports present keys correctly."""
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)
        policy = KeyPolicy.managed_signing_key()

        binding = software_backend.generate_managed_key(
            alias='test-verify-present',
            key_spec=key_spec,
            policy=policy,
        )

        verification = software_backend.verify_managed_key(binding)

        assert verification.status is ManagedKeyVerificationStatus.PRESENT
        assert verification.resolved_public_key_fingerprint_sha256
        assert verification.resolved_public_key_fingerprint_sha256 == binding.public_key_fingerprint_sha256


class TestMLDSACapabilities:
    """Tests for ML-DSA capability reporting in the software backend."""

    def test_software_backend_reports_mldsa_capability(self, software_backend: SoftwareBackend) -> None:
        """Test that software backend reports ML-DSA support in its capabilities."""
        capabilities = software_backend.probe_capabilities()

        assert 'mldsa' in capabilities.supported_key_algorithms
        assert 'mldsa' in capabilities.supported_signature_algorithms

    def test_software_backend_supports_all_mldsa_variants(self, software_backend: SoftwareBackend) -> None:
        """Test that all ML-DSA variants can be generated and used."""
        policy = KeyPolicy.managed_signing_key()

        for variant in MlDsaVariant:
            key_spec = MlDsaKeySpec(variant=variant)

            binding = software_backend.generate_managed_key(
                alias=f'test-variant-{variant.value}',
                key_spec=key_spec,
                policy=policy,
            )

            # Each variant should work
            public_key = software_backend.get_public_key(binding)
            assert public_key is not None

            # Each variant should be able to sign
            signature = software_backend.sign(
                key=binding,
                data=b'test',
                request=SignRequest.mldsa_pure(),
            )
            assert signature


class TestSoftwareBackendMixedAlgorithms:
    """Tests for the software backend handling multiple algorithm types."""

    def test_rsa_ec_and_mldsa_keys_coexist(self, software_backend: SoftwareBackend) -> None:
        """Test that RSA, EC, and ML-DSA keys can all be generated and used together."""
        policy = KeyPolicy.managed_signing_key()

        # Generate one key of each type
        rsa_binding = software_backend.generate_managed_key(
            alias='test-rsa',
            key_spec=RsaKeySpec(key_size=2048),
            policy=policy,
        )

        ec_binding = software_backend.generate_managed_key(
            alias='test-ec',
            key_spec=EcKeySpec(curve=EllipticCurveName.SECP256R1),
            policy=policy,
        )

        mldsa_binding = software_backend.generate_managed_key(
            alias='test-mldsa',
            key_spec=MlDsaKeySpec(variant=MlDsaVariant.MLDSA44),
            policy=policy,
        )

        # Verify each key type
        rsa_public = software_backend.get_public_key(rsa_binding)
        ec_public = software_backend.get_public_key(ec_binding)
        mldsa_public = software_backend.get_public_key(mldsa_binding)

        assert isinstance(rsa_public, rsa.RSAPublicKey)
        assert isinstance(ec_public, ec.EllipticCurvePublicKey)
        assert isinstance(mldsa_public, mldsa.MLDSA44PublicKey)

        # Sign with each key type
        rsa_sig = software_backend.sign(
            key=rsa_binding,
            data=b'test',
            request=SignRequest.rsa_pkcs1v15_sha256(),
        )
        ec_sig = software_backend.sign(
            key=ec_binding,
            data=b'test',
            request=SignRequest.ecdsa_sha256(),
        )
        mldsa_sig = software_backend.sign(
            key=mldsa_binding,
            data=b'test',
            request=SignRequest.mldsa_pure(),
        )

        assert rsa_sig
        assert ec_sig
        assert mldsa_sig

    def test_mldsa_key_fingerprints_are_unique(self, software_backend: SoftwareBackend) -> None:
        """Test that different ML-DSA keys have unique fingerprints."""
        policy = KeyPolicy.managed_signing_key()
        key_spec = MlDsaKeySpec(variant=MlDsaVariant.MLDSA44)

        binding1 = software_backend.generate_managed_key(
            alias='test-fingerprint1',
            key_spec=key_spec,
            policy=policy,
        )

        binding2 = software_backend.generate_managed_key(
            alias='test-fingerprint2',
            key_spec=key_spec,
            policy=policy,
        )

        # Each key should have a unique fingerprint
        assert binding1.public_key_fingerprint_sha256 != binding2.public_key_fingerprint_sha256
