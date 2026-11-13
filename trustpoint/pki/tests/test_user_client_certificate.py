# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for user TLS client-certificate issuance."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase
from django.utils import timezone
from trustpoint_core.crypto_types import PrivateKey

from pki.models import CertificateProfileModel
from pki.services.management_issuance import sign_certificate_builder, sign_certificate_request
from pki.services.user_client_certificate import create_user_client_certificate
from users.models import TrustpointUser

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:
    mldsa = None  # type: ignore[assignment]


class UserClientCertificateCreationTest(SimpleTestCase):
    """Verify the identity binding and TLS-client constraints of generated certificates."""

    @staticmethod
    def create_issuer(
        *,
        valid_for: timedelta = timedelta(days=30),
        key: PrivateKey | None = None,
    ) -> tuple[x509.Certificate, PrivateKey]:
        key = key or ec.generate_private_key(ec.SECP256R1())
        now = timezone.now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Management Issuing CA')])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + valid_for)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return certificate, key

    @staticmethod
    def create_mldsa_issuer() -> tuple[x509.Certificate, object]:
        """Return an ML-DSA issuer certificate and key."""
        assert mldsa is not None
        key = mldsa.MLDSA65PrivateKey.generate()
        now = timezone.now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ML-DSA Management CA')])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, None)
        )
        return certificate, key

    @staticmethod
    def patch_dependencies(
        issuer_certificate: x509.Certificate,
        issuer_key: PrivateKey,
        *,
        user_id: int = 42,
    ) -> tuple[Mock, Mock]:
        user = SimpleNamespace(
            pk=user_id,
            username='alice',
            account_type=TrustpointUser.AccountType.HUMAN,
            is_active=True,
        )
        issuing_ca = Mock()
        issuing_ca.user_authentication_config.certificate_profile = None
        issuing_ca.credential = Mock()
        issuing_ca.credential.get_private_key.return_value = issuer_key
        issuing_ca.credential.get_certificate_chain.return_value = []
        issuing_ca.get_certificate.return_value = issuer_certificate
        return user, issuing_ca

    def test_generated_certificate_binds_user_and_identifier(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer()
        user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)

        with (
            patch(
                'pki.services.user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.services.management_ca.ManagementCAService.get_issuing_ca',
                return_value=issuing_ca,
            ),
        ):
            certificate, private_key = create_user_client_certificate(user.pk, 'laptop')

        common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert common_name == 'trustpoint-client-certificate'
        assert certificate.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value == 'alice'
        assert certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value == str(user.pk)
        assert certificate.subject.get_attributes_for_oid(NameOID.UNSTRUCTURED_NAME)[0].value == 'laptop'
        assert certificate.public_key().public_numbers() == private_key.public_key().public_numbers()
        certificate.verify_directly_issued_by(issuer_certificate)

    def test_client_key_matches_management_ca_algorithm_and_parameters(self) -> None:
        for issuer_key in [
            rsa.generate_private_key(public_exponent=65537, key_size=3072),
            ec.generate_private_key(ec.SECP384R1()),
        ]:
            with self.subTest(key_type=type(issuer_key)):
                issuer_certificate, _key = self.create_issuer(key=issuer_key)
                user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)
                with patch('pki.services.user_client_certificate.TrustpointUser.objects.get', return_value=user):
                    certificate, key = create_user_client_certificate(user.pk, 'matching-key', issuing_ca=issuing_ca)

                if isinstance(issuer_key, rsa.RSAPrivateKey):
                    assert isinstance(key, rsa.RSAPrivateKey)
                    assert key.key_size == issuer_key.key_size
                else:
                    assert isinstance(key, ec.EllipticCurvePrivateKey)
                    assert key.curve.name == issuer_key.curve.name
                assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
                assert certificate.signature_algorithm_oid == issuer_certificate.signature_algorithm_oid
                certificate.verify_directly_issued_by(issuer_certificate)

    @pytest.mark.skipif(mldsa is None, reason='cryptography ML-DSA classes unavailable')
    def test_generated_certificate_supports_mldsa_management_ca(self) -> None:
        """ML-DSA management CAs sign client certificates without an explicit hash algorithm."""
        issuer_certificate, issuer_key = self.create_mldsa_issuer()
        user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)

        with patch(
            'pki.services.user_client_certificate.TrustpointUser.objects.get',
            return_value=user,
        ):
            certificate, private_key = create_user_client_certificate(
                user.pk,
                'mldsa-client',
                issuing_ca=issuing_ca,
            )

        certificate.verify_directly_issued_by(issuer_certificate)
        assert certificate.signature_hash_algorithm is None
        assert isinstance(private_key, mldsa.MLDSA65PrivateKey)
        assert isinstance(certificate.public_key(), mldsa.MLDSA65PublicKey)

    def test_generated_certificate_has_required_client_auth_extensions(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer()
        user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)

        with (
            patch(
                'pki.services.user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.services.management_ca.ManagementCAService.get_issuing_ca',
                return_value=issuing_ca,
            ),
        ):
            certificate, _private_key = create_user_client_certificate(user.pk, 'workstation')

        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert not basic_constraints.ca
        assert key_usage.digital_signature
        assert not key_usage.key_cert_sign
        assert ExtendedKeyUsageOID.CLIENT_AUTH in extended_usage

    def test_requested_validity_is_capped_at_issuer_expiry(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer(valid_for=timedelta(days=2))
        user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)

        with (
            patch(
                'pki.services.user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.services.management_ca.ManagementCAService.get_issuing_ca',
                return_value=issuing_ca,
            ),
        ):
            certificate, _private_key = create_user_client_certificate(user.pk, 'short-lived', validity_days=365)

        assert certificate.not_valid_after_utc == issuer_certificate.not_valid_after_utc

    def test_shared_csr_signer_caps_validity_and_preserves_request(self) -> None:
        """TLS and owner requests use the same CA limits and signing path as user requests."""
        issuer_certificate, issuer_key = self.create_issuer(valid_for=timedelta(days=2))
        _user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'shared-client')])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(key, hashes.SHA256())
        )
        profile = CertificateProfileModel(profile_json={'validity': {'days': 365}})

        certificate, chain = sign_certificate_request(csr, profile, issuing_ca)

        certificate.verify_directly_issued_by(issuer_certificate)
        assert certificate.subject == subject
        assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
        assert certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage) == csr.extensions[0]
        assert certificate.not_valid_before_utc == issuer_certificate.not_valid_before_utc
        assert certificate.not_valid_after_utc == issuer_certificate.not_valid_after_utc
        assert chain == [issuer_certificate]

    def test_shared_signer_rejects_expired_ca(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer(valid_for=timedelta(seconds=0))
        _user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)

        with pytest.raises(ValidationError, match='not currently valid'):
            sign_certificate_builder(x509.CertificateBuilder(), issuing_ca)

    def test_shared_signer_rejects_expired_or_future_leaf(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer()
        _user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)
        now = timezone.now()
        for start, end in [(now - timedelta(days=1), now), (now + timedelta(days=1), now + timedelta(days=2))]:
            builder = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([]))
                .public_key(issuer_key.public_key())
                .not_valid_before(start)
                .not_valid_after(end)
            )
            with pytest.raises(ValidationError, match='currently valid certificate'):
                sign_certificate_builder(builder, issuing_ca)

    def test_non_positive_validity_is_rejected(self) -> None:
        for validity_days in [0, -1]:
            with self.subTest(validity_days=validity_days):
                with pytest.raises(ValidationError, match='positive number of days'):
                    create_user_client_certificate(1, 'device', validity_days=validity_days)

    def test_only_active_human_users_can_receive_client_certificates(self) -> None:
        """Issuance must query for both the HUMAN account type and active state."""
        with patch(
            'pki.services.user_client_certificate.TrustpointUser.objects.get',
            side_effect=TrustpointUser.DoesNotExist,
        ) as get_user:
            with pytest.raises(ValidationError, match='No active human user exists'):
                create_user_client_certificate(42, 'device')

        get_user.assert_called_once_with(
            pk=42,
            account_type=TrustpointUser.AccountType.HUMAN,
            is_active=True,
        )

    def test_missing_management_issuing_ca_is_rejected(self) -> None:
        user = SimpleNamespace(
            pk=42,
            username='alice',
            account_type=TrustpointUser.AccountType.HUMAN,
            is_active=True,
        )
        with (
            patch(
                'pki.services.user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.services.management_ca.ManagementCAService.get_issuing_ca',
                return_value=None,
            ),
        ):
            with pytest.raises(ValidationError, match='No management CA is configured'):
                create_user_client_certificate(user.pk, 'device')

    def test_issuing_ca_missing_required_extensions_is_rejected(self) -> None:
        """A CA record without BasicConstraints/KeyUsage must never be used for client issuance."""
        issuer_certificate, issuer_key = self.create_issuer()
        incomplete_certificate = (
            x509.CertificateBuilder()
            .subject_name(issuer_certificate.subject)
            .issuer_name(issuer_certificate.subject)
            .public_key(issuer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(issuer_certificate.not_valid_before_utc)
            .not_valid_after(issuer_certificate.not_valid_after_utc)
            .sign(issuer_key, hashes.SHA256())
        )
        user, issuing_ca = self.patch_dependencies(incomplete_certificate, issuer_key)

        with (
            patch(
                'pki.services.user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.services.management_ca.ManagementCAService.get_issuing_ca',
                return_value=issuing_ca,
            ),
        ):
            with pytest.raises(ValidationError, match='missing required CA extensions'):
                create_user_client_certificate(user.pk, 'device')

    def test_ca_without_signing_permission_is_rejected(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer()
        invalid_certificate = (
            x509.CertificateBuilder()
            .subject_name(issuer_certificate.subject)
            .issuer_name(issuer_certificate.subject)
            .public_key(issuer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(issuer_certificate.not_valid_before_utc)
            .not_valid_after(issuer_certificate.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(issuer_key, hashes.SHA256())
        )
        user, issuing_ca = self.patch_dependencies(invalid_certificate, issuer_key)

        with (
            patch(
                'pki.services.user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.services.management_ca.ManagementCAService.get_issuing_ca',
                return_value=issuing_ca,
            ),
        ):
            with pytest.raises(ValidationError, match='does not permit certificate signing'):
                create_user_client_certificate(user.pk, 'device')
