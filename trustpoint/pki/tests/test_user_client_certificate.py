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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.core.management import CommandError
from django.test import SimpleTestCase
from django.utils import timezone

from pki.management.commands.create_user_client_certificate import create_user_client_certificate
from users.models import TrustpointUser


class UserClientCertificateCreationTest(SimpleTestCase):
    """Verify the identity binding and TLS-client constraints of generated certificates."""

    @staticmethod
    def create_issuer(
        *, valid_for: timedelta = timedelta(days=30),
    ) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        key = ec.generate_private_key(ec.SECP256R1())
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
    def patch_dependencies(
        issuer_certificate: x509.Certificate,
        issuer_key: ec.EllipticCurvePrivateKey,
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
        issuing_ca.credential = Mock()
        issuing_ca.credential.get_private_key.return_value = issuer_key
        issuing_ca.get_certificate.return_value = issuer_certificate
        return user, issuing_ca

    def test_generated_certificate_binds_user_and_identifier(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer()
        user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)

        with (
            patch(
                'pki.management.commands.create_user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.management.commands.create_user_client_certificate.CaModel.objects.select_related',
            ) as select_related,
        ):
            select_related.return_value.filter.return_value.first.return_value = issuing_ca
            certificate, private_key = create_user_client_certificate(user.pk, 'laptop')

        common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert common_name == 'trustpoint-client-certificate'
        assert certificate.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value == 'alice'
        assert certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value == str(user.pk)
        assert certificate.subject.get_attributes_for_oid(NameOID.UNSTRUCTURED_NAME)[0].value == 'laptop'
        assert certificate.public_key().public_numbers() == private_key.public_key().public_numbers()
        certificate.verify_directly_issued_by(issuer_certificate)

    def test_generated_certificate_has_required_client_auth_extensions(self) -> None:
        issuer_certificate, issuer_key = self.create_issuer()
        user, issuing_ca = self.patch_dependencies(issuer_certificate, issuer_key)

        with (
            patch(
                'pki.management.commands.create_user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.management.commands.create_user_client_certificate.CaModel.objects.select_related',
            ) as select_related,
        ):
            select_related.return_value.filter.return_value.first.return_value = issuing_ca
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
                'pki.management.commands.create_user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.management.commands.create_user_client_certificate.CaModel.objects.select_related',
            ) as select_related,
        ):
            select_related.return_value.filter.return_value.first.return_value = issuing_ca
            certificate, _private_key = create_user_client_certificate(user.pk, 'short-lived', validity_days=365)

        assert certificate.not_valid_after_utc == issuer_certificate.not_valid_after_utc

    @pytest.mark.parametrize('validity_days', [0, -1])
    def test_non_positive_validity_is_rejected(self, validity_days: int) -> None:
        with pytest.raises(CommandError, match='positive number of days'):
            create_user_client_certificate(1, 'device', validity_days=validity_days)

    def test_missing_management_issuing_ca_is_rejected(self) -> None:
        user = SimpleNamespace(
            pk=42,
            username='alice',
            account_type=TrustpointUser.AccountType.HUMAN,
            is_active=True,
        )
        with (
            patch(
                'pki.management.commands.create_user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.management.commands.create_user_client_certificate.CaModel.objects.select_related',
            ) as select_related,
        ):
            select_related.return_value.filter.return_value.first.return_value = None
            with pytest.raises(CommandError, match='Management Issuing CA is missing'):
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
                'pki.management.commands.create_user_client_certificate.TrustpointUser.objects.get',
                return_value=user,
            ),
            patch(
                'pki.management.commands.create_user_client_certificate.CaModel.objects.select_related',
            ) as select_related,
        ):
            select_related.return_value.filter.return_value.first.return_value = issuing_ca
            with pytest.raises(CommandError, match='does not permit certificate signing'):
                create_user_client_certificate(user.pk, 'device')
