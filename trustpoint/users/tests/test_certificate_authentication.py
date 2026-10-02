# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for TLS client-certificate authentication."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.core.exceptions import ValidationError
from django.test import RequestFactory, TestCase, override_settings

from users.authentication import ClientCertificateBackend
from users.models import TrustpointUser


@override_settings(CLIENT_CERTIFICATE_TRUSTED_PROXY_IPS=['127.0.0.1'])
class ClientCertificateBackendProxyTest(TestCase):
    """Verify that certificate proof is trusted only from the configured TLS proxy."""

    def setUp(self) -> None:
        self.backend = ClientCertificateBackend()
        self.factory = RequestFactory()

    def test_authenticate_ignores_password_attempts(self) -> None:
        """The certificate backend must not consume ordinary username/password logins."""
        request = self.factory.post('/users/login/')

        assert self.backend.authenticate(request, username='alice', password='secret') is None

    def test_validate_proxy_accepts_expected_nginx_headers(self) -> None:
        """Accept a certificate forwarded by the trusted HTTPS proxy."""
        request = self.factory.get(
            '/',
            REMOTE_ADDR='127.0.0.1',
            HTTP_X_FORWARDED_PROTO='https',
            HTTP_X_SSL_CLIENT_VERIFY='SUCCESS',
        )

        self.backend._validate_proxy(request)  # noqa: SLF001

    def test_validate_proxy_rejects_invalid_proxy_proof(self) -> None:
        """Reject spoofed, insecure, or unverified proxy metadata."""
        invalid_proofs = [
            (
                {
                    'REMOTE_ADDR': '192.0.2.1',
                    'HTTP_X_FORWARDED_PROTO': 'https',
                    'HTTP_X_SSL_CLIENT_VERIFY': 'SUCCESS',
                },
                'trusted TLS proxy',
            ),
            (
                {
                    'REMOTE_ADDR': '127.0.0.1',
                    'HTTP_X_FORWARDED_PROTO': 'http',
                    'HTTP_X_SSL_CLIENT_VERIFY': 'SUCCESS',
                },
                'requires HTTPS',
            ),
            (
                {
                    'REMOTE_ADDR': '127.0.0.1',
                    'HTTP_X_FORWARDED_PROTO': 'https',
                    'HTTP_X_SSL_CLIENT_VERIFY': 'NONE',
                },
                'did not confirm',
            ),
        ]
        for headers, message in invalid_proofs:
            with self.subTest(headers=headers):
                request = self.factory.get('/', **headers)

                with pytest.raises(ValidationError, match=message):
                    self.backend._validate_proxy(request)  # noqa: SLF001


class ClientCertificateSubjectTest(TestCase):
    """Resolve users from the stable numeric ID embedded in the certificate subject."""

    def setUp(self) -> None:
        self.user = TrustpointUser.objects.create_user(username='certificate-user')

    @staticmethod
    def certificate_with_user_ids(*values: str) -> Mock:
        certificate = Mock()
        certificate.subject = x509.Name([
            x509.NameAttribute(NameOID.SERIAL_NUMBER, value)
            for value in values
        ])
        return certificate

    def test_subject_resolves_existing_user_by_primary_key(self) -> None:
        certificate = self.certificate_with_user_ids(str(self.user.pk))

        assert ClientCertificateBackend._get_subject_user(certificate) == self.user  # noqa: SLF001

    def test_subject_rejects_invalid_user_ids(self) -> None:
        for value in ['', '0', '-1', 'abc', str(2**63)]:
            with self.subTest(value=value):
                certificate = self.certificate_with_user_ids(value)

                with pytest.raises(ValidationError, match='invalid user ID'):
                    ClientCertificateBackend._get_subject_user(certificate)  # noqa: SLF001

    def test_subject_requires_exactly_one_user_id(self) -> None:
        certificate = self.certificate_with_user_ids(str(self.user.pk), str(self.user.pk))

        with pytest.raises(ValidationError, match='exactly one user ID'):
            ClientCertificateBackend._get_subject_user(certificate)  # noqa: SLF001

    def test_subject_rejects_unknown_user(self) -> None:
        certificate = self.certificate_with_user_ids(str(self.user.pk + 1000))

        with pytest.raises(ValidationError, match='No user exists'):
            ClientCertificateBackend._get_subject_user(certificate)  # noqa: SLF001


@override_settings(CLIENT_CERTIFICATE_TRUSTED_PROXY_IPS=['127.0.0.1'])
class ClientCertificateBackendAuthenticationTest(TestCase):
    """Exercise association checks around the cryptographic validation pipeline."""

    def setUp(self) -> None:
        self.backend = ClientCertificateBackend()
        self.request = RequestFactory().get(
            '/',
            REMOTE_ADDR='127.0.0.1',
            HTTP_X_FORWARDED_PROTO='https',
            HTTP_X_SSL_CLIENT_VERIFY='SUCCESS',
        )
        self.user = TrustpointUser.objects.create_user(username='certificate-user')
        self.certificate = Mock()
        self.certificate.fingerprint.return_value = bytes.fromhex('ABCD')
        self.association = Mock(is_active=True)
        self.association.certificate = Mock()

    def authenticate_with_association(self, association: Mock | None) -> TrustpointUser | None:
        """Run the backend while isolating the cryptographic checks covered separately."""
        with (
            patch(
                'users.authentication.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                return_value=(self.certificate, []),
            ),
            patch.object(self.backend, '_get_subject_user', return_value=self.user),
            patch('users.authentication.UserClientCertificate.objects.select_related') as select_related,
            patch.object(self.backend, '_validate_registered_fingerprint') as fingerprint_check,
            patch.object(self.backend, '_validate_status') as status_check,
            patch.object(self.backend, '_validate_client_usage') as usage_check,
            patch.object(self.backend, '_validate_issuer') as issuer_check,
        ):
            select_related.return_value.filter.return_value.first.return_value = association
            result = self.backend.authenticate(self.request, certificate_login=True)
            if association is not None and association.is_active and self.user.is_active:
                fingerprint_check.assert_called_once_with(self.certificate, association.certificate)
                status_check.assert_called_once_with(association.certificate)
                usage_check.assert_called_once_with(self.certificate)
                issuer_check.assert_called_once_with(self.certificate)
            return result

    def test_authenticate_returns_user_after_all_checks(self) -> None:
        assert self.authenticate_with_association(self.association) == self.user

    def test_authenticate_rejects_unregistered_certificate(self) -> None:
        with pytest.raises(ValidationError, match='not configured'):
            self.authenticate_with_association(None)

    def test_authenticate_rejects_disabled_certificate(self) -> None:
        self.association.is_active = False

        with pytest.raises(ValidationError, match='disabled'):
            self.authenticate_with_association(self.association)

    def test_authenticate_rejects_disabled_user(self) -> None:
        self.user.is_active = False

        with pytest.raises(ValidationError, match='account associated .* disabled'):
            self.authenticate_with_association(self.association)

    def test_authenticate_rejects_service_account(self) -> None:
        self.user.account_type = TrustpointUser.AccountType.SERVICE

        with pytest.raises(ValidationError, match='Service accounts'):
            self.authenticate_with_association(self.association)


class ClientCertificateUsageTest(TestCase):
    """Validate the TLS-client extensions required by certificate authentication."""

    @staticmethod
    def certificate_with_usage(*, ca: bool, digital_signature: bool, client_auth: bool) -> Mock:
        certificate = Mock()
        values = {
            x509.BasicConstraints: x509.BasicConstraints(ca=ca, path_length=0 if ca else None),
            x509.KeyUsage: x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            x509.ExtendedKeyUsage: x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH] if client_auth else [ExtendedKeyUsageOID.SERVER_AUTH],
            ),
        }
        certificate.extensions.get_extension_for_class.side_effect = lambda cls: SimpleNamespace(value=values[cls])
        return certificate

    def test_valid_client_usage_is_accepted(self) -> None:
        certificate = self.certificate_with_usage(ca=False, digital_signature=True, client_auth=True)

        ClientCertificateBackend._validate_client_usage(certificate)  # noqa: SLF001

    def test_invalid_client_usage_is_rejected(self) -> None:
        invalid_usages = [
            (True, True, True),
            (False, False, True),
            (False, True, False),
        ]
        for ca, digital_signature, client_auth in invalid_usages:
            with self.subTest(ca=ca, digital_signature=digital_signature, client_auth=client_auth):
                certificate = self.certificate_with_usage(
                    ca=ca,
                    digital_signature=digital_signature,
                    client_auth=client_auth,
                )

                with pytest.raises(ValidationError, match='does not permit TLS client authentication'):
                    ClientCertificateBackend._validate_client_usage(certificate)  # noqa: SLF001

    def test_missing_required_extension_is_rejected(self) -> None:
        certificate = Mock()
        certificate.extensions.get_extension_for_class.side_effect = x509.ExtensionNotFound(
            'missing', x509.BasicConstraints,
        )

        with pytest.raises(ValidationError, match='missing required TLS client extensions'):
            ClientCertificateBackend._validate_client_usage(certificate)  # noqa: SLF001
