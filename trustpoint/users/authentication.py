# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Authentication backends for service accounts and TLS client certificates."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import Criticality, ExtensionPolicy, PolicyBuilder, Store, VerificationError
from django.conf import settings
from django.contrib.auth.backends import BaseBackend, ModelBackend
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext as _

from management.models import CertificateAuthenticationConfig
from pki.management.commands.create_management_ca import ISSUING_CA_NAME
from pki.models import CertificateModel
from pki.util.x509 import ClientCertificateAuthenticationError, NginxTLSClientCertExtractor

from .models import ServiceAccountCredential, TrustpointUser, UserClientCertificate

if TYPE_CHECKING:
    from django.http import HttpRequest


CERTIFICATE_BACKEND = 'users.authentication.ClientCertificateBackend'
CERTIFICATE_LOGIN_ERROR_SESSION_KEY = 'certificate_login_error'
REJECTED_CERTIFICATE_SESSION_KEY = 'rejected_client_certificate'


class ClientCertificateBackend(ModelBackend):
    """Validate proxy-supplied TLS certificates while retaining Django model permissions."""

    def authenticate(
        self,
        request: HttpRequest | None = None,
        username: str | None = None,  # noqa: ARG002
        password: str | None = None,  # noqa: ARG002
        *,
        certificate_login: bool = False,
        **_kwargs: Any,
    ) -> TrustpointUser | None:
        """Authenticate only explicit certificate attempts; never accept password credentials here."""
        if not certificate_login or request is None:
            return None

        self._validate_proxy(request)
        try:
            certificate, _chain = NginxTLSClientCertExtractor.get_client_cert_as_x509(request)
        except ClientCertificateAuthenticationError as exc:
            raise ValidationError(_('The client certificate could not be read.')) from exc

        try:
            user = self._get_subject_user(certificate)
        except ValueError as exc:
            raise ValidationError(_('The client certificate subject could not be read.')) from exc
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
        association = UserClientCertificate.objects.select_related('certificate').filter(
            user=user, certificate__sha256_fingerprint=fingerprint,
        ).first()
        if association is None:
            raise ValidationError(_('The client certificate is not configured for the user identified in its subject.'))
        if not association.is_active:
            raise ValidationError(_('The client certificate is disabled.'))
        if not user.is_active:
            raise ValidationError(_('The account associated with the client certificate is disabled.'))
        if user.account_type != TrustpointUser.AccountType.HUMAN:
            raise ValidationError(_('Service accounts cannot sign in to the web interface.'))

        try:
            self._validate_registered_fingerprint(certificate, association.certificate)
            self._validate_status(association.certificate)
            self._validate_client_usage(certificate)
            self._validate_issuer(certificate)
        except (ValueError, UnsupportedAlgorithm, x509.DuplicateExtension) as exc:
            raise ValidationError(_('The certificate contains invalid or unsupported certificate data.')) from exc
        return user

    @staticmethod
    def _validate_registered_fingerprint(certificate: x509.Certificate, configured: CertificateModel) -> None:
        """Compare the supplied certificate with the actual certificate stored for this user."""
        configured_certificate = configured.get_certificate_serializer().as_crypto()
        if certificate.fingerprint(hashes.SHA256()) != configured_certificate.fingerprint(hashes.SHA256()):
            raise ValidationError(_('The client certificate does not match the certificate configured for this user.'))

    @staticmethod
    def _get_subject_user(certificate: x509.Certificate) -> TrustpointUser:
        """Resolve the stable user ID from the subject, independently of the mutable username."""
        user_ids = certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if len(user_ids) != 1:
            raise ValidationError(_('The certificate subject must contain exactly one user ID.'))
        user_id = user_ids[0].value
        if not isinstance(user_id, str) or not user_id.isascii() or not user_id.isdecimal():
            raise ValidationError(_('The certificate subject contains an invalid user ID.'))
        # Reject IDs outside the BigAutoField range before querying.
        max_user_id = 2**63 - 1
        if len(user_id) > len(str(max_user_id)) or not 0 < int(user_id) <= max_user_id:
            raise ValidationError(_('The certificate subject contains an invalid user ID.'))
        user = TrustpointUser.objects.filter(pk=int(user_id)).first()
        if user is None:
            raise ValidationError(_('No user exists with the ID in the certificate subject.'))
        return user

    @staticmethod
    def _validate_proxy(request: HttpRequest) -> None:
        """Trust TLS proof only from the configured proxy, which must overwrite these headers."""
        if request.META.get('REMOTE_ADDR') not in settings.CLIENT_CERTIFICATE_TRUSTED_PROXY_IPS:
            raise ValidationError(_('The client certificate was not supplied by a trusted TLS proxy.'))
        if request.META.get('HTTP_X_FORWARDED_PROTO') != 'https':
            raise ValidationError(_('Client certificate login requires HTTPS.'))
        verification = request.META.get('HTTP_X_SSL_CLIENT_VERIFY', '')
        # Nginx uses optional_no_ca: we validate the issuing CA ourselves below.
        if verification != 'SUCCESS' and not verification.startswith('FAILED:'):
            raise ValidationError(_('The TLS proxy did not confirm a client certificate.'))

    @staticmethod
    def _validate_status(certificate: CertificateModel) -> None:
        """Reject expired, not-yet-valid, or locally revoked certificates, including the CA."""
        status = certificate.certificate_status
        if status != CertificateModel.CertificateStatus.OK:
            raise ValidationError(_('Certificate validation failed: %(status)s.'), params={'status': status.label})

    @staticmethod
    def _validate_client_usage(certificate: x509.Certificate) -> None:
        """Require an end-entity certificate with digital signatures and TLS client authentication."""
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
            extended_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise ValidationError(_('The certificate is missing required TLS client extensions.')) from exc
        if (
            basic_constraints.ca or not key_usage.digital_signature
            or ExtendedKeyUsageOID.CLIENT_AUTH not in extended_usage
        ):
            raise ValidationError(_('The certificate does not permit TLS client authentication.'))

    @classmethod
    def _validate_issuer(cls, certificate: x509.Certificate) -> None:
        """Validate the certificate path against the explicitly enabled management issuing CA."""
        config = CertificateAuthenticationConfig.objects.select_related('issuing_ca__credential__certificate').filter(
            enabled=True, issuing_ca__unique_name=ISSUING_CA_NAME,
        ).first()
        if config is None:
            raise ValidationError(_('Certificate based authentication is not enabled.'))
        issuer_model = config.issuing_ca.ca_certificate_model
        if issuer_model is None:
            raise ValidationError(_('The management issuing CA has no certificate.'))
        cls._validate_status(issuer_model)
        issuer = issuer_model.get_certificate_serializer().as_crypto()
        try:
            certificate.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ValidationError(
                _('The certificate signature does not match the current management issuing CA.'),
            ) from exc
        # Our client certificates identify users in the subject and intentionally have no SAN.
        leaf_policy = ExtensionPolicy.webpki_defaults_ee().may_be_present(
            x509.SubjectAlternativeName, Criticality.NON_CRITICAL, None,
        )
        verifier = (
            PolicyBuilder().store(Store([issuer])).time(timezone.now()).max_chain_depth(0)
            .extension_policies(ca_policy=ExtensionPolicy.webpki_defaults_ca(), ee_policy=leaf_policy)
            .build_client_verifier()
        )
        try:
            verifier.verify(certificate, [])
        except VerificationError as exc:
            raise ValidationError(
                _('Client certificate validation failed: %(reason)s.'), params={'reason': str(exc)},
            ) from exc


class ServiceAccountBackend(BaseBackend):
    """Authentication backend for service accounts using API keys.

    This backend authenticates service accounts using client_id and secret.
    It should not be used for human accounts or Web UI login.
    """

    def authenticate(
        self,
        request: HttpRequest | None = None,  # noqa: ARG002
        client_id: str | None = None,
        secret: str | None = None,
        **kwargs: object,  # noqa: ARG002
    ) -> TrustpointUser | None:
        """Authenticate a service account using client ID and secret.

        Args:
            request: The HTTP request (unused, required for compatibility with BaseBackend).
            client_id: The service account's client ID.
            secret: The service account's API secret (plaintext).
            **kwargs: Additional keyword arguments (unused, required for compatibility with BaseBackend).

        Returns:
            The authenticated TrustpointUser (service account) or None.
        """
        client_id = (client_id or '').strip()
        secret = (secret or '').strip()
        if not client_id or not secret:
            return None

        try:
            credential = ServiceAccountCredential.objects.select_related('service_account').get(
                client_id=client_id,
                is_active=True,
            )
        except ServiceAccountCredential.DoesNotExist:
            return None

        if not credential.is_valid():
            return None

        user = credential.service_account
        if user.account_type != TrustpointUser.AccountType.SERVICE or not user.is_active:
            return None

        if not check_password(secret, credential.hashed_secret):
            return None

        credential.record_usage()

        return user

    def get_user(self, user_id: int) -> TrustpointUser | None:
        """Retrieve a user by ID.

        Args:
            user_id: The user's primary key.

        Returns:
            The TrustpointUser or None if not found.
        """
        try:
            return TrustpointUser.objects.get(pk=user_id)
        except TrustpointUser.DoesNotExist:
            return None
