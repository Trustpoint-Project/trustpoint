"""This module contains the AOKI endpoints (views)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.views import View
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from pki.util.x509 import ApacheTLSClientCertExtractor, ClientCertificateAuthenticationError

from trustpoint.views.base import LoggedHttpResponse, LoggerMixin

if TYPE_CHECKING:
    from cryptography import x509
    from django.http import HttpRequest


class AokiNoOwnerIdError(Exception):
    """Exception raised when no owner ID for the device IDevID in the AOKI request."""


class AokiServiceMixin:
    """Mixin for AOKI functionality."""
    def get_owner_cert(self, idevid_subj_sn: str) -> x509.Certificate:
        """Get the ownership certificate for the given IDevID."""
        # This method should be implemented to retrieve the ownership certificate
        # based on the provided IDevID subject serial number.

        # Build URI string "<idevid_subj_sn>.<idevid_sha256_fingerprint>.owner.aoki.alt"
        # Check SAN extension in DB for owner cert
        # if present, check that the certificate is in truststore with usage "Device Owner ID"

class AokiInitializationRequestView(AokiServiceMixin, LoggerMixin, View):
    """View for handling AOKI initialization requests."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle POST requests for AOKI initialization."""
        del args, kwargs  # Unused
        try:
            client_cert, intermediary_cas = ApacheTLSClientCertExtractor.get_client_cert_as_x509(request)
        except ClientCertificateAuthenticationError:
            return LoggedHttpResponse(
                'No valid TLS client certificate provided.', status = 401
            )

        try:
            domain, idevid_subj_sn = IDevIDAuthenticator.authenticate_idevid_from_x509_no_device(
                client_cert, intermediary_cas, domain=None)
        except IDevIDAuthenticationError as e:
            return LoggedHttpResponse(
                f'IDevID authentication failed: {e}', status = 403
            )

        try:
            self.get_owner_cert(client_cert, idevid_subj_sn)
        except AokiNoOwnerIdError:
            return LoggedHttpResponse(
                'No Owner ID present for this IDevID.', status = 422
            )

        return LoggedHttpResponse(
            'AOKI initialization request received.',
            status = 200,
        )
        # Verify Device IDevID against Truststores
        # (need to figure out how to do this efficiently as we have no domain here)
        # Maybe first look for ownership certs and reference the truststore there?

        # extract SN from client cert
        # go through all registration patterns and check for truststore

        # Check we have a valid ownership certificate for this device

        # Send the device a response of the form:
        # (OwnershipCert as PEM || TLS Truststore as PEM || enrollment_info) signed by owner private key
        # enrollment_info =
        #   {protocols: [{"protocol": "EST", "url": "/.well-known/est/domain/domaincredential/simpleenroll"}]}
