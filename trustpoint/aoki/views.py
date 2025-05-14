"""This module contains the AOKI endpoints (views)."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from django.http import JsonResponse
from django.views import View
from pki.models.certificate import CertificateModel
from pki.models.extension import GeneralNameUniformResourceIdentifier, SubjectAlternativeNameExtension
from pki.models.issuing_ca import IssuingCaModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from pki.util.x509 import ApacheTLSClientCertExtractor, ClientCertificateAuthenticationError
from trustpoint_core.oid import AlgorithmIdentifier

from trustpoint.views.base import LoggedHttpResponse, LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest


class AokiNoOwnerIdError(Exception):
    """Exception raised when no owner ID is found in the database for the device IDevID in the AOKI request."""


class AokiServiceMixin:
    """Mixin for AOKI functionality."""
    @staticmethod
    def _get_idevid_owner_san_uri(idevid_cert: x509.Certificate) -> str:
        """Get the Owner ID SAN URI corresponding to a IDevID certificate.

        Formatted as "<idevid_subj_sn>.aoki.owner.<idevid_x509_sn>.<idevid_sha256_fingerprint>.alt
        """
        try:
            sn_b = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
            idevid_subj_sn = sn_b.decode() if isinstance(sn_b, bytes) else sn_b
        except (ValueError, IndexError):
            idevid_subj_sn = '_'
        idevid_x509_sn = hex(idevid_cert.serial_number)[2:].zfill(16)
        idevid_sha256_fingerprint = idevid_cert.fingerprint(hashes.SHA256()).hex()
        return f'{idevid_subj_sn}.aoki.owner.{idevid_x509_sn}.{idevid_sha256_fingerprint}.alt'

    def get_owner_cert(self, idevid_cert: x509.Certificate) -> CertificateModel:
        """Get the ownership certificate for the given IDevID."""
        # This method should be implemented to retrieve the ownership certificate
        # based on the provided IDevID subject serial number.

        # Build URI string "<idevid_subj_sn>.<idevid_sha256_fingerprint>.owner.aoki.alt"
        # Check SAN extension in DB for owner cert
        # if present, check that the certificate is in truststore with usage "Device Owner ID"
        idevid_san_uri = self._get_idevid_owner_san_uri(idevid_cert)
        gn_uri_query = GeneralNameUniformResourceIdentifier.objects.filter(value=idevid_san_uri)
        if not gn_uri_query.exists():
            exc_msg = f'No Owner ID SAN URI found for IDevID with owner SAN URI {idevid_san_uri}.'
            raise AokiNoOwnerIdError(exc_msg)
        gn = gn_uri_query.first().general_names_set.first()
        san_ext = SubjectAlternativeNameExtension.objects.filter(subject_alt_name=gn).first()
        if not san_ext:
            exc_msg = f'No SAN extension found for IDevID with owner SAN URI {idevid_san_uri}.'
            raise AokiNoOwnerIdError(exc_msg)
        cert = CertificateModel.objects.filter(subject_alternative_name_extension=san_ext).first()
        if not cert:
            exc_msg = f'No certificate found for IDevID with owner SAN URI {idevid_san_uri}.'
            raise AokiNoOwnerIdError(exc_msg)
        # Check that the certificate is in a truststore with usage "Device Owner ID"


        return cert

class AokiInitializationRequestView(AokiServiceMixin, LoggerMixin, View):
    """View for handling AOKI initialization requests."""

    http_method_names = ('get',)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse | JsonResponse:
        """Handle GET requests for AOKI initialization."""
        del args, kwargs  # Unused
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert:
            return LoggedHttpResponse(
                'No TLS server certificate available. Are you on the development server?', status = 500
            )
        try:
            client_cert, intermediary_cas = ApacheTLSClientCertExtractor.get_client_cert_as_x509(request)
        except ClientCertificateAuthenticationError:
            return LoggedHttpResponse(
                'No valid TLS client certificate provided.', status = 401
            )

        try:
            domain, _idevid_subj_sn = IDevIDAuthenticator.authenticate_idevid_from_x509_no_device(
                client_cert, intermediary_cas, domain=None)
        except IDevIDAuthenticationError as e:
            return LoggedHttpResponse(
                f'IDevID authentication failed: {e}', status = 403
            )

        try:
            owner_id_cert = self.get_owner_cert(client_cert)
        except AokiNoOwnerIdError:
            return LoggedHttpResponse(
                'No Owner ID present for this IDevID.', status = 422
            )

        # Problem: We need to store an owner credential, not just the cert
        # Probably should create a new OwnerCredentialModel for this
        demo_owner_cred = IssuingCaModel.objects.get(unique_name='DevOwnerID')
        owner_pk = demo_owner_cred.credential.get_private_key()

        aoki_init_response = {
            'aoki-init': {
                'version': '1.0',
                'enrollment-info': {
                    'protocols': [
                        {
                            'protocol': 'EST',
                            'url': f'/.well-known/est/{domain.unique_name}/domaincredential/'
                        }
                    ]
                },
                'owner-id-cert': owner_id_cert.get_certificate_serializer().as_pem().decode(),
                'tls-truststore': tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode()
            },
        }
        resp = JsonResponse(aoki_init_response)

        if isinstance(owner_pk, rsa.RSAPrivateKey):
            owner_signature = owner_pk.sign(
                data=resp.content,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )
            signature_algo = AlgorithmIdentifier.RSA_SHA256.dotted_string
        elif isinstance(owner_pk, ec.EllipticCurvePrivateKey):
            owner_signature = owner_pk.sign(
                data=resp.content,
                signature_algorithm=ec.ECDSA(hashes.SHA256()),
            )
            signature_algo = AlgorithmIdentifier.ECDSA_SHA256.dotted_string
        else:
            exc_msg = f'Unsupported private key type: {type(owner_pk)} for AOKI owner signing.'
            raise TypeError(exc_msg)

        resp.headers['AOKI-Signature'] = base64.b64encode(owner_signature).decode()
        resp.headers['AOKI-Signature-Algorithm'] = signature_algo
        self.logger.info(resp.content)

        return resp
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
