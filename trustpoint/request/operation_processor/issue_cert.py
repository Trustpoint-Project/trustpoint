"""Certificate issuance operation processor classes."""

import contextlib
from typing import TYPE_CHECKING, get_args

from cryptography import x509
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.oid import SignatureSuite

from devices.issuer import CredentialSaver
from devices.models import IssuedCredentialModel
from management.models import TlsSettings
from pki.models import CaModel
from pki.util.keys import is_supported_public_key
from request.clients.est_client import EstClient
from request.request_context import (
    BaseCertificateRequestContext,
    BaseRequestContext,
    EstCertificateRequestContext,
    HttpBaseRequestContext,
)
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor

if TYPE_CHECKING:
    from django.http import HttpRequest


class CertificateIssueProcessor(AbstractOperationProcessor):
    """Operation processor for issuing certificates."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the certificate issuance operation.

        Routes to the appropriate certificate issuance processor based on the
        domain's issuing CA configuration (local, remote issuing CA, or remote RA).
        """
        if not isinstance(context, BaseCertificateRequestContext):
            exc_msg = 'Certificate issuance requires a subclass of BaseCertificateRequestContext.'
            raise TypeError(exc_msg)
        if context.enrollment_request and not context.enrollment_request.is_valid():
            return None

        if context.domain and context.domain.issuing_ca:
            issuing_ca = context.domain.issuing_ca

            # Remote Issuing CAs
            if issuing_ca.ca_type == CaModel.CaTypeChoice.REMOTE_ISSUING_EST:
                processor: (
                    LocalCaCertificateIssueProcessor | RemoteCaCertificateIssueProcessor
                ) = LocalCaCertificateIssueProcessor()
                return processor.process_operation(context)
            if issuing_ca.ca_type == CaModel.CaTypeChoice.REMOTE_ISSUING_CMP:
                processor = LocalCaCertificateIssueProcessor()
                return processor.process_operation(context)
            # Remote RAs - forward requests to remote CA via RA
            if issuing_ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA:
                processor = RemoteCaCertificateIssueProcessor(ca_type='est')
                return processor.process_operation(context)
            if issuing_ca.ca_type == CaModel.CaTypeChoice.REMOTE_CMP_RA:
                processor = RemoteCaCertificateIssueProcessor(ca_type='cmp')
                return processor.process_operation(context)
            # Local CAs
            processor = LocalCaCertificateIssueProcessor()
            return processor.process_operation(context)

        exc_msg = 'No suitable operation processor found for certificate issuance.'
        raise ValueError(exc_msg)

    @staticmethod
    def _get_credential_type_for_template(context: BaseCertificateRequestContext
            ) -> tuple[IssuedCredentialModel.IssuedCredentialType, str]:
        """Map certificate template to issued credential type."""
        if context.certificate_profile_model is None:
            exc_msg = 'Certificate profile model is required but not set in context.'
            raise ValueError(exc_msg)

        profile_display_name = (context.certificate_profile_model.display_name
                                or context.certificate_profile_model.unique_name)

        if context.certificate_profile_model.unique_name == 'domain_credential':
            return (IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL, profile_display_name)

        return (IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL, profile_display_name)

class LocalCaCertificateIssueProcessor(CertificateIssueProcessor):
    """Operation processor for issuing certificates via a local CA."""

    def _get_crl_distribution_point_url(self, context: BaseRequestContext, ca_id: int) -> str:
        """Get the CRL distribution point URL for this Issuing CA.

        Returns:
            str: The CRL distribution point URL.
        """
        request: HttpRequest | None = None
        if isinstance(context, HttpBaseRequestContext):
            request = context.raw_message
        port = request.META.get('SERVER_PORT', '') if request else ''
        if port == '443': # CRL always served via HTTP
            port = ''
        port_str = f':{port}' if port else ''
        return f'http://{TlsSettings.get_first_ipv4_address()}{port_str}/crl/{ca_id}'

    def process_operation(self, context: BaseRequestContext) -> None:  # noqa: C901, PLR0915 - Core pipeline orchestration requires multiple validation and conditional paths
        """Process the certificate issuance operation."""
        if not isinstance(context, BaseCertificateRequestContext):
            exc_msg = 'Certificate issuance requires a subclass of BaseCertificateRequestContext.'
            raise TypeError(exc_msg)
        if not context.device:
            exc_msg = 'Device must be set in the context to issue a certificate.'
            raise ValueError(exc_msg)
        if not context.domain:
            exc_msg = 'Domain must be set in the context to issue a certificate.'
            raise ValueError(exc_msg)
        if not context.domain.is_active:
            exc_msg = f'Cannot issue certificate: Domain "{context.domain.unique_name}" is currently disabled.'
            raise ValueError(exc_msg)
        if not context.cert_requested:
            exc_msg = 'Certificate request must be set in the context to issue a certificate.'
            raise ValueError(exc_msg)

        cert_req = context.cert_requested
        ca = context.domain.get_issuing_ca_or_value_error()
        public_key = cert_req._public_key if isinstance(cert_req, x509.CertificateBuilder) else cert_req.public_key()  # noqa: SLF001

        if not is_supported_public_key(public_key):
            err_msg = f'The public key in the certificate is missing or of unsupported type: {type(public_key)}.'
            raise TypeError(err_msg)

        issuing_credential = ca.get_credential()
        if not issuing_credential:
            err_msg = 'Issuing CA does not have a credential'
            raise ValueError(err_msg)
        issuer_certificate = issuing_credential.get_certificate()
        context.issuer_credential = issuing_credential

        signature_suite = SignatureSuite.from_certificate(issuer_certificate)
        if not signature_suite.public_key_matches_signature_suite(public_key):
            err_msg = 'Requested cert public key type does not match the CA signature suite.'
            raise ValueError(err_msg)

        hash_algorithm_enum = signature_suite.algorithm_identifier.hash_algorithm
        if hash_algorithm_enum is None:
            err_msg = 'Failed to get hash algorithm.'
            raise ValueError(err_msg)
        hash_algorithm = hash_algorithm_enum.hash_algorithm()

        if not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
            err_msg = f'The hash algorithm must be one of {AllowedCertSignHashAlgos}, but found {type(hash_algorithm)}'
            raise TypeError(err_msg)

        certificate_builder = context.cert_requested_profile_validated
        if certificate_builder is None:
            exc_msg = 'The certificate request has not been validated against a profile.'
            raise ValueError(exc_msg)

        certificate_builder = certificate_builder.issuer_name(
            issuing_credential.get_certificate().subject
        )

        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.public_key(public_key)

        default_extensions = {
            x509.BasicConstraints: (x509.BasicConstraints(ca=False, path_length=None), False),
            x509.KeyUsage: (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
            x509.AuthorityKeyIdentifier: (
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuing_credential.get_private_key_serializer().public_key_serializer.as_crypto()
                ),
                False,
            ),
            x509.SubjectKeyIdentifier: (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
            x509.CRLDistributionPoints: (x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        self._get_crl_distribution_point_url(context, ca.id)
                    )], relative_name=None, reasons=None, crl_issuer=None
                ),
            ]), False),
        }

        for ext, critical in default_extensions.values():
            with contextlib.suppress(ValueError): # extension already present
                certificate_builder = certificate_builder.add_extension(ext, critical)

        signed_cert = certificate_builder.sign(
            private_key=issuing_credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm,
        )
        common_names = signed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = common_names[0].value if common_names else '(no CN set)'
        common_name = cn.decode() if isinstance(cn, bytes) else cn
        credential_type, cert_profile_disp_name = self._get_credential_type_for_template(context)
        saver = CredentialSaver(device=context.device, domain=context.domain)
        saver.save_keyless_credential(
            signed_cert,
            [
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
            common_name,
            credential_type,
            cert_profile_disp_name,
        )
        context.issued_certificate = signed_cert


class RemoteCaCertificateIssueProcessor(CertificateIssueProcessor, LoggerMixin):
    """Operation processor for issuing certificates via a remote CA."""

    def __init__(self, ca_type: str = 'est') -> None:
        """Initialize the remote CA certificate issue processor.

        Args:
            ca_type: The type of remote CA ('est' or 'cmp'). Defaults to 'est'.
        """
        self.ca_type = ca_type

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the certificate issuance operation via a remote CA.

        This processor forwards the certificate signing request to a remote
        issuing CA using the appropriate protocol (EST or CMP).

        Args:
            context: The certificate request context.

        Raises:
            TypeError: If context is not a BaseCertificateRequestContext.
            ValueError: If required context fields are missing or invalid.
        """
        if not isinstance(context, BaseCertificateRequestContext):
            exc_msg = 'Certificate issuance requires a subclass of BaseCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not context.device:
            exc_msg = 'Device must be set in the context to issue a certificate.'
            raise ValueError(exc_msg)

        if not context.domain:
            exc_msg = 'Domain must be set in the context to issue a certificate.'
            raise ValueError(exc_msg)

        if not context.domain.issuing_ca:
            exc_msg = 'Domain must have an associated issuing CA.'
            raise ValueError(exc_msg)

        if not context.cert_requested:
            exc_msg = 'Certificate request must be set in the context to issue a certificate.'
            raise ValueError(exc_msg)

        if self.ca_type == 'est':
            self._process_est_enrollment(context)
        elif self.ca_type == 'cmp':
            exc_msg = 'CMP remote certificate issuance is not yet implemented.'
            raise NotImplementedError(exc_msg)
        else:
            exc_msg = f'Unknown remote CA type: {self.ca_type}'
            raise ValueError(exc_msg)

    def _validate_est_enrollment_config(self, issuing_ca: CaModel) -> None:
        """Validate EST enrollment configuration.

        Args:
            issuing_ca: The issuing CA model.

        Raises:
            ValueError: If any required configuration is missing or invalid.
        """
        if issuing_ca.ca_type not in (CaModel.CaTypeChoice.REMOTE_ISSUING_EST, CaModel.CaTypeChoice.REMOTE_EST_RA):
            exc_msg = f'Expected REMOTE_ISSUING_EST or REMOTE_EST_RA, got {issuing_ca.get_ca_type_display()}'
            raise ValueError(exc_msg)

        if not issuing_ca.remote_host:
            exc_msg = 'Remote EST host is not configured for the issuing CA.'
            raise ValueError(exc_msg)

        if not issuing_ca.remote_port:
            exc_msg = 'Remote EST port is not configured for the issuing CA.'
            raise ValueError(exc_msg)

        if not issuing_ca.remote_path:
            exc_msg = 'Remote EST path is not configured for the issuing CA.'
            raise ValueError(exc_msg)

        if not issuing_ca.chain_truststore:
            exc_msg = 'Chain truststore is not configured for the issuing CA.'
            raise ValueError(exc_msg)

    def _build_est_context(
        self, context: BaseCertificateRequestContext, issuing_ca: CaModel
    ) -> EstCertificateRequestContext:
        """Build EST certificate request context.

        Args:
            context: The base certificate request context.
            issuing_ca: The issuing CA model.

        Returns:
            The EST certificate request context.
        """
        est_password = None
        if issuing_ca.no_onboarding_config:
            est_password = issuing_ca.no_onboarding_config.est_password

        return EstCertificateRequestContext(
            operation='simpleenroll',
            protocol='est',
            domain=context.domain,
            device=context.device,
            certificate_profile_model=context.certificate_profile_model,
            cert_profile_str=context.cert_profile_str,
            cert_requested=context.cert_requested,
            est_server_host=issuing_ca.remote_host,
            est_server_port=issuing_ca.remote_port,
            est_server_path=issuing_ca.remote_path,
            est_username=issuing_ca.est_username,
            est_password=est_password,
            est_server_truststore=issuing_ca.chain_truststore,
        )

    def _process_est_enrollment(self, context: BaseCertificateRequestContext) -> None:
        """Process certificate issuance via remote EST CA.

        Args:
            context: The certificate request context.

        Raises:
            ValueError: If EST server configuration is invalid or enrollment fails.
            EstClientError: If communication with the EST server fails.
        """
        if context.domain is None:
            exc_msg = 'Domain must be set in the certificate request context.'
            raise ValueError(exc_msg)

        issuing_ca = context.domain.issuing_ca
        if not issuing_ca:
            exc_msg = 'Issuing CA must be set in the domain.'
            raise ValueError(exc_msg)

        self._validate_est_enrollment_config(issuing_ca)

        est_context = self._build_est_context(context, issuing_ca)

        csr = context.cert_requested
        if isinstance(csr, x509.CertificateBuilder):
            exc_msg = 'Cannot extract CSR from CertificateBuilder for EST enrollment.'
            raise TypeError(exc_msg)
        if csr is None:
            exc_msg = 'Certificate request is required for EST enrollment.'
            raise ValueError(exc_msg)

        est_client = EstClient(est_context)
        try:
            issued_cert = est_client.simple_enroll(csr)
        except Exception as e:
            exc_msg = f'EST enrollment failed: {e!s}'
            raise ValueError(exc_msg) from e

        if issuing_ca.chain_truststore is None:
            exc_msg = 'Chain truststore is required for EST enrollment.'
            raise ValueError(exc_msg)

        ca_chain = [
            cert.certificate.get_certificate_serializer().as_crypto()
            for cert in issuing_ca.chain_truststore.truststoreordermodel_set.order_by('order')
        ]

        common_names = issued_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = common_names[0].value if common_names else '(no CN set)'
        common_name = cn.decode() if isinstance(cn, bytes) else cn

        credential_type, cert_profile_disp_name = self._get_credential_type_for_template(context)
        if context.device is None:
            exc_msg = 'Device is required for saving credentials.'
            raise ValueError(exc_msg)

        saver = CredentialSaver(device=context.device, domain=context.domain)
        saver.save_keyless_credential(
            issued_cert,
            ca_chain,
            common_name,
            credential_type,
            cert_profile_disp_name,
        )

        context.issued_certificate = issued_cert
        self.logger.info(
            'Successfully issued certificate via remote EST CA: %s',
            issuing_ca.unique_name
        )
