"""CSR operation processor classes."""
from abc import abstractmethod
from typing import get_args

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.oid import SignatureSuite

from pki.models import CredentialModel
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor


class EstCsrSignProcessor(LoggerMixin, AbstractOperationProcessor):
    """Base operation processor for signing a CSR (Certificate Signing Request) for EST protocol."""

    _signed_csr: x509.CertificateSigningRequest | None = None

    @abstractmethod
    def _get_signing_credential(self, context: BaseCertificateRequestContext) -> CredentialModel:
        """Get the credential to use for signing the CSR.

        Args:
            context: Request context containing necessary credentials.

        Returns:
            The credential to use for signing.

        Raises:
            ValueError: If the required credential is not available.
        """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Sign the CSR from cert_requested using the appropriate credential.

        Args:
            context: Request context containing the CSR in cert_requested
                    and the signing credential.

        Raises:
            TypeError: If context is not a BaseCertificateRequestContext.
            ValueError: If required context attributes are missing.
        """
        if not isinstance(context, BaseCertificateRequestContext):
            exc_msg = 'CSR signing requires a BaseCertificateRequestContext.'
            raise TypeError(exc_msg)

        if context.cert_requested is None:
            exc_msg = 'CSR (cert_requested) must be set in the context.'
            raise ValueError(exc_msg)

        if not isinstance(context.cert_requested, x509.CertificateSigningRequest):
            exc_msg = (
                f'cert_requested must be a CertificateSigningRequest, '
                f'but found {type(context.cert_requested)}.'
            )
            raise TypeError(exc_msg)

        signing_credential = self._get_signing_credential(context)
        csr = context.cert_requested

        # Determine hash algorithm
        if signing_credential.certificate:
            signature_suite = SignatureSuite.from_certificate(signing_credential.get_certificate())
            hash_algorithm_enum = signature_suite.algorithm_identifier.hash_algorithm
            if hash_algorithm_enum is None:
                err_msg = 'Failed to get hash algorithm from signing certificate.'
                raise ValueError(err_msg)
            hash_algorithm = hash_algorithm_enum.hash_algorithm()
        else:
            hash_algorithm = hashes.SHA256()

        if not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
            err_msg = (
                f'The hash algorithm must be one of {AllowedCertSignHashAlgos}, '
                f'but found {type(hash_algorithm)}'
            )
            raise TypeError(err_msg)

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(csr.subject)

        for extension in csr.extensions:
            csr_builder = csr_builder.add_extension(extension.value, extension.critical)

        private_key = signing_credential.get_private_key_serializer().as_crypto()
        self._signed_csr = csr_builder.sign(private_key=private_key, algorithm=hash_algorithm)

        if signing_credential.certificate:
            self.logger.info(
                'Signed CSR for EST with credential: %s',
                signing_credential.get_certificate().subject.rfc4514_string()
            )
        else:
            self.logger.info('Signed CSR for EST with credential (certificate pending)')

    def get_signed_csr(self) -> x509.CertificateSigningRequest:
        """Get the signed CSR.

        Returns:
            The signed CertificateSigningRequest.

        Raises:
            ValueError: If CSR has not been signed yet.
        """
        if self._signed_csr is None:
            exc_msg = 'CSR not signed. Call process_operation first.'
            raise ValueError(exc_msg)
        return self._signed_csr


class EstCaCsrSignProcessor(EstCsrSignProcessor):
    """Operation processor for signing a CSR with the CA's issuer credential for EST protocol."""

    def _get_signing_credential(self, context: BaseCertificateRequestContext) -> CredentialModel:
        """Get the issuer credential (CA) for signing the CSR.

        Args:
            context: Request context containing the issuer credential or domain.

        Returns:
            The issuer credential to use for signing.

        Raises:
            ValueError: If issuer credential is not available.
        """
        if not context.issuer_credential:
            if not context.domain:
                exc_msg = 'Domain must be set in the context to get issuer credential for CSR signing.'
                raise ValueError(exc_msg)

            ca = context.domain.get_issuing_ca_or_value_error()
            context.issuer_credential = ca.get_credential()

        return context.issuer_credential


class EstDeviceCsrSignProcessor(EstCsrSignProcessor):
    """Operation processor for signing a CSR with the device's owner credential for EST protocol."""

    def _get_signing_credential(self, context: BaseCertificateRequestContext) -> CredentialModel:
        """Get the owner credential (device) for signing the CSR.

        Args:
            context: Request context containing the owner credential.

        Returns:
            The owner credential to use for signing.

        Raises:
            ValueError: If owner credential is not available.
        """
        if not context.owner_credential:
            exc_msg = 'Owner credential must be set in the context for device CSR signing.'
            raise ValueError(exc_msg)

        return context.owner_credential
