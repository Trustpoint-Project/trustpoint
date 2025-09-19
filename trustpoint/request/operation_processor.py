"""Carries out the requested operation after authentication and authorization."""
from abc import ABC, abstractmethod
from typing import get_args

from cryptography import x509
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.oid import SignatureSuite

from request.request_context import RequestContext


class AbstractOperationProcessor(ABC):
    """Abstract base class for operation processors."""

    @abstractmethod
    def process_operation(self, context: RequestContext) -> None:
        """Execute operation processing logic."""


class CertificateIssueProcessor(AbstractOperationProcessor):
    """Operation processor for issuing certificates."""

    def process_operation(self, context: RequestContext) -> None:
        """Process the certificate issuance operation."""
        # decide which processor to use based on domain configuration
        if context.domain and context.domain.issuing_ca:
            processor = LocalCaCertificateIssueProcessor()
            return processor.process_operation(context)

        exc_msg = 'No suitable operation processor found for certificate issuance.'
        raise ValueError(exc_msg)


class LocalCaCertificateIssueProcessor(AbstractOperationProcessor):
    """Operation processor for issuing certificates via a local CA."""

    def process_operation(self, context: RequestContext) -> None:
        """Process the certificate issuance operation."""
        ca = context.domain.get_issuing_ca_or_value_error()
        public_key = context.cert_requested.public_key()

        issuing_credential = ca.credential
        issuer_certificate = issuing_credential.get_certificate()
        hash_algorithm_enum = SignatureSuite.from_certificate(issuer_certificate).algorithm_identifier.hash_algorithm
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
        }

        for ext, critical in default_extensions.values():
            certificate_builder = certificate_builder.add_extension(ext, critical)

        signed_cert = certificate_builder.sign(
            private_key=issuing_credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm,
        )
        context.issued_certificate = signed_cert
