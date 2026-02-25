"""Signature operation processor classes."""
from typing import get_args

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.oid import SignatureSuite

from pki.models import CredentialModel
from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor


class GenericSigner(LoggerMixin):
    """Provides general signing functionality."""

    @staticmethod
    def sign(data: bytes, signer_credential: CredentialModel) -> bytes:
        """Sign the provided data with the given signer credential."""
        signature_suite = SignatureSuite.from_certificate(signer_credential.get_certificate())
        private_key = signer_credential.get_private_key_serializer().as_crypto()

        hash_algorithm_enum = signature_suite.algorithm_identifier.hash_algorithm
        if hash_algorithm_enum is None:
            err_msg = 'Failed to get hash algorithm.'
            raise ValueError(err_msg)
        hash_algorithm = hash_algorithm_enum.hash_algorithm()

        if not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
            err_msg = f'The hash algorithm must be one of {AllowedCertSignHashAlgos}, but found {type(hash_algorithm)}'
            raise TypeError(err_msg)

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                data,
                padding.PKCS1v15(),
                hash_algorithm,
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                data,
                ec.ECDSA(hash_algorithm),
            )
        else:
            exc_msg = 'Cannot sign due to unsupported private key type.'
            raise TypeError(exc_msg)
        GenericSigner.logger.debug('Signed %d bytes of data using %s', len(data), signer_credential)

        return signature


class GenericSignatureVerifier:
    """Provides general signature verification functionality."""

    @staticmethod
    def verify(data: bytes, signature: bytes, signer_certificate: x509.Certificate) -> None:
        """Verify the provided signature over the data using the signer's certificate."""
        signature_suite = SignatureSuite.from_certificate(signer_certificate)
        public_key = signer_certificate.public_key()

        hash_algorithm_enum = signature_suite.algorithm_identifier.hash_algorithm
        if hash_algorithm_enum is None:
            err_msg = 'Failed to get hash algorithm.'
            raise ValueError(err_msg)
        hash_algorithm = hash_algorithm_enum.hash_algorithm()

        if not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
            err_msg = f'The hash algorithm must be one of {AllowedCertSignHashAlgos}, but found {type(hash_algorithm)}'
            raise TypeError(err_msg)

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature=signature,
                data=data,
                padding=padding.PKCS1v15(),
                algorithm=hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature=signature,
                data=data,
                signature_algorithm=ec.ECDSA(hash_algorithm),
            )
        else:
            exc_msg = 'Cannot verify signature due to unsupported public key type.'
            raise TypeError(exc_msg)


class LocalCaCmpSignatureProcessor(LoggerMixin, AbstractOperationProcessor):
    """Operation processor for signing a CMP message via a local CA."""

    _data: bytes | None = None
    _signature: bytes | None = None

    def __init__(self, message: bytes | None = None) -> None:
        """Initialize the processor with data to be signed."""
        # Air: Consider adding data to be signed to RequestContext
        self._data = message

    def process_operation(self, context: BaseRequestContext) -> None:
        """Sign the provided data using the local CA's private key."""
        if self._data is None:
            exc_msg = 'Data to be signed must be set in the processor.'
            raise ValueError(exc_msg)

        # if this is an AOKI request, the DevOwnerID is used to sign the CMP message
        if context.owner_credential:
            signer_credential = context.owner_credential
        else:
            if not context.issuer_credential:
                if not context.domain:
                    exc_msg = 'Domain must be set in the context to sign data.'
                    raise ValueError(exc_msg)

                ca = context.domain.get_issuing_ca_or_value_error()
                context.issuer_credential = ca.get_credential()
                if not context.issuer_credential:
                    exc_msg = 'Issuing CA does not have a credential'
                    raise ValueError(exc_msg)
            signer_credential = context.issuer_credential

        self._signature = GenericSigner.sign(self._data, signer_credential)

    def get_signature(self) -> bytes:
        """Get the generated signature."""
        if self._signature is None:
            exc_msg = 'Signature not generated. Call process_operation first.'
            raise ValueError(exc_msg)
        return self._signature
