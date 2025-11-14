"""Carries out the requested operation after authentication and authorization."""
from abc import ABC, abstractmethod
from typing import get_args

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from devices.issuer import CredentialSaver
from devices.models import IssuedCredentialModel
from pki.models import CredentialModel
from pki.util.keys import is_supported_public_key
from trustpoint.logger import LoggerMixin
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

    @staticmethod
    def _get_credential_type_for_template(context: RequestContext
            ) -> tuple[IssuedCredentialModel.IssuedCredentialType, IssuedCredentialModel.IssuedCredentialPurpose]:
        """Map certificate template to issued credential type."""
        if context.certificate_template == 'domaincredential':
            return (IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                    IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL)

        if context.certificate_template == 'tls-client':
            purpose = IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT
        elif context.certificate_template == 'tls-server':
            purpose = IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER
        else:
            purpose = IssuedCredentialModel.IssuedCredentialPurpose.GENERIC

        return (IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL, purpose)

class LocalCaCertificateIssueProcessor(CertificateIssueProcessor):
    """Operation processor for issuing certificates via a local CA."""

    def process_operation(self, context: RequestContext) -> None:
        """Process the certificate issuance operation."""
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

        issuing_credential = ca.credential
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
        }

        for ext, critical in default_extensions.values():
            certificate_builder = certificate_builder.add_extension(ext, critical)

        signed_cert = certificate_builder.sign(
            private_key=issuing_credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm,
        )
        common_names = signed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = common_names[0].value if common_names else '(no CN set)'
        common_name = cn.decode() if isinstance(cn, bytes) else cn
        credential_type, credential_purpose = self._get_credential_type_for_template(context)
        saver = CredentialSaver(device=context.device, domain=context.domain)
        saver.save_keyless_credential(
            signed_cert,
            [
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
            common_name,
            credential_type,
            credential_purpose,
        )
        context.issued_certificate = signed_cert


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

    def process_operation(self, context: RequestContext) -> None:
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
                context.issuer_credential = ca.credential
            signer_credential = context.issuer_credential

        self._signature = GenericSigner.sign(self._data, signer_credential)

    def get_signature(self) -> bytes:
        """Get the generated signature."""
        if self._signature is None:
            exc_msg = 'Signature not generated. Call process_operation first.'
            raise ValueError(exc_msg)
        return self._signature

