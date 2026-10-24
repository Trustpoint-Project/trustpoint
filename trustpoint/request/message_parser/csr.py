# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared signature verification for HTTP certificate requests."""

from typing import ClassVar

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:
    mldsa = None  # type: ignore[assignment]

from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import ParsingComponent


class CsrSignatureVerification(ParsingComponent, LoggerMixin):
    """Verify supported CSR signatures while retaining protocol-specific input errors."""

    context_type: ClassVar[type[BaseCertificateRequestContext]]
    protocol: ClassVar[str]
    missing_csr_message: ClassVar[str]
    invalid_csr_message: ClassVar[str]
    invalid_csr_exception: ClassVar[type[Exception]] = TypeError

    def parse(self, context: BaseRequestContext) -> None:
        """Check the CSR type, supported algorithm, and signature."""
        if not isinstance(context, self.context_type):
            article = 'an' if self.protocol == 'EST' else 'a'
            msg = f'{type(self).__name__} requires {article} {self.context_type.__name__}.'
            raise TypeError(msg)

        csr = context.cert_requested
        if csr is None:
            self.logger.warning('%s CSR signature verification failed: CSR not found', self.protocol)
            raise ValueError(self.missing_csr_message)
        if not isinstance(csr, x509.CertificateSigningRequest):
            self.logger.warning(
                '%s CSR signature verification failed: Wrong type %s', self.protocol, type(csr).__name__
            )
            raise self.invalid_csr_exception(self.invalid_csr_message)

        public_key = csr.public_key()
        hash_algorithm = csr.signature_hash_algorithm
        is_mldsa = mldsa is not None and isinstance(
            public_key,
            (
                mldsa.MLDSA44PublicKey,
                mldsa.MLDSA65PublicKey,
                mldsa.MLDSA87PublicKey,
            ),
        )
        if hash_algorithm is None and not is_mldsa:
            msg = 'CSR does not contain a signature hash algorithm.'
            self.logger.warning('%s CSR signature verification failed: No signature hash algorithm', self.protocol)
            raise ValueError(msg)
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)) and not is_mldsa:
            msg = 'Unsupported public key type for CSR signature verification.'
            self.logger.warning('%s CSR signature verification failed: Unsupported public key type', self.protocol)
            raise TypeError(msg)

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                key_type = 'RSA'
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=hash_algorithm,  # type: ignore[arg-type]
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_type = 'EC'
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    signature_algorithm=ec.ECDSA(hash_algorithm),  # type: ignore[arg-type]
                )
            else:
                key_type = public_key.__class__.__name__.replace('PublicKey', '').replace('MLDSA', 'ML-DSA-')
                public_key.verify(signature=csr.signature, data=csr.tbs_certrequest_bytes)  # type: ignore[union-attr,call-arg]
            hash_info = f' with {hash_algorithm.name}' if hash_algorithm else ''
            self.logger.info('%s CSR signature verification successful: %s key%s', self.protocol, key_type, hash_info)
        except Exception as exc:
            msg = 'Failed to verify the CSR signature.'
            self.logger.exception('%s CSR signature verification failed', self.protocol)
            raise ValueError(msg) from exc
