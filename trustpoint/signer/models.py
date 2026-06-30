"""Contains Models For Signers App."""

from __future__ import annotations

import datetime
import logging
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from django.db import DatabaseError, models
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid

from crypto.application.private_keys import (
    ManagedECPrivateKey,
    ManagedRSAPrivateKey,
    generate_managed_signing_private_key,
)
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.errors import CryptoError
from crypto.models import CryptoManagedKeyModel
from pki.models.credential import CredentialModel
from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    from trustpoint_core.serializer import CredentialSerializer

    from crypto.domain.specs import KeySpec

logger = logging.getLogger(__name__)


class SignerModel(CustomDeleteActionModel):
    """Contains fields for signer model."""
    unique_name = models.CharField(max_length=30, unique=True)

    credential = models.OneToOneField(
        CredentialModel,
        related_name='signer',
        on_delete=models.PROTECT,
    )
    is_active = models.BooleanField(
        _('Active'),
        default=True,
    )
    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)

    def __str__(self) -> str:
        """To represent the signer object with its unique name.

        Returns: Give out signer objects unique name.

        """
        return self.unique_name

    @property
    def common_name(self) -> str:
        """Returns common name."""
        return self.credential.certificate_or_error.common_name

    @property
    def signature_suite(self) -> oid.SignatureSuite:
        """The signature suite for the CA public key certificate."""
        return oid.SignatureSuite.from_certificate(self.credential.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        """The public key info for the CA certificate's public key."""
        return self.signature_suite.public_key_info

    @property
    def hash_algorithm(self) -> str:
        """Returns the hash algorithm name used by this signer's certificate."""
        if self.credential.hash_algorithm is None:
            return 'unknown'
        return self.credential.hash_algorithm.name

    @classmethod
    def create_new_signer(
        cls,
        unique_name: str,
        credential_serializer: CredentialSerializer,
    ) -> SignerModel:
        """Create a new SignerModel instance."""
        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )

        signer = cls(
            unique_name=unique_name,
            credential=credential_model,
        )
        signer.save()
        return signer

    @classmethod
    def create_backend_managed_signer(
        cls,
        *,
        unique_name: str,
        key_spec: KeySpec,
        validity_days: int = 3650,
    ) -> SignerModel:
        """Create a signer whose private key is owned by the configured crypto backend."""
        private_key = generate_managed_signing_private_key(
            alias=unique_name,
            key_spec=key_spec,
        )
        try:
            certificate = cls._create_self_signed_signer_certificate(
                unique_name=unique_name,
                private_key=private_key,
                validity_days=validity_days,
            )
            managed_key = CryptoManagedKeyModel.objects.get(pk=private_key.managed_key_ref.id)
            credential = CredentialModel.save_managed_key_credential(
                certificate=certificate,
                certificate_chain=[],
                credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
                managed_key=managed_key,
            )
            signer = cls(unique_name=unique_name, credential=credential)
            signer.save()
        except Exception:
            cls._cleanup_generated_managed_key(unique_name=unique_name, private_key=private_key)
            raise
        return signer

    @staticmethod
    def _cleanup_generated_managed_key(
        *,
        unique_name: str,
        private_key: ManagedRSAPrivateKey | ManagedECPrivateKey,
    ) -> None:
        """Best-effort cleanup for a generated backend key when signer persistence fails."""
        try:
            TrustpointCryptoBackend().destroy_managed_key(private_key.managed_key_ref)
        except (CryptoError, DatabaseError, RuntimeError, TypeError, ValueError):
            logger.warning(
                'Failed to clean up generated managed key for signer %r after creation failure.',
                unique_name,
                exc_info=True,
            )

    @staticmethod
    def _create_self_signed_signer_certificate(
        *,
        unique_name: str,
        private_key: ManagedRSAPrivateKey | ManagedECPrivateKey,
        validity_days: int,
    ) -> x509.Certificate:
        """Create a self-signed certificate suitable for hash signing."""
        one_day = datetime.timedelta(days=1)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, unique_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Trustpoint'),
            ]
        )
        public_key = private_key.public_key()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .not_valid_before(datetime.datetime.now(tz=datetime.UTC) - one_day)
            .not_valid_after(datetime.datetime.now(tz=datetime.UTC) + (one_day * validity_days))
            .serial_number(x509.random_serial_number())
            .public_key(public_key)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        )
        return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


class SignedMessageModel(models.Model):
    """Model to store signed messages, its signature and certificate(with public key)."""
    signer = models.ForeignKey(SignerModel, on_delete=models.CASCADE, related_name='signed_messages')
    hash_value = models.CharField(max_length=256)
    signature = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        """String representation of SignedMessage object.

        Returns: String formated name of signer and when it was signed.

        """
        return f'Signature by {self.signer.unique_name} on {self.created_at.strftime("%Y-%m-%d %H:%M:%S")}'
