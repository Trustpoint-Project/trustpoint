"""Contains Models For Signers App."""



from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid
from trustpoint_core.serializer import CredentialSerializer

from pki.models.credential import CredentialModel
from util.db import CustomDeleteActionModel


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
    ) -> 'SignerModel':
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
