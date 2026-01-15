"""Module that contains the KeylessCaModel."""

from __future__ import annotations

from cryptography import x509
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from pki.models.certificate import CertificateModel
from trustpoint.logger import LoggerMixin
from util.db import CustomDeleteActionModel


class KeylessCaModel(LoggerMixin, CustomDeleteActionModel):
    """Keyless CA Model.

    This model stores CA certificate and optional certificate chain for CAs
    where we cannot issue certificates (no private key/credential).
    Similar to CredentialModel but without the private key component.
    """

    certificate = models.ForeignKey(
        CertificateModel,
        related_name='certificate_only_ca',
        on_delete=models.PROTECT,
        verbose_name=_('CA Certificate'),
        help_text=_('The CA certificate')
    )

    class Meta:
        """Meta options for KeylessCaModel."""

        verbose_name = _('Keyless CA')
        verbose_name_plural = _('Keyless CAs')

    def __str__(self) -> str:
        """Returns a human-readable string representation.

        Returns:
            str: Human-readable string representation.
        """
        return f'CertificateOnlyCa({self.certificate.common_name})'

    def __repr__(self) -> str:
        """Returns a string representation of the instance."""
        return f'CertificateOnlyCaModel(id={self.pk}, certificate={self.certificate_id})'

    @classmethod
    def create_from_certificate(
        cls,
        certificate: x509.Certificate,
    ) -> KeylessCaModel:
        """Creates a new KeylessCaModel from a certificate.

        Args:
            certificate: The CA certificate as cryptography x509.Certificate.

        Returns:
            CertificateOnlyCaModel: The newly created certificate-only CA model.

        Raises:
            ValidationError: If the certificate is not a valid CA certificate.
        """
        try:
            bc_extension = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound as e:
            raise ValidationError(
                _(
                    'The provided certificate is not a valid CA certificate; '
                    'it does not contain a Basic Constraints extension.'
                )
            ) from e

        if not bc_extension.value.ca:
            raise ValidationError(
                _(
                    'The provided certificate is not a valid CA certificate; '
                    'it is an End Entity certificate.'
                )
            )

        cert_model = CertificateModel.save_certificate(certificate)

        cert_only_ca = cls(
            certificate=cert_model,
        )
        cert_only_ca.save()
        return cert_only_ca

    @property
    def common_name(self) -> str:
        """Returns the common name from the CA certificate."""
        return self.certificate.common_name

    @property
    def subject_public_bytes(self) -> bytes:
        """Returns the subject public bytes from the CA certificate."""
        return self.certificate.subject_public_bytes

    def get_certificate_crypto(self) -> x509.Certificate:
        """Returns the certificate as a cryptography object.

        Returns:
            x509.Certificate: The CA certificate.
        """
        return self.certificate.get_certificate_serializer().as_crypto()

    def pre_delete(self) -> None:
        """Called before deleting the model."""
        self.logger.info('Deleting KeylessCaModel for certificate %s', self.certificate.common_name)

    def post_delete(self) -> None:
        """Called after deleting the model.

        Note: We don't delete the certificate as it might be referenced elsewhere.
        """
