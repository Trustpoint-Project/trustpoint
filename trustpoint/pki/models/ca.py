"""Module that contains the base CaModel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cryptography import x509
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid

from pki.models.certificate import CertificateModel
from pki.models.keyless_ca import KeylessCaModel
from trustpoint.logger import LoggerMixin
from util.db import CustomDeleteActionModel
from util.field import UniqueNameValidator

if TYPE_CHECKING:
    from django.db.models.query import QuerySet

    from pki.models.crl import CrlModel
    from pki.models.issuing_ca import IssuingCaModel


class CaModel(LoggerMixin, CustomDeleteActionModel):
    """CA Model representing any Certificate Authority.

    This model can represent two types of CAs:
    1. Keyless CAs: CAs where we only have the certificate (no private key).
       Used for trust anchors, upstream CAs, certificate chain validation.
    2. Issuing CAs: CAs managed by Trustpoint that can issue certificates.

    Exactly one of keyless_ca or issuing_ca_ref must be set (enforced via validation).
    CRLs can be associated with either type through the reverse relation.
    """

    unique_name = models.CharField(
        verbose_name=_('CA Name'),
        max_length=100,
        validators=[UniqueNameValidator()],
        unique=True,
        help_text=_('Unique identifier for this CA')
    )

    # Mutually exclusive: exactly one must be set
    keyless_ca = models.OneToOneField(
        KeylessCaModel,
        related_name='ca',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('Keyless CA'),
        help_text=_('The keyless CA (certificate without private key)')
    )

    issuing_ca_ref = models.OneToOneField(
        'IssuingCaModel',
        related_name='ca',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('Issuing CA'),
        help_text=_('The issuing CA (can issue certificates)')
    )

    parent_ca = models.ForeignKey(
        'self',
        related_name='child_cas',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('Parent CA'),
        help_text=_('The parent CA in the hierarchy (issuer of this CA)')
    )

    is_active = models.BooleanField(
        _('Active'),
        default=True,
        help_text=_('Whether this CA is currently active')
    )

    created_at = models.DateTimeField(
        verbose_name=_('Created'),
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        verbose_name=_('Updated'),
        auto_now=True
    )

    class Meta:
        """Meta options for CaModel."""

        verbose_name = _('Certificate Authority')
        verbose_name_plural = _('Certificate Authorities')
        ordering: ClassVar[list[str]] = ['unique_name']
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(keyless_ca__isnull=False, issuing_ca_ref__isnull=True) |
                    models.Q(keyless_ca__isnull=True, issuing_ca_ref__isnull=False)
                ),
                name='exactly_one_ca_type'
            )
        ]

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CaModel entry.

        Returns:
            str: Human-readable string that represents this CaModel entry.
        """
        return self.unique_name

    def __repr__(self) -> str:
        """Returns a string representation of the CaModel instance."""
        ca_type = 'issuing' if self.issuing_ca_ref else 'keyless'
        return f'CaModel(unique_name={self.unique_name}, type={ca_type})'

    @property
    def is_issuing_ca(self) -> bool:
        """Returns True if this is an issuing CA (can issue certificates)."""
        return self.issuing_ca_ref is not None

    @property
    def common_name(self) -> str:
        """Returns the common name from the CA certificate."""
        if self.keyless_ca:
            return self.keyless_ca.common_name
        return self.issuing_ca_ref.credential.certificate.common_name

    @property
    def subject_public_bytes(self) -> bytes:
        """Returns the subject public bytes from the CA certificate."""
        if self.keyless_ca:
            return self.keyless_ca.subject_public_bytes
        return self.issuing_ca_ref.credential.certificate.subject_public_bytes

    @property
    def certificate(self) -> CertificateModel:
        """Returns the certificate model."""
        if self.keyless_ca:
            return self.keyless_ca.certificate
        return self.issuing_ca_ref.credential.certificate

    @property
    def signature_suite(self) -> str:
        """Returns the signature suite (hash algorithm) for this CA."""
        if self.keyless_ca:
            # For keyless CAs, extract signature suite from certificate
            return str(oid.SignatureSuite.from_certificate(
                self.keyless_ca.certificate.get_certificate_serializer().as_crypto()))
        return str(oid.SignatureSuite.from_certificate(
            self.issuing_ca_ref.credential.get_certificate_serializer().as_crypto()))

    @property
    def issuing_ca_certificate(self) -> CertificateModel:
        """Returns the issuing CA certificate (same as certificate for issuing CAs)."""
        return self.certificate

    @property
    def root_ca_certificate(self) -> CertificateModel | None:
        """Returns the root CA certificate (last in chain)."""
        if self.keyless_ca:
            return self.keyless_ca.certificate
        chain = self.issuing_ca_ref.credential.ordered_certificate_chain_queryset
        if chain.exists():
            return chain.last().certificate
        return self.issuing_ca_ref.credential.certificate

    def get_issuing_ca(self) -> IssuingCaModel | None:
        """Returns the IssuingCaModel if this CA is an issuing CA.

        Returns:
            IssuingCaModel | None: The issuing CA or None if this is a keyless CA.
        """
        return self.issuing_ca_ref

    def clean(self) -> None:
        """Validates that exactly one of keyless_ca or issuing_ca_ref is set."""
        super().clean()
        if self.keyless_ca is None and self.issuing_ca_ref is None:
            raise ValidationError(_('Either keyless_ca or issuing_ca_ref must be set.'))
        if self.keyless_ca is not None and self.issuing_ca_ref is not None:
            raise ValidationError(_('Cannot set both keyless_ca and issuing_ca_ref.'))

    def save(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        """Override save to ensure validation."""
        self.clean()
        super().save(*args, **kwargs)

    @classmethod
    def create_from_keyless(
        cls,
        unique_name: str,
        certificate: x509.Certificate,
        crl_pem: str | None = None,
    ) -> CaModel:
        """Creates a new keyless CA model from a certificate.

        Args:
            unique_name: The unique name that will be used to identify the CA.
            certificate: The CA certificate as cryptography x509.Certificate.
            crl_pem: Optional CRL in PEM format (will be stored in a separate CrlModel).

        Returns:
            CaModel: The newly created CA model.

        Raises:
            ValidationError: If the certificate is not a valid CA certificate.
        """
        from pki.models.crl import CrlModel  # noqa: PLC0415

        keyless_ca = KeylessCaModel.create_from_certificate(certificate)

        ca = cls(
            unique_name=unique_name,
            keyless_ca=keyless_ca,
        )
        ca.save()

        if crl_pem:
            CrlModel.create_from_pem(ca=ca, crl_pem=crl_pem, set_active=True)

        return ca

    @classmethod
    def create_from_issuing(
        cls,
        unique_name: str,
        issuing_ca: IssuingCaModel,
    ) -> CaModel:
        """Creates a new CA model from an existing IssuingCaModel.

        Args:
            unique_name: The unique name that will be used to identify the CA.
            issuing_ca: The IssuingCaModel to wrap.

        Returns:
            CaModel: The newly created CA model.

        Raises:
            ValidationError: If the issuing CA already has a CaModel.
        """
        if hasattr(issuing_ca, 'ca') and issuing_ca.ca is not None:
            raise ValidationError(
                _('The issuing CA "%s" already has a CaModel.') % issuing_ca.unique_name
            )

        ca = cls(
            unique_name=unique_name,
            issuing_ca_ref=issuing_ca,
        )
        ca.save()

        return ca


    def import_crl(self, crl_pem: str, *, set_active: bool = True) -> CrlModel:
        """Imports a CRL for this CA.

        Args:
            crl_pem: The CRL in PEM format.
            set_active: If True, this CRL becomes the active one for the CA.

        Returns:
            CrlModel: The created CRL model.

        Raises:
            ValidationError: If the CRL is invalid or doesn't match this CA.
        """
        from pki.models.crl import CrlModel  # noqa: PLC0415

        return CrlModel.create_from_pem(ca=self, crl_pem=crl_pem, set_active=set_active)

    def get_active_crl(self) -> CrlModel | None:
        """Returns the currently active CRL for this CA.

        Returns:
            CrlModel | None: The active CRL or None if no CRL exists.
        """
        from pki.models.crl import CrlModel  # noqa: PLC0415

        try:
            return CrlModel.objects.get(ca=self, is_active=True)
        except CrlModel.DoesNotExist:
            return None

    def get_latest_crl(self) -> CrlModel | None:
        """Returns the most recent CRL for this CA (by this_update).

        Returns:
            CrlModel | None: The latest CRL or None if no CRL exists.
        """
        from pki.models.crl import CrlModel  # noqa: PLC0415

        return CrlModel.objects.filter(ca=self).order_by('-this_update').first()

    def get_crl_as_crypto(self) -> x509.CertificateRevocationList | None:
        """Returns the active CRL as a cryptography CertificateRevocationList object.

        Returns:
            x509.CertificateRevocationList | None: The CRL or None if no active CRL is available.
        """
        active_crl = self.get_active_crl()
        if not active_crl:
            return None
        return active_crl.get_crl_as_crypto()

    def get_issued_certificates(self) -> QuerySet[CertificateModel, CertificateModel]:
        """Returns certificates issued by this CA, except its own in case of a self-signed CA.

        This goes through all active certificates and checks issuance by this CA
        based on cert.issuer_public_bytes == ca.subject_public_bytes.

        Warning:
            This means that it may inadvertently return certificates
            that were issued by a different CA with the same subject name.

        Returns:
            QuerySet: Certificates issued by this CA.
        """
        ca_subject_public_bytes = self.subject_public_bytes

        return CertificateModel.objects.filter(issuer_public_bytes=ca_subject_public_bytes).exclude(
            subject_public_bytes=ca_subject_public_bytes
        )

    def get_hierarchy_depth(self) -> int:
        """Returns the depth of this CA in the hierarchy.

        Returns:
            int: The depth (0 for root CA, 1 for intermediate, etc.)
        """
        depth = 0
        current_ca = self
        while current_ca.parent_ca is not None:
            depth += 1
            current_ca = current_ca.parent_ca
        return depth

    def get_root_ca(self) -> CaModel:
        """Returns the root CA in the hierarchy.

        Returns:
            CaModel: The root CA (self if this is already a root CA).
        """
        current_ca = self
        while current_ca.parent_ca is not None:
            current_ca = current_ca.parent_ca
        return current_ca

    def get_all_child_cas(self, *, include_self: bool = False) -> QuerySet[CaModel, CaModel]:
        """Returns all descendant CAs (children, grandchildren, etc.).

        Args:
            include_self: If True, includes this CA in the result.

        Returns:
            QuerySet: All descendant CAs.
        """
        descendants = []
        if include_self:
            descendants.append(self.pk)

        def collect_descendants(ca: CaModel) -> None:
            for child in ca.child_cas.all():
                descendants.append(child.pk)
                collect_descendants(child)

        collect_descendants(self)
        return CaModel.objects.filter(pk__in=descendants)

    def get_hierarchy_path(self) -> list[CaModel]:
        """Returns the path from root CA to this CA.

        Returns:
            list[CaModel]: List of CAs from root to this CA (inclusive).
        """
        path: list[CaModel] = []
        current_ca: CaModel | None = self
        while current_ca is not None:
            path.insert(0, current_ca)
            current_ca = current_ca.parent_ca
        return path

    def is_root_ca(self) -> bool:
        """Returns True if this CA has no parent (is a root CA).

        Returns:
            bool: True if this is a root CA.
        """
        return self.parent_ca is None

    def pre_delete(self) -> None:
        """Checks for unexpired certificates issued by this CA and child CAs before deleting it.

        Raises:
            ValidationError: If there are unexpired certificates issued by this CA or if this CA has child CAs.
        """
        self.logger.info('Deleting CA %s', self)

        if self.child_cas.exists():
            child_names = ', '.join(child.unique_name for child in self.child_cas.all())
            exc_msg = f'Cannot delete the CA {self} because it has child CAs: {child_names}.'
            raise ValidationError(exc_msg)

        qs = self.get_issued_certificates()

        for cert in qs:
            if cert.certificate_status != CertificateModel.CertificateStatus.EXPIRED:
                exc_msg = f'Cannot delete the CA {self} because it has issued unexpired certificate {cert}.'
                raise ValidationError(exc_msg)

    def post_delete(self) -> None:
        """Deletes the underlying CA model (KeylessCaModel or IssuingCaModel) after deleting this CA."""
        if self.keyless_ca:
            self.logger.debug('Deleting KeylessCaModel of CA %s', self)
            self.keyless_ca.delete()
        elif self.issuing_ca_ref:
            self.logger.debug('Deleting IssuingCaModel of CA %s', self)
            self.issuing_ca_ref.delete()

