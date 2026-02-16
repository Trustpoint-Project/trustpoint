"""Module that contains the CaModel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.credential import CredentialModel
from pki.models.crl import CrlModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from trustpoint.logger import LoggerMixin
from util.db import CustomDeleteActionModel
from util.field import UniqueNameValidator

if TYPE_CHECKING:
    import datetime

    from django.db.models.query import QuerySet
    from trustpoint_core.serializer import CredentialSerializer


class CaModel(LoggerMixin, CustomDeleteActionModel):
    """Generic CA Model representing any Certificate Authority.

    This unified model can represent two types of CAs:
    1. Keyless CAs: CAs where we only have the certificate (no private key).
       Used for trust anchors, upstream CAs, certificate chain validation.
    2. Issuing CAs: CAs managed by Trustpoint that can issue certificates.

    For keyless CAs: Only 'certificate' field is set, 'credential' is null, ca_type is KEYLESS.
    For issuing CAs: 'credential' and 'ca_type' are set, 'certificate' is null.
    """

    class CaTypeChoice(models.IntegerChoices):
        """The CaTypeChoice defines the type of CA.

        Depending on the type, different fields are required:
        - KEYLESS: Only certificate field is set (no private key)
        - LOCAL issuing types: credential field is set, certificate obtained locally
        - REMOTE issuing types: credential field is set, certificate requested remotely
        - REMOTE RA types: no credential/certificate, used for connection to external CAs as Registration Authority
        """

        KEYLESS = -1, _('Keyless CA')
        AUTOGEN_ROOT = 0, _('Auto-Generated Root') # Trustpoint = CA
        AUTOGEN = 1, _('Auto-Generated') # Trustpoint = CA
        LOCAL_UNPROTECTED = 2, _('Local-Unprotected') # Trustpoint = CA
        LOCAL_PKCS11 = 3, _('Local-PKCS11') # Trustpoint = CA
        REMOTE_EST_RA = 4, _('Remote-EST-RA') # Trustpoint = RA
        REMOTE_CMP_RA = 5, _('Remote-CMP-RA') # Trustpoint = RA
        REMOTE_ISSUING_EST = 6, _('Remote-Issuing-EST') # Trustpoint = CA
        REMOTE_ISSUING_CMP = 7, _('Remote-Issuing-CMP') # Trustpoint = CA


    unique_name = models.CharField(
        verbose_name=_('CA Name'),
        max_length=100,
        validators=[UniqueNameValidator()],
        unique=True,
        help_text=_('Unique identifier for this CA')
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

    # CA type field
    ca_type = models.IntegerField(
        verbose_name=_('CA Type'),
        choices=CaTypeChoice,
        null=True,
        blank=True,
        help_text=_('Type of CA - KEYLESS for keyless CAs')
    )

    # For keyless CAs: certificate without private key
    certificate = models.ForeignKey(
        CertificateModel,
        related_name='keyless_cas',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('CA Certificate'),
        help_text=_('The CA certificate (for keyless CAs)')
    )

    # For issuing CAs: full credential with private key
    credential: models.OneToOneField[CredentialModel | None] = models.OneToOneField(
        CredentialModel,
        related_name='issuing_ca',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('Credential'),
        help_text=_('The CA credential with private key (for issuing CAs)')
    )

    chain_truststore = models.OneToOneField(
        'pki.TruststoreModel',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='issuing_ca',
        verbose_name=_('Chain Truststore'),
        help_text=_('The truststore containing the full certificate chain for this CA.')
    )

    remote_host = models.CharField(
        verbose_name=_('Remote Host'),
        max_length=253,
        blank=True,
        default='',
        help_text=_('The hostname or IP address of the remote PKI')
    )

    remote_port = models.PositiveIntegerField(
        verbose_name=_('Remote Port'),
        blank=True,
        null=True,
        help_text=_('The port number of the remote PKI')
    )

    remote_path = models.CharField(
        verbose_name=_('Remote Path'),
        max_length=255,
        blank=True,
        default='',
        help_text=_('The path on the remote PKI')
    )

    est_username = models.CharField(
        verbose_name=_('EST Username'),
        max_length=128,
        blank=True,
        default='',
        help_text=_('Username for EST authentication')
    )

    onboarding_config = models.ForeignKey(
        'onboarding.OnboardingConfigModel',
        related_name='remote_cas',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('Onboarding Config'),
        help_text=_('Onboarding configuration for remote CA connection')
    )

    no_onboarding_config = models.ForeignKey(
        'onboarding.NoOnboardingConfigModel',
        related_name='remote_cas',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('No Onboarding Config'),
        help_text=_('No-onboarding configuration for remote CA connection')
    )

    class Meta:
        """Meta options for CaModel."""

        verbose_name = _('Certificate Authority')
        verbose_name_plural = _('Certificate Authorities')
        db_table = 'pki_genericcamodel'
        ordering: ClassVar[list[str]] = ['unique_name']
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=(
                    models.Q(ca_type=-1, certificate__isnull=False, credential__isnull=True) |
                    models.Q(ca_type__in=[4, 5], credential__isnull=True) |
                    models.Q(ca_type__in=[0, 1, 2, 3, 6, 7], certificate__isnull=True, credential__isnull=False)
                ),
                name='ca_mode_constraint',
                violation_error_message=_('Invalid CA configuration')
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
        return f'CaModel({self.unique_name})'


    @property
    def is_issuing_ca(self) -> bool:
        """Returns True if this is an issuing CA (can issue certificates)."""
        return self.ca_type not in (
            self.CaTypeChoice.KEYLESS,
            self.CaTypeChoice.REMOTE_CMP_RA,
            self.CaTypeChoice.REMOTE_EST_RA,
        )


    @property
    def is_keyless_ca(self) -> bool:
        """Returns True if this is a keyless CA, or a remote RA with a certificate."""
        return (
            self.certificate is not None and
            self.ca_type in (
                self.CaTypeChoice.KEYLESS,
                self.CaTypeChoice.REMOTE_CMP_RA,
                self.CaTypeChoice.REMOTE_EST_RA,
            )
        )


    @property
    def common_name(self) -> str:
        """Returns common name, or a placeholder if missing."""
        if self.is_keyless_ca:
            if self.certificate is not None:
                return self.certificate.common_name
            return f'{self.unique_name} (Certificate missing)'
        if self.credential is not None:
            if self.credential.certificate is not None:
                return self.credential.certificate_or_error.common_name
            return f'{self.unique_name} (Certificate pending)'
        return f'{self.unique_name} (Credential missing)'


    @property
    def subject_public_bytes(self) -> bytes:
        """Returns the subject public bytes from the CA certificate, or b'' if missing."""
        if self.is_keyless_ca:
            if self.certificate is not None:
                return bytes.fromhex(self.certificate.subject_public_bytes)
            return b''
        if self.credential is not None and self.credential.certificate is not None:
            return bytes.fromhex(self.credential.certificate_or_error.subject_public_bytes)
        return b''


    @property
    def ca_certificate_model(self) -> CertificateModel | None:
        """Returns the CA certificate model for both issuing and keyless CAs, or None if missing."""
        if self.is_issuing_ca and self.credential is not None and self.credential.certificate is not None:
            return self.credential.certificate_or_error
        if self.is_keyless_ca and self.certificate is not None:
            return self.certificate
        return None


    def get_certificate(self) -> x509.Certificate | None:
        """Returns the CA certificate (crypto object) for both issuing and keyless CAs, or None if missing."""
        cert_model = self.ca_certificate_model
        if cert_model is not None:
            return cert_model.get_certificate_serializer().as_crypto()
        return None


    def get_credential(self) -> CredentialModel | None:
        """Returns the credential for issuing CAs, or None if not present."""
        if self.is_keyless_ca:
            return None
        return self.credential

    def get_ca_chain_from_truststore(self) -> list[CaModel]:
        """Returns the CA chain from the associated chain_truststore.

        This method validates that the chain_truststore contains certificates that correspond to CAs
        in the hierarchy path, and returns the CA objects in issuing CA to root order.

        Returns:
            list[CaModel]: List of CA models from issuing CA to root CA.

        Raises:
            ValueError: If the chain_truststore is not properly configured or contains invalid certificates.
        """
        if not self.chain_truststore:
            msg = f'CA "{self.unique_name}" has no chain_truststore configured'
            raise ValueError(msg)

        ca_chain = []
        for truststore_order in self.chain_truststore.truststoreordermodel_set.order_by('order'):
            cert = truststore_order.certificate
            try:
                ca = CaModel.objects.get(
                    models.Q(credential__certificate=cert) | models.Q(certificate=cert)
                )
                ca_chain.append(ca)
            except CaModel.DoesNotExist as e:
                msg = f'Certificate in chain_truststore does not correspond to any CA: {cert.common_name}'
                raise ValueError(msg) from e

        ca_chain.reverse()
        return ca_chain

    @property
    def last_crl_issued_at(self) -> datetime.datetime | None:
        """Returns when the last CRL was issued (from active CRL).

        Returns:
            datetime | None: The this_update time of the active CRL, or None if no CRL exists.
        """
        active_crl = self.get_active_crl()
        return active_crl.this_update if active_crl else None

    @property
    def crl_number(self) -> int:
        """Returns the current CRL number (from active CRL).

        Returns:
            int: The CRL number of the active CRL, or 0 if no CRL exists.
        """
        active_crl = self.get_active_crl()
        return active_crl.crl_number if active_crl and active_crl.crl_number else 0

    @property
    def crl_pem(self) -> str:
        """Returns the active CRL in PEM format.

        Returns:
            str: The CRL in PEM format, or empty string if no CRL exists.
        """
        active_crl = self.get_active_crl()
        return active_crl.crl_pem if active_crl else ''

    def clean(self) -> None:
        """Validates that exactly one of certificate or credential is set."""
        super().clean()
        if self.ca_type in (self.CaTypeChoice.REMOTE_EST_RA, self.CaTypeChoice.REMOTE_CMP_RA):
            self._clean_remote_non_issuing_ca()
        elif self.ca_type in (self.CaTypeChoice.REMOTE_ISSUING_EST, self.CaTypeChoice.REMOTE_ISSUING_CMP):
            self._clean_remote_issuing_ca()
        else:
            self._clean_local_or_keyless_ca()

    def _clean_remote_non_issuing_ca(self) -> None:
        """Validates remote non-issuing CA fields."""
        if self.credential is not None:
            raise ValidationError(_('Remote CAs cannot have credential.'))
        if self.pk is not None and self.certificate is None:
            raise ValidationError(_('Remote CAs must have certificate set.'))
        if not self.remote_host:
            raise ValidationError(_('Remote host must be set for remote CAs.'))
        if self.remote_port is None:
            raise ValidationError(_('Remote port must be set for remote CAs.'))
        if not self.remote_path:
            raise ValidationError(_('Remote path must be set for remote CAs.'))
        if not (self.onboarding_config or self.no_onboarding_config):
            raise ValidationError(_('Either onboarding or no-onboarding config must be set for remote CAs.'))
        if self.onboarding_config and self.no_onboarding_config:
            raise ValidationError(_('Only one of onboarding or no-onboarding config can be set for remote CAs.'))

    def _clean_remote_issuing_ca(self) -> None:
        """Validates remote issuing CA fields."""
        if self.certificate is not None:
            raise ValidationError(_('Remote issuing CAs cannot have certificate set.'))
        # Allow credential to be None for unsaved instances (will be set in form save method)
        if self.pk is not None and self.credential is None:
            raise ValidationError(_('Remote issuing CAs must have credential set.'))
        if self.ca_type is None:
            raise ValidationError(_('ca_type must be set for remote issuing CAs.'))
        if not self.remote_host:
            raise ValidationError(_('Remote host must be set for remote issuing CAs.'))
        if self.remote_port is None:
            raise ValidationError(_('Remote port must be set for remote issuing CAs.'))
        if not self.remote_path:
            raise ValidationError(_('Remote path must be set for remote issuing CAs.'))
        if self.ca_type == self.CaTypeChoice.REMOTE_ISSUING_EST and not self.est_username:
            raise ValidationError(_('EST username must be set for remote EST issuing CAs.'))
        if self.pk is not None and not (self.onboarding_config or self.no_onboarding_config):
            raise ValidationError(_('Either onboarding or no-onboarding config must be set for remote issuing CAs.'))
        if self.onboarding_config and self.no_onboarding_config:
            raise ValidationError(_('Only one onboarding config can be set for remote issuing CAs.'))

    def _clean_local_or_keyless_ca(self) -> None:
        """Validates local or keyless CA fields."""
        if self.certificate is None and self.credential is None:
            raise ValidationError(_('Either certificate (keyless CA) or credential (issuing CA) must be set.'))
        if self.certificate is not None and self.credential is not None:
            raise ValidationError(_('Cannot set both certificate and credential.'))
        if self.credential is not None and self.ca_type is None:
            raise ValidationError(_('ca_type must be set for issuing CAs.'))
        if self.certificate is not None and self.ca_type != self.CaTypeChoice.KEYLESS:
            raise ValidationError(_('ca_type must be KEYLESS for keyless CAs.'))
        # Remote fields should not be set for local/keyless CAs
        if (self.remote_host or self.remote_port is not None or self.remote_path or self.est_username or
            self.onboarding_config or self.no_onboarding_config):
            raise ValidationError(_('Remote fields can only be set for remote CAs.'))

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Override save to ensure validation."""
        self.clean()
        super().save(*args, **kwargs)

    @classmethod
    def create_keyless_ca(
        cls,
        unique_name: str,
        certificate_obj: x509.Certificate,
        parent_ca: CaModel | None = None,
    ) -> CaModel:
        """Creates a new keyless CA from a certificate.

        Args:
            unique_name: The unique name that will be used to identify the CA.
            certificate_obj: The CA certificate as cryptography x509.Certificate.
            parent_ca: Optional parent CA in the hierarchy.

        Returns:
            CaModel: The newly created keyless CA.

        Raises:
            ValidationError: If the certificate is not a valid CA certificate.
        """
        try:
            bc_extension = certificate_obj.extensions.get_extension_for_class(x509.BasicConstraints)
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

        cert_model = CertificateModel.save_certificate(certificate_obj)

        keyless_ca = cls(
            unique_name=unique_name,
            certificate=cert_model,
            parent_ca=parent_ca,
            ca_type=cls.CaTypeChoice.KEYLESS,  # Keyless CAs use KEYLESS type
        )
        keyless_ca.save()
        return keyless_ca

    @classmethod
    def create_new_issuing_ca(
        cls,
        credential_serializer: CredentialSerializer,
        ca_type: CaModel.CaTypeChoice | None = None,
        unique_name: str | None = None,
        parent_ca: CaModel | None = None,
    ) -> CaModel:
        """Creates a new Issuing CA model.

        Args:
            credential_serializer:
                The credential as CredentialSerializer instance.
                It will be normalized and validated, if it is a valid credential to be used as an Issuing CA.
            ca_type: The CA type (must be an issuing type, not KEYLESS).
            unique_name:
                The unique name for the CA.
                If not provided, will be auto-generated from certificate common name.
            parent_ca: Optional parent CA in the hierarchy.

        Returns:
            CaModel: The newly created Issuing CA model.

        Raises:
            ValidationError: If the certificate is not a valid CA certificate.
            ValueError: If the CA type is not supported
        """
        if ca_type is None:
            msg = 'Must specify ca_type parameter.'
            raise ValueError(msg)
        ca_cert = credential_serializer.certificate
        if not ca_cert:
            raise ValidationError(_('The provided credential is not a valid CA; it does not contain a certificate.'))

        # Auto-generate unique_name from certificate if not provided
        if unique_name is None:
            from cryptography.x509.oid import NameOID  # noqa: PLC0415
            try:
                cn_attrs = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                unique_name = str(cn_attrs[0].value) if cn_attrs else 'CA'
            except Exception:  # noqa: BLE001
                unique_name = 'CA'
        if unique_name is None:
            raise ValidationError(_('Unable to generate unique name for CA.'))
        try:
            bc_extension = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
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

        ca_types = (
            cls.CaTypeChoice.AUTOGEN_ROOT,
            cls.CaTypeChoice.AUTOGEN,
            cls.CaTypeChoice.LOCAL_UNPROTECTED,
            cls.CaTypeChoice.LOCAL_PKCS11,
            cls.CaTypeChoice.REMOTE_ISSUING_EST,
            cls.CaTypeChoice.REMOTE_ISSUING_CMP,
        )
        if ca_type not in ca_types:
            exc_msg = f'CA Type {ca_type} is not supported for issuing CAs.'
            raise ValueError(exc_msg)

        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential_serializer, credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA
        )

        issuing_ca = cls(
            unique_name=unique_name,
            credential=credential_model,
            ca_type=ca_type,
            parent_ca=parent_ca,
        )
        issuing_ca.save()

        chain = issuing_ca.get_hierarchy_path()
        cert_models = [ca.ca_certificate_model for ca in chain]
        truststore = TruststoreModel.objects.create(
            unique_name=f'{unique_name}_chain',
            intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN,
        )
        for idx, cert in enumerate(cert_models):
            if cert:  # Only add non-None certificates
                TruststoreOrderModel.objects.create(
                    order=idx,
                    certificate=cert,
                    trust_store=truststore
                )
        issuing_ca.chain_truststore = truststore
        issuing_ca.save(update_fields=['chain_truststore'])

        return issuing_ca

    def _issue_crl(self, crl_validity_hours: int = 24) -> None:
        """Issues a CRL with revoked certificates issued by this CA.

        Only issuing CAs can issue CRLs (keyless CAs don't have private keys).

        Args:
            crl_validity_hours: Hours until the next CRL update (nextUpdate field). Defaults to 24.

        Raises:
            AttributeError: If called on a keyless CA.
        """
        from pki.util.crl import generate_crl_with_revoked_certs  # noqa: PLC0415

        crl = generate_crl_with_revoked_certs(self, crl_validity_hours)

        crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM).decode()

        CrlModel.create_from_pem(ca=self, crl_pem=crl_pem, set_active=True)

        self.logger.info('CRL generation for CA %s finished.', self.unique_name)

    def issue_crl(self, crl_validity_hours: int = 24) -> bool:
        """Issues a CRL with revoked certificates issued by this CA.

        Args:
            crl_validity_hours: Hours until the next CRL update (nextUpdate field). Defaults to 24.

        Returns:
            bool: True if the CRL was successfully issued, False otherwise.
        """
        self.logger.debug('Generating CRL for CA %s', self.unique_name)
        try:
            self._issue_crl(crl_validity_hours=crl_validity_hours)
            self.logger.info('CRL generation for CA %s finished.', self.unique_name)
        except Exception:
            self.logger.exception('CRL generation for CA %s failed', self.unique_name)
            return False

        return True

    @property

    def signature_suite(self) -> oid.SignatureSuite | None:
        """The signature suite for the CA public key certificate, or None if missing."""
        if self.is_keyless_ca:
            if self.certificate is not None:
                return oid.SignatureSuite.from_certificate(self.certificate.get_certificate_serializer().as_crypto())
            return None
        if self.credential is not None and self.credential.certificate is not None:
            return oid.SignatureSuite.from_certificate(self.credential.get_certificate_serializer().as_crypto())
        return None

    @property
    def public_key_info(self) -> oid.PublicKeyInfo | None:
        """The public key info for the CA certificate's public key.

        Returns None if the CA doesn't have a certificate yet (e.g., remote CA pending).
        """
        if self.signature_suite is None:
            return None
        return self.signature_suite.public_key_info

    def get_issued_certificates(self) -> QuerySet[CertificateModel, CertificateModel]:
        """Returns certificates issued by this CA, except its own in case of a self-signed CA.

        This goes through all active certificates and checks issuance by this CA
        based on cert.issuer_public_bytes == ca.subject_public_bytes.

        Warning:
            This means that it may inadvertently return certificates
            that were issued by a different CA with the same subject name.

        Returns:
            QuerySet: Certificates issued by this CA, or empty queryset for RAs/keyless CAs.
        """
        # RAs and keyless CAs don't issue certificates themselves
        if self.is_keyless_ca or self.credential is None:
            return CertificateModel.objects.none()
        if self.credential.certificate is None:
            return CertificateModel.objects.none()
        ca_subject_public_bytes = self.credential.certificate_or_error.subject_public_bytes

        # do not return self-signed CA certificate
        return CertificateModel.objects.filter(issuer_public_bytes=ca_subject_public_bytes).exclude(
            subject_public_bytes=ca_subject_public_bytes
        )

    # ===== CRL Helper Methods =====

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

    # ===== Hierarchy Methods =====

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
        if self.parent_ca is not None:
            return False

        if not self.ca_certificate_model:
            msg = f'Cannot determine if CA {self.unique_name} is a root CA: no certificate model'
            raise ValueError(msg)

        try:
            ca_cert = self.ca_certificate_model.get_certificate_serializer().as_crypto()
        except (AttributeError, ValueError) as err:
            msg = f'Cannot determine if CA {self.unique_name} is a root CA: unable to access certificate'
            raise ValueError(msg) from err

        try:
            ca_cert.verify_directly_issued_by(ca_cert)
        except InvalidSignature:
            return False
        else:
            return True

    def revoke_all_issued_certificates(self, reason: str = RevokedCertificateModel.ReasonCode.UNSPECIFIED) -> None:
        """Revokes all certificates issued by this CA."""
        qs = self.get_issued_certificates()

        for cert in qs:
            if (cert.certificate_status
                not in [CertificateModel.CertificateStatus.OK, CertificateModel.CertificateStatus.NOT_YET_VALID]):
                continue
            RevokedCertificateModel.objects.create(certificate=cert, revocation_reason=reason, ca=self)

        self.logger.info('All %i certificates issued by CA %s have been revoked.', qs.count(), self.unique_name)
        self.issue_crl()

    def pre_delete(self) -> None:
        """Checks for unexpired certificates issued by this CA and child CAs before deleting it.

        Raises:
            ValidationError: If there are unexpired certificates issued by this CA or if this CA has child CAs.
        """
        self.logger.info('Deleting CA %s', self)

        # Check for child CAs
        if self.child_cas.exists():
            child_names = ', '.join(child.unique_name for child in self.child_cas.all())
            exc_msg = f'Cannot delete the CA {self} because it has child CAs: {child_names}.'
            raise ValidationError(exc_msg)

        # Check for unexpired certificates
        qs = self.get_issued_certificates()

        for cert in qs:
            if cert.certificate_status != CertificateModel.CertificateStatus.EXPIRED:
                exc_msg = f'Cannot delete the CA {self} because it has issued unexpired certificate {cert}.'
                raise ValidationError(exc_msg)

    def post_delete(self) -> None:
        """Deletes the underlying credential or certificate after deleting this CA."""
        if self.is_keyless_ca:
            self.logger.debug('Deleting certificate of keyless CA %s', self)
            if self.certificate:
                self.certificate.delete()
        elif self.is_issuing_ca:
            self.logger.debug('Deleting credential of issuing CA %s', self)
            if self.credential:
                self.credential.delete()

    @property
    def display_not_valid_after(self) -> datetime.datetime | None:
        """Returns the not valid after date for display purposes."""
        if self.credential and self.credential.certificate:
            return self.credential.certificate.not_valid_after
        if self.certificate:
            return self.certificate.not_valid_after
        return None
