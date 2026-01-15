"""Module that contains the IssuingCaModel."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, get_args

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.credential import CredentialModel
from trustpoint.logger import LoggerMixin
from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    from django.db.models.query import QuerySet
    from trustpoint_core.serializer import CredentialSerializer


class IssuingCaModel(LoggerMixin, CustomDeleteActionModel):
    """Issuing CA Model.

    This model contains the configurations of all Issuing CAs available within the Trustpoint.
    """

    class IssuingCaTypeChoice(models.IntegerChoices):
        """The IssuingCaTypeChoice defines the type of Issuing CA.

        Depending on the type other fields may be set, e.g. a credential will only be available for local
        Issuing CAs.
        """

        AUTOGEN_ROOT = 0, _('Auto-Generated Root')
        AUTOGEN = 1, _('Auto-Generated')
        LOCAL_UNPROTECTED = 2, _('Local-Unprotected')
        LOCAL_PKCS11 = 3, _('Local-PKCS11')
        REMOTE_EST = 4, _('Remote-EST')
        REMOTE_CMP = 5, _('Remote-CMP')

    credential: models.OneToOneField[CredentialModel] = models.OneToOneField(
        CredentialModel,
        related_name='issuing_cas',
        on_delete=models.PROTECT,
    )

    issuing_ca_type = models.IntegerField(
        verbose_name=_('Issuing CA Type'), choices=IssuingCaTypeChoice, null=False, blank=False
    )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this IssuingCaModel entry.

        Returns:
            str: Human-readable string that represents this IssuingCaModel entry.
        """
        if hasattr(self, 'ca') and self.ca:
            return self.ca.unique_name
        return f'IssuingCaModel(id={self.pk})'

    def __repr__(self) -> str:
        """Returns a string representation of the IssuingCaModel instance."""
        unique_name = self.ca.unique_name if hasattr(self, 'ca') and self.ca else f'id={self.pk}'
        return f'IssuingCaModel({unique_name})'

    @property
    def unique_name(self) -> str:
        """Returns the unique name from the CaModel.

        Returns:
            str: The unique name of this CA.

        Raises:
            AttributeError: If this IssuingCaModel is not wrapped in a CaModel.
        """
        if hasattr(self, 'ca') and self.ca:
            return self.ca.unique_name
        msg = 'This IssuingCaModel does not have a CaModel. Create a CaModel wrapper to access unique_name.'
        raise AttributeError(msg)

    @unique_name.setter
    def unique_name(self, value: str) -> None:
        """Sets the unique name in the CaModel.

        Args:
            value: The new unique name.

        Raises:
            AttributeError: If this IssuingCaModel is not wrapped in a CaModel.
        """
        if hasattr(self, 'ca') and self.ca:
            self.ca.unique_name = value
            self.ca.save()
        else:
            msg = 'This IssuingCaModel does not have a CaModel. Create a CaModel wrapper to set unique_name.'
            raise AttributeError(msg)

    @property
    def is_active(self) -> bool:
        """Returns whether this CA is active from the CaModel.

        Returns:
            bool: True if the CA is active.

        Raises:
            AttributeError: If this IssuingCaModel is not wrapped in a CaModel.
        """
        if hasattr(self, 'ca') and self.ca:
            return self.ca.is_active
        msg = 'This IssuingCaModel does not have a CaModel. Create a CaModel wrapper to access is_active.'
        raise AttributeError(msg)

    @is_active.setter
    def is_active(self, value: bool) -> None:
        """Sets the is_active in the CaModel.

        Args:
            value: The new is_active value.

        Raises:
            AttributeError: If this IssuingCaModel is not wrapped in a CaModel.
        """
        if hasattr(self, 'ca') and self.ca:
            self.ca.is_active = value
            self.ca.save()
        else:
            msg = 'This IssuingCaModel does not have a CaModel. Create a CaModel wrapper to set is_active.'
            raise AttributeError(msg)

    @property
    def common_name(self) -> str:
        """Returns common name."""
        return self.credential.certificate.common_name

    @property
    def last_crl_issued_at(self) -> datetime.datetime | None:
        """Returns when the last CRL was issued (from active CRL).

        Returns:
            datetime | None: The this_update time of the active CRL, or None if no CRL exists.
        """
        if not hasattr(self, 'ca') or not self.ca:
            return None
        active_crl = self.ca.get_active_crl()
        return active_crl.this_update if active_crl else None

    @property
    def crl_number(self) -> int:
        """Returns the current CRL number (from active CRL).

        Returns:
            int: The CRL number of the active CRL, or 0 if no CRL exists.
        """
        if not hasattr(self, 'ca') or not self.ca:
            return 0
        active_crl = self.ca.get_active_crl()
        return active_crl.crl_number if active_crl and active_crl.crl_number else 0

    @property
    def crl_pem(self) -> str:
        """Returns the active CRL in PEM format.

        Returns:
            str: The CRL in PEM format, or empty string if no CRL exists.
        """
        if not hasattr(self, 'ca') or not self.ca:
            return ''
        active_crl = self.ca.get_active_crl()
        return active_crl.crl_pem if active_crl else ''

    @classmethod
    def create_new_issuing_ca(
        cls,
        credential_serializer: CredentialSerializer,
        issuing_ca_type: IssuingCaModel.IssuingCaTypeChoice,
    ) -> IssuingCaModel:
        """Creates a new Issuing CA model and returns it.

        Note: This creates only the IssuingCaModel. You should wrap it in a CaModel
        to manage unique_name, is_active, and timestamps.

        Args:
            credential_serializer:
                The credential as CredentialSerializer instance.
                It will be normalized and validated, if it is a valid credential to be used as an Issuing CA.
            issuing_ca_type: The Issuing CA type.

        Returns:
            IssuingCaModel: The newly created Issuing CA model.
        """
        ca_cert = credential_serializer.certificate
        if not ca_cert:
            raise ValidationError(_('The provided credential is not a valid CA; it does not contain a certificate.'))
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

        issuing_ca_types = (
            cls.IssuingCaTypeChoice.AUTOGEN_ROOT,
            cls.IssuingCaTypeChoice.AUTOGEN,
            cls.IssuingCaTypeChoice.LOCAL_UNPROTECTED,
            cls.IssuingCaTypeChoice.LOCAL_PKCS11,
        )
        if issuing_ca_type in issuing_ca_types:
            credential_type = CredentialModel.CredentialTypeChoice.ISSUING_CA
        else:
            exc_msg = f'Issuing CA Type {issuing_ca_type} is not yet supported.'
            raise ValueError(exc_msg)

        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential_serializer, credential_type=credential_type
        )

        issuing_ca = cls(
            credential=credential_model,
            issuing_ca_type=issuing_ca_type,
        )
        issuing_ca.save()
        return issuing_ca

    def _issue_crl(self, crl_validity_hours: int = 24) -> None:
        """Issues a CRL with revoked certificates issued by this CA.

        CRLs are now managed through CrlModel via the CaModel relationship.
        This method maintains backward compatibility.

        Args:
            crl_validity_hours: Hours until the next CRL update (nextUpdate field). Defaults to 24.
        """
        # Check if this IssuingCaModel has a CaModel wrapper
        if not hasattr(self, 'ca') or not self.ca:
            msg = 'This IssuingCaModel must be wrapped in a CaModel to issue CRLs.'
            raise AttributeError(msg)

        from pki.models.crl import CrlModel  # noqa: PLC0415

        crl_issued_at = timezone.now()
        ca_subject = self.credential.certificate.get_certificate_serializer().as_crypto().subject

        latest_crl = self.ca.get_latest_crl()
        next_crl_number = (latest_crl.crl_number + 1) if latest_crl and latest_crl.crl_number else 1

        crl_builder = x509.CertificateRevocationListBuilder(
            issuer_name=ca_subject,
            last_update=crl_issued_at,
            next_update=crl_issued_at + datetime.timedelta(hours=crl_validity_hours),
        )
        crl_builder = crl_builder.add_extension(x509.CRLNumber(next_crl_number), critical=False)

        crl_certificates = self.revoked_certificates.all()

        for cert in crl_certificates:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(cert.certificate.serial_number, 16))
                .revocation_date(cert.revoked_at)
                .add_extension(x509.CRLReason(x509.ReasonFlags(cert.revocation_reason)), critical=False)
                .build()
            )
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        hash_algorithm = self.credential.hash_algorithm

        if hash_algorithm is not None and not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
            err_msg = f'CRL: Hash algo must be one of {AllowedCertSignHashAlgos}, but found {type(hash_algorithm)}'
            raise TypeError(err_msg)

        priv_k = self.credential.get_private_key_serializer().as_crypto()

        crl = crl_builder.sign(private_key=priv_k, algorithm=hash_algorithm)

        crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM).decode()

        CrlModel.create_from_pem(ca=self.ca, crl_pem=crl_pem, set_active=True)

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
    def signature_suite(self) -> oid.SignatureSuite:
        """The signature suite for the CA public key certificate."""
        return oid.SignatureSuite.from_certificate(self.credential.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        """The public key info for the CA certificate's public key."""
        return self.signature_suite.public_key_info

    def get_issued_certificates(self) -> QuerySet[CertificateModel, CertificateModel]:
        """Returns certificates issued by this CA, except its own in case of a self-signed CA.

        This goes through all active certificates and checks issuance by this CA
        based on cert.issuer_public_bytes == ca.subject_public_bytes
        WARNING: This means that it may inadvertently return certificates
        that were issued by a different CA with the same subject name
        """
        ca_subject_public_bytes = self.credential.certificate.subject_public_bytes

        # do not return self-signed CA certificate
        return CertificateModel.objects.filter(issuer_public_bytes=ca_subject_public_bytes).exclude(
            subject_public_bytes=ca_subject_public_bytes
        )

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
        """Check for unexpired certificates issued by this CA before deleting it."""
        self.logger.info('Deleting Issuing CA %s', self)
        qs = self.get_issued_certificates()

        for cert in qs:
            if cert.certificate_status != CertificateModel.CertificateStatus.EXPIRED:
                exc_msg = f'Cannot delete the Issuing CA {self} because it has issued unexpired certificate {cert}.'
                raise ValidationError(exc_msg)

    def post_delete(self) -> None:
        """Deletes the credential of this CA after deleting it."""
        self.logger.debug('Deleting credential of Issuing CA %s', self)
        self.credential.delete()
