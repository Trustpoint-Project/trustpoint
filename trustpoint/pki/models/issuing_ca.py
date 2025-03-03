"""Module that contains the IssuingCaModel."""
from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from util.field import UniqueNameValidator
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.credential import CredentialModel
from pki.util.keys import CryptographyUtils
from trustpoint.views.base import LoggerMixin

if TYPE_CHECKING:
    from trustpoint_core.serializer import CredentialSerializer

class IssuingCaModel(LoggerMixin, models.Model):
    """Issuing CA Model.

    This model contains the configurations of all Issuing CAs available within the Trustpoint.
    """

    objects: models.Manager[IssuingCaModel]

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

    unique_name = models.CharField(
        verbose_name=_('Issuing CA Name'),
        max_length=100,
        validators=[UniqueNameValidator()],
        unique=True)
    credential = models.OneToOneField(CredentialModel, related_name='issuing_cas', on_delete=models.PROTECT)

    issuing_ca_type = models.IntegerField(
        verbose_name=_('Issuing CA Type'),
        choices=IssuingCaTypeChoice,
        null=False, blank=False
    )

    is_active = models.BooleanField(
        _('Active'),
        default=True,
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)
    last_crl_issued_at = models.DateTimeField(verbose_name=_('Last CRL Issued'), null=True, blank=True)

    crl_pem = models.TextField(editable=False, default='', verbose_name=_('CRL in PEM format'))

    def __str__(self) -> str:
        """Returns a human-readable string that represents this IssuingCaModel entry.

        Returns:
            str: Human-readable string that represents this IssuingCaModel entry.
        """
        return self.unique_name

    def __repr__(self) -> str:
        return f'IssuingCaModel(unique_name={self.unique_name})'

    @property
    def common_name(self) -> str:
        """Returns common name"""
        return self.credential.certificate.common_name

    @classmethod
    @LoggerMixin.log_exceptions
    def create_new_issuing_ca(
            cls,
            unique_name: str,
            credential_serializer: CredentialSerializer,
            issuing_ca_type: IssuingCaModel.IssuingCaTypeChoice) -> IssuingCaModel:
        """Creates a new Issuing CA model and returns it.

        Args:
            unique_name: The unique name that will be used to identify the Issuing CA.
            credential_serializer:
                The credential as CredentialSerializer instance.
                It will be normalized and validated, if it is a valid credential to be used as an Issuing CA.
            issuing_ca_type: The Issuing CA type.

        Returns:
            IssuingCaModel: The newly created Issuing CA model.
        """
        issuing_ca_types = (
            cls.IssuingCaTypeChoice.AUTOGEN_ROOT,
            cls.IssuingCaTypeChoice.AUTOGEN,
            cls.IssuingCaTypeChoice.LOCAL_UNPROTECTED,
            cls.IssuingCaTypeChoice.LOCAL_PKCS11
        )
        if issuing_ca_type in issuing_ca_types:
            credential_type = CredentialModel.CredentialTypeChoice.ISSUING_CA
        else:
            exc_msg = f'Issuing CA Type {issuing_ca_type} is not yet supported.'
            raise ValueError(exc_msg)

        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential_serializer,
            credential_type=credential_type
        )

        issuing_ca = cls(
            unique_name=unique_name,
            credential=credential_model,
            issuing_ca_type=issuing_ca_type,
        )
        issuing_ca.save()
        return issuing_ca

    def issue_crl(self) -> bool:
        """Issues a CRL with revoked certificates issued by this CA."""
        self.logger.debug('Generating CRL for CA %s', self.unique_name)

        try:
            crl_issued_at = timezone.now()
            self.last_crl_issued_at = crl_issued_at

            ca_subject = self.credential.certificate.get_certificate_serializer().as_crypto().subject

            crl_builder = x509.CertificateRevocationListBuilder(
                issuer_name=ca_subject,
                last_update=crl_issued_at,
                next_update=crl_issued_at + datetime.timedelta(hours=24) #(minutes=self.next_crl_generation_time)
            )

            crl_certificates = self.revoked_certificates.all()

            for cert in crl_certificates:
                revoked_cert = (x509.RevokedCertificateBuilder()
                    .serial_number(int(cert.certificate.serial_number, 16))
                    .revocation_date(cert.revoked_at)
                    .add_extension(x509.CRLReason(
                        x509.ReasonFlags(cert.revocation_reason)), critical=False)
                    .build()
                )
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

            hash_algorithm = CryptographyUtils.get_hash_algorithm_from_credential(credential=self.credential)

            priv_k = self.credential.get_private_key_serializer().as_crypto()

            crl = crl_builder.sign(
                private_key=priv_k,
                algorithm=hash_algorithm
            )

            self.crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM).decode()
            self.save()

            self.logger.info('CRL generation for CA %s finished.', self.unique_name)
        except Exception:
            self.logger.exception('CRL generation for CA %s failed', self.unique_name)
            return False

        return True

    @property
    def signature_suite(self) -> oid.SignatureSuite:
        return oid.SignatureSuite.from_certificate(self.credential.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        return self.signature_suite.public_key_info

    def revoke_all_issued_certificates(self, reason: str = RevokedCertificateModel.ReasonCode.UNSPECIFIED) -> None:
        """Revokes all certificates issued by this CA."""
        # Note: This goes through all active certificates and checks issuance by this CA based on cert.issuer_public_bytes == ca.subject_public_bytes
        # WARNING: This means that it may inadvertently revoke certificates that were issued by a different CA with the same subject name
        ca_subject_public_bytes = self.credential.certificate.subject_public_bytes
        qs = CertificateModel.objects.filter(issuer_public_bytes=ca_subject_public_bytes) \
                                     .exclude(subject_public_bytes=ca_subject_public_bytes) # do not self-revoke self-signed CA certificate

        for cert in qs:
            if cert.certificate_status != CertificateModel.CertificateStatus.OK:
                continue
            RevokedCertificateModel.objects.create(
                certificate=cert,
                revocation_reason=reason,
                ca=self
            )

        self.logger.info('All %i certificates issued by CA %s have been revoked.', qs.count(), self.unique_name)
        self.issue_crl()