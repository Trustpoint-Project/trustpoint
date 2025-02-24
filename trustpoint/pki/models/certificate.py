"""Module that contains the CertificateModel."""
from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from core.oid import (
    AlgorithmIdentifier,
    CertificateExtensionOid,
    NamedCurve,
    NameOid,
    PublicKeyAlgorithmOid,
    PublicKeyInfo,
    SignatureSuite,
)
from core.serializer import CertificateSerializer, PublicKeySerializer
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _

from pki.models.extension import (
    AttributeTypeAndValue,
    AuthorityInformationAccessExtension,
    AuthorityKeyIdentifierExtension,
    BasicConstraintsExtension,
    CertificatePoliciesExtension,
    CrlDistributionPointsExtension,
    ExtendedKeyUsageExtension,
    FreshestCrlExtension,
    InhibitAnyPolicyExtension,
    IssuerAlternativeNameExtension,
    KeyUsageExtension,
    NameConstraintsExtension,
    PolicyConstraintsExtension,
    SubjectAlternativeNameExtension,
    SubjectDirectoryAttributesExtension,
    SubjectInformationAccessExtension,
    SubjectKeyIdentifierExtension,
)
from trustpoint.views.base import LoggerMixin

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


__all__ = [
    'CertificateModel',
    'RevokedCertificateModel'
]

class CertificateModel(LoggerMixin, models.Model):
    """X509 Certificate Model.

    See RFC5280 for more information.
    """

    class CertificateStatus(models.TextChoices):
        """CertificateModel status"""
        OK = 'OK', _('OK')
        REVOKED = 'REV', _('Revoked')
        EXPIRED = 'EXP', _('Expired')
        NOT_YET_VALID = 'NYV', _('Not Yet Valid')

    # ------------------------------------------------- Django Choices -------------------------------------------------

    class Version(models.IntegerChoices):
        """X509 RFC 5280 - Certificate Version."""
        # We only allow version 3 or later if any are available in the future.
        V3 = 2, _('Version 3')

    SignatureAlgorithmOidChoices = models.TextChoices(
        'SIGNATURE_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in AlgorithmIdentifier])

    PublicKeyAlgorithmOidChoices = models.TextChoices(
        'PUBLIC_KEY_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in PublicKeyAlgorithmOid]
    )

    PublicKeyEcCurveOidChoices = models.TextChoices(
        'PUBLIC_KEY_EC_CURVE_OID', [(x.dotted_string, x.dotted_string) for x in NamedCurve]
    )

    # ----------------------------------------------- Custom Data Fields -----------------------------------------------

    @property
    def signature_suite(self) -> SignatureSuite:
        return SignatureSuite.from_certificate(self.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> PublicKeyInfo:
        return self.signature_suite.public_key_info

    @property
    def certificate_status(self) -> CertificateStatus:
        if RevokedCertificateModel.objects.filter(certificate=self).exists():
            return self.CertificateStatus.REVOKED
        if datetime.datetime.now(datetime. UTC) < self.not_valid_before:
            return self.CertificateStatus.NOT_YET_VALID
        if datetime.datetime.now(datetime. UTC) > self.not_valid_after:
            return self.CertificateStatus.EXPIRED
        return self.CertificateStatus.OK

    is_self_signed = models.BooleanField(verbose_name=_('Self-Signed'), null=False, blank=False)

    # TODO: This is kind of a hack.
    # TODO: This information is already available through the subject relation
    # TODO: Property would not be sortable.
    # TODO: We may want to resolve this later by modifying the queryset within the view
    common_name = models.CharField(
        verbose_name=_('Common Name'),
        max_length=256,
        default=''
    )
    sha256_fingerprint = models.CharField(verbose_name=_('Fingerprint (SHA256)'), max_length=256, editable=False)

    # ------------------------------------------ Certificate Fields (Header) -------------------------------------------

    # OID of the signature algorithm -> dotted_string in DB
    signature_algorithm_oid = models.CharField(
        _('Signature Algorithm OID'),
        max_length=256,
        editable=False,
        choices=SignatureAlgorithmOidChoices)

    # Name of the signature algorithm
    @property
    def signature_algorithm(self) -> str:
        return AlgorithmIdentifier(self.signature_algorithm_oid).verbose_name

    signature_algorithm.fget.short_description = _('Signature Algorithm')

    # Padding scheme if RSA is used, otherwise None
    @property
    def signature_algorithm_padding_scheme(self) -> str:
        return AlgorithmIdentifier(self.signature_algorithm_oid).padding_scheme.verbose_name

    signature_algorithm_padding_scheme.fget.short_description = _('Signature Padding Scheme')

    # The DER encoded signature value as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    signature_value = models.CharField(verbose_name=_('Signature Value'), max_length=65536, editable=False)

    # ------------------------------------------ TBSCertificate Fields (Body) ------------------------------------------
    # order of fields, attributes and choices follows RFC5280

    # X.509 Certificate Version (RFC5280)
    version = models.PositiveSmallIntegerField(verbose_name=_('Version'), choices=Version, editable=False)

    # X.509 Certificate Serial Number (RFC5280)
    # This is not part of the subject. It is the serial number of the certificate itself.
    serial_number = models.CharField(verbose_name=_('Serial Number'), max_length=256, editable=False)

    issuer = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Issuer'),
        related_name='issuer',
        editable=False)

    # The DER encoded issuer as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    issuer_public_bytes = models.CharField(verbose_name=_('Issuer Public Bytes'), max_length=2048, editable=False)

    # The validity entries use datetime objects with UTC timezone.
    not_valid_before = models.DateTimeField(verbose_name=_('Not Valid Before (UTC)'), editable=False)
    not_valid_after = models.DateTimeField(verbose_name=_('Not Valid After (UTC)'), editable=False)

    # Stored as a set of AttributeTypeAndValue objects directly.
    # Hence, looses some information if for example multiple rdns structures were used.
    # However, this suffices for our use-case.
    # Do not use these to compare certificate subjects. Use issuer_public_bytes for this.
    subject = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Subject'),
        related_name='subject',
        editable=False)

    # The DER encoded subject as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    subject_public_bytes = models.CharField(verbose_name=_('Subject Public Bytes'), max_length=2048, editable=False)

    # Subject Public Key Info - Algorithm OID
    spki_algorithm_oid = models.CharField(
        _('Public Key Algorithm OID'),
        max_length=256,
        editable=False,
        choices=PublicKeyAlgorithmOidChoices)

    # Subject Public Key Info - Algorithm Name
    spki_algorithm = models.CharField(
        verbose_name=_('Public Key Algorithm'),
        max_length=256,
        editable=False)

    # Subject Public Key Info - Key Size
    spki_key_size = models.PositiveIntegerField(_('Public Key Size'), editable=False)

    # Subject Public Key Info - Curve OID if ECC, None otherwise
    spki_ec_curve_oid = models.CharField(
        verbose_name=_('Public Key Curve OID (ECC)'),
        max_length=256,
        editable=False,
        choices=PublicKeyEcCurveOidChoices,
        default=None)

    # Subject Public Key Info - Curve Name if ECC, None otherwise
    spki_ec_curve = models.CharField(
        verbose_name=_('Public Key Curve (ECC)'),
        max_length=256,
        editable=False,
        default=None)

    # ---------------------------------------------------- Raw Data ----------------------------------------------------

    cert_pem = models.CharField(verbose_name=_('Certificate (PEM)'), max_length=65536, editable=False, unique=True)
    public_key_pem = models.CharField(verbose_name=_('Public Key (PEM, SPKI)'), max_length=65536, editable=False)

    # ----------------------------------------- CertificateModel Creation Data -----------------------------------------

    created_at = models.DateTimeField(verbose_name=_('Created-At'), auto_now_add=True)

    # --------------------------------------------- Data Retrieval Methods ---------------------------------------------

    def get_certificate_serializer(self) -> CertificateSerializer:
        return CertificateSerializer(self.cert_pem)

    def get_public_key_serializer(self) -> PublicKeySerializer:
        return PublicKeySerializer(self.public_key_pem)

    # --------------------------------------------------- Extensions ---------------------------------------------------
    # order of extensions follows RFC5280

    key_usage_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.KEY_USAGE.verbose_name,
        to=KeyUsageExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT)

    subject_alternative_name_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.SUBJECT_ALTERNATIVE_NAME.verbose_name,
        to=SubjectAlternativeNameExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT
    )

    issuer_alternative_name_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.ISSUER_ALTERNATIVE_NAME.verbose_name,
        to=IssuerAlternativeNameExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT
    )

    basic_constraints_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.BASIC_CONSTRAINTS.verbose_name,
        to=BasicConstraintsExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE)

    authority_key_identifier_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.AUTHORITY_KEY_IDENTIFIER.verbose_name,
        to=AuthorityKeyIdentifierExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    subject_key_identifier_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.SUBJECT_KEY_IDENTIFIER.verbose_name,
        to=SubjectKeyIdentifierExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    certificate_policies_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.CERTIFICATE_POLICIES.verbose_name,
        to=CertificatePoliciesExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    extended_key_usage_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.EXTENDED_KEY_USAGE.verbose_name,
        to=ExtendedKeyUsageExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    name_constraints_extension = models.ForeignKey(
        NameConstraintsExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    crl_distribution_points_extension = models.ForeignKey(
        CrlDistributionPointsExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    authority_information_access_extension = models.ForeignKey(
        AuthorityInformationAccessExtension,
        null=True, blank=True, on_delete=models.CASCADE
    )

    subject_information_access_extension = models.ForeignKey(
        SubjectInformationAccessExtension,
        null=True, blank=True, on_delete=models.CASCADE
    )

    inhibit_any_policy_extension = models.ForeignKey(
        InhibitAnyPolicyExtension,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    policy_constraints_extension = models.ForeignKey(
        PolicyConstraintsExtension,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    subject_directory_attributes_extension = models.ForeignKey(
        SubjectDirectoryAttributesExtension,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )


    freshest_crl_extension = models.ForeignKey(
        FreshestCrlExtension,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    # --------------------------------------------- No Cryptography support -------------------------------------

    # policy_mappings = None
    # ext_subject_directory_attributes = None
    # ext_name_constraints = None
    # ext_policy_constraints = None
    # ext_extended_key_usage = None
    # ext_crl_distribution_points = None
    # ext_inhibit_any_policy = None
    # ext_freshest_crl = None

    # Private Internet Access
    # ext_authority_information_access = None
    # ext_subject_information_access = None

    # --------------------------------------------------- Properties ---------------------------------------------------

    @property
    def is_ca(self) -> bool:
        if self.basic_constraints_extension and self.basic_constraints_extension.ca:
            return True
        return False

    @property
    def is_root_ca(self) -> bool:
        if self.is_self_signed and self.is_ca:
            return True
        return False

    @property
    def is_end_entity(self) -> bool:
        return not self.is_ca

    def __repr__(self) -> str:
        return f'Certificate(CN={self.common_name})'

    def __str__(self) -> str:
        return self.common_name

    @classmethod
    def get_cert_by_sha256_fingerprint(cls, sha256_fingerprint: str) -> None | CertificateModel:
        sha256_fingerprint = sha256_fingerprint.upper()
        return cls.objects.filter(sha256_fingerprint=sha256_fingerprint).first()

    @staticmethod
    def _get_subject(cert: x509.Certificate) -> list[tuple[str, str]]:
        subject = []
        for rdn in cert.subject.rdns:
            for attr_type_and_value in rdn:
                subject.append(
                    (attr_type_and_value.oid.dotted_string, attr_type_and_value.value)
                )
        return subject

    @staticmethod
    def _get_issuer(cert: x509.Certificate) -> list[tuple[str, str]]:
        issuer = []
        for rdn in cert.issuer.rdns:
            for attr_type_and_value in rdn:
                issuer.append(
                    (attr_type_and_value.oid.dotted_string, attr_type_and_value.value)
                )
        return issuer

    @staticmethod
    def _get_spki_info(cert: x509.Certificate) -> tuple[PublicKeyAlgorithmOid, int, NamedCurve]:
        if isinstance(cert.public_key(), rsa.RSAPublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.RSA
            spki_ec_curve_oid = NamedCurve.NONE
        elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.ECC
            spki_ec_curve_oid = NamedCurve[cert.public_key().curve.name.upper()]
        else:
            raise ValueError('Subject Public Key Info contains an unsupported key type.')

        return spki_algorithm_oid, cert.public_key().key_size, spki_ec_curve_oid

    # ---------------------------------------------- Private save methods ----------------------------------------------

    def _save(self, *args, **kwargs) -> None:
        return super().save(*args, **kwargs)

    @classmethod
    def _save_certificate(cls, certificate: x509.Certificate | CertificateSerializer) -> CertificateModel:
        if isinstance(certificate, CertificateSerializer):
            certificate = certificate.as_crypto()

        # ------------------------------------------------ Exist Checks ------------------------------------------------

        certificate_in_db = cls.get_cert_by_sha256_fingerprint(certificate.fingerprint(algorithm=hashes.SHA256()).hex())
        if certificate_in_db:
            return certificate_in_db

        # --------------------------------------------- Custom Data Fields ---------------------------------------------

        sha256_fingerprint = certificate.fingerprint(algorithm=hashes.SHA256()).hex().upper()

        # ---------------------------------------- Certificate Fields (Header) -----------------------------------------

        signature_algorithm_oid = certificate.signature_algorithm_oid.dotted_string
        signature_value = certificate.signature.hex().upper()

        # ---------------------------------------- TBSCertificate Fields (Body) ----------------------------------------

        version = certificate.version.value
        serial_number = hex(certificate.serial_number)[2:].upper()

        issuer = cls._get_issuer(certificate)
        issuer_public_bytes = certificate.issuer.public_bytes().hex().upper()

        not_valid_before = certificate.not_valid_before_utc
        not_valid_after = certificate.not_valid_after_utc

        subject = cls._get_subject(certificate)
        subject_public_bytes = certificate.subject.public_bytes().hex().upper()

        spki_algorithm_oid, spki_key_size, spki_ec_curve_oid = cls._get_spki_info(certificate)

        try:
            certificate.verify_directly_issued_by(certificate)
            is_self_signed = True
        except (ValueError, TypeError, InvalidSignature):
            is_self_signed = False

        # -------------------------------------------------- Raw Data --------------------------------------------------

        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode()

        public_key_pem = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        # ----------------------------------------- Certificate Model Instance -----------------------------------------

        cert_model = CertificateModel(
            sha256_fingerprint=sha256_fingerprint,
            signature_algorithm_oid=signature_algorithm_oid,
            signature_value=signature_value,
            version=version,
            serial_number=serial_number,
            issuer_public_bytes=issuer_public_bytes,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            subject_public_bytes=subject_public_bytes,
            spki_algorithm_oid=spki_algorithm_oid.dotted_string,
            spki_algorithm=spki_algorithm_oid.name,
            spki_key_size=spki_key_size,
            spki_ec_curve_oid=spki_ec_curve_oid.dotted_string,
            spki_ec_curve=spki_ec_curve_oid.verbose_name,
            cert_pem=cert_pem,
            public_key_pem=public_key_pem,
            is_self_signed=is_self_signed
        )

        # --------------------------------------------- Store in DataBase ----------------------------------------------

        return cls._atomic_save(cert_model=cert_model, certificate=certificate, subject=subject, issuer=issuer)

    @staticmethod
    def _save_attribute_and_value_pairs(oid: str, value: str) -> AttributeTypeAndValue:
        existing_attr_type_and_val = AttributeTypeAndValue.objects.filter(oid=oid, value=value).first()
        if existing_attr_type_and_val:
            return existing_attr_type_and_val

        attr_type_and_val = AttributeTypeAndValue(oid=oid, value=value)
        attr_type_and_val.save()
        return attr_type_and_val

    @classmethod
    def _save_subject(cls, cert_model: CertificateModel, subject: list[tuple[str, str]]) -> None:
        for entry in subject:
            oid, value = entry
            attr_type_and_val = cls._save_attribute_and_value_pairs(oid=oid, value=value)
            cert_model.subject.add(attr_type_and_val)

    @classmethod
    def _save_issuer(cls, cert_model: CertificateModel, issuer: list[tuple[str, str]]) -> None:
        for entry in issuer:
            oid, value = entry
            attr_type_and_val = cls._save_attribute_and_value_pairs(oid=oid, value=value)
            cert_model.issuer.add(attr_type_and_val)


    @staticmethod
    def _save_extensions(cert_model: CertificateModel, cert: x509.Certificate) -> None:
        for extension in cert.extensions:
            if isinstance(extension.value, x509.BasicConstraints):
                cert_model.basic_constraints_extension = \
                    BasicConstraintsExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.KeyUsage):
                cert_model.key_usage_extension = \
                    KeyUsageExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.IssuerAlternativeName):
                cert_model.issuer_alternative_name_extension = \
                    IssuerAlternativeNameExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.SubjectAlternativeName):
                cert_model.subject_alternative_name_extension = \
                    SubjectAlternativeNameExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.AuthorityKeyIdentifier):
                cert_model.authority_key_identifier_extension = \
                    AuthorityKeyIdentifierExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.SubjectKeyIdentifier):
                cert_model.subject_key_identifier_extension = \
                    SubjectKeyIdentifierExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.CertificatePolicies):
                cert_model.certificate_policies_extension = CertificatePoliciesExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.ExtendedKeyUsage):
                cert_model.extended_key_usage_extension = ExtendedKeyUsageExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.NameConstraints):
                cert_model.name_constraints_extension = NameConstraintsExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.CRLDistributionPoints):
                cert_model.crl_distribution_points_extension = CrlDistributionPointsExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.AuthorityInformationAccess):
                cert_model.authority_information_access_extension = AuthorityInformationAccessExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.SubjectInformationAccess):
                cert_model.subject_information_access_extension = SubjectInformationAccessExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.InhibitAnyPolicy):
                cert_model.inhibit_any_policy_extension = InhibitAnyPolicyExtension.save_from_crypto_extensions(extension)
            # elif isinstance(extension.value, x509.PolicyMappings):  # no x509 PolicyMapping implemented
            #     cert_model.pol = InhibitAnyPolicyExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.PolicyConstraints):
                cert_model.policy_constraints_extension = PolicyConstraintsExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.FreshestCRL):
                cert_model.freshest_crl_extension = FreshestCrlExtension.save_from_crypto_extensions(extension)

    @classmethod
    @transaction.atomic
    def _atomic_save(
            cls,
            cert_model: CertificateModel,
            certificate: x509.Certificate,
            subject: list[tuple[str, str]],
            issuer: list[tuple[str, str]]) -> CertificateModel:

        cert_model._save()
        for oid, value in subject:
            if oid == NameOid.COMMON_NAME.dotted_string:
                cert_model.common_name = value
        cls._save_subject(cert_model, subject)
        cls._save_issuer(cert_model, issuer)
        cls._save_extensions(cert_model, certificate)

        cert_model._save()  # noqa: SLF001
        return cert_model

    # ---------------------------------------------- Public save methods -----------------------------------------------

    def save(self, *args, **kwargs) -> None:
        """Save method must not be called directly to protect the integrity.

        This method makes sure, save() is not called by mistake.

        Raises:
            NotImplementedError
        """
        raise NotImplementedError(
            '.save() must not be called directly on a Certificate instance to protect the integrity of the database. '
            'Use .save_certificate() or .save_certificate_and_key() passing the required cryptography objects.'
        )

    @classmethod
    def save_certificate(cls, certificate: x509.Certificate | CertificateSerializer) -> CertificateModel:
        """Store the certificate in the database.

        Returns:
            trustpoint.pki.models.Certificate: The certificate object that has just been saved.
        """
        return cls._save_certificate(certificate=certificate)


class RevokedCertificateModel(models.Model):
    """Model to store revoked certificates."""

    class ReasonCode(models.TextChoices):
        """Revocation reasons per RFC 5280"""
        UNSPECIFIED = 'unspecified', _('Unspecified')
        KEY_COMPROMISE = 'keyCompromise', _('Key Compromise')
        CA_COMPROMISE = 'cACompromise', _('CA Compromise')
        AFFILIATION_CHANGED = 'affiliationChanged', _('Affiliation Changed')
        SUPERSEDED = 'superseded', _('Superseded')
        CESSATION = 'cessationOfOperation', _('Cessation of Operation')
        CERTIFICATE_HOLD = 'certificateHold', _('Certificate Hold')
        PRIVILEGE_WITHDRAWN = 'privilegeWithdrawn', _('Privilege Withdrawn')
        AA_COMPROMISE = 'aACompromise', _('AA Compromise')
        REMOVE_FROM_CRL = 'removeFromCRL', _('Remove from CRL')

    certificate = models.OneToOneField(
        CertificateModel,
        verbose_name=_('Certificate'),
        related_name='revoked_certificate',
        on_delete=models.CASCADE
    )

    revoked_at = models.DateTimeField(verbose_name=_('Revocation Date'), auto_now_add=True)

    revocation_reason = models.TextField(
        verbose_name=_('Revocation Reason'),
        choices=ReasonCode,
        default=ReasonCode.UNSPECIFIED
    )

    ca = models.ForeignKey(
        'IssuingCaModel',
        verbose_name=_('Issuing CA'),
        related_name='revoked_certificates',
        on_delete=models.SET_NULL,  # Safe to remove CRL if CA is removed?
        null=True
    )

    def __str__(self) -> str:
        return f'RevokedCertificate({self.certificate.common_name})'
