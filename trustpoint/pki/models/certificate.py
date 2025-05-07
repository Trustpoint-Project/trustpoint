"""Module that contains the CertificateModel."""

from __future__ import annotations

import datetime
from types import MappingProxyType
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta
from trustpoint_core.oid import (
    AlgorithmIdentifier,
    CertificateExtensionOid,
    NamedCurve,
    NameOid,
    PublicKeyAlgorithmOid,
    PublicKeyInfo,
    SignatureSuite,
)
from trustpoint_core.serializer import CertificateSerializer, PublicKeySerializer
from util.db import CustomDeleteActionModel

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

__all__ = ['CertificateModel', 'RevokedCertificateModel']


class CertificateModel(LoggerMixin, CustomDeleteActionModel):
    """X509 Certificate Model.

    See RFC5280 for more information.
    """

    objects: models.Manager[CertificateModel]

    class CertificateStatus(models.TextChoices):
        """CertificateModel status."""

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
        'SIGNATURE_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in AlgorithmIdentifier]
    )

    PublicKeyAlgorithmOidChoices = models.TextChoices(
        'PUBLIC_KEY_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in PublicKeyAlgorithmOid]
    )

    PublicKeyEcCurveOidChoices = models.TextChoices(
        'PUBLIC_KEY_EC_CURVE_OID', [(x.dotted_string, x.dotted_string) for x in NamedCurve]
    )

    # ----------------------------------------------- Custom Data Fields -----------------------------------------------

    is_self_signed = models.BooleanField(verbose_name=_('Self-Signed'), null=False, blank=False)

    # TODO(Alex): This is kind of a hack.
    # This information is already available through the subject relation
    # Property would not be sortable.
    # We may want to resolve this later by modifying the queryset within the view
    common_name = models.CharField(verbose_name=_('Common Name'), max_length=256, default='')
    sha256_fingerprint = models.CharField(
        verbose_name=_('Fingerprint (SHA256)'), max_length=256, editable=False, unique=True
    )

    # ------------------------------------------ Certificate Fields (Header) -------------------------------------------

    # OID of the signature algorithm -> dotted_string in DB
    signature_algorithm_oid = models.CharField(
        _('Signature Algorithm OID'), max_length=256, editable=False, choices=SignatureAlgorithmOidChoices
    )

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
        AttributeTypeAndValue, verbose_name=_('Issuer'), related_name='issuer', editable=False
    )

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
        AttributeTypeAndValue, verbose_name=_('Subject'), related_name='subject', editable=False
    )

    # The DER encoded subject as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    subject_public_bytes = models.CharField(verbose_name=_('Subject Public Bytes'), max_length=2048, editable=False)

    # Subject Public Key Info - Algorithm OID
    spki_algorithm_oid = models.CharField(
        _('Public Key Algorithm OID'), max_length=256, editable=False, choices=PublicKeyAlgorithmOidChoices
    )

    # Subject Public Key Info - Algorithm Name
    spki_algorithm = models.CharField(verbose_name=_('Public Key Algorithm'), max_length=256, editable=False)

    # Subject Public Key Info - Key Size
    spki_key_size = models.PositiveIntegerField(_('Public Key Size'), editable=False)

    # Subject Public Key Info - Curve OID if ECC, None otherwise
    spki_ec_curve_oid = models.CharField(
        verbose_name=_('Public Key Curve OID (ECC)'),
        max_length=256,
        editable=False,
        choices=PublicKeyEcCurveOidChoices,
        default=None,
    )

    # Subject Public Key Info - Curve Name if ECC, None otherwise
    spki_ec_curve = models.CharField(
        verbose_name=_('Public Key Curve (ECC)'), max_length=256, editable=False, default=None
    )

    # ---------------------------------------------------- Raw Data ----------------------------------------------------

    cert_pem = models.TextField(verbose_name=_('Certificate (PEM)'), editable=False)
    public_key_pem = models.CharField(verbose_name=_('Public Key (PEM, SPKI)'), max_length=65536, editable=False)

    # ----------------------------------------- CertificateModel Creation Data -----------------------------------------

    created_at = models.DateTimeField(verbose_name=_('Created-At'), auto_now_add=True)

    # --------------------------------------------------- Extensions ---------------------------------------------------
    # order of extensions follows RFC5280

    key_usage_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.KEY_USAGE.verbose_name,
        to=KeyUsageExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    subject_alternative_name_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.SUBJECT_ALTERNATIVE_NAME.verbose_name,
        to=SubjectAlternativeNameExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    issuer_alternative_name_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.ISSUER_ALTERNATIVE_NAME.verbose_name,
        to=IssuerAlternativeNameExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    basic_constraints_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.BASIC_CONSTRAINTS.verbose_name,
        to=BasicConstraintsExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    authority_key_identifier_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.AUTHORITY_KEY_IDENTIFIER.verbose_name,
        to=AuthorityKeyIdentifierExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    subject_key_identifier_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.SUBJECT_KEY_IDENTIFIER.verbose_name,
        to=SubjectKeyIdentifierExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    certificate_policies_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.CERTIFICATE_POLICIES.verbose_name,
        to=CertificatePoliciesExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    extended_key_usage_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.EXTENDED_KEY_USAGE.verbose_name,
        to=ExtendedKeyUsageExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    name_constraints_extension = models.ForeignKey(
        NameConstraintsExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    crl_distribution_points_extension = models.ForeignKey(
        CrlDistributionPointsExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    authority_information_access_extension = models.ForeignKey(
        AuthorityInformationAccessExtension,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    subject_information_access_extension = models.ForeignKey(
        SubjectInformationAccessExtension,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    inhibit_any_policy_extension = models.ForeignKey(
        InhibitAnyPolicyExtension,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    policy_constraints_extension = models.ForeignKey(
        PolicyConstraintsExtension,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    subject_directory_attributes_extension = models.ForeignKey(
        SubjectDirectoryAttributesExtension,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    freshest_crl_extension = models.ForeignKey(
        FreshestCrlExtension,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
    )

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    # ------------------------------------------ Magic and default methods -------------------------------------------

    def __repr__(self) -> str:
        """Representation of the CertificateModel instance."""
        return f'Certificate(CN={self.common_name})'

    def __str__(self) -> str:
        """Human-readable representation of the CertificateModel instance."""
        return self.common_name

    def save(self, *_args: Any, **_kwargs: Any) -> None:
        """Save method must not be called directly to protect the integrity.

        This method makes sure save() is not called by mistake.

        Raises:
            NotImplementedError
        """
        exc_msg = (
            '.save() must not be called directly on a Certificate instance to protect the integrity of the database. '
            'Use .save_certificate() or .save_certificate_and_key() passing the required cryptography objects.'
        )
        raise NotImplementedError(exc_msg)

    # --------------------------------------------------- Properties ---------------------------------------------------

    @property
    def signature_algorithm(self) -> str:
        """Name of the signature algorithm."""
        return AlgorithmIdentifier(self.signature_algorithm_oid).verbose_name

    signature_algorithm.fget.short_description = _('Signature Algorithm')

    @property
    def signature_algorithm_padding_scheme(self) -> str:
        """Padding scheme if RSA is used, otherwise None."""
        return AlgorithmIdentifier(self.signature_algorithm_oid).padding_scheme.verbose_name

    signature_algorithm_padding_scheme.fget.short_description = _('Signature Padding Scheme')

    @property
    def signature_suite(self) -> SignatureSuite:
        """Signature Suite of the certificate."""
        return SignatureSuite.from_certificate(self.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> PublicKeyInfo:
        """Public Key Info of the certificate."""
        return self.signature_suite.public_key_info

    @property
    def certificate_status(self) -> CertificateStatus:
        """Status of the certificate."""
        if RevokedCertificateModel.objects.filter(certificate=self).exists():
            return self.CertificateStatus.REVOKED
        if datetime.datetime.now(datetime.UTC) < self.not_valid_before:
            return self.CertificateStatus.NOT_YET_VALID
        if datetime.datetime.now(datetime.UTC) > self.not_valid_after:
            return self.CertificateStatus.EXPIRED
        return self.CertificateStatus.OK

    @property
    def is_ca(self) -> bool:
        """Check if the certificate is a CA certificate."""
        return self.basic_constraints_extension is not None and self.basic_constraints_extension.ca

    @property
    def is_root_ca(self) -> bool:
        """Check if the certificate is a root CA certificate."""
        return self.is_self_signed and self.is_ca

    @property
    def is_end_entity(self) -> bool:
        """Check if the certificate is an end entity certificate."""
        return not self.is_ca

    @classmethod
    def get_cert_by_sha256_fingerprint(cls, sha256_fingerprint: str) -> None | CertificateModel:
        """Get a CertificateModel instance by its SHA256 fingerprint."""
        sha256_fingerprint = sha256_fingerprint.upper()
        return cls.objects.filter(sha256_fingerprint=sha256_fingerprint).first()

    @staticmethod
    def _get_subject(cert: x509.Certificate) -> list[tuple[str, str]]:
        subject: list[tuple[str, str]] = []
        for rdn in cert.subject.rdns:
            subject.extend(
                [attr_type_and_value.oid.dotted_string, attr_type_and_value.value] for attr_type_and_value in rdn
            )
        return subject

    @staticmethod
    def _get_issuer(cert: x509.Certificate) -> list[tuple[str, str]]:
        issuer: list[tuple[str, str]] = []
        for rdn in cert.issuer.rdns:
            issuer.extend(
                [attr_type_and_value.oid.dotted_string, attr_type_and_value.value] for attr_type_and_value in rdn
            )
        return issuer

    @staticmethod
    def _get_spki_info(cert: x509.Certificate) -> tuple[PublicKeyAlgorithmOid, int, NamedCurve]:
        cert_public_key = cert.public_key()
        if isinstance(cert_public_key, rsa.RSAPublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.RSA
            spki_ec_curve_oid = NamedCurve.NONE
        elif isinstance(cert_public_key, ec.EllipticCurvePublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.ECC
            spki_ec_curve_oid = NamedCurve[cert_public_key.curve.name.upper()]
        else:
            exc_msg = 'Subject Public Key Info contains an unsupported key type.'
            raise TypeError(exc_msg)

        return spki_algorithm_oid, cert_public_key.key_size, spki_ec_curve_oid

    # --------------------------------------------- Data Retrieval Methods ---------------------------------------------

    def get_certificate_serializer(self) -> CertificateSerializer:
        """Get the serializer for the certificate."""
        return CertificateSerializer.from_pem(self.cert_pem.encode())

    def get_public_key_serializer(self) -> PublicKeySerializer:
        """Get the serializer for the certificate's public key."""
        return PublicKeySerializer.from_pem(self.public_key_pem.encode())

    # ---------------------------------------------- Private save methods ----------------------------------------------

    def _save(self, **kwargs: Any) -> None:
        return super().save(**kwargs)

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

        public_key_pem = (
            certificate.public_key()
            .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )

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
            is_self_signed=is_self_signed,
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

    EXTENSION_MAP = MappingProxyType(
        {
            x509.BasicConstraints: ('basic_constraints_extension', BasicConstraintsExtension),
            x509.KeyUsage: ('key_usage_extension', KeyUsageExtension),
            x509.IssuerAlternativeName: ('issuer_alternative_name_extension', IssuerAlternativeNameExtension),
            x509.SubjectAlternativeName: ('subject_alternative_name_extension', SubjectAlternativeNameExtension),
            x509.AuthorityKeyIdentifier: ('authority_key_identifier_extension', AuthorityKeyIdentifierExtension),
            x509.SubjectKeyIdentifier: ('subject_key_identifier_extension', SubjectKeyIdentifierExtension),
            x509.CertificatePolicies: ('certificate_policies_extension', CertificatePoliciesExtension),
            x509.ExtendedKeyUsage: ('extended_key_usage_extension', ExtendedKeyUsageExtension),
            x509.NameConstraints: ('name_constraints_extension', NameConstraintsExtension),
            x509.CRLDistributionPoints: ('crl_distribution_points_extension', CrlDistributionPointsExtension),
            x509.AuthorityInformationAccess: (
                'authority_information_access_extension',
                AuthorityInformationAccessExtension,
            ),
            x509.SubjectInformationAccess: ('subject_information_access_extension', SubjectInformationAccessExtension),
            x509.InhibitAnyPolicy: ('inhibit_any_policy_extension', InhibitAnyPolicyExtension),
            x509.PolicyConstraints: ('policy_constraints_extension', PolicyConstraintsExtension),
            x509.FreshestCRL: ('freshest_crl_extension', FreshestCrlExtension),
        }
    )

    @staticmethod
    def _save_extensions(cert_model: CertificateModel, cert: x509.Certificate) -> None:
        for extension in cert.extensions:
            for x509_extension_type, (field_name, extension_model_class) in CertificateModel.EXTENSION_MAP.items():
                if isinstance(extension.value, x509_extension_type):
                    extension_model = extension_model_class.save_from_crypto_extensions(extension)
                    setattr(cert_model, field_name, extension_model)
                    break

    @classmethod
    @transaction.atomic
    def _atomic_save(
        cls,
        cert_model: CertificateModel,
        certificate: x509.Certificate,
        subject: list[tuple[str, str]],
        issuer: list[tuple[str, str]],
    ) -> CertificateModel:
        cert_model._save()  # noqa: SLF001
        for oid, value in subject:
            if oid == NameOid.COMMON_NAME.dotted_string:
                cert_model.common_name = value
        cls._save_subject(cert_model, subject)
        cls._save_issuer(cert_model, issuer)
        cls._save_extensions(cert_model, certificate)

        cert_model._save()  # noqa: SLF001
        return cert_model

    # ---------------------------------------------- Public save methods -----------------------------------------------

    @classmethod
    def save_certificate(cls, certificate: x509.Certificate | CertificateSerializer) -> CertificateModel:
        """Store the certificate in the database.

        Returns:
            trustpoint.pki.models.Certificate: The certificate object that has just been saved.
        """
        return cls._save_certificate(certificate=certificate)

    # ---------------------------------------------- Post-deletion cleanup ---------------------------------------------
    def pre_delete(self) -> None:
        """Store the related objects before deletion."""
        self._related_objects = {
            'basic_constraints_extension': self.basic_constraints_extension,
            'key_usage_extension': self.key_usage_extension,
            'issuer_alternative_name_extension': self.issuer_alternative_name_extension,
            'subject_alternative_name_extension': self.subject_alternative_name_extension,
            'authority_key_identifier_extension': self.authority_key_identifier_extension,
            'subject_key_identifier_extension': self.subject_key_identifier_extension,
            'certificate_policies_extension': self.certificate_policies_extension,
            'extended_key_usage_extension': self.extended_key_usage_extension,
            'name_constraints_extension': self.name_constraints_extension,
            'crl_distribution_points_extension': self.crl_distribution_points_extension,
            'authority_information_access_extension': self.authority_information_access_extension,
            'subject_information_access_extension': self.subject_information_access_extension,
            'inhibit_any_policy_extension': self.inhibit_any_policy_extension,
            'policy_constraints_extension': self.policy_constraints_extension,
            'freshest_crl_extension': self.freshest_crl_extension,
        }

    def post_delete(self) -> None:
        """Clean up related orphaned extension models."""
        BasicConstraintsExtension.delete_if_orphaned(self._related_objects['basic_constraints_extension'])
        KeyUsageExtension.delete_if_orphaned(self._related_objects['key_usage_extension'])
        IssuerAlternativeNameExtension.delete_if_orphaned(self._related_objects['issuer_alternative_name_extension'])
        SubjectAlternativeNameExtension.delete_if_orphaned(self._related_objects['subject_alternative_name_extension'])
        AuthorityKeyIdentifierExtension.delete_if_orphaned(self._related_objects['authority_key_identifier_extension'])
        SubjectKeyIdentifierExtension.delete_if_orphaned(self._related_objects['subject_key_identifier_extension'])
        CertificatePoliciesExtension.delete_if_orphaned(self._related_objects['certificate_policies_extension'])
        ExtendedKeyUsageExtension.delete_if_orphaned(self._related_objects['extended_key_usage_extension'])
        NameConstraintsExtension.delete_if_orphaned(self._related_objects['name_constraints_extension'])
        CrlDistributionPointsExtension.delete_if_orphaned(self._related_objects['crl_distribution_points_extension'])
        AuthorityInformationAccessExtension.delete_if_orphaned(
            self._related_objects['authority_information_access_extension']
        )
        SubjectInformationAccessExtension.delete_if_orphaned(
            self._related_objects['subject_information_access_extension']
        )
        InhibitAnyPolicyExtension.delete_if_orphaned(self._related_objects['inhibit_any_policy_extension'])
        PolicyConstraintsExtension.delete_if_orphaned(self._related_objects['policy_constraints_extension'])
        FreshestCrlExtension.delete_if_orphaned(self._related_objects['freshest_crl_extension'])

    # ---------------------------------------------- Utility ---------------------------------------------
    def subjects_match(self, other_subject: x509.Name) -> bool:
        """Check if the provided subject is identical to the one of this certificate.

        Args:
            other_subject (x509.Name): The subject to compare to.

        Returns:
            bool: True if the subjects match, False otherwise.
        """
        return self.subject_public_bytes == other_subject.public_bytes().hex().upper()


class RevokedCertificateModel(models.Model):
    """Model to store revoked certificates."""

    objects: models.Manager[RevokedCertificateModel]

    class ReasonCode(models.TextChoices):
        """Revocation reasons per RFC 5280."""

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
        CertificateModel, verbose_name=_('Certificate'), related_name='revoked_certificate', on_delete=models.CASCADE
    )

    revoked_at = models.DateTimeField(verbose_name=_('Revocation Date'), auto_now_add=True)

    revocation_reason = models.TextField(
        verbose_name=_('Revocation Reason'), choices=ReasonCode, default=ReasonCode.UNSPECIFIED
    )

    ca = models.ForeignKey(
        'IssuingCaModel',
        verbose_name=_('Issuing CA'),
        related_name='revoked_certificates',
        on_delete=models.SET_NULL,  # Safe to remove CRL if CA is removed?
        null=True,
    )

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """String representation of the RevokedCertificateModel instance."""
        return f'RevokedCertificate({self.certificate.common_name})'
