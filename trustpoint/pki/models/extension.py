"""Module that contains X.509 Extension Models."""


from __future__ import annotations

import abc
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import ClassVar

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core.oid import CertificateExtensionOid, NameOid

__all__ = [
    'AttributeTypeAndValue',
    'BasicConstraintsExtension',
    'CertificateExtension',
    'GeneralNameDNSName',
    'GeneralNameDirectoryName',
    'GeneralNameIpAddress',
    'GeneralNameOtherName',
    'GeneralNameRFC822Name',
    'GeneralNameRegisteredId',
    'GeneralNameUniformResourceIdentifier',
    'GeneralNamesModel',
    'IssuerAlternativeNameExtension',
    'KeyUsageExtension',
    'SubjectAlternativeNameExtension'
]


EXTENSION_STR = 'Extension'


class AttributeTypeAndValue(models.Model):
    """AttributeTypeAndValue Model.

    Used for subject entries as well as the GeneralNameDirectoryName entries within
    the SubjectAlternativeName and IssuerAlternativeName.

    See RFC5280 for more information.
    """
    oid = models.CharField(max_length=256, editable=False, verbose_name='OID')
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value')


    class Meta:  # noqa: D106
        unique_together = ('oid', 'value')


    def __str__(self) -> str:
        """Returns a string representation of the attribute type and value."""
        try:
            name_oid = NameOid(self.oid).full_name
        except ValueError:
            name_oid = self.oid
        return f'{name_oid}={self.value}'

    @property
    def abbreviation(self) -> str:
        """Returns the abbreviation of the attribute's OID."""
        return NameOid(self.oid).abbreviation

    @property
    def verbose_name(self) -> str:
        """Returns the verbose name of the attribute's OID."""
        return NameOid(self.oid).verbose_name


class GeneralNameRFC822Name(models.Model):
    """GeneralNameRFC822Name Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=1024, editable=False, verbose_name='Value', unique=True)

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameRFC822Name."""
        return f'{self.value}'


class GeneralNameDNSName(models.Model):
    """GeneralNameDNSName Model.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=1024, editable=False, verbose_name='Value', unique=True)

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameDNSName."""
        return f'{self.value}'


class GeneralNameDirectoryName(models.Model):
    """GeneralNameDirectoryName Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    names = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Name'),
        editable=False)

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameDirectoryName."""
        names = self.names.all()
        string = ''
        for name in names:
            string += f'{name!s}, '

        return string[:-2]


class GeneralNameUniformResourceIdentifier(models.Model):
    """GeneralNameUniformResourceIdentifier Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value', unique=True)

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameUniformResourceIdentifier."""
        return f'{self.value}'


class GeneralNameIpAddress(models.Model):
    """GeneralNameIpAddress Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    class IpType(models.TextChoices):  # noqa: D106
        IPV4_ADDRESS = 'A4', _('IPv4 Address')
        IPV6_ADDRESS = 'A6', _('IPv6 Address')
        IPV4_NETWORK = 'N4', _('IPv4 Network')
        IPV6_NETWORK = 'N6', _('IPv6 Network')

    ip_type = models.CharField(max_length=2, choices=IpType, editable=False, verbose_name='IP Type')
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value')

    class Meta:  # noqa: D106
        unique_together = ('ip_type', 'value')

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameIpAddress."""
        return f'{self.IpType(self.ip_type).label}:{self.value}'


class GeneralNameRegisteredId(models.Model):
    """GeneralNameRegisteredId Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=256, editable=False, verbose_name='Value')

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameRegisteredId."""
        return f'{self.value}'


class GeneralNameOtherName(models.Model):
    """GeneralNameOtherName Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    type_id = models.CharField(max_length=256, editable=False, verbose_name='OID')
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value')


    class Meta:  # noqa: D106
        unique_together = ('type_id', 'value')


    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameOtherName."""
        return f'OID: {self.type_id}, DER: {self.value[:10]}...'


class CertificateExtension:
    """Abstract Base Class of Extension Models.

    Due to a Metaclass conflict, this class is not derived from abc.ABC on purpose.
    # TODO: check if this can be rectified
    """

    @classmethod
    @abc.abstractmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | CertificateExtension:
        """Stores the extension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            extension (x509.Extension): The X.509 extension object.

        Returns:
            CertificateExtension: The instance of the saved extension.
        """


class BasicConstraintsExtension(CertificateExtension, models.Model):
    """Represents the BasicConstraints extension in X.509 certificates.

    This extension indicates whether a certificate is a CA and its path length.
    """
    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)
    ca = models.BooleanField(verbose_name=_('CA'), editable=False)
    path_length_constraint = models.PositiveSmallIntegerField(
        verbose_name=_('Path Length Constraint'),
        editable=False,
        null=True,
        blank=True)

    class Meta:  # noqa: D106
        unique_together = ('critical', 'ca', 'path_length_constraint')

    def __str__(self) -> str:
        """Returns a string representation of the extension."""
        return (
            f'BasicConstraintsExtension(critical={self.critical}, '
            f'oid={self.extension_oid})')

    @property
    def extension_oid(self) -> str:  # noqa: D102
        return CertificateExtensionOid.BASIC_CONSTRAINTS.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, crypto_basic_constraints_extension: x509.Extension) \
            -> None | BasicConstraintsExtension:
        """Stores the BasicConstraintsExtension in the database.

        Args:
            crypto_basic_constraints_extension (x509.Extension):
                The X.509 extension containing BasicConstraints.

        Returns:
            BasicConstraintsExtension: The instance of the saved extension.
        """
        try:
            existing_entry = BasicConstraintsExtension.objects.filter(
                critical=crypto_basic_constraints_extension.critical,
                ca=crypto_basic_constraints_extension.value.ca,
                path_length_constraint=crypto_basic_constraints_extension.value.path_length).first()
            if existing_entry:
                return existing_entry

            basic_constraints_extension = cls()
            basic_constraints_extension.critical = crypto_basic_constraints_extension.critical
            basic_constraints_extension.ca = crypto_basic_constraints_extension.value.ca
            basic_constraints_extension.path_length_constraint = crypto_basic_constraints_extension.value.path_length
            basic_constraints_extension.save()
        except ExtensionNotFound:
            return None

        return basic_constraints_extension


class KeyUsageExtension(CertificateExtension, models.Model):
    """Represents the KeyUsage extension in X.509 certificates.

    Specifies the permitted usage of the certificate's public key.
    """

    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)
    digital_signature = models.BooleanField(verbose_name=_('Digital Signature'), default=False, editable=False)
    content_commitment = models.BooleanField(verbose_name=_('Content Commitment'), default=False, editable=False)
    key_encipherment = models.BooleanField(verbose_name=_('Key Encipherment'), default=False, editable=False)
    data_encipherment = models.BooleanField(verbose_name=_('Data Encipherment'), default=False, editable=False)
    key_agreement = models.BooleanField(verbose_name=_('Key Agreement'), default=False, editable=False)
    key_cert_sign = models.BooleanField(verbose_name=_('Key Cert Sign'), default=False, editable=False)
    crl_sign = models.BooleanField(verbose_name=_('CRL Sign'), default=False, editable=False)
    encipher_only = models.BooleanField(verbose_name=_('Encipher Only'), default=False, editable=False)
    decipher_only = models.BooleanField(verbose_name=_('Decipher Only'), default=False, editable=False)

    class Meta:  # noqa: D106
        unique_together = (
            'digital_signature',
            'content_commitment',
            'key_encipherment',
            'data_encipherment',
            'key_agreement',
            'key_cert_sign',
            'crl_sign',
            'encipher_only',
            'decipher_only')

    def __str__(self) -> str:
        """Returns a string representation of the extension."""
        return (
            f'KeyUsageExtension(critical={self.critical}, '
            f'oid={self.extension_oid})')

    @property
    def extension_oid(self) -> str:  # noqa: D102
        return CertificateExtensionOid.KEY_USAGE.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR


    @classmethod
    def save_from_crypto_extensions(cls, crypto_basic_constraints_extension: x509.Extension) \
            -> None | KeyUsageExtension:
        """Stores the KeyUsage extension in the database.

        Args:
            crypto_basic_constraints_extension (x509.Extension):
                The X.509 extension containing KeyUsage.

        Returns:
            KeyUsageExtension: The instance of the saved extension.
        """
        try:
            # noinspection PyProtectedMember
            existing_entry = KeyUsageExtension.objects.filter(
                critical=crypto_basic_constraints_extension.critical,
                digital_signature=crypto_basic_constraints_extension.value.digital_signature,
                content_commitment=crypto_basic_constraints_extension.value.content_commitment,
                key_encipherment=crypto_basic_constraints_extension.value.key_encipherment,
                data_encipherment=crypto_basic_constraints_extension.value.data_encipherment,
                key_agreement=crypto_basic_constraints_extension.value.key_agreement,
                key_cert_sign=crypto_basic_constraints_extension.value.key_cert_sign,
                crl_sign=crypto_basic_constraints_extension.value.crl_sign,
                encipher_only=crypto_basic_constraints_extension.value._encipher_only,  # noqa: SLF001
                decipher_only=crypto_basic_constraints_extension.value._decipher_only).first()  # noqa: SLF001
            if existing_entry:
                return existing_entry

            key_usage_extension = cls()
            key_usage_extension.critical = crypto_basic_constraints_extension.critical
            key_usage_extension.digital_signature = crypto_basic_constraints_extension.value.digital_signature
            key_usage_extension.content_commitment = crypto_basic_constraints_extension.value.content_commitment
            key_usage_extension.key_encipherment = crypto_basic_constraints_extension.value.key_encipherment
            key_usage_extension.data_encipherment = crypto_basic_constraints_extension.value.data_encipherment
            key_usage_extension.key_agreement = crypto_basic_constraints_extension.value.key_agreement
            key_usage_extension.key_cert_sign = crypto_basic_constraints_extension.value.key_cert_sign
            key_usage_extension.crl_sign = crypto_basic_constraints_extension.value.crl_sign
            # noinspection PyProtectedMember
            key_usage_extension.encipher_only = crypto_basic_constraints_extension.value._encipher_only  # noqa: SLF001
            # noinspection PyProtectedMember
            key_usage_extension.decipher_only = crypto_basic_constraints_extension.value._decipher_only  # noqa: SLF001
            key_usage_extension.save()
        except ExtensionNotFound:
            return None

        return key_usage_extension


class GeneralNamesModel(models.Model):
    """Represents a collection of general names as per RFC5280.

    Used for both SubjectAlternativeName and IssuerAlternativeName extensions.
    """

    _alternative_name_extension_type: str


    rfc822_names = models.ManyToManyField(
        to=GeneralNameRFC822Name,
        verbose_name=_('RFC822 Names'),
        related_name='issuer_alternative_names')

    dns_names = models.ManyToManyField(
        GeneralNameDNSName,
        verbose_name=_('DNS Names'),
        related_name='issuer_alternative_names')

    directory_names = models.ManyToManyField(
        GeneralNameDirectoryName,
        verbose_name=_('Directory Names'),
        related_name='issuer_alternative_names')

    uniform_resource_identifiers = models.ManyToManyField(
        GeneralNameUniformResourceIdentifier,
        verbose_name=_('Uniform Resource Identifiers'),
        related_name='issuer_alternative_names')

    ip_addresses = models.ManyToManyField(
        GeneralNameIpAddress,
        verbose_name=_('IP Addresses'),
        related_name='issuer_alternative_names')

    registered_ids = models.ManyToManyField(
        GeneralNameRegisteredId,
        verbose_name=_('Registered IDs'),
        related_name='issuer_alternative_names')

    other_names = models.ManyToManyField(
        GeneralNameOtherName,
        verbose_name=_('Other Names'),
        related_name='issuer_alternative_names')

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNamesModel."""
        parts = []

        for field_name, related_manager in [
            ('RFC822', self.rfc822_names),
            ('DNS', self.dns_names),
            ('Directory', self.directory_names),
            ('URI', self.uniform_resource_identifiers),
            ('IP', self.ip_addresses),
            ('RegisteredID', self.registered_ids),
            ('OtherName', self.other_names)
        ]:
            values = [str(name) for name in related_manager.all()]
            if values:
                parts.append(f"{field_name}: {', '.join(values)}")

        return f"GeneralNamesModel({'; '.join(parts)})" if parts else 'GeneralNamesModel(Empty)'

    @property
    def extension_oid(self) -> str:  # noqa: D102
        msg = 'This base class (AlternativeNameExtensionModel) does not have an extension_oid.'
        raise NotImplementedError(msg)

    extension_oid.fget.short_description = EXTENSION_STR

    def _save_rfc822_name(self, entry: x509.RFC822Name) -> None:
        existing_entry = GeneralNameRFC822Name.objects.filter(value=entry.value).first()
        if existing_entry:
            self.rfc822_names.add(existing_entry)
        else:
            rfc822_name = GeneralNameRFC822Name(value=entry.value)
            rfc822_name.save()
            self.rfc822_names.add(rfc822_name)
        self.save()

    def _save_dns_name(self, entry: x509.DNSName) -> None:
        existing_entry = GeneralNameDNSName.objects.filter(value=entry.value).first()
        if existing_entry:
            self.dns_names.add(existing_entry)
        else:
            dns_name = GeneralNameDNSName(value=entry.value)
            dns_name.save()
            self.dns_names.add(dns_name)
        self.save()

    def _save_ip_address(self, entry: x509.IPAddress) -> None:
        if isinstance(entry.value, IPv4Address):
            ip_type = GeneralNameIpAddress.IpType.IPV4_ADDRESS
        elif isinstance(entry.value, IPv6Address):
            ip_type = GeneralNameIpAddress.IpType.IPV6_ADDRESS
        elif isinstance(entry.value, IPv4Network):
            ip_type = GeneralNameIpAddress.IpType.IPV4_NETWORK
        elif isinstance(entry.value, IPv6Network):
            ip_type = GeneralNameIpAddress.IpType.IPV6_NETWORK
        else:
            msg = f'Unknown IP address type: {type(entry.value).__name__}.'
            raise TypeError(msg)

        existing_entry = GeneralNameIpAddress.objects.filter(ip_type=ip_type, value=entry.value).first()
        if existing_entry:
            self.ip_addresses.add(existing_entry)
        else:
            ip_address = GeneralNameIpAddress(ip_type=ip_type, value=entry.value)
            ip_address.save()
            self.ip_addresses.add(ip_address)
        self.save()

    def _save_uri(self, entry: x509.UniformResourceIdentifier) -> None:
        existing_entry = GeneralNameUniformResourceIdentifier.objects.filter(value=entry.value).first()
        if existing_entry:
            self.uniform_resource_identifiers.add(existing_entry)
        else:
            uri = GeneralNameUniformResourceIdentifier(value=entry.value)
            uri.save()
            self.uniform_resource_identifiers.add(uri)
        self.save()

    def _save_registered_id(self, entry: x509.RegisteredID) -> None:
        existing_entry = GeneralNameRegisteredId.objects.filter(value=entry.value.dotted_string).first()
        if existing_entry:
            self.registered_ids.add(existing_entry)
        else:
            registered_id = GeneralNameRegisteredId(value=entry.value.dotted_string)
            registered_id.save()
            self.registered_ids.add(registered_id)
        self.save()

    def _save_other_name(self, entry: x509.OtherName) -> None:
        type_id = entry.type_id.dotted_string
        value = entry.value.hex().upper()
        existing_entry = GeneralNameOtherName.objects.filter(type_id=type_id, value=value).first()
        if existing_entry:
            self.other_names.add(existing_entry)
        else:
            other_name = GeneralNameOtherName(
                type_id=type_id,
                value=value
            )
            other_name.save()
            self.other_names.add(other_name)
        self.save()

    def _save_directory_name(self, entry: x509.DirectoryName) -> None:
        directory_name = GeneralNameDirectoryName()
        directory_name.save()

        self.directory_names.add(directory_name)
        self.save()

        for name in entry.value:
            existing_entry = AttributeTypeAndValue.objects.filter(oid=name.oid.dotted_string, value=name.value).first()
            if existing_entry:
                directory_name.names.add(existing_entry)
            else:
                attr_type_and_val = AttributeTypeAndValue(oid=name.oid.dotted_string, value=name.value)
                attr_type_and_val.save()
                directory_name.names.add(attr_type_and_val)

        directory_name.save()

    def save_general_names(
            self,
            general_names: x509.Extension | list[x509.GeneralName]) \
            -> None | GeneralNamesModel:
        """Stores general names in the database.

        Args:
            general_names (x509.Extension | list[x509.GeneralName]):
                The X.509 general names extension or a list of general names.

        Returns:
            GeneralNamesModel: The instance of the saved general names.
        """
        if isinstance(general_names, x509.Extension):
            general_names = general_names.value

        for entry in general_names:
            if isinstance(entry, x509.RFC822Name):
                self._save_rfc822_name(entry=entry)
            if isinstance(entry, x509.DNSName):
                self._save_dns_name(entry=entry)
            elif isinstance(entry, x509.IPAddress):
                self._save_ip_address(entry=entry)
            elif isinstance(entry, x509.DirectoryName):
                self._save_directory_name(entry=entry)
            elif isinstance(entry, x509.UniformResourceIdentifier):
                self._save_uri(entry=entry)
            elif isinstance(entry, x509.RegisteredID):
                self._save_registered_id(entry=entry)
            elif isinstance(entry, x509.OtherName):
                self._save_other_name(entry=entry)

        return self


class IssuerAlternativeNameExtension(CertificateExtension, models.Model):
    """IssuerAlternativeNameExtension Model.

    See RFC5280 for more information.
    """
    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)
    issuer_alt_name = models.ForeignKey(
        GeneralNamesModel,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        verbose_name=_('Issuer Alternative Name Issuer')
    )

    def __str__(self) -> str:
        """Returns a string representation of the IssuerAlternativeName extension."""
        return (
            f'{self.__class__.__name__}(critical={self.critical}, '
            f'oid={self.extension_oid})')

    @property
    def extension_oid(self) -> str:  # noqa: D102
        return CertificateExtensionOid.ISSUER_ALTERNATIVE_NAME.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | IssuerAlternativeNameExtension:
        """Stores the IssuerAlternativeNameExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            extension (x509.Extension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.IssuerAlternativeNameExtension:
            The instance of the saved IssuerAlternativeNameExtension.
        """
        try:
            gn = GeneralNamesModel()
            gn.save()
            gn.save_general_names(extension)

            issuer_alt_name_ext = IssuerAlternativeNameExtension(critical=extension.critical, issuer_alt_name=gn)
            issuer_alt_name_ext.save()
        except ExtensionNotFound:
            return None
        return issuer_alt_name_ext


class SubjectAlternativeNameExtension(CertificateExtension, models.Model):
    """Represents the SubjectAlternativeName extension in X.509 certificates.

    Stores alternative names for the certificate's subject.
    """
    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)
    subject_alt_name = models.ForeignKey(
        GeneralNamesModel,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        verbose_name=_('Issuer Alternative Name Issuer')
    )

    def __str__(self) -> str:
        """Returns a string representation of the SubjectAlternativeName extension."""
        return (
            f'{self.__class__.__name__}(critical={self.critical}, '
            f'oid={self.extension_oid})')

    @property
    def extension_oid(self) -> str:  # noqa: D102
        return CertificateExtensionOid.SUBJECT_ALTERNATIVE_NAME.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | SubjectAlternativeNameExtension:
        """Stores the SubjectAlternativeName extension in the database.

        Args:
            extension (x509.Extension): The X.509 extension containing SubjectAlternativeName.

        Returns:
            SubjectAlternativeNameExtension: The instance of the saved extension.
        """
        try:
            gn = GeneralNamesModel()
            gn.save()
            gn.save_general_names(extension)

            alt_name_ext = cls(critical=extension.critical, subject_alt_name=gn)
            alt_name_ext.save()
        except ExtensionNotFound:
            return None

        return alt_name_ext


class AuthorityKeyIdentifierExtension(CertificateExtension, models.Model):
    """Represents the AuthorityKeyIdentifier extension in X.509 certificates.

    Identifies the public key of the issuing CA.
    """

    _extension_type = 'AuthorityKeyIdentifier'

    key_identifier = models.CharField(  # noqa: DJ001
        max_length=256,
        editable=False,
        null=True, blank=True,
        verbose_name='Key Identifier'
    )
    authority_cert_serial_number = models.CharField(  # noqa: DJ001
        max_length=256,
        editable=False,
        null=True,
        blank=True,
        verbose_name='Authority Cert Serial Number'
    )
    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)
    authority_cert_issuer = models.ForeignKey(
        GeneralNamesModel,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        verbose_name=_('Issuer Alternative Name Issuer')
    )

    def __str__(self) -> str:
        """Returns a string representation of the AuthorityKeyIdentifier extension."""
        return (
            f'{self._extension_type}(critical={self.critical}, '
            f'oid={self.extension_oid})')

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.AUTHORITY_KEY_IDENTIFIER.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | AuthorityKeyIdentifierExtension:
        """Stores the AuthorityKeyIdentifier extension in the database.

        Args:
            extension (x509.Extension): The X.509 extension containing AuthorityKeyIdentifier.

        Returns:
            AuthorityKeyIdentifierExtension: The instance of the saved extension.
        """
        try:
            aki: x509.AuthorityKeyIdentifier = extension.value
            key_identifier = aki.key_identifier.hex().upper() if aki.key_identifier else None
            authority_cert_serial_number = hex(aki.authority_cert_serial_number)[2:].upper() \
                if aki.authority_cert_serial_number else None
            gn = None

            if aki.authority_cert_issuer:
                gn = GeneralNamesModel()
                gn.save()
                gn.save_general_names(aki.authority_cert_issuer)

            aki_extension = cls(
                key_identifier=key_identifier,
                authority_cert_serial_number=authority_cert_serial_number,
                critical=extension.critical,
                authority_cert_issuer=gn
            )
            aki_extension.save()
        except ExtensionNotFound:
            return None

        return aki_extension


class SubjectKeyIdentifierExtension(CertificateExtension, models.Model):
    """SubjectKeyIdentifierExtension Model.

    Stores the Subject Key Identifier (SKI) extension of an X.509 certificate.
    """
    # TODO(Anyone): Add critical and storage mechanism

    # The key_identifier is a hex-encoded, uppercase string representing the SKI
    key_identifier = models.CharField(
        max_length=256,
        editable=False,
        verbose_name='Key Identifier',
        unique=True
    )

    def __str__(self) -> str:
        """Returns a string representation of the SubjectKeyIdentifier extension."""
        return f'SubjectKeyIdentifierExtension(key_identifier={self.key_identifier})'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.SUBJECT_KEY_IDENTIFIER.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | SubjectKeyIdentifierExtension:
        """Stores the SubjectKeyIdentifierExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            extension (x509.Extension):
                The x509.Extension object containing the SKI.

        Returns:
            SubjectKeyIdentifierExtension: The saved instance of SubjectKeyIdentifierExtension.
        """
        try:
            ski_value: x509.SubjectKeyIdentifier = extension.value
            key_id_hex = ski_value.digest.hex().upper()

            existing_entry = cls.objects.filter(key_identifier=key_id_hex).first()
            if existing_entry:
                return existing_entry

            ski_extension = cls(key_identifier=key_id_hex)
            ski_extension.save()
        except ExtensionNotFound:
            return None
        return ski_extension


class NoticeReference(models.Model):
    """Represents a NoticeReference as per RFC5280."""
    organization = models.CharField(max_length=200, editable=False, verbose_name='Organization', null=True, blank=True)  # noqa: DJ001
    notice_numbers = models.CharField(  # noqa: DJ001
        max_length=1024,
        editable=False,
        verbose_name='Notice Numbers',
        null=True,
        blank=True
    )

    def __str__(self) -> str:
        """Returns a string representation of the NoticeReference."""
        return f'{self.organization or "Unknown"}: {self.notice_numbers}'


class UserNotice(models.Model):
    """Represents a UserNotice as per RFC5280."""
    notice_ref = models.ForeignKey(NoticeReference, null=True, blank=True, on_delete=models.CASCADE)
    explicit_text = models.CharField( # noqa: DJ001
        max_length=200,
        editable=False,
        verbose_name='Explicit Text',
        null=True,
        blank=True
    )

    def __str__(self) -> str:
        """Returns a string representation of the UserNotice."""
        return f'UserNotice: {self.explicit_text or "No Explicit Text"}'


class CPSUriModel(models.Model):
    """Represents a CPS URI as per RFC5280."""
    cps_uri = models.CharField(max_length=2048, editable=False, verbose_name='CPS URI')

    def __str__(self) -> str:
        """Returns a string representation of the CPSUriModel."""
        return f'CPS URI: {self.cps_uri}'


class QualifierModel(models.Model):
    """Generic model to represent either a CPS URI or a User Notice."""
    cps_uri = models.ForeignKey(CPSUriModel, null=True, blank=True, on_delete=models.CASCADE, related_name='qualifiers')
    user_notice = models.ForeignKey(
        UserNotice,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='qualifiers'
    )

    def __str__(self) -> str:
        """Returns a string representation of the QualifierModel."""
        if self.cps_uri:
            return f'Qualifier: CPS URI - {self.cps_uri}'
        if self.user_notice:
            return f'Qualifier: User Notice - {self.user_notice}'
        return 'Qualifier: Undefined'

    def save(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        if self.cps_uri and self.user_notice:
            msg = "Only one of 'cps_uri' or 'user_notice' can be set, not both."
            raise ValueError(msg)
        super().save(*args, **kwargs)


class PolicyQualifierInfo(models.Model):
    """Represents a PolicyQualifierInfo as per RFC5280."""
    policy_qualifier_id = models.CharField(max_length=256, editable=False, verbose_name='Policy Qualifier ID')
    qualifier = models.ForeignKey(QualifierModel, null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self) -> str:
        """Returns a string representation of the PolicyQualifierInfo."""
        return f'PolicyQualifierInfo: {self.policy_qualifier_id}'


class PolicyInformation(models.Model):
    """Model representing PolicyInformation as per RFC5280."""
    policy_identifier = models.CharField(max_length=256, editable=False, verbose_name='Policy Identifier')
    policy_qualifiers = models.ManyToManyField(PolicyQualifierInfo, blank=True, related_name='policies', editable=False)

    def __str__(self) -> str:
        """Returns a string representation of the PolicyInformation."""
        return f'PolicyInformation(policy_identifier={self.policy_identifier})'


class CertificatePoliciesExtension(CertificateExtension, models.Model):
    """CertificatePoliciesExtension Model.

    Stores the certificatePolicies extension as per RFC5280.
    """
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    certificate_policies = models.ManyToManyField(
        PolicyInformation,
        related_name='certificate_policies',
        editable=False
    )
    def __str__(self) -> str:
        """Returns a string representation of the CertificatePolicies extension."""
        return f'CertificatePoliciesExtension(critical={self.critical}, ' \
               f'policies={[policy.policy_identifier for policy in self.certificate_policies.all()]})'  # noqa: ISC002

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.CERTIFICATE_POLICIES.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR


    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | CertificatePoliciesExtension:
        """Stores the CertificatePoliciesExtension in the database.

        Args:
            extension (x509.Extension): The x509.Extension object that contains the CertificatePolicies.

        Returns:
            CertificatePoliciesExtension: The instance of the saved CertificatePoliciesExtension.
        """
        if not isinstance(extension.value, x509.CertificatePolicies):
            msg = 'Expected a CertificatePolicies extension.'
            raise TypeError(msg)

        try:
            policies_extension = cls(critical=extension.critical)
            policies_extension.save()

            for policy_info in extension.value:
                policy_identifier = policy_info.policy_identifier.dotted_string
                policy_information = PolicyInformation.objects.filter(policy_identifier=policy_identifier).first()

                if not policy_information:
                    policy_information = PolicyInformation(policy_identifier=policy_identifier)
                    policy_information.save()

                # Add policy qualifiers if present
                for qualifier in policy_info.policy_qualifiers or []:
                    if isinstance(qualifier, x509.UserNotice):
                        # Save User Notice
                        notice_reference = qualifier.notice_reference
                        user_notice = UserNotice.objects.create(
                            notice_ref=NoticeReference.objects.create(
                                organization=notice_reference.organization if notice_reference else None,
                                notice_numbers=','.join(map(str, notice_reference.notice_numbers)) \
                                    if notice_reference else None,
                            ) if notice_reference else None,
                            explicit_text=qualifier.explicit_text,
                        )
                        qualifier_model = QualifierModel(user_notice=user_notice)
                        qualifier_model.save()

                    elif isinstance(qualifier, str):
                        # Save CPS URI
                        cps_uri = CPSUriModel.objects.create(cps_uri=qualifier)
                        qualifier_model = QualifierModel(cps_uri=cps_uri)
                        qualifier_model.save()

                    # Add the qualifier to the policy
                    policy_qualifier_info = PolicyQualifierInfo.objects.create(
                        policy_qualifier_id=qualifier_model.pk,
                        qualifier=qualifier_model,
                    )
                    policy_information.policy_qualifiers.add(policy_qualifier_info)

                policy_information.save()
                policies_extension.certificate_policies.add(policy_information)

            policies_extension.save()
        except x509.ExtensionNotFound:
            return None
        return policies_extension


class KeyPurposeIdModel(models.Model):
    """Represents a KeyPurposeId (OID) used in Extended Key Usage extension."""
    oid = models.CharField(max_length=256, editable=False, verbose_name='Key Purpose OID', unique=True)

    def __str__(self) -> str:
        """Returns a string representation of the KeyPurposeIdModel."""
        return f'KeyPurposeId({self.oid})'


class ExtendedKeyUsageExtension(models.Model):
    """Represents the ExtendedKeyUsage extension in X.509 certificates.

    Specifies additional purposes for which the certified public key may be used.
    """
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    key_purpose_ids = models.ManyToManyField(KeyPurposeIdModel, related_name='extended_key_usages', editable=False)

    def __str__(self) -> str:
        """Returns a string representation of the ExtendedKeyUsage extension."""
        purposes = [k.oid for k in self.key_purpose_ids.all()]
        return f'ExtendedKeyUsageExtension(critical={self.critical}, key_purposes={purposes})'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.EXTENDED_KEY_USAGE.dotted_string


    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | ExtendedKeyUsageExtension:
        """Stores the ExtendedKeyUsage extension in the database.

        Args:
            extension (x509.Extension): The X.509 extension containing ExtendedKeyUsage.

        Returns:
            ExtendedKeyUsageExtension: The instance of the saved extension.
        """
        if not isinstance(extension.value, x509.ExtendedKeyUsage):
            msg = 'Expected an ExtendedKeyUsage extension.'
            raise TypeError(msg)

        try:
            eku_extension = cls(critical=extension.critical)
            eku_extension.save()

            for oid in extension.value:
                oid_str = oid.dotted_string
                key_purpose = KeyPurposeIdModel.objects.filter(oid=oid_str).first()
                if not key_purpose:
                    key_purpose = KeyPurposeIdModel(oid=oid_str)
                    key_purpose.save()

                eku_extension.key_purpose_ids.add(key_purpose)

            eku_extension.save()
        except ExtensionNotFound:
            return None
        return eku_extension

class GeneralNameModel(models.Model):
    rfc822_name = models.ForeignKey(GeneralNameRFC822Name, null=True, blank=True, on_delete=models.CASCADE)
    dns_name = models.ForeignKey(GeneralNameDNSName, null=True, blank=True, on_delete=models.CASCADE)
    directory_name = models.ForeignKey(GeneralNameDirectoryName, null=True, blank=True, on_delete=models.CASCADE)
    uri = models.ForeignKey(GeneralNameUniformResourceIdentifier, null=True, blank=True, on_delete=models.CASCADE)
    ip_address = models.ForeignKey(GeneralNameIpAddress, null=True, blank=True, on_delete=models.CASCADE)
    registered_id = models.ForeignKey(GeneralNameRegisteredId, null=True, blank=True, on_delete=models.CASCADE)
    other_name = models.ForeignKey(GeneralNameOtherName, null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self) -> str:
        """Returns a string representation of the GeneralNameModel."""
        return f'GeneralSubtree(GeneralName={self.get_str()}, min={self.minimum}, max={self.maximum})'

    def get_str(self) -> str:  # noqa: PLR0911
        """Returns a string representation of the GeneralNameModel."""
        if self.rfc822_name:
            return f'rfc822Name={self.rfc822_name.value}'
        if self.dns_name:
            return f'dNSName={self.dns_name.value}'
        if self.directory_name:
            return f"directoryName={','.join(str(n) for n in self.directory_name.names.all())}"
        if self.uri:
            return f'uri={self.uri.value}'
        if self.ip_address:
            return f'ipAddress={self.ip_address.value}'
        if self.registered_id:
            return f'registeredID={self.registered_id.value}'
        if self.other_name:
            return f'otherName={self.other_name.type_id}'
        return 'No GeneralName set'

    @classmethod
    def from_x509_general_name(cls, gname: x509.GeneralName) -> GeneralNameModel:  # noqa: C901
        """Creates and returns a GeneralNameModel instance from a cryptography.x509.GeneralName.

        Args:
            gname (x509.GeneralName): The cryptography GeneralName object.

        Returns:
            GeneralNameModel: A newly created or updated GeneralNameModel.
        """
        gn_model = cls()
        gn_model.save()

        if isinstance(gname, x509.RFC822Name):
            obj, _ = GeneralNameRFC822Name.objects.get_or_create(value=gname.value)
            gn_model.rfc822_name = obj

        elif isinstance(gname, x509.DNSName):
            obj, _ = GeneralNameDNSName.objects.get_or_create(value=gname.value)
            gn_model.dns_name = obj

        elif isinstance(gname, x509.DirectoryName):
            dir_name = GeneralNameDirectoryName()
            dir_name.save()
            for rdn in gname.value.rdns:
                for attr in rdn:
                    # Possibly store attribute in your DB
                    atv = AttributeTypeAndValue.objects.filter(
                        oid=attr.oid.dotted_string, value=attr.value
                    ).first()
                    if not atv:
                        atv = AttributeTypeAndValue(oid=attr.oid.dotted_string, value=attr.value)
                        atv.save()
                    dir_name.names.add(atv)
            dir_name.save()
            gn_model.directory_name = dir_name

        elif isinstance(gname, x509.UniformResourceIdentifier):
            obj, _ = GeneralNameUniformResourceIdentifier.objects.get_or_create(value=gname.value)
            gn_model.uri = obj

        elif isinstance(gname, x509.IPAddress):
            ip_str = str(gname.value)
            ip_type = (
                GeneralNameIpAddress.IpType.IPV4_ADDRESS
                if gname.value.version == 4  # noqa: PLR2004
                else GeneralNameIpAddress.IpType.IPV6_ADDRESS
            )
            obj, _ = GeneralNameIpAddress.objects.get_or_create(ip_type=ip_type, value=ip_str)
            gn_model.ip_address = obj

        elif isinstance(gname, x509.RegisteredID):
            obj, _ = GeneralNameRegisteredId.objects.get_or_create(value=gname.value.dotted_string)
            gn_model.registered_id = obj

        elif isinstance(gname, x509.OtherName):
            # Convert the value to hex
            hex_val = gname.value.hex().upper()
            obj, _ = GeneralNameOtherName.objects.get_or_create(
                type_id=gname.type_id.dotted_string, value=hex_val
            )
            gn_model.other_name = obj

        else:
            raise TypeError(gname)

        gn_model.save()
        return gn_model


class GeneralSubtree(models.Model):  # noqa: DJ008
    """Represents a single GeneralSubtree as per RFC5280.

    Base is a single GeneralName.
    minimum defaults to 0 and maximum is optional.
    """
    base = models.ForeignKey(GeneralNameModel, on_delete=models.CASCADE)

    minimum = models.PositiveIntegerField(default=0, editable=False)
    maximum = models.PositiveIntegerField(null=True, blank=True, editable=False, default=None)


class NameConstraintsExtension(CertificateExtension, models.Model):
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    permitted_subtrees = models.ManyToManyField(GeneralSubtree, related_name='permitted_subtrees_set', editable=False)
    excluded_subtrees = models.ManyToManyField(GeneralSubtree, related_name='excluded_subtrees_set', editable=False)

    def __str__(self) -> str:
        """Returns a string representation of the NameConstraintsExtension."""
        permitted = [str(subtree) for subtree in self.permitted_subtrees.all()]
        excluded = [str(subtree) for subtree in self.excluded_subtrees.all()]

        permitted_str = f"Permitted: {', '.join(permitted)}" if permitted else 'Permitted: None'
        excluded_str = f"Excluded: {', '.join(excluded)}" if excluded else 'Excluded: None'

        return f'NameConstraintsExtension(critical={self.critical}, {permitted_str}; {excluded_str})'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.NAME_CONSTRAINTS.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | NameConstraintsExtension:
        """Stores the NameConstraints extension in the database.

        Args:
            extension (x509.Extension): The x509.Extension object containing NameConstraints.

        Returns:
            NameConstraintsExtension: The saved instance of NameConstraintsExtension or None.
        """
        if not isinstance(extension.value, x509.NameConstraints):
            msg = 'Expected a NameConstraints extension.'
            raise TypeError(msg)

        try:
            nc_ext = cls(critical=extension.critical)
            nc_ext.save()

            def save_general_subtree(general_name: x509.GeneralName) -> GeneralSubtree:
                gn_model = GeneralNameModel.from_x509_general_name(general_name)
                subtree = GeneralSubtree(base=gn_model, minimum=0, maximum=None)
                subtree.save()
                return subtree

            if extension.value.permitted_subtrees is not None:
                for general_name in extension.value.permitted_subtrees:
                    subtree_obj = save_general_subtree(general_name)
                    nc_ext.permitted_subtrees.add(subtree_obj)

            if extension.value.excluded_subtrees is not None:
                for general_name in extension.value.excluded_subtrees:
                    subtree_obj = save_general_subtree(general_name)
                    nc_ext.excluded_subtrees.add(subtree_obj)

            nc_ext.save()
        except ExtensionNotFound:
            return None
        return nc_ext


class DistributionPointName(models.Model):
    full_name = models.ForeignKey(
        GeneralNamesModel,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    name_relative_to_crl_issuer = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Name relative to crl issuer'),
        related_name='distribution_point_name',
        editable=False,
        blank=True
    )

    def __str__(self) -> str:
        """Returns a string representation of the DistributionPointName."""
        if self.full_name:
            return f'DistributionPointName(full_name={self.full_name})'
        nrci = ', '.join(str(a) for a in self.name_relative_to_crl_issuer.all())
        return f'DistributionPointName(nameRelativeToCRLIssuer={nrci})'

    def save(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        if self.full_name and self.name_relative_to_crl_issuer.exists():
            msg = "Only one of 'full_name' or 'name_relative_to_crl_issuer' can be set, not both."
            raise ValueError(msg)
        super().save(*args, **kwargs)


class DistributionPointModel(CertificateExtension, models.Model):
    distribution_point_name = models.ForeignKey(
        DistributionPointName,
        verbose_name='Distribution Point Name',
        blank=True,
        on_delete=models.CASCADE
    )
    reasons = models.CharField(max_length=16, blank=True, null=True, verbose_name=_('Reasons'))  # noqa: DJ001
    crl_issuer = models.ForeignKey(
        GeneralNamesModel,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        verbose_name=_('CRL Issuer')
    )

    mapping: ClassVar[dict[str, int]] = {
        'unused': 0,
        'keyCompromise': 1,
        'cACompromise': 2,
        'affiliationChanged': 3,
        'superseded': 4,
        'cessationOfOperation': 5,
        'certificateHold': 6,
        'privilegeWithdrawn': 7,
        'aACompromise': 8
    }

    def __str__(self) -> str:
        """Returns a string representation of the DistributionPointModel."""
        dp_name = str(self.distribution_point_name) if self.distribution_point_name else 'None'
        crl_issuer_str = str(self.crl_issuer) if self.crl_issuer else 'None'
        reasons_list = self.bitstring_to_reasons_list(self.reasons) if self.reasons else []
        reasons_str = ', '.join(reasons_list) if reasons_list else 'None'

        return (
            f'DistributionPointModel(distribution_point_name={dp_name}, '
            f'reasons=[{reasons_str}], crl_issuer={crl_issuer_str})'
        )

    @classmethod
    def reasons_list_to_bitstring(cls, reasons_list: list[str]) -> str:
        """Converts a list of reasons into a binary bitstring."""
        bits = ['0'] * 9
        for reason in reasons_list:
            idx = cls.mapping[reason]
            bits[idx] = '1'
        return ''.join(bits)

    @classmethod
    def bitstring_to_reasons_list(cls, bitstr: str) -> list[str]:
        """Converts a binary bitstring back into a list of reasons."""
        reverse_mapping = {v: k for k, v in cls.mapping.items()}
        reasons = []
        for i, bit in enumerate(bitstr):
            if bit == '1':
                reasons.append(reverse_mapping[i])
        return reasons


    @classmethod
    def parse_distribution_points(cls, extension: x509.Extension) -> list[DistributionPointModel]:
        """Parses and stores DistributionPoints from an x509.Extension.

        Args:
            extension (x509.Extension): An x509.Extension containing DistributionPoints.

        Returns:
            List[DistributionPointModel]: List of created DistributionPoint objects.
        """
        if not isinstance(extension.value, x509.CRLDistributionPoints):
            raise TypeError(extension)

        distribution_points = []
        dp: x509.DistributionPoint

        for dp in extension.value:
            dpn = DistributionPointName()
            dpn.save()

            if dp.full_name:
                gn = GeneralNamesModel()
                gn.save()
                GeneralNamesModel.save_general_names(gn, dp.full_name)
                dpn.full_name = gn
                dpn.save()
            elif dp.relative_name:
                for atv in dp.relative_name:
                    attr, _ = AttributeTypeAndValue.objects.get_or_create(
                        oid=atv.oid.dotted_string,
                        value=atv.value
                    )
                    dpn.name_relative_to_crl_issuer.add(attr)
                dpn.save()

            crl_issuer = None
            if dp.crl_issuer:
                crl_issuer = GeneralNamesModel()
                crl_issuer.save()
                GeneralNamesModel.save_general_names(crl_issuer, dp.crl_issuer)

            reasons_list = ['']
            """# TODO: Check if x509 is using the correct ReasonFlags for Distribution Point. -> It is commented out?
            # if dp.reasons:
                #     reasons_list = []
                #     if x509.ReasonFlags.unused in dp.reasons:
                #         reasons_list.append("unused")
                #     if x509.ReasonFlags.key_compromise in dp.reasons:
                #         reasons_list.append("keyCompromise")
                #     if x509.ReasonFlags.ca_compromise in dp.reasons:
                #         reasons_list.append("cACompromise")
                #     if x509.ReasonFlags.affiliation_changed in dp.reasons:
                #         reasons_list.append("affiliationChanged")
                #     if x509.ReasonFlags.superseded in dp.reasons:
                #         reasons_list.append("superseded")
                #     if x509.ReasonFlags.cessation_of_operation in dp.reasons:
                #         reasons_list.append("cessationOfOperation")
                #     if x509.ReasonFlags.certificate_hold in dp.reasons:
                #         reasons_list.append("certificateHold")
                #     if x509.ReasonFlags.privilege_withdrawn in dp.reasons:
                #         reasons_list.append("privilegeWithdrawn")
                #     if x509.ReasonFlags.aA_compromise in dp.reasons:
                #         reasons_list.append("aACompromise")
                # reasons_list = cls.reasons_list_to_bitstring(dp.reasons)"""

            dp_model, _created = DistributionPointModel.objects.get_or_create(
                distribution_point_name=dpn,
                reasons=reasons_list,
                crl_issuer=crl_issuer
            )
            distribution_points.append(dp_model)

        return distribution_points


class CrlDistributionPointsExtension(CertificateExtension, models.Model):
    """Represents the CRLDistributionPoints extension in X.509 certificates.

    Specifies where to retrieve CRLs related to the certificate.
    """
    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)
    distribution_points = models.ManyToManyField(
        DistributionPointModel,
        verbose_name='Distribution Points',
        blank=True
    )

    def __str__(self) -> str:
        """Returns a string representation of the extension."""
        return f'CRLDistributionPointsExtension(critical={self.critical}, dp_count={self.distribution_points.count()})'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.CRL_DISTRIBUTION_POINTS.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR


    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> CrlDistributionPointsExtension | None:
        """Stores the CRLDistributionPoints extension in the database.

        Args:
            extension (x509.Extension): The X.509 extension containing CRLDistributionPoints.

        Returns:
            CrlDistributionPointsExtension: The instance of the saved extension.
        """
        if not isinstance(extension.value, x509.CRLDistributionPoints):
            msg = 'Expected a CRLDistributionPoints extension.'
            raise TypeError(msg)

        ext_instance = cls(critical=extension.critical)
        ext_instance.save()
        distribution_points = DistributionPointModel.parse_distribution_points(extension)
        ext_instance.distribution_points.add(*distribution_points)
        ext_instance.save()
        return ext_instance

class AccessDescriptionModel(CertificateExtension, models.Model):
    access_method = models.CharField(max_length=256, editable=False, verbose_name='Access Method OID')
    access_location = models.ForeignKey(GeneralNameModel, verbose_name='Access Location', on_delete=models.CASCADE)

    def __str__(self) -> str:
        """Returns a string representation of the AccessDescriptionModel."""
        return f'AccessDescription(method={self.access_method}, location={self.access_location})'


class AuthorityInformationAccessExtension(CertificateExtension, models.Model):
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    authority_info_access_syntax = models.ManyToManyField(
        AccessDescriptionModel,
        related_name='authority_info_access_syntax',
        blank=True
    )

    def __str__(self) -> str:
        return f'AuthorityInformationAccessExtension(critical={self.critical}, #authority_info_access_syntax={self.authority_info_access_syntax.count()})'  # noqa: E501

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.AUTHORITY_INFORMATION_ACCESS.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR


    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> AuthorityInformationAccessExtension | None:
        """Creates an AuthorityInformationAccessExtension from the cryptography AuthorityInformationAccess object."""
        if not isinstance(extension.value, x509.AuthorityInformationAccess):
            msg = 'Expected an AuthorityInformationAccess extension.'
            raise TypeError(msg)

        aia_ext = cls(critical=extension.critical)
        aia_ext.save()

        for access_desc in extension.value:
            adm = AccessDescriptionModel()
            adm.access_method = access_desc.access_method.dotted_string

            gn_model = None
            if access_desc.access_location is not None:
                gn_model = GeneralNameModel.from_x509_general_name(access_desc.access_location)

            adm.access_location = gn_model
            adm.save()

            aia_ext.authority_info_access_syntax.add(adm)

        aia_ext.save()
        return aia_ext


class SubjectInformationAccessExtension(CertificateExtension, models.Model):
    """Represents the SubjectInformationAccess extension (SIA)."""
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    subject_info_access_syntax = models.ManyToManyField(
        AccessDescriptionModel,
        related_name='subject_info_access_syntax',
        blank=True
    )

    def __str__(self) -> str:
        """Returns a string representation of the SubjectInformationAccess extension."""
        return f'SubjectInformationAccessExtension(critical={self.critical}, #subject_info_access_syntax={self.subject_info_access_syntax.count()})'  # noqa: E501

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.SUBJECT_INFORMATION_ACCESS.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> SubjectInformationAccessExtension | None:
        """Creates a SubjectInformationAccessExtension from the cryptography.x509.SubjectInformationAccess object."""
        if not isinstance(extension.value, x509.SubjectInformationAccess):
            msg = 'Expected a SubjectInformationAccess extension.'
            raise TypeError(msg)

        sia_ext = cls(critical=extension.critical)
        sia_ext.save()

        for access_desc in extension.value:
            adm = AccessDescriptionModel()
            adm.access_method = access_desc.access_method.dotted_string

            gn_model = None
            if access_desc.access_location is not None:
                gn_model = GeneralNameModel.from_x509_general_name(access_desc.access_location)

            adm.access_location = gn_model
            adm.save()

            sia_ext.subject_info_access_syntax.add(adm)

        sia_ext.save()
        return sia_ext

class InhibitAnyPolicyExtension(CertificateExtension, models.Model):
    """Represents the InhibitAnyPolicy extension in X.509 certificates.

    This extension specifies the number of additional certificates that may appear
    in the path before an explicit policy is required.
    """
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    inhibit_any_policy = models.PositiveIntegerField(
        blank=True,
        null=True,
        verbose_name='InhibitAnyPolicy',
        editable=False
    )

    def __str__(self) -> str:
        """Returns a string representation of the InhibitAnyPolicyExtension."""
        return (
            f'InhibitAnyPolicyExtension(critical={self.critical}, '
            f'inhibit_any_policy={self.inhibit_any_policy if self.inhibit_any_policy is not None else "None"})'
        )

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.INHIBIT_ANY_POLICY.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> InhibitAnyPolicyExtension | None:
        """Creates a InhibitAnyPolicyExtension from the cryptography.x509.InhibitAnyPolicy object."""
        if not isinstance(extension.value, x509.InhibitAnyPolicy):
            msg = 'Expected a InhibitAnyPolicy extension.'
            raise TypeError(msg)

        if not isinstance(extension.value.skip_certs, int):
            raise TypeError(extension.value.skip_certs)
        iap_ext = cls(critical=extension.critical, inhibit_any_policy=extension.value.skip_certs)
        iap_ext.save()

        return iap_ext


class PolicyMappingModel(models.Model):
    """Represents a single Policy Mapping as per RFC5280.

    Each mapping includes an issuerDomainPolicy and a subjectDomainPolicy.
    """
    issuer_domain_policy = models.CharField(
        max_length=256,
        verbose_name='Issuer Domain Policy OID',
        editable=False
    )
    subject_domain_policy = models.CharField(
        max_length=256,
        verbose_name='Subject Domain Policy OID',
        editable=False
    )

    class Meta:
        unique_together = ('issuer_domain_policy', 'subject_domain_policy')

    def __str__(self) -> str:
        """Returns a string representation of the PolicyMappingModel."""
        return f'PolicyMapping(issuerDomainPolicy={self.issuer_domain_policy}, subjectDomainPolicy={self.subject_domain_policy})'  # noqa: E501


class PolicyMappingsExtension(CertificateExtension, models.Model):
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    policy_mappings = models.ManyToManyField(
        PolicyMappingModel,
        related_name='policy_mappings_extension',
        editable=False
    )

    def __str__(self) -> str:
        mappings = ', '.join(
            f'{mapping.issuer_domain_policy} -> {mapping.subject_domain_policy}'
            for mapping in self.policy_mappings.all()
        )
        return f'PolicyMappingsExtension(critical={self.critical}, mappings=[{mappings}])'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.POLICY_MAPPINGS.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | PolicyMappingsExtension:
        """Stores the PolicyMappingsExtension in the database.

        Args:
            extension (x509.Extension): The x509.Extension object containing PolicyMappings.

        Returns:
            PolicyMappingsExtension: The saved instance of PolicyMappingsExtension or None.
        """
        if not isinstance(extension.value, x509.PolicyMappings):
            msg = 'Expected a PolicyMappings extension.'
            raise TypeError(msg)

        try:
            mappings_ext = cls(critical=extension.critical)
            mappings_ext.save()

            for mapping in extension.value:
                issuer_policy = mapping.issuer_domain_policy.dotted_string
                subject_policy = mapping.subject_domain_policy.dotted_string

                policy_mapping, _ = PolicyMappingModel.objects.get_or_create(
                    issuer_domain_policy=issuer_policy,
                    subject_domain_policy=subject_policy
                )
                mappings_ext.policy_mappings.add(policy_mapping)

            mappings_ext.save()
        except x509.ExtensionNotFound:
            return None
        return mappings_ext


class PolicyConstraintsExtension(CertificateExtension, models.Model):
    """Represents the PolicyConstraints extension in X.509 certificates.

    This extension specifies whether an explicit policy is required and whether policy mapping is inhibited.
    """
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    require_explicit_policy = models.PositiveIntegerField(
        blank=True,
        null=True,
        verbose_name='requireExplicitPolicy',
        editable=False
    )
    inhibit_policy_mapping = models.PositiveIntegerField(
        blank=True,
        null=True,
        verbose_name='inhibitPolicyMapping',
        editable=False
    )

    def __str__(self) -> str:
        """Returns a string representation of the PolicyConstraintsExtension."""
        return (
            f'PolicyConstraintsExtension(critical={self.critical}, '
            f'require_explicit_policy={self.require_explicit_policy}, '
            f'inhibit_policy_mapping={self.inhibit_policy_mapping})'
        )

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.POLICY_CONSTRAINTS.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | PolicyConstraintsExtension:
        """Stores the PolicyMappingsExtension in the database.

        Args:
            extension (x509.Extension): The x509.Extension object containing PolicyConstraints.

        Returns:
            PolicyConstraintsExtension: The saved instance of PolicyConstraintsExtension or None.
        """
        if not isinstance(extension.value, x509.PolicyConstraints):
            msg = 'Expected a PolicyConstraints extension.'
            raise TypeError(msg)

        try:
            policy_constraint_ext = cls(
                critical=extension.critical,
                require_explicit_policy=extension.value.require_explicit_policy,
                inhibit_policy_mapping=extension.value.inhibit_policy_mapping
            )
            policy_constraint_ext.save()
        except x509.ExtensionNotFound:
            return None
        return policy_constraint_ext


class SubjectDirectoryAttributesExtension(CertificateExtension, models.Model):
    """Represents the SubjectDirectoryAttributes extension in X.509 certificates.

    This extension contains additional subject attributes, such as date of birth or place of birth.
    """
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    subject_directory_attributes  = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Subject Directory Attributes'),
        editable=False,
        blank=True
    )

    def __str__(self) -> str:
        """Returns a string representation of the SubjectDirectoryAttributesExtension."""
        attributes = ', '.join(str(attr) for attr in self.subject_directory_attributes.all())
        return f'SubjectDirectoryAttributesExtension(critical={self.critical}, attributes=[{attributes}])'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.SUBJECT_DIRECTORY_ATTRIBUTES.dotted_string
    extension_oid.fget.short_description = EXTENSION_STR

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | SubjectDirectoryAttributesExtension:
        """Stores the SubjectDirectoryAttributesExtension in the database.

        Args:
            extension (x509.Extension): The x509.Extension object containing SubjectDirectoryAttributes.

        Returns:
            SubjectDirectoryAttributesExtension: The saved instance of SubjectDirectoryAttributesExtension or None.
        """
        # Not supported
        """if not isinstance(extension.value, x509.SubjectDirectoryAttributes):
            msg = 'Expected a SubjectDirectoryAttributes extension.'
            raise TypeError(msg)"""

        try:
            subject_directory_attributes = cls(critical=extension.critical)

            for sdae in extension.value:
                oid = sdae.oid.dotted_string
                value = sdae.value

                attr_type_and_val = AttributeTypeAndValue(oid=oid, value=value)
                subject_directory_attributes.subject_directory_attributes.add(attr_type_and_val)

            subject_directory_attributes.save()
        except x509.ExtensionNotFound:
            return None
        return subject_directory_attributes


class FreshestCrlExtension(CertificateExtension, models.Model):
    """Represents the Freshest CRL extension (RFC5280).

    Specifies the location of the freshest CRL available for a certificate.
    """
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    distribution_points = models.ManyToManyField(DistributionPointModel, blank=True)

    def __str__(self) -> str:
        """Returns a string representation of the FreshestCrlExtension."""
        return f'FreshestCrlExtension(critical={self.critical}, distribution_points={self.distribution_points.count()})'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.FRESHEST_CRL.dotted_string

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> FreshestCrlExtension | None:
        """Stores the Freshest CRL extension in the database.

        Args:
            extension (x509.Extension): The X.509 extension containing Freshest CRL.

        Returns:
            FreshestCrlExtension: The instance of the saved extension.
        """
        if not isinstance(extension.value, x509.FreshestCRL):
            msg = 'Expected a FreshestCRL extension.'
            raise TypeError(msg)

        ext_instance = cls(critical=extension.critical)
        ext_instance.save()
        distribution_points = DistributionPointModel.parse_distribution_points(extension)
        ext_instance.distribution_points.add(*distribution_points)
        ext_instance.save()
        return ext_instance


# class OcspNoCheckExtension(CertificateExtension, models.Model):
#     pass
#
#
# class TlsFeatureExtension(CertificateExtension, models.Model):
#     pass
#
#
# class CrlNumberExtension(CertificateExtension, models.Model):
#     pass
#
#
# class DeltaCrlIndicatorExtension(CertificateExtension, models.Model):
#     pass
#
#
# class PrecertSignedCertificateTimestampsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class PrecertPoisonExtension(CertificateExtension, models.Model):
#     pass
#
#
# class SignedCertificateTimestampsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class IssuingDistributionPointsExtension(CertificateExtension, models.Model):
#     pass
#
#
#
# class MsCertificateTemplateExtension(CertificateExtension, models.Model):
#     pass
