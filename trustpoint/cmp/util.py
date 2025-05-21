"""This module provides some utility functions regarding CMP."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.x509.name import _ASN1Type as X509_Asn1Type
from pyasn1.codec.der import decoder  # type: ignore[import-untyped]
from pyasn1.type.char import (  # type: ignore[import-untyped]
    BMPString,
    IA5String,
    NumericString,
    PrintableString,
    T61String,
    UniversalString,
    UTF8String,
    VisibleString,
)
from pyasn1.type.univ import BitString, OctetString  # type: ignore[import-untyped]
from pyasn1.type.useful import GeneralizedTime, UTCTime  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from pyasn1_modules import rfc2459  # type: ignore[import-untyped]


class PkiMessageType(enum.Enum):
    """PKI Message Type (CMP) Enum."""

    IR = 'ir'


class GeneralNameType(enum.Enum):
    """General Name Type Enum,"""

    RFC822_NAME = 'rfc822Name'
    DNS_NAME = 'dNSName'
    DIRECTORY_NAME = 'directoryName'
    UNIFORM_RESOURCE_IDENTIFIER = 'uniformResourceIdentifier'
    IP_ADDRESS = 'iPAddress'
    REGISTERED_ID = 'registeredID'
    OTHER_NAME = 'otherName'


class Popo(enum.Enum):
    """Proof of Possession Enum."""

    RA_VERIFIED = 'raVerified'
    SIGNATURE = 'signature'
    KEY_ENCIPHERMENT = 'keyEncipherment'
    KEY_AGREEMENT = 'keyAgreement'


class NameParser:
    """Provides class methods to transform pyasn1 (General)Names into x509.(General)Names."""

    @classmethod
    def parse_general_name(cls, general_name: rfc2459.GeneralName) -> x509.GeneralName:
        """Parses the pyasn1_modules.rfc2459.GeneralName object and transforms it into a x509.GeneralName object.

        Args:
            general_name: The pyasn1_modules.rfc2459.GeneralName object to parse.

        Returns:
            The cryptography.x509.Name object.
        """
        general_name_type = GeneralNameType(general_name.getName())
        if general_name_type == GeneralNameType.DIRECTORY_NAME:
            return x509.DirectoryName(cls.parse_name(general_name[GeneralNameType.DIRECTORY_NAME.value]))
        err_msg = 'Currently only supporting DirectoryName as GeneralName.'
        raise ValueError(err_msg)

    @staticmethod
    def parse_name(name: rfc2459.Name) -> x509.Name:  # noqa: C901, PLR0912, PLR0915
        """Parses the pyasn1_modules.rfc2459.Name object and transforms it into a x509.Name object.

        Args:
            name: The pyasn1_modules.rfc2459.Name object to parse.

        Returns:
            The cryptography.x509.Name object.
        """
        rdns_sequence = name[0]
        if rdns_sequence.isValue:
            crypto_rdns_sequence: list[x509.RelativeDistinguishedName] = []
            for rdns in rdns_sequence:
                if len(rdns) < 1:
                    err_msg = 'Found empty RDN in the subject field of the certTemplate.'
                    raise ValueError(err_msg)
                if len(rdns) > 1:
                    err_msg = 'This CMP implementation does not support multi-valued RDNs.'
                    raise ValueError(err_msg)

                attribute_type_and_value = rdns[0]
                if (
                    not attribute_type_and_value.isValue
                    or not attribute_type_and_value['type'].isValue
                    or not attribute_type_and_value['value'].isValue
                ):
                    err_msg = 'Found empty RDN in the subject field of the certTemplate.'
                    raise ValueError(err_msg)

                attribute_type = attribute_type_and_value['type']
                crypto_oid = x509.ObjectIdentifier(str(attribute_type))

                attribute_value = attribute_type_and_value['value']
                decoded_attribute_value, _ = decoder.decode(attribute_value)

                if isinstance(decoded_attribute_value, UTF8String):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName([x509.NameAttribute(crypto_oid, str(decoded_attribute_value))])
                    )
                    continue

                if isinstance(decoded_attribute_value, NumericString):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.NumericString
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, PrintableString):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.PrintableString
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, T61String):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.T61String
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, IA5String):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.IA5String
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, VisibleString):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.VisibleString
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, UniversalString):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.UniversalString
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, BMPString):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.BMPString
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, BitString):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, bytes(decoded_attribute_value), _type=X509_Asn1Type.BitString
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, OctetString):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.OctetString
                                )
                            ]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, UTCTime):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [x509.NameAttribute(crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.UTCTime)]
                        )
                    )
                    continue

                if isinstance(decoded_attribute_value, GeneralizedTime):
                    crypto_rdns_sequence.append(
                        x509.RelativeDistinguishedName(
                            [
                                x509.NameAttribute(
                                    crypto_oid, str(decoded_attribute_value), _type=X509_Asn1Type.GeneralizedTime
                                )
                            ]
                        )
                    )
                    continue

                err_msg = f'Found NameAttribute in an RDN with unknown value type: {type(decoded_attribute_value)}.'
                raise ValueError(err_msg)

            return x509.Name(crypto_rdns_sequence)
        raise ValueError
