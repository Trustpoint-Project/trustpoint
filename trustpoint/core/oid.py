"""OID Enums and Public Key / SignatureSuite wrappers."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519, dh

if TYPE_CHECKING:
    from typing import Self, Union, Optional

    from cryptography import x509

    PublicKey = Union[
        dh.DHPublicKey,
        dsa.DSAPublicKey,
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
        x25519.X25519PublicKey,
        x448.X448PublicKey,
    ]
    PrivateKey = Union[
        dh.DHPrivateKey,
        dsa.DSAPrivateKey,
        rsa.RSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
        x25519.X25519PrivateKey,
        x448.X448PrivateKey,
    ]


RSA_MIN_KEY_SIZE = 2048
EC_MIN_KEY_SIZE = 128


class NameOid(enum.Enum):
    """Name OID Enum."""

    dotted_string: str
    abbreviation: str
    full_name: str
    verbose_name: str

    OBJECT_CLASS = ('2.5.4.0', '', 'objectClass', 'Object Class')
    ALIASED_ENTRY_NAME = ('2.5.4.1', '', 'aliasedEntryName', 'Aliased Entry Name')
    KNOWLEDGE_INFORMATION = ('2.5.4.2', '', 'knowledgeInformation', 'Knowledge Information')
    COMMON_NAME = ('2.5.4.3', 'CN', 'commonName', 'Common Name')
    SURNAME = ('2.5.4.4', 'SN', 'Surname', 'Surname')
    SERIAL_NUMBER = ('2.5.4.5', '', 'serialNumber', 'Serial Number')
    COUNTRY_NAME = ('2.5.4.6', 'C', 'countryName', 'Country Name')
    LOCALITY_NAME = ('2.5.4.7', 'L', 'localityName', 'Locality Name')
    STATE_OR_PROVINCE_NAME = ('2.5.4.8', 'ST', 'stateOrProvinceName', 'State or Province Name')
    STREET_ADDRESS = ('2.5.4.9', '', 'streetAddress', 'Street Address')
    ORGANIZATION_NAME = ('2.5.4.10', 'O', 'organizationName', 'Organization Name')
    ORGANIZATIONAL_UNIT_NAME = ('2.5.4.11', 'OU', 'organizationalUnitName', 'Organizational Unit Name')
    TITLE = ('2.5.4.12', 'T', 'title', 'Title')
    DESCRIPTION = ('2.5.4.13', '', 'description', 'Description')
    SEARCH_GUIDE = ('2.5.4.14', '', 'searchGuide', 'Search Guide')
    BUSINESS_CATEGORY = ('2.5.4.15', '', 'businessCategory', 'Business Category')
    POSTAL_ADDRESS = ('2.5.4.16', '', 'postalAddress', 'Postal Address')
    POSTAL_CODE = ('2.5.4.17', '', 'postalCode', 'Postal Code')
    POST_OFFICE_BOX = ('2.5.4.18', '', 'postOfficeBox', 'Post Office Box')
    PHYSICAL_DELIVERY_OFFICE_NAME = ('2.5.4.19', '', 'physicalDeliveryOfficeName', 'Physical Delivery Office Name')
    TELEPHONE_NUMBER = ('2.5.4.20', '', 'telephoneNumber', 'Telephone Number')
    TELEX_NUMBER = ('2.5.4.21', '', 'telexNumber', 'Telex Number')
    TELEX_TERMINAL_IDENTIFIER = ('2.5.4.22', '', 'telexTerminalIdentifier', 'Telex Terminal Identifier')
    FACSIMILE_TELEPHONE_NUMBER = ('2.5.4.23', '', 'facsimileTelephoneNumber', 'Facsimile Telephone Number')
    X121_Address = ('2.5.4.24', '', 'x121Address', 'X121 Address')
    INTERNATIONAL_ISD_NUMBER = ('2.5.4.25', '', 'internationalISDNumber', 'International ISD Number')
    REGISTERED_ADDRESS = ('2.5.4.26', '', 'registeredAddress', 'Registered Address')
    DESTINATION_INDICATOR = ('2.5.4.27', '', 'destinationIndicator', 'Destination Indicator')
    PREFERRED_DELIVERY_METHOD = ('2.5.4.28', '', 'preferredDeliveryMethod', 'Preferred Delivery Method')
    PRESENTATION_ADDRESS = ('2.5.4.29', '', 'presentationAddress', 'Presentation Address')
    SUPPORTED_APPLICATION_CONTEXT = ('2.5.4.30', '', 'supportedApplicationContext', 'Supported Application Context')
    MEMBER = ('2.5.4.31', '', 'member', 'Member')
    OWNER = ('2.5.4.32', '', 'owner', 'Owner')
    ROLE_OCCUPANT = ('2.5.4.33', '', 'roleOccupant', 'Role Occupant')
    SEE_ALSO = ('2.5.4.34', '', 'seeAlso', 'See Also')
    USER_PASSWORD = ('2.5.4.35', '', 'userPassword', 'User Password')
    USER_CERTIFICATE = ('2.5.4.36', '', 'userCertificate', 'User Certificate')
    CA_Certificate = ('2.5.4.37', '', 'cACertificate', 'CA Certificate')
    AUTHORITY_REVOCATION_LIST = ('2.5.4.38', '', 'authorityRevocationList', 'Authority Revocation List')
    CERTIFICATE_REVOCATION_LIST = ('2.5.4.39', '', 'certificateRevocationList', 'Certificate Revocation List')
    CROSS_CERTIFICATE_PAIR = ('2.5.4.40', '', 'crossCertificatePair', 'Cross Certificate Pair')
    NAME = ('2.5.4.41', '', 'name', 'Name')
    GIVEN_NAME = ('2.5.4.42', 'GN', 'givenName', 'Given name')
    INITIALS = ('2.5.4.43', '', 'initials', 'Initials')
    GENERATION_QUALIFIER = ('2.5.4.44', '', 'generationQualifier', 'Generation Qualifier')
    X500_UNIQUE_IDENTIFIER = ('2.5.4.45', '', 'x500UniqueIdentifier', 'X500 Unique identifier')
    DN_QUALIFIER = ('2.5.4.46', '', 'dnQualifier', 'DN Qualifier')
    ENHANCED_SEARCH_GUIDE = ('2.5.4.47', '', 'enhancedSearchGuide', 'Enhanced Search Guide')
    PROTOCOL_INFORMATION = ('2.5.4.48', '', 'protocolInformation', 'Protocol Information')
    DISTINGUISHED_NAME = ('2.5.4.49', '', 'distinguishedName', 'Distinguished Name')
    UNIQUE_MEMBER = ('2.5.4.50', '', 'uniqueMember', 'Unique Member')
    HOUSE_IDENTIFIER = ('2.5.4.51', '', 'houseIdentifier', 'House Identifier')
    SUPPORTED_ALGORITHMS = ('2.5.4.52', '', 'supportedAlgorithms', 'Supported Algorithms')
    DELTA_REVOCATION_LIST = ('2.5.4.53', '', 'deltaRevocationList', 'Delta Revocation List')
    DMD_NAME = ('2.5.4.54', '', 'dmdName', 'DMD Name')
    CLEARANCE = ('2.5.4.55', '', 'clearance', 'Clearance')
    DEFAULT_DIR_QOP = ('2.5.4.56', '', 'defaultDirQop', 'Default DIR QOP')
    ATTRIBUTE_INTEGRITY_INFO = ('2.5.4.57', '', 'attributeIntegrityInfo', 'Attribute Integrity Info')
    ATTRIBUTE_CERTIFICATE = ('2.5.4.58', '', 'attributeCertificate', 'Attribute Certificate')
    ATTRIBUTE_CERTIFICATE_REVOCATION_LIST = (
        '2.5.4.59',
        '',
        'attributeCertificateRevocationList',
        'Attribute Certificate Revocation List',
    )
    CONF_KEY_INFO = ('2.5.4.60', '', 'confKeyInfo', 'Conf Key Info')
    AA_Certificate = ('2.5.4.61', '', 'aACertificate', 'AA Certificate')
    ATTRIBUTE_DESCRIPTOR_CERTIFICATE = (
        '2.5.4.62',
        '',
        'attributeDescriptorCertificate',
        'Attribute Descriptor Certificate',
    )
    ATTRIBUTE_AUTHORITY_REVOCATION_LIST = (
        '2.5.4.63',
        '',
        'attributeAuthorityRevocationList',
        'Attribute Authority Revocation List',
    )
    FAMILY_INFORMATION = ('2.5.4.64', '', 'familyInformation', 'Family Information')
    PSEUDONYM = ('2.5.4.65', '', 'pseudonym', 'Pseudonym')
    COMMUNICATIONS_SERVICE = ('2.5.4.66', '', 'communicationsService', 'Communications Service')
    COMMUNICATIONS_NETWORK = ('2.5.4.67', '', 'communicationsNetwork', 'Communications Network')
    CERTIFICATION_PRACTICE_STMT = ('2.5.4.68', '', 'certificationPracticeStmt', 'Certification Practice Statement')
    CERTIFICATE_POLICY = ('2.5.4.69', '', 'certificatePolicy', 'Certificate Policy')
    PKI_PATH = ('2.5.4.70', '', 'pkiPath', 'PKI Path')
    PRIVILEGE_POLICY = ('2.5.4.71', '', 'privilegePolicy', 'Privilege Policy')
    ROLE = ('2.5.4.72', '', 'role', 'Role')
    PMI_DELEGATION_PATH = ('2.5.4.73', '', 'pmiDelegationPath', 'PMI Delegation Path')
    PROTECTED_PRIVILEGE_POLICY = ('2.5.4.74', '', 'protectedPrivilegePolicy', 'Protected Privilege Policy')
    XML_PRIVILEGE_INFO = ('2.5.4.75', '', 'xMLPrivilegeInfo', 'XML Privilege Info')
    XML_PRIV_POLICY = ('2.5.4.76', '', 'xmlPrivPolicy', 'XML Privilege Policy')
    UUID_PAIR = ('2.5.4.77', '', 'uuidPair', 'UUID Pair')
    TAG_OID = ('2.5.4.78', '', 'tagOid', 'Tag OID')
    UII_FORMAT = ('2.5.4.79', '', 'uiiFormat', 'Unique Item Identifier Format')
    UII_IN_URN = ('2.5.4.80', '', 'uiiInUrn', 'Unique Item Identifier in URN')
    CONTENT_URL = ('2.5.4.81', '', 'contentUrl', 'Content URL')
    PERMISSION = ('2.5.4.82', '', 'permission', 'Permission')
    URI = ('2.5.4.83', '', 'uri', 'Uniform Resource Identifier (URI)')
    PWD_ATTRIBUTE = ('2.5.4.84', '', 'pwdAttribute', 'Password Attribute')
    USER_PWD = ('2.5.4.85', '', 'userPwd', 'User Password')
    URN = ('2.5.4.86', '', 'urn', 'Uniform Resource Name (URN)')
    URL = ('2.5.4.87', '', 'url', 'Uniform Resource Locator (URL)')
    UTM_COORDINATES = ('2.5.4.88', '', 'utmCoordinates', 'UTM (Universal Transverse Mercator) Coordinates')
    URN_C = ('2.5.4.89', '', 'urnC', 'Uniform Resource Locator Component (urnC)')
    UII = ('2.5.4.90', '', 'uii', 'Unique Item Identifier (UII)')
    EPC = ('2.5.4.91', '', 'epc', 'Electronic Product Code')
    TAG_AFI = ('2.5.4.92', '', 'tagAfi', 'Tag Application Family Identifier (Tag AFI)')
    EPC_FORMAT = ('2.5.4.93', '', 'epcFormat', 'Electronic Product Code Format')
    EPC_IN_URN = ('2.5.4.94', '', 'epcInUrn', 'Electronic Product Code in URN')
    LDAP_URL = ('2.5.4.95', '', 'ldapUrl', 'LDAP URL')
    TAG_LOCATION = ('2.5.4.96', '', 'tagLocation', 'Tag Location')
    ORGANIZATION_IDENTIFIER = ('2.5.4.97', '', 'organizationIdentifier', 'Organization Identifier')
    COUNTRY_CODE_3C = ('2.5.4.98', '', 'countryCode3c', 'Country Code 3C (ISO 3166-1 alpha-3)')
    COUNTRY_CODE_3N = ('2.5.4.99', '', 'countryCode3n', 'Country Code 3N ( ISO 3166-1 numeric-3)')
    DNS_NAME = ('2.5.4.100', '', 'dnsName', 'DNS Name')
    EE_PK_CERTIFICATE_REVOCATION_LIST = (
        '2.5.4.101',
        '',
        'eepkCertificateRevocationList',
        'End-Entity Public-Key Certificate Revocation List',
    )
    EE_ATTR_CERTIFICATE_REVOCATION_LIST = (
        '2.5.4.102',
        '',
        'eeAttrCertificateRevocationList',
        'End-Entity Attribute Certificate Revocation List',
    )
    SUPPORTED_PUBLIC_KEY_ALGORITHMS = (
        '2.5.4.103',
        '',
        'supportedPublicKeyAlgorithms',
        'Supported Public-Key Algorithms',
    )
    INT_EMAIL = ('2.5.4.104', '', 'intEmail', 'Internationalized Email Address')
    JID = ('2.5.4.105', '', 'jid', 'Jabber Identifier')
    OBJECT_IDENTIFIER = ('2.5.4.106', '', 'objectIdentifier', 'Object Identifier')

    # GOST Algorithms, RFC 9215, Russian, Broken Cypher!
    OGRN = ('1.2.643.100.1', '', 'ogrn', 'Main State Registration Number of juridical entities (OGRN)')
    SNILS = ('1.2.643.100.3', '', 'snils', 'Individual Insurance Account Number (SNILS)')
    INNLE = ('1.2.643.100.4', '', 'innle', 'Individual Taxpayer Number (ITN) of the legal entity')
    OGRN_IP = ('1.2.643.100.5', '', 'ogrnip', 'Main State Registration Number of individual entrepreneurs')
    IDENTIFICATION_KIND = ('1.2.643.100.114', '', 'identificationKind', 'Identification Kind')
    INN = ('1.2.643.3.131.1.1', '', 'inn', 'Individual Taxpayer Number (ITN, INN)')

    # RFC 2985
    # emailAddress is deprecated, use altName extension
    EMAIL_ADDRESS = ('1.2.840.113549.1.9.1', 'E', 'emailAddress', 'Email Address (Deprecated)')
    UNSTRUCTURED_NAME = ('1.2.840.113549.1.9.2', '', 'unstructuredName', 'Unstructured Name (FQDN)')
    CONTENT_TYPE = ('1.2.840.113549.1.9.3', '', 'contentType', 'Content Type')
    UNSTRUCTURED_ADDRESS = ('1.2.840.113549.1.9.8', '', 'unstructuredAddress', 'Unstructured Address')

    # RFC 3039, RFC 2247, RFC 4519, RFC 5912
    UID = ('0.9.2342.19200300.100.1.1', 'UID', 'uid', 'User ID (UID)')
    DOMAIN_COMPONENT = ('0.9.2342.19200300.100.1.25', 'DC', 'domainComponent', 'Domain Component')

    JURISDICTION_OF_INCORPORATION_LOCALITY_NAME = (
        '1.3.6.1.4.1.311.60.2.1.1',
        '',
        'jurisdictionOfIncorporationLocalityName',
        'Jurisdiction Of Incorporation Locality Name',
    )
    JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME = (
        '1.3.6.1.4.1.311.60.2.1.2',
        '',
        'jurisdictionOfIncorporationStateOrProvinceName',
        'Jurisdiction Of Incorporation State Or Province Name',
    )
    JURISDICTION_OF_INCORPORATION_COUNTRY_NAME = (
        '1.3.6.1.4.1.311.60.2.1.3',
        '',
        'jurisdictionOfIncorporationCountryName',
        'Jurisdiction Of Incorporation Country Name',
    )

    # Spain related
    DNI = ('1.3.6.1.4.1.19126.3', '', 'dni', 'DNI - National identity document (Spain)')
    NSS = ('1.3.6.1.4.1.19126.4', '', 'nss', 'NSS - Social Security Number (Spain)')
    CIRCULATION_PERMIT_NUMBER = (
        '1.3.6.1.4.1.19126.5',
        '',
        'circulationPermitNumber',
        'Circulation Permit Number (SPAIN)',
    )
    CIF = ('1.3.6.1.4.1.19126.21', '', 'cif', 'CIF - Tax Identification Code (Spain)')
    NIF = ('2.16.724.4.307', '', 'nif', 'NIF - Number of fiscal identification (Spain)')

    def __new__(cls, dotted_string: str, abbreviation: str, full_name: str, verbose_name: str) -> Self:
        """Sets the values for this multi value enum.

        Args:
            dotted_string: The corresponding OID value, also used as the enum value.
            abbreviation: A common abbreviation for the NameOid. Maybe an emtpy string.
            full_name: The full name for the NameOid.
            verbose_name: The verbose name for displaying it to a user.
        """
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.abbreviation = abbreviation
        obj.full_name = full_name
        obj.verbose_name = verbose_name
        return obj


class CertificateExtensionOid(enum.Enum):
    """Certificate Extension OID Enum."""

    dotted_string: str
    verbose_name: str

    SUBJECT_DIRECTORY_ATTRIBUTES = ('2.5.29.9', 'Subject Directory Attributes')
    SUBJECT_KEY_IDENTIFIER = ('2.5.29.14', 'Subject Key Identifier')
    KEY_USAGE = ('2.5.29.15', 'Key Usage')
    SUBJECT_ALTERNATIVE_NAME = ('2.5.29.17', 'Subject Alternative Name')
    ISSUER_ALTERNATIVE_NAME = ('2.5.29.18', 'Issuer Alternative Name')
    BASIC_CONSTRAINTS = ('2.5.29.19', 'Basic Constraints')
    NAME_CONSTRAINTS = ('2.5.29.30', 'Name Constraints')
    CRL_DISTRIBUTION_POINTS = ('2.5.29.31', 'Crl Distribution Points')
    CERTIFICATE_POLICIES = ('2.5.29.32', 'Certificate Policies')
    POLICY_MAPPINGS = ('2.5.29.33', 'Policy Mappings')
    AUTHORITY_KEY_IDENTIFIER = ('2.5.29.35', 'Authority Key Identifier')
    POLICY_CONSTRAINTS = ('2.5.29.36', 'Policy Constraints')
    EXTENDED_KEY_USAGE = ('2.5.29.37', 'Extended Key Usage')
    FRESHEST_CRL = ('2.5.29.46', 'Freshest CRL')
    INHIBIT_ANY_POLICY = ('2.5.29.54', 'Inhibit Any Policy')
    ISSUING_DISTRIBUTION_POINT = ('2.5.29.28', 'Issuing Distribution Point')
    AUTHORITY_INFORMATION_ACCESS = ('1.3.6.1.5.5.7.1.1', 'Authority Information Access')
    SUBJECT_INFORMATION_ACCESS = ('1.3.6.1.5.5.7.1.11', 'Subject Information Access')
    OCSP_NO_CHECK = ('1.3.6.1.5.5.7.48.1.5', 'OCSP No Check')
    TLS_FEATURE = ('1.3.6.1.5.5.7.1.24', 'TLS Feature')
    CRL_NUMBER = ('2.5.29.20', 'CRL Number')
    DELTA_CRL_INDICATOR = ('2.5.29.27', 'Delta CRL Indicator')
    PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS = ('1.3.6.1.4.1.11129.2.4.2', 'Precert Signed Certificate Timestamps')
    PRECERT_POISON = ('1.3.6.1.4.1.11129.2.4.3', 'Precert Poison')
    SIGNED_CERTIFICATE_TIMESTAMPS = ('1.3.6.1.4.1.11129.2.4.5', 'Signed Certificate Timestamps')
    MS_CERTIFICATE_TEMPLATE = ('1.3.6.1.4.1.311.21.7', 'Microsoft Certificate Template')

    def __new__(cls, dotted_string: str, verbose_name: str) -> Self:
        """Sets the values for this multi value enum.

        Args:
            dotted_string: The corresponding OID value, also used as the enum value.
            verbose_name: The verbose name for displaying it to a user.
        """
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        return obj


class NamedCurve(enum.Enum):
    """Named Curve Enum."""

    dotted_string: str
    verbose_name: str
    key_size: int
    curve: Optional[type[ec.EllipticCurve]]
    ossl_curve_name: str

    NONE = ('None', 'None', 0, None, '')
    SECP192R1 = ('1.2.840.10045.3.1.1', 'SECP192R1', 192, ec.SECP192R1, 'prime192v1')
    SECP224R1 = ('1.3.132.0.33', 'SECP224R1', 224, ec.SECP224R1, 'secp224r1')
    SECP256K1 = ('1.3.132.0.10', 'SECP256K1', 256, ec.SECP256K1, 'secp256k1')
    SECP256R1 = ('1.2.840.10045.3.1.7', 'SECP256R1', 256, ec.SECP256R1, 'prime256v1')
    SECP384R1 = ('1.3.132.0.34', 'SECP384R1', 384, ec.SECP384R1, 'secp384r1')
    SECP521R1 = ('1.3.132.0.35', 'SECP521R1', 521, ec.SECP521R1, 'secp521r1')
    BRAINPOOLP256R1 = ('1.3.36.3.3.2.8.1.1.7', 'BRAINPOOLP256R1', 256, ec.BrainpoolP256R1, 'brainpoolP256r1')
    BRAINPOOLP384R1 = ('1.3.36.3.3.2.8.1.1.11', 'BRAINPOOLP384R1', 384, ec.BrainpoolP384R1, 'brainpoolP384r1')
    BRAINPOOLP512R1 = ('1.3.36.3.3.2.8.1.1.13', 'BRAINPOOLP512R1', 512, ec.BrainpoolP512R1, 'brainpoolP512r1')
    SECT163K1 = ('1.3.132.0.1', 'SECT163K1', 163, ec.SECT163K1, 'sect163r1')
    SECT163R2 = ('1.3.132.0.15', 'SECT163R2', 163, ec.SECT163R2, 'sect163r2')
    SECT233K1 = ('1.3.132.0.26', 'SECT233K1', 233, ec.SECT233K1, 'sect233k1')
    SECT233R1 = ('1.3.132.0.27', 'SECT233R1', 233, ec.SECT233R1, 'sect233r1')
    SECT283K1 = ('1.3.132.0.16', 'SECT283K1', 283, ec.SECT283K1, 'sect283k1')
    SECT283R1 = ('1.3.132.0.17', 'SECT283R1', 283, ec.SECT283R1, 'sect283r1')
    SECT409K1 = ('1.3.132.0.36', 'SECT409K1', 409, ec.SECT409K1, 'sect409k1')
    SECT409R1 = ('1.3.132.0.37', 'SECT409R1', 409, ec.SECT409R1, 'sect409r1')
    SECT571K1 = ('1.3.132.0.38', 'SECT571K1', 571, ec.SECT571K1, 'sect571k1')
    SECT571R1 = ('1.3.132.0.39', 'SECT571R1', 570, ec.SECT571R1, 'sect571r1')

    def __new__(
            cls,
            dotted_string: str,
            verbose_name: str,
            key_size: int,
            curve: Optional[type[ec.EllipticCurve]],
            ossl_curve_name: str) -> Self:
        """Sets the values for this multi value enum.

        Args:
            dotted_string: The corresponding OID value, also used as the enum value.
            verbose_name: The verbose name for displaying it to a user.
            key_size: The key size of the corresponding named curve.
            curve: The corresponding python cryptography curve class.
        """
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.key_size = key_size
        obj.curve = curve
        obj.ossl_curve_name = ossl_curve_name
        return obj


class RsaPaddingScheme(enum.Enum):
    """RSA Padding Scheme Enum."""

    NONE = 'None'
    PKCS1v15 = 'PKCS#1 v1.5'
    PSS = 'PSS'


class PublicKeyAlgorithmOid(enum.Enum):
    """Public Key Algorithm Enum."""

    dotted_string: str
    verbose_name: str

    NONE = ('NONE', 'None')
    ECC = ('1.2.840.10045.2.1', 'ECC')
    RSA = ('1.2.840.113549.1.1.1', 'RSA')

    # TODO(AlexHx8472): Support ED25519, ED448

    def __new__(cls, dotted_string: str, verbose_name: str) -> Self:
        """Sets the values for this multi value enum.

        Args:
            dotted_string: The corresponding OID value, also used as the enum value.
            verbose_name: The verbose name for displaying it to a user.
        """
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        return obj

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> PublicKeyAlgorithmOid:
        """Gets the PublicKeyAlgorithmOid enum matching the public key of the provided certificate.

        Args:
            certificate: The certificate to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.
        """
        return cls.from_public_key(certificate.public_key())

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeyAlgorithmOid:
        """Gets the PublicKeyAlgorithmOid enum matching the provided private key.

        Args:
            private_key: The private key to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.
        """
        return cls.from_public_key(private_key.public_key())

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> PublicKeyAlgorithmOid:
        """Gets the PublicKeyAlgorithmOid enum matching the provided public key.

        Args:
            public_key: The public_key to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return cls.RSA
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return cls.ECC
        err_msg = 'Unsupported key type, expected RSA or ECC key.'
        raise TypeError(err_msg)


class HashAlgorithm(enum.Enum):
    """Hash Algorithm Enum."""

    dotted_string: str
    verbose_name: str
    hash_algorithm: type[hashes.HashAlgorithm]

    MD5 = ('1.2.840.113549.2.5', 'MD5', hashes.MD5)

    SHA1 = ('1.3.14.3.2.26', 'SHA1', hashes.SHA1)

    SHA224 = ('2.16.840.1.101.3.4.2.4', 'SHA224', hashes.SHA224)
    SHA256 = ('2.16.840.1.101.3.4.2.1', 'SHA256', hashes.SHA256)
    SHA384 = ('2.16.840.1.101.3.4.2.2', 'SHA384', hashes.SHA384)
    SHA512 = ('2.16.840.1.101.3.4.2.3', 'SHA512', hashes.SHA512)

    # SHA-3 family
    SHA3_224 = ('2.16.840.1.101.3.4.2.7', 'SHA3-224', hashes.SHA3_224)
    SHA3_256 = ('2.16.840.1.101.3.4.2.8', 'SHA3-256', hashes.SHA3_256)
    SHA3_384 = ('2.16.840.1.101.3.4.2.9', 'SHA3-384', hashes.SHA3_384)
    SHA3_512 = ('2.16.840.1.101.3.4.2.10', 'SHA3-512', hashes.SHA3_512)

    # SHAKE algorithms
    SHAKE128 = ('2.16.840.1.101.3.4.2.11', 'Shake-128', hashes.SHAKE128)
    SHAKE256 = ('2.16.840.1.101.3.4.2.12', 'Shake-256', hashes.SHAKE256)

    def __new__(cls, dotted_string: str, verbose_name: str, hash_algorithm: type[hashes.HashAlgorithm]) -> Self:
        """Sets the values for this multi value enum.

        Args:
            dotted_string: The corresponding OID value, also used as the enum value.
            verbose_name: The verbose name for displaying it to a user.
            hash_algorithm: The corresponding (cryptography) hashes.HashAlgorithm class.
        """
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.hash_algorithm = hash_algorithm
        return obj


class AlgorithmIdentifier(enum.Enum):
    """Algorithm Identifier Enum."""

    dotted_string: str
    verbose_name: str
    public_key_algo_oid: PublicKeyAlgorithmOid
    padding_scheme: RsaPaddingScheme
    hash_algorithm: HashAlgorithm

    RSA_MD5 = (
        '1.2.840.113549.1.1.4',
        'RSA with MD5',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.MD5,
    )
    RSA_SHA1 = (
        '1.2.840.113549.1.1.5',
        'RSA with SHA1',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA1,
    )
    RSA_SHA1_ALT = (
        '1.3.14.3.2.29',
        'RSA with SHA1',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA1,
    )
    RSA_SHA224 = (
        '1.3.14.3.2.29',
        'RSA with SHA224',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA224,
    )
    RSA_SHA256 = (
        '1.2.840.113549.1.1.11',
        'RSA with SHA256',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA256,
    )
    RSA_SHA384 = (
        '1.2.840.113549.1.1.12',
        'RSA with SHA384',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA384,
    )
    RSA_SHA512 = (
        '1.2.840.113549.1.1.13',
        'RSA with SHA512',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA512,
    )
    RSA_SHA3_224 = (
        '2.16.840.1.101.3.4.3.13',
        'RSA with SHA3-224',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_224,
    )
    RSA_SHA3_256 = (
        '2.16.840.1.101.3.4.3.14',
        'RSA with SHA3-256',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_256,
    )
    RSA_SHA3_384 = (
        '2.16.840.1.101.3.4.3.15',
        'RSA with SHA3-384',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_384,
    )
    RSA_SHA3_512 = (
        '2.16.840.1.101.3.4.3.16',
        'RSA with SHA3-512',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_512,
    )

    # TODO(AlexHx8472): Add RSA PSS support.

    ECDSA_SHA1 = (
        '1.2.840.10045.4.1',
        'ECDSA with SHA1',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA1,
    )
    ECDSA_SHA224 = (
        '1.2.840.10045.4.3.1',
        'ECDSA with SHA224',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA224,
    )
    ECDSA_SHA256 = (
        '1.2.840.10045.4.3.2',
        'ECDSA with SHA256',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA256,
    )
    ECDSA_SHA384 = (
        '1.2.840.10045.4.3.3',
        'ECDSA with SHA384',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA384,
    )
    ECDSA_SHA512 = (
        '1.2.840.10045.4.3.4',
        'ECDSA with SHA512',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA512,
    )
    ECDSA_SHA3_224 = (
        '2.16.840.1.101.3.4.3.9',
        'ECDSA with SHA3-224',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA3_224,
    )
    ECDSA_SHA3_256 = (
        '2.16.840.1.101.3.4.3.10',
        'ECDSA with SHA3-256',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA3_256,
    )
    ECDSA_SHA3_384 = (
        '2.16.840.1.101.3.4.3.11',
        'ECDSA with SHA3-384',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA3_384,
    )
    ECDSA_SHA3_512 = (
        '2.16.840.1.101.3.4.3.12',
        'ECDSA with SHA3-512',
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
        HashAlgorithm.SHA3_512,
    )
    PASSWORD_BASED_MAC = (
        '1.2.840.113533.7.66.13',
        'Password Based MAC',
        PublicKeyAlgorithmOid.NONE,
        RsaPaddingScheme.NONE,
        None,
    )

    def __new__(
        cls,
        dotted_string: str,
        verbose_name: str,
        public_key_algo_oid: PublicKeyAlgorithmOid,
        padding_scheme: RsaPaddingScheme,
        hash_algorithm: None | HashAlgorithm
    ) -> Self:
        """Sets the values for this multi value enum.

        Args:
            dotted_string: The corresponding OID value, also used as the enum value.
            verbose_name: The verbose name for displaying it to a user.
            public_key_algo_oid: The corresponding PublicKeyAlgorithmOid enum.
            padding_scheme: The corresponding RsaPaddingScheme enum.
            hash_algorithm: The corresponding python cryptography hash algorithm class.
        """
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.public_key_algo_oid = public_key_algo_oid
        obj.padding_scheme = padding_scheme
        obj.hash_algorithm = hash_algorithm
        return obj

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> AlgorithmIdentifier:
        """Gets the AlgorithmIdentifier enum matching the signature used to sign the certificate.

        Args:
            certificate: The certificate to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.
        """
        for member in cls:
            if member.dotted_string == certificate.signature_algorithm_oid.dotted_string:
                return member
        err_msg = f'AlgorithmIdentifier {certificate.signature_algorithm_oid.dotted_string} is unkown.'
        raise ValueError(err_msg)


class HmacAlgorithm(enum.Enum):
    """HMAC Algorithm Enum."""

    dotted_string: str
    hash_algorithm: HashAlgorithm

    HMAC_MD5 = ('1.3.6.1.5.5.8.1.1', HashAlgorithm.MD5)

    HMAC_SHA1 = ('1.3.6.1.5.5.8.1.2', HashAlgorithm.SHA1)

    HMAC_SHA224 = ('1.3.6.1.5.5.8.1.4', HashAlgorithm.SHA224)
    HMAC_SHA256 = ('1.3.6.1.5.5.8.1.5', HashAlgorithm.SHA256)
    HMAC_SHA384 = ('1.3.6.1.5.5.8.1.6', HashAlgorithm.SHA384)
    HMAC_SHA512 = ('1.3.6.1.5.5.8.1.7', HashAlgorithm.SHA512)

    HMAC_SHA3_224 = ('2.16.840.1.101.3.4.2.13', HashAlgorithm.SHA3_224)
    HMAC_SHA3_256 = ('2.16.840.1.101.3.4.2.14', HashAlgorithm.SHA3_256)
    HMAC_SHA3_384 = ('2.16.840.1.101.3.4.2.15', HashAlgorithm.SHA3_384)
    HMAC_SHA3_512 = ('2.16.840.1.101.3.4.2.16', HashAlgorithm.SHA3_512)

    # No HMAC with SHAKE

    def __new__(cls, dotted_string: str, hash_algorithm: HashAlgorithm) -> Self:
        """Sets the values for this multi value enum.

        Args:
            dotted_string: The corresponding OID value, also used as the enum value.
            hash_algorithm: The corresponding HashAlgorithm.
        """
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.hash_algorithm = hash_algorithm
        return obj


class PublicKeyInfo:
    """Holds information and properties about a public key."""

    _public_key_algorithm_oid: PublicKeyAlgorithmOid
    _key_size: None | int = None
    _named_curve: None | NamedCurve = None

    def __init__(
        self,
        public_key_algorithm_oid: PublicKeyAlgorithmOid,
        key_size: None | int = None,
        named_curve: None | NamedCurve = None,
    ) -> None:
        """Initializes a PublicKeyInfo object.

        Args:
            public_key_algorithm_oid: The corresponding PublicKeyAlgorithmOid enum.
            key_size: The size of the key.
            named_curve: The NamedCurve enum, if it is an EC key.
        """
        self._public_key_algorithm_oid = public_key_algorithm_oid
        self._key_size = key_size
        if self._public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            if self._key_size is None:
                err_msg = 'Missing key size for RSA key.'
                raise ValueError(err_msg)
            if self._key_size < RSA_MIN_KEY_SIZE:
                err_msg = 'RSA key size must at least be 2048 bits.'
                raise ValueError(err_msg)
            if named_curve is not None:
                err_msg = 'RSA keys cannot have a named curve associated with it.'
                raise ValueError(err_msg)
        elif self._public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            if named_curve is None:
                err_msg = 'ECC key must have a named curve associated with it.'
                raise ValueError(err_msg)
            self._key_size = named_curve.key_size
            self._named_curve = named_curve

    def __eq__(self, other: object) -> bool:
        """Defines the behaviour on use of the equality operator.

        Args:
            other: The other PublicKeyInfo object to compare this instance to.

        Returns:
            True if the two objects are equal as defined by this method, False otherwise.
        """
        if not isinstance(other, PublicKeyInfo):
            return NotImplemented
        if self.public_key_algorithm_oid != other.public_key_algorithm_oid:
            return False
        if self.key_size != other.key_size:
            return False
        return self.named_curve == other.named_curve

    def __str__(self) -> str:
        """Constructs a human-readable string representation of this SignatureSuite.

        Returns:
            A human-readable string representation of this SignatureSuite.
        """
        if self.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            return f'RSA-{self.key_size}'
        if self.public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            return f'ECC-{self.named_curve.verbose_name}'
        return 'Invalid Signature Suite'

    @property
    def public_key_algorithm_oid(self) -> PublicKeyAlgorithmOid:
        """Property to get the associated PublicKeyAlgorithmOid.

        Returns:
            The associated PublicKeyAlgorithmOid.
        """
        return self._public_key_algorithm_oid

    @property
    def key_size(self) -> int:
        """Property to get the associated key size.

        Returns:
            The associated key size.
        """
        return self._key_size

    @property
    def named_curve(self) -> None | NamedCurve:
        """Property to get the associated NamedCurve.

        Returns:
            The associated NamedCurve.
        """
        return self._named_curve

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> PublicKeyInfo:
        """Gets the corresponding PublicKeyInfo for the public key.

        Args:
            public_key: The public key to get the corresponding PublicKeyInfo for.

        Returns:
            The corresponding PublicKeyInfo for the public key.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return cls(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=public_key.key_size)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return cls(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC,
                key_size=public_key.key_size,
                named_curve=cast(NamedCurve, NamedCurve[public_key.curve.name.upper()]),
            )
        err_msg = 'Unsupported public key type found. Must be RSA or ECC key.'
        raise TypeError(err_msg)

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeyInfo:
        """Gets the corresponding PublicKeyInfo for the private key.

        Args:
            private_key: The private key to get the corresponding PublicKeyInfo for.

        Returns:
            The corresponding PublicKeyInfo for the private key.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        return cls.from_public_key(private_key.public_key())

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> PublicKeyInfo:
        """Gets the corresponding PublicKeyInfo for the certificate.

        Args:
            certificate: The certificate to get the corresponding PublicKeyInfo for.

        Returns:
            The corresponding PublicKeyInfo for the certificate.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        return cls.from_public_key(certificate.public_key())


class SignatureSuite:
    """Holds information and properties about a signature suite."""

    _public_key_info: PublicKeyInfo
    _algorithm_identifier: AlgorithmIdentifier

    def __init__(self, algorithm_identifier: AlgorithmIdentifier, public_key_info: PublicKeyInfo) -> None:
        """Initializes a SignatureSuite object.

        Args:
            algorithm_identifier: The corresponding AlgorithmIdentifier enum.
            public_key_info: The corresponding PublicKeyInfo enum.
        """
        self._algorithm_identifier = algorithm_identifier
        self._public_key_info = public_key_info

        self._validate_consistency()

    def __eq__(self, other: object) -> bool:
        """Defines the behaviour on use of the equality operator.

        Args:
            other: The other SignatureSuite object to compare this instance to.

        Returns:
            True if the two objects are equal as defined by this method, False otherwise.
        """
        if not isinstance(other, SignatureSuite):
            return NotImplemented

        return self.public_key_info == other.public_key_info and self.algorithm_identifier == other.algorithm_identifier

    def __str__(self) -> str:
        """Constructs a human-readable string representation of this SignatureSuite.

        Returns:
            A human-readable string representation of this SignatureSuite.
        """
        hash_alg_name = self.algorithm_identifier.hash_algorithm.verbose_name
        if self.public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            return f'RSA-{self.public_key_info.key_size}-{hash_alg_name}'
        if self.public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            return f'ECC-{self.public_key_info.named_curve.verbose_name}-{hash_alg_name}'
        return 'Invalid Signature Suite'

    def _validate_consistency(self) -> None:
        """Validates if the PublicKeyInfo details matches the AlgorithmIdentifier.

        This makes sure that the private key matches the algorithm used to sign a certificate. We are not supporting
        different signature suites within the same domain (PKI hierarchy).

        Raises:
            ValueError: If the consistency check failed.
        """
        if self.algorithm_identifier.public_key_algo_oid != self.public_key_info.public_key_algorithm_oid:
            err_msg = (
                f'Signature algorithm uses {self.algorithm_identifier.public_key_algo_oid.name}, '
                f'but the public key is a {self.public_key_info.public_key_algorithm_oid.name} key.'
            )
            raise ValueError(err_msg)

    @property
    def algorithm_identifier(self) -> AlgorithmIdentifier:
        """Property to get the associated AlgorithmIdentifier.

        Returns:
            The associated AlgorithmIdentifier.
        """
        return self._algorithm_identifier

    @property
    def public_key_info(self) -> PublicKeyInfo:
        """Property to get the associated PublicKeyInfo.

        Returns:
            The associated PublicKeyInfo.
        """
        return self._public_key_info

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> SignatureSuite:
        """Gets the corresponding SignatureSuite for the certificate.

        Args:
            certificate: The certificate to get the corresponding SignatureSuite for.

        Returns:
            The corresponding SignatureSuite for the certificate.

        Raises:
            ValueError:
                If the public key contained in the certificate does not match the
                signature suite used to sign the certificate.

            TypeError: If the key provided is of a type that is not supported.
        """
        return cls(
            algorithm_identifier=AlgorithmIdentifier.from_certificate(certificate),
            public_key_info=PublicKeyInfo.from_certificate(certificate),
        )

    def public_key_matches_signature_suite(self, public_key: PublicKey) -> bool:
        """Checks if the provided public key can be used with this SignatureSuite.

        Args:
            public_key: The public key to check against this SignatureSuite.

        Returns:
            True if the public key can be used with this SignatureSuite, False otherwise.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        public_key_info = PublicKeyInfo.from_public_key(public_key)
        return self.public_key_info == public_key_info

    def private_key_matches_signature_suite(self, private_key: PrivateKey) -> bool:
        """Checks if the provided private key can be used with this SignatureSuite.

        Args:
            private_key: The private key to check against this SignatureSuite.

        Returns:
            True if the private key can be used with this SignatureSuite, False otherwise.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        return self.public_key_matches_signature_suite(private_key.public_key())

    def certificate_matches_signature_suite(self, certificate: x509.Certificate) -> bool:
        """Checks if the provided certificate can be used with this SignatureSuite.

        Args:
            certificate: The certificate to check against this SignatureSuite.

        Returns:
            True if the certificate can be used with this SignatureSuite, False otherwise.

        Raises:
            ValueError:
                If the public key contained in the certificate does not match the
                signature suite used to sign the certificate.

            TypeError: If the key provided is of a type that is not supported.
        """
        signature_suite = SignatureSuite.from_certificate(certificate)
        return self == signature_suite


class KeyPairGenerator:
    """Helper methods to generate key pairs corresponding to several objects."""

    @staticmethod
    def generate_key_pair_for_public_key(public_key: PublicKey) -> PrivateKey:
        """Generates a new key-pair with the same type and key size as the provided public key.

        Args:
            public_key: The public key used to determine the key type and key size to generate the new key-pair.

        Returns:
            The generated key pair.

        Raises:
            TypeError: If the key type of the provided public key is not supported.
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return rsa.generate_private_key(public_exponent=65537, key_size=public_key.key_size)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return ec.generate_private_key(public_key.curve)
        err_msg = 'Unsupported key type found.'
        raise TypeError(err_msg)

    @classmethod
    def generate_key_pair_for_private_key(cls, private_key: PrivateKey) -> PrivateKey:
        """Generates a new key-pair with the same type and key size as the provided private key.

        Args:
            private_key: The private key used to determine the key type and key size to generate the new key-pair.

        Returns:
            The generated key-pair.

        Raises:
            TypeError: If the key type of the provided private key is not supported.
        """
        return cls.generate_key_pair_for_public_key(private_key.public_key())

    @classmethod
    def generate_key_pair_for_certificate(cls, certificate: x509.Certificate) -> PrivateKey:
        """Generates a new key-pair with the same type and key size as the public key present in the certificate.

        Args:
            certificate: The certificate used to determine the key type and key size to generate the new key-pair.

        Returns:
            The generated key-pair.

        Raises:
            TypeError: If the key type of the provided public key within the certificate is not supported.
        """
        return cls.generate_key_pair_for_public_key(certificate.public_key())

    @staticmethod
    def generate_key_pair_for_public_key_info(public_key_info: PublicKeyInfo) -> PrivateKey:
        """Generates a new key-pair of the type given by the PublicKeyInfo object.

        Args:
            public_key_info: The PublicKeyInfo object determining the key type of the key-pair to generate.

        Returns:
            The generated key-pair.

        Raises:
            ValueError: If the RSA key size is too small or no named curve is given when generating an EC key.
            TypeError: If the key type of the provided PublicKeyInfo is not supported.
        """
        if public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            if public_key_info.key_size < RSA_MIN_KEY_SIZE:
                err_msg = (
                    f'RSA key size must be at least {RSA_MIN_KEY_SIZE} bits, '
                    f'but found {public_key_info.key_size} bits.'
                )
                raise ValueError(err_msg)
            return rsa.generate_private_key(public_exponent=65537, key_size=public_key_info.key_size)
        if public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            if public_key_info.named_curve is None:
                err_msg = 'Named curve missing. Only named curves are supported for ECC keys.'
                raise ValueError(err_msg)
            return ec.generate_private_key(curve=public_key_info.named_curve.curve())
        err_msg = 'Unsupported key type found.'
        raise TypeError(err_msg)

    @classmethod
    def generate_key_pair_for_signature_suite(cls, signature_suite: SignatureSuite) -> PrivateKey:
        """Generates a new key-pair of the type given by the SignatureSuite object.

        Args:
            signature_suite: The SignatureSuite object determining the key type of the key-pair to generate.

        Returns:
            The generated key-pair.

        Raises:
            ValueError: If the RSA key size is too small or no named curve is given when generating an EC key.
            TypeError: If the key type of the provided PublicKeyInfo is not supported.
        """
        return cls.generate_key_pair_for_public_key_info(signature_suite.public_key_info)
