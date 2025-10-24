"""To be added to trustpoint_core as trustpoint_core.oid.CertificateExtensionOid."""

import enum
from dataclasses import dataclass

@dataclass(frozen=True)
class CertificateExtensionOidData:
    """The Certificate Extension OID Data class holding all of the information."""

    dotted_string: str
    abbreviation: str | None
    full_name: str
    verbose_name: str


class CertificateExtensionOid(enum.Enum):
    """Certificate Extension OID Enum holding extension metadata as dataclass instances and lookup helpers."""

    SUBJECT_DIRECTORY_ATTRIBUTES = CertificateExtensionOidData(
        '2.5.29.9', None, 'subjectDirectoryAttributes', 'Subject Directory Attributes')
    SUBJECT_KEY_IDENTIFIER = CertificateExtensionOidData(
        '2.5.29.14', 'ski', 'subjectKeyIdentifier', 'Subject Key Identifier')
    KEY_USAGE = CertificateExtensionOidData('2.5.29.15', 'ku', 'keyUsage', 'Key Usage')
    SUBJECT_ALTERNATIVE_NAME = CertificateExtensionOidData(
        '2.5.29.17', 'san', 'subjectAlternativeName', 'Subject Alternative Name')
    ISSUER_ALTERNATIVE_NAME = CertificateExtensionOidData(
        '2.5.29.18', 'ian', 'issuerAlternativeName', 'Issuer Alternative Name')
    BASIC_CONSTRAINTS = CertificateExtensionOidData('2.5.29.19', 'bc', 'basicConstraints', 'Basic Constraints')
    NAME_CONSTRAINTS = CertificateExtensionOidData('2.5.29.30', 'nc', 'nameConstraints', 'Name Constraints')
    CRL_DISTRIBUTION_POINTS = CertificateExtensionOidData(
        '2.5.29.31', 'crl', 'crlDistributionPoints', 'CRL Distribution Points')
    CERTIFICATE_POLICIES = CertificateExtensionOidData('2.5.29.32', 'cp', 'certificatePolicies', 'Certificate Policies')
    POLICY_MAPPINGS = CertificateExtensionOidData('2.5.29.33', 'pm', 'policyMappings', 'Policy Mappings')
    AUTHORITY_KEY_IDENTIFIER = CertificateExtensionOidData(
        '2.5.29.35', 'aki', 'authorityKeyIdentifier', 'Authority Key Identifier')
    POLICY_CONSTRAINTS = CertificateExtensionOidData('2.5.29.36', 'pc', 'policyConstraints', 'Policy Constraints')
    EXTENDED_KEY_USAGE = CertificateExtensionOidData('2.5.29.37', 'eku', 'extendedKeyUsage', 'Extended Key Usage')
    FRESHEST_CRL = CertificateExtensionOidData('2.5.29.46', None, 'freshestCRL', 'Freshest CRL')
    INHIBIT_ANY_POLICY = CertificateExtensionOidData('2.5.29.54', 'iap', 'inhibitAnyPolicy','Inhibit Any Policy')
    ISSUING_DISTRIBUTION_POINT = CertificateExtensionOidData(
        '2.5.29.28', None, 'issuingDistributionPoint', 'Issuing Distribution Point')
    AUTHORITY_INFORMATION_ACCESS = CertificateExtensionOidData(
        '1.3.6.1.5.5.7.1.1', 'aia', 'authorityInformationAccess','Authority Information Access')
    SUBJECT_INFORMATION_ACCESS = CertificateExtensionOidData(
        '1.3.6.1.5.5.7.1.11', 'sia', 'subjectInformationAccess','Subject Information Access')
    OCSP_NO_CHECK = CertificateExtensionOidData('1.3.6.1.5.5.7.48.1.5', None, 'ocspNoCheck','OCSP No Check')
    TLS_FEATURE = CertificateExtensionOidData('1.3.6.1.5.5.7.1.24', None, 'tlsFeature','TLS Feature')
    CRL_NUMBER = CertificateExtensionOidData('2.5.29.20', None, 'crlNumber','CRL Number')
    DELTA_CRL_INDICATOR = CertificateExtensionOidData('2.5.29.27', None, 'deltaCrlIndicator','Delta CRL Indicator')
    PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS = CertificateExtensionOidData(
        '1.3.6.1.4.1.11129.2.4.2',
        None,
        'precertSignedCertificateTimestamps',
        'Precert Signed Certificate Timestamps',
    )
    PRECERT_POISON = CertificateExtensionOidData('1.3.6.1.4.1.11129.2.4.3', None, 'precertPoison', 'Precert Poison')
    SIGNED_CERTIFICATE_TIMESTAMPS = CertificateExtensionOidData(
        '1.3.6.1.4.1.11129.2.4.5',
        None,
        'signedCertificateTimestamps',
        'Signed Certificate Timestamps',
    )
    MS_CERTIFICATE_TEMPLATE = CertificateExtensionOidData(
        '1.3.6.1.4.1.311.21.7', None, 'microsoftCertificateTemplate','Microsoft Certificate Template')

    @property
    def dotted_string(self) -> str:
        """Return the dotted string OID.

        Returns:
            The dotted string OID.
        """
        return self.value.dotted_string

    @property
    def abbreviation(self) -> str | None:
        """Return the abbreviation for the NameOid, if any.

        Returns:
            The abbreviation, or None if not defined.
        """
        return self.value.abbreviation

    @property
    def full_name(self) -> str:
        """Return the full name for the NameOid.

        Returns:
            The full name.
        """
        return self.value.full_name

    @property
    def verbose_name(self) -> str:
        """Return the verbose name for display.

        Returns:
            The verbose name.
        """
        return self.value.verbose_name


class ExtendedKeyUsageOid(enum.Enum):
    """OIDs for Extended Key Usage values."""
    SERVER_AUTH = '1.3.6.1.5.5.7.3.1'
    CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'
    CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
    EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4'
    TIME_STAMPING = '1.3.6.1.5.5.7.3.8'
    OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'
    ANY_EXTENDED_KEY_USAGE = '2.5.29.37.0'
    SMARTCARD_LOGON = '1.3.6.1.4.1.311.20.2.2'
    KERBEROS_PKINIT_KDC = '1.3.6.1.5.2.3.5'
    IPSEC_IKE = '1.3.6.1.5.5.7.3.17'
    BUNDLE_SECURITY = '1.3.6.1.5.5.7.3.35'
    CERTIFICATE_TRANSPARENCY = '1.3.6.1.4.1.11129.2.4.4'
