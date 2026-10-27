# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Extension aliases used by Trustpoint profiles alongside Core's OID metadata."""

import enum

from trustpoint_core import oid

CertificateExtensionOid = oid.CertificateExtensionOid

# Core 0.4.1 supplies the OIDs and display names; profile aliases remain local.
CERTIFICATE_EXTENSION_ALIASES: dict[str, tuple[str | None, str]] = {
    'SUBJECT_DIRECTORY_ATTRIBUTES': (None, 'subjectDirectoryAttributes'),
    'SUBJECT_KEY_IDENTIFIER': ('ski', 'subjectKeyIdentifier'),
    'KEY_USAGE': ('ku', 'keyUsage'),
    'SUBJECT_ALTERNATIVE_NAME': ('san', 'subjectAlternativeName'),
    'ISSUER_ALTERNATIVE_NAME': ('ian', 'issuerAlternativeName'),
    'BASIC_CONSTRAINTS': ('bc', 'basicConstraints'),
    'NAME_CONSTRAINTS': ('nc', 'nameConstraints'),
    'CRL_DISTRIBUTION_POINTS': ('crl', 'crlDistributionPoints'),
    'CERTIFICATE_POLICIES': ('cp', 'certificatePolicies'),
    'POLICY_MAPPINGS': ('pm', 'policyMappings'),
    'AUTHORITY_KEY_IDENTIFIER': ('aki', 'authorityKeyIdentifier'),
    'POLICY_CONSTRAINTS': ('pc', 'policyConstraints'),
    'EXTENDED_KEY_USAGE': ('eku', 'extendedKeyUsage'),
    'FRESHEST_CRL': (None, 'freshestCRL'),
    'INHIBIT_ANY_POLICY': ('iap', 'inhibitAnyPolicy'),
    'ISSUING_DISTRIBUTION_POINT': (None, 'issuingDistributionPoint'),
    'AUTHORITY_INFORMATION_ACCESS': ('aia', 'authorityInformationAccess'),
    'SUBJECT_INFORMATION_ACCESS': ('sia', 'subjectInformationAccess'),
    'OCSP_NO_CHECK': (None, 'ocspNoCheck'),
    'TLS_FEATURE': (None, 'tlsFeature'),
    'CRL_NUMBER': (None, 'crlNumber'),
    'DELTA_CRL_INDICATOR': (None, 'deltaCrlIndicator'),
    'PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS': (None, 'precertSignedCertificateTimestamps'),
    'PRECERT_POISON': (None, 'precertPoison'),
    'SIGNED_CERTIFICATE_TIMESTAMPS': (None, 'signedCertificateTimestamps'),
    'MS_CERTIFICATE_TEMPLATE': (None, 'microsoftCertificateTemplate'),
}


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
