import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

# General constant for tests
COMMON_NAME = 'example common name'
COUNTRY_NAME = 'DE'
ORGANIZATION_NAME = 'Example Org'

# GeneralName Values
RFC822_EMAIL = 'user@example.com'
DNS_NAME_VALUE = 'example.com'
URI_VALUE = 'http://example.com'
REGISTERED_ID_OID = '1.2.3.4.5'
IP_ADDRESS_VALUE = '192.168.0.1'
OTHER_NAME_OID = '1.3.6.1.4.1.311.20.2.3'
OTHER_NAME_CONTENT = 'Trustpoint to the top'
INHIBIT_ANY_POLICY_VALUE = 5
INHIBIT_POLICY_MAPPING = 4
REQUIRE_EXPLICIT_POLICY = 5

KEY_USAGE_FLAGS = {
    'digital_signature': True,
    'content_commitment': True,
    'key_encipherment': True,
    'data_encipherment': True,
    'key_agreement': True,
    'key_cert_sign': True,
    'crl_sign': True,
    'encipher_only': True,
    'decipher_only': True,
}
