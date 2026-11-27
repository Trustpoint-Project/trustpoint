# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""OPC UA SecurityPolicy metadata shared by configuration and the GDS Push client."""

from __future__ import annotations

from dataclasses import dataclass

from trustpoint_core.oid import HashAlgorithm

OPC_UA_SECURITY_POLICY_URI_PREFIX = 'http://opcfoundation.org/UA/SecurityPolicy#'


@dataclass(frozen=True)
class OpcUaSecurityPolicyDefinition:
    """Supported OPC UA SecurityPolicy and its asymmetric signature digest."""

    name: str
    signature_hash_oid: str
    requires_rsa: bool = True
    legacy: bool = False


# Strongest first. Legacy policies stay last and are only selectable when the
# SecurityConfig allow-list explicitly contains them.
OPC_UA_SECURITY_POLICY_PREFERENCE: tuple[OpcUaSecurityPolicyDefinition, ...] = (
    OpcUaSecurityPolicyDefinition('Aes256Sha256RsaPss', HashAlgorithm.SHA256.dotted_string),
    OpcUaSecurityPolicyDefinition('Aes128Sha256RsaOaep', HashAlgorithm.SHA256.dotted_string),
    OpcUaSecurityPolicyDefinition('Basic256Sha256', HashAlgorithm.SHA256.dotted_string),
    OpcUaSecurityPolicyDefinition('Basic256', HashAlgorithm.SHA1.dotted_string, legacy=True),
    OpcUaSecurityPolicyDefinition('Basic128Rsa15', HashAlgorithm.SHA1.dotted_string, legacy=True),
)

OPC_UA_SECURITY_POLICIES: dict[str, OpcUaSecurityPolicyDefinition] = {
    definition.name: definition for definition in OPC_UA_SECURITY_POLICY_PREFERENCE
}

DEFAULT_OPC_UA_SECURITY_POLICIES: tuple[str, ...] = (
    'Aes256Sha256RsaPss',
    'Aes128Sha256RsaOaep',
    'Basic256Sha256',
)

# Names the OPC UA client library does not implement. Kept for actionable errors.
UNSUPPORTED_ECC_SECURITY_POLICIES: frozenset[str] = frozenset(
    {
        'EccNistP256',
        'EccNistP384',
        'EccBrainpoolP256r1',
        'EccBrainpoolP384r1',
        'EccCurve25519',
        'EccCurve448',
    }
)


def policy_name_from_uri(uri: str) -> str:
    """Return the short policy name from a SecurityPolicyUri."""
    return uri.rsplit('#', 1)[-1]
