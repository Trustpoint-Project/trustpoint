"""Partial ASN.1 updates from RFC 9480 (CMP Updates) applied on top of RFC 4210.

RFC 9480 adds an optional ``hashAlg`` field to ``CertStatus``, which clients
(e.g. OpenSSL) include in certConf messages for certificates signed with
algorithms lacking an implicit hash (such as ML-DSA). The plain RFC 4210
schema fails to decode such messages ('Excessive components decoded').
"""

from pyasn1.type import namedtype, tag, univ  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210, rfc5280  # type: ignore[import-untyped]


def _build_cert_status_component_type() -> namedtype.NamedTypes:
    """Build the CertStatus component types including the hashAlg field (RFC 9480)."""
    return namedtype.NamedTypes(
        namedtype.NamedType('certHash', univ.OctetString()),
        namedtype.NamedType('certReqId', univ.Integer()),
        namedtype.OptionalNamedType('statusInfo', rfc4210.PKIStatusInfo()),
        namedtype.OptionalNamedType(
            'hashAlg',
            rfc5280.AlgorithmIdentifier().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
    )

CertStatus = type('CertStatus', (univ.Sequence,), {'componentType': _build_cert_status_component_type()})
CertConfirmContent = type('CertConfirmContent', (univ.SequenceOf,), {'componentType': CertStatus()})


def _build_pki_body_component_type() -> namedtype.NamedTypes:
    """Build the PKIBody component types with the updated CertConfirmContent."""
    components = []
    for named_type in rfc4210.PKIBody.componentType.namedTypes:
        if named_type.name == 'certConf':
            components.append(
                namedtype.NamedType(
                    'certConf',
                    CertConfirmContent().subtype(
                        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 24)
                    ),
                )
            )
        else:
            components.append(named_type)
    return namedtype.NamedTypes(*components)


PKIBody = type('PKIBody', (rfc4210.PKIBody,), {'componentType': _build_pki_body_component_type()})


def _build_pki_message_component_type() -> namedtype.NamedTypes:
    """Build the PKIMessage component types with the updated PKIBody."""
    components = []
    for named_type in rfc4210.PKIMessage.componentType.namedTypes:
        if named_type.name == 'body':
            components.append(namedtype.NamedType('body', PKIBody()))
        else:
            components.append(named_type)
    return namedtype.NamedTypes(*components)


PKIMessage = type('PKIMessage', (rfc4210.PKIMessage,), {'componentType': _build_pki_message_component_type()})


def build_pki_message_spec() -> rfc4210.PKIMessage:
    """Build a PKIMessage schema accepting the RFC 9480 CertStatus hashAlg field."""
    return PKIMessage()
