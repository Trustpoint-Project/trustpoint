# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Encode profile-based EST CSR attributes (RFC 7030, RFC 8951, RFC 9908)."""

from typing import Any, ClassVar

from cryptography import x509
from pyasn1.codec.der import encoder  # type: ignore[import-untyped]
from pyasn1.type import namedtype, univ  # type: ignore[import-untyped]
from pyasn1_modules import rfc2986, rfc5280  # type: ignore[import-untyped]
from trustpoint_core.oid import NameOid

from est.channel_binding import CHALLENGE_PASSWORD_OID
from pki.util.cert_profile import JSONProfileVerifier
from pki.util.cert_req_converter import JSONCertRequestConverter

EXTENSION_REQUEST_OID = '1.2.840.113549.1.9.14'


class AttrOrOID(univ.Choice):
    """An attribute identifier or an attribute with supplied values."""

    componentType: ClassVar = namedtype.NamedTypes(  # noqa: N815 - pyasn1 schema API.
        namedtype.NamedType('oid', univ.ObjectIdentifier()),
        namedtype.NamedType('attribute', rfc2986.Attribute()),
    )


class CsrAttrs(univ.SequenceOf):
    """The DER sequence carried by application/csrattrs."""

    componentType: ClassVar = AttrOrOID()  # noqa: N815 - pyasn1 schema API.


def _is_literal(value: Any) -> bool:
    """Exclude request placeholders and templates needing an enrollment context."""
    if isinstance(value, str):
        return not value.startswith('CHANGEME_') and '{' not in value
    if isinstance(value, dict):
        return all(_is_literal(item) for item in value.values())
    if isinstance(value, list):
        return all(_is_literal(item) for item in value)
    return True


def build_csrattrs(profile: dict[str, Any] | None = None, *, require_channel_binding: bool = False) -> bytes:
    """Advertise required subject OIDs and profile extension values as DER.

    Literal extension values use one extensionRequest Attribute containing an
    Extensions sequence. When values depend on the client or a template, request
    extensionRequest by OID only rather than inventing an extension value.
    """
    attributes = CsrAttrs()
    if require_channel_binding:
        item = AttrOrOID()
        item['oid'] = univ.ObjectIdentifier(CHALLENGE_PASSWORD_OID)
        attributes.append(item)
    if profile is None:
        return encoder.encode(attributes)

    verifier = JSONProfileVerifier(profile)
    subject_oids = {
        NameOid[field.path[1].upper()].value.dotted_string
        for field in verifier.get_editable_fields()
        if field.path[:-1] == ('subject',) and field.required and field.default is None
    }
    for oid in sorted(subject_oids):
        item = AttrOrOID()
        item['oid'] = univ.ObjectIdentifier(oid)
        attributes.append(item)

    sample_extensions = verifier.get_sample_request().get('extensions', {})
    literal_extensions = {name: value for name, value in sample_extensions.items() if _is_literal(value)}
    builder = JSONCertRequestConverter.add_extensions(
        {'extensions': literal_extensions}, x509.CertificateSigningRequestBuilder()
    )
    extensions = rfc5280.Extensions().clear()
    for extension in builder._extensions:  # noqa: SLF001 - unsigned builders expose no public extensions accessor.
        value = rfc5280.Extension()
        value['extnID'] = univ.ObjectIdentifier(extension.oid.dotted_string)
        value['critical'] = extension.critical
        value['extnValue'] = extension.value.public_bytes()
        extensions.append(value)

    if extensions:
        item = AttrOrOID()
        item['attribute']['type'] = univ.ObjectIdentifier(EXTENSION_REQUEST_OID)
        item['attribute']['values'][0] = encoder.encode(extensions)
        attributes.append(item)
    elif sample_extensions:
        item = AttrOrOID()
        item['oid'] = univ.ObjectIdentifier(EXTENSION_REQUEST_OID)
        attributes.append(item)
    return encoder.encode(attributes)
