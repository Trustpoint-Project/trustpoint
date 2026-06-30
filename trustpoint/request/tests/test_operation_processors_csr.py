"""Tests for CSR build, sign, and revocation operation processors."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from request.operation_processor.csr_build import CsrBuilder, ProfileAwareCsrBuilder
from request.operation_processor.csr_sign import EstCaCsrSignProcessor, EstDeviceCsrSignProcessor
from request.operation_processor.revoke_cert import CertificateRevocationProcessor
from request.request_context import (
    BaseCertificateRequestContext,
    BaseRevocationRequestContext,
    CmpRevocationRequestContext,
    EstCertificateRequestContext,
)


def _make_ec_csr(cn: str = 'test') -> x509.CertificateSigningRequest:
    """Return a valid EC P-256 CSR for use as cert_requested."""
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )


def _make_ec_key() -> ec.EllipticCurvePrivateKey:
    """Return a fresh EC P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def _make_rsa_key() -> rsa.RSAPrivateKey:
    """Return a fresh RSA-2048 private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ---------------------------------------------------------------------------
# CsrBuilder — helper methods
# ---------------------------------------------------------------------------


class TestCsrBuilderBuildSubject:
    """Tests for CsrBuilder._build_subject."""

    def _builder(self) -> CsrBuilder:
        return CsrBuilder()

    def test_common_name_only(self) -> None:
        """Subject with only CN produces a single-attribute Name."""
        data = {'subject': {'common_name': 'My Device'}}
        subject = self._builder()._build_subject(data)
        assert subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'My Device'

    def test_all_standard_fields_are_included(self) -> None:
        """All six standard DN fields map to the correct OIDs."""
        data = {
            'subject': {
                'common_name': 'device',
                'organization_name': 'Acme',
                'organizational_unit_name': 'Eng',
                'country_name': 'DE',
                'state_or_province_name': 'Bavaria',
                'locality_name': 'Munich',
                'email_address': 'device@acme.example',
            }
        }
        subject = self._builder()._build_subject(data)
        assert subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value == 'Acme'
        assert subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == 'DE'
        assert subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value == 'device@acme.example'

    def test_empty_subject_produces_empty_name(self) -> None:
        """validated_request_data without a 'subject' key yields an empty Name."""
        data: dict = {}
        subject = self._builder()._build_subject(data)
        assert len(list(subject)) == 0

    def test_subj_key_alias_is_accepted(self) -> None:
        """'subj' key is treated as an alias for 'subject'."""
        data = {'subj': {'common_name': 'alias-device'}}
        subject = self._builder()._build_subject(data)
        assert subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'alias-device'


class TestCsrBuilderIterSanField:
    """Tests for CsrBuilder._iter_san_field static method."""

    def test_comma_separated_string_is_split(self) -> None:
        """Comma-separated string yields a trimmed list of values."""
        result = CsrBuilder._iter_san_field('a.example.com, b.example.com')
        assert result == ['a.example.com', 'b.example.com']

    def test_list_input_is_returned_as_stripped_list(self) -> None:
        """A list input is returned with each item stripped."""
        result = CsrBuilder._iter_san_field(['  foo.com  ', ' bar.com'])
        assert result == ['foo.com', 'bar.com']

    def test_empty_segments_are_dropped(self) -> None:
        """Empty segments from trailing commas are removed."""
        result = CsrBuilder._iter_san_field('a.com,, ,b.com,')
        assert result == ['a.com', 'b.com']


class TestCsrBuilderBuildExtensions:
    """Tests for CsrBuilder._build_extensions."""

    def _builder(self) -> CsrBuilder:
        return CsrBuilder()

    def test_no_san_yields_empty_extensions(self) -> None:
        """Data with no SAN produces an empty extension list."""
        exts = self._builder()._build_extensions({})
        assert exts == []

    def test_dns_san_is_included(self) -> None:
        """DNS SAN is present when dns_names is provided."""
        data = {'ext': {'subject_alternative_name': {'dns_names': 'host.example.com'}}}
        exts = self._builder()._build_extensions(data)
        assert len(exts) == 1
        san_ext, _critical = exts[0]
        dns_names = [n for n in san_ext if isinstance(n, x509.DNSName)]
        assert any(n.value == 'host.example.com' for n in dns_names)

    def test_ip_san_ipv4_is_included(self) -> None:
        """IPv4 SAN is parsed and included correctly."""
        data = {'ext': {'subject_alternative_name': {'ip_addresses': '192.168.1.1'}}}
        exts = self._builder()._build_extensions(data)
        san_ext, _ = exts[0]
        ips = [n for n in san_ext if isinstance(n, x509.IPAddress)]
        assert any(str(n.value) == '192.168.1.1' for n in ips)

    def test_invalid_ip_is_silently_skipped(self) -> None:
        """Invalid IP strings are logged and skipped rather than raising."""
        data = {'ext': {'subject_alternative_name': {'ip_addresses': '999.999.999.999'}}}
        exts = self._builder()._build_extensions(data)
        assert exts == []  # no valid SANs → no extension

    def test_rfc822_name_is_included(self) -> None:
        """Email SAN is included when rfc822_names is provided."""
        data = {'ext': {'subject_alternative_name': {'rfc822_names': 'user@example.com'}}}
        exts = self._builder()._build_extensions(data)
        san_ext, _ = exts[0]
        emails = [n for n in san_ext if isinstance(n, x509.RFC822Name)]
        assert any(n.value == 'user@example.com' for n in emails)

    def test_uri_is_included(self) -> None:
        """URI SAN is included when uris is provided."""
        data = {'ext': {'subject_alternative_name': {'uris': 'urn:example:device'}}}
        exts = self._builder()._build_extensions(data)
        san_ext, _ = exts[0]
        uris = [n for n in san_ext if isinstance(n, x509.UniformResourceIdentifier)]
        assert any(n.value == 'urn:example:device' for n in uris)


# ---------------------------------------------------------------------------
# CsrBuilder — process_operation + get_csr
# ---------------------------------------------------------------------------


class TestCsrBuilderProcessOperation:
    """Tests for CsrBuilder.process_operation and get_csr."""

    def _make_context(self, profile: bool = True, data: dict | None = None, with_key: bool = True) -> EstCertificateRequestContext:
        ctx = EstCertificateRequestContext()
        ctx.certificate_profile_model = Mock() if profile else None
        ctx.validated_request_data = data if data is not None else {'subject': {'common_name': 'dev'}}
        if with_key:
            key = _make_ec_key()
            cred = Mock()
            cred.get_private_key.return_value = key
            ctx.owner_credential = cred
        else:
            ctx.owner_credential = None
            ctx.issuer_credential = None
        return ctx

    def test_wrong_context_type_raises_type_error(self) -> None:
        """Non-BaseCertificateRequestContext raises TypeError."""
        from request.request_context import BaseRequestContext
        ctx = Mock(spec=BaseRequestContext)
        with pytest.raises(TypeError, match='CSR building requires'):
            CsrBuilder().process_operation(ctx)

    def test_missing_profile_raises_value_error(self) -> None:
        """Missing certificate_profile_model raises ValueError."""
        ctx = self._make_context(profile=False)
        with pytest.raises(ValueError, match='Certificate profile model must be set'):
            CsrBuilder().process_operation(ctx)

    def test_missing_validated_data_raises_value_error(self) -> None:
        """Missing validated_request_data raises ValueError."""
        ctx = self._make_context()
        ctx.validated_request_data = None
        with pytest.raises(ValueError, match='Validated request data must be set'):
            CsrBuilder().process_operation(ctx)

    def test_no_credential_raises_value_error(self) -> None:
        """No owner or issuer credential raises ValueError."""
        ctx = self._make_context(with_key=False)
        with pytest.raises(ValueError, match='No credential with private key available'):
            CsrBuilder().process_operation(ctx)

    def test_valid_context_builds_csr(self) -> None:
        """Valid context produces a signed CertificateSigningRequest."""
        ctx = self._make_context()
        builder = CsrBuilder()
        builder.process_operation(ctx)
        csr = builder.get_csr()
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_get_csr_before_build_raises_value_error(self) -> None:
        """Calling get_csr() before process_operation() raises ValueError."""
        with pytest.raises(ValueError, match='CSR not built'):
            CsrBuilder().get_csr()

    def test_issuer_credential_is_used_when_owner_absent(self) -> None:
        """issuer_credential is used as fallback when owner_credential is None."""
        ctx = EstCertificateRequestContext()
        ctx.certificate_profile_model = Mock()
        ctx.validated_request_data = {'subject': {'common_name': 'fallback'}}
        ctx.owner_credential = None
        key = _make_ec_key()
        cred = Mock()
        cred.get_private_key.return_value = key
        ctx.issuer_credential = cred
        builder = CsrBuilder()
        builder.process_operation(ctx)
        assert isinstance(builder.get_csr(), x509.CertificateSigningRequest)


# ---------------------------------------------------------------------------
# EstCsrSignProcessor (via concrete subclasses)
# ---------------------------------------------------------------------------


class TestEstCaCsrSignProcessor:
    """Tests for EstCaCsrSignProcessor.process_operation."""

    def _make_context(self, csr: x509.CertificateSigningRequest | None = None) -> EstCertificateRequestContext:
        ctx = EstCertificateRequestContext()
        ctx.cert_requested = csr if csr is not None else _make_ec_csr()
        ctx.issuer_credential = None
        ctx.domain = None
        return ctx

    def test_wrong_context_type_raises_type_error(self) -> None:
        """Non-BaseCertificateRequestContext raises TypeError."""
        ctx = Mock(spec=BaseRevocationRequestContext)
        with pytest.raises(TypeError, match='CSR signing requires'):
            EstCaCsrSignProcessor().process_operation(ctx)

    def test_missing_csr_raises_value_error(self) -> None:
        """None cert_requested raises ValueError."""
        ctx = self._make_context()
        ctx.cert_requested = None
        with pytest.raises(ValueError, match='CSR .cert_requested. must be set'):
            EstCaCsrSignProcessor().process_operation(ctx)

    def test_wrong_csr_type_raises_type_error(self) -> None:
        """Non-CertificateSigningRequest cert_requested raises TypeError."""
        ctx = self._make_context()
        ctx.cert_requested = 'not a csr'  # type: ignore[assignment]
        with pytest.raises(TypeError, match='cert_requested must be a CertificateSigningRequest'):
            EstCaCsrSignProcessor().process_operation(ctx)

    def test_missing_domain_and_credential_raises_value_error(self) -> None:
        """No issuer_credential and no domain raises ValueError."""
        ctx = self._make_context()
        with pytest.raises(ValueError, match='Domain must be set'):
            EstCaCsrSignProcessor().process_operation(ctx)

    def test_valid_signing_produces_signed_csr(self) -> None:
        """Valid context with issuer credential produces a signed CSR."""
        key = _make_ec_key()
        cred = Mock()
        cred.certificate = None  # skip hash-from-cert branch
        cred.get_private_key.return_value = key

        ctx = self._make_context()
        ctx.issuer_credential = cred

        proc = EstCaCsrSignProcessor()
        proc.process_operation(ctx)
        assert isinstance(proc.get_signed_csr(), x509.CertificateSigningRequest)

    def test_get_signed_csr_before_process_raises_value_error(self) -> None:
        """get_signed_csr() before process_operation() raises ValueError."""
        with pytest.raises(ValueError, match='CSR not signed'):
            EstCaCsrSignProcessor().get_signed_csr()


class TestEstDeviceCsrSignProcessor:
    """Tests for EstDeviceCsrSignProcessor.process_operation."""

    def test_missing_owner_credential_raises_value_error(self) -> None:
        """None owner_credential raises ValueError."""
        ctx = EstCertificateRequestContext()
        ctx.cert_requested = _make_ec_csr()
        ctx.owner_credential = None
        with pytest.raises(ValueError, match='Owner credential must be set'):
            EstDeviceCsrSignProcessor().process_operation(ctx)

    def test_valid_signing_produces_signed_csr(self) -> None:
        """Valid device context with owner credential produces a signed CSR."""
        key = _make_ec_key()
        cred = Mock()
        cred.certificate = None
        cred.get_private_key.return_value = key

        ctx = EstCertificateRequestContext()
        ctx.cert_requested = _make_ec_csr()
        ctx.owner_credential = cred

        proc = EstDeviceCsrSignProcessor()
        proc.process_operation(ctx)
        assert isinstance(proc.get_signed_csr(), x509.CertificateSigningRequest)


# ---------------------------------------------------------------------------
# CertificateRevocationProcessor
# ---------------------------------------------------------------------------


class TestCertificateRevocationProcessor:
    """Tests for CertificateRevocationProcessor.process_operation."""

    def test_wrong_context_type_raises_type_error(self) -> None:
        """Non-BaseRevocationRequestContext raises TypeError."""
        ctx = Mock(spec=BaseCertificateRequestContext)
        with pytest.raises(TypeError, match='Certificate revocation requires'):
            CertificateRevocationProcessor().process_operation(ctx)

    def test_no_issuing_ca_raises_value_error(self) -> None:
        """Domain without an issuing CA raises ValueError."""
        ctx = CmpRevocationRequestContext()
        ctx.domain = Mock()
        ctx.domain.issuing_ca = None  # no CA on domain
        with pytest.raises(ValueError, match='No suitable operation processor'):
            CertificateRevocationProcessor().process_operation(ctx)

    def test_missing_domain_raises_value_error(self) -> None:
        """None domain raises ValueError."""
        ctx = CmpRevocationRequestContext()
        ctx.domain = None
        with pytest.raises(ValueError, match='No suitable operation processor'):
            CertificateRevocationProcessor().process_operation(ctx)

    def test_missing_device_raises_value_error(self) -> None:
        """None device raises ValueError from the local CA sub-processor."""
        ctx = CmpRevocationRequestContext()
        ctx.domain = Mock()
        ctx.domain.issuing_ca = Mock()
        ctx.device = None
        ctx.credential_to_revoke = Mock()
        ctx.domain.get_issuing_ca_or_value_error.return_value.get_credential.return_value = Mock()
        with pytest.raises(ValueError, match='Device must be set'):
            CertificateRevocationProcessor().process_operation(ctx)

    def test_missing_credential_to_revoke_raises_value_error(self) -> None:
        """None credential_to_revoke raises ValueError from the local CA sub-processor."""
        ctx = CmpRevocationRequestContext()
        ctx.domain = Mock()
        ctx.domain.issuing_ca = Mock()
        ctx.device = Mock()
        ctx.credential_to_revoke = None
        ctx.domain.get_issuing_ca_or_value_error.return_value.get_credential.return_value = Mock()
        with pytest.raises(ValueError, match='Credential to revoke must be set'):
            CertificateRevocationProcessor().process_operation(ctx)
