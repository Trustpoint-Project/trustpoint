# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for CSR-based application credential issuance input handling."""

from __future__ import annotations

from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils.datastructures import MultiValueDict

from pki.forms.csr import CsrIssuanceForm
from pki.services.csr import MAX_CSR_SIZE, CsrValidationError, csr_to_request, parse_csr


def make_csr(private_key: Any, common_name: str = 'device.example.com') -> x509.CertificateSigningRequest:
    """Create a signed CSR for the input and validation tests."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )


@pytest.fixture
def rsa_csr() -> x509.CertificateSigningRequest:
    """Return a valid RSA CSR."""
    return make_csr(rsa.generate_private_key(public_exponent=65537, key_size=2048))


class TestParseCsr:
    """Test parsing and cryptographic validation of supplied CSRs."""

    def test_accepts_pem(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """PEM-encoded CSRs are parsed and signature-validated."""
        parsed = parse_csr(rsa_csr.public_bytes(Encoding.PEM))

        assert parsed.subject == rsa_csr.subject
        assert parsed.is_signature_valid

    def test_accepts_der(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """DER-encoded CSRs are detected from their contents."""
        parsed = parse_csr(rsa_csr.public_bytes(Encoding.DER))

        assert parsed.subject == rsa_csr.subject

    def test_rejects_invalid_signature(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """A CSR with a modified signature is rejected."""
        der = bytearray(rsa_csr.public_bytes(Encoding.DER))
        der[-1] ^= 1

        with pytest.raises(CsrValidationError, match='signature is invalid'):
            parse_csr(bytes(der))

    @pytest.mark.parametrize('data', [b'', b'not a csr', b'-----BEGIN CERTIFICATE REQUEST-----\ninvalid'])
    def test_rejects_malformed_input(self, data: bytes) -> None:
        """Empty, malformed, and incomplete PEM data produce a validation error."""
        with pytest.raises(CsrValidationError):
            parse_csr(data)

    def test_rejects_oversized_input(self) -> None:
        """CSR input over the configured limit is rejected before parsing."""
        with pytest.raises(CsrValidationError, match='too large'):
            parse_csr(b'x' * (MAX_CSR_SIZE + 1))

    def test_rejects_unsupported_public_key(self) -> None:
        """Unsupported public-key algorithms are rejected after parsing."""
        csr = make_csr(dsa.generate_private_key(key_size=2048))

        with pytest.raises(CsrValidationError, match='public key algorithm'):
            parse_csr(csr.public_bytes(Encoding.DER))

    def test_converts_csr_to_request_data(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """A validated CSR can enter the existing request conversion pipeline."""
        request_data = csr_to_request(rsa_csr)

        request_subject = cast('dict[str, Any]', request_data['subj'])
        assert request_subject[NameOID.COMMON_NAME.dotted_string] == 'device.example.com'


class TestCsrIssuanceForm:
    """Test the CSR form's source-selection contract."""

    def test_accepts_pasted_pem(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """The pasted PEM source is parsed into cleaned CSR data."""
        form = CsrIssuanceForm({'csr_text': rsa_csr.public_bytes(Encoding.PEM).decode()})

        assert form.is_valid()
        assert isinstance(form.cleaned_data['csr'], x509.CertificateSigningRequest)

    def test_accepts_uploaded_der(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """An uploaded DER file is parsed regardless of its filename extension."""
        uploaded = SimpleUploadedFile('request.csr', rsa_csr.public_bytes(Encoding.DER))
        form = CsrIssuanceForm(files=MultiValueDict({'csr_file': [uploaded]}))

        assert form.is_valid()
        assert isinstance(form.cleaned_data['csr'], x509.CertificateSigningRequest)

    def test_accepts_uploaded_pem(self, rsa_csr: x509.CertificateSigningRequest) -> None:
        """An uploaded PEM file is parsed regardless of its filename extension."""
        uploaded = SimpleUploadedFile('request.der', rsa_csr.public_bytes(Encoding.PEM))
        form = CsrIssuanceForm(files=MultiValueDict({'csr_file': [uploaded]}))

        assert form.is_valid()

    def test_rejects_empty_input(self) -> None:
        """The form rejects a request with neither CSR source supplied."""
        form = CsrIssuanceForm(data={})

        assert not form.is_valid()
        assert 'exactly one CSR' in str(form.errors)

    def test_rejects_both_sources(self) -> None:
        """The form rejects requests containing both CSR sources."""
        uploaded = SimpleUploadedFile('request.csr', b'data')
        form = CsrIssuanceForm(
            data={'csr_text': 'pasted'},
            files=MultiValueDict({'csr_file': [uploaded]}),
        )

        assert not form.is_valid()
        assert 'exactly one CSR' in str(form.errors)
