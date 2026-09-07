# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for truststore form validation and CA chain construction."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from pki.forms.truststores import (
    TruststoreAddForm,
    _create_or_get_keyless_ca,
    _sort_certificate_chain,
    _validate_chain_integrity,
    validate_and_create_ca_chain,
)
from pki.models.ca import CaModel
from pki.models.truststore import TruststoreModel
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db


def _pem(*certificates: x509.Certificate) -> bytes:
    """Concatenate certificates into a single PEM bundle."""
    return b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates)


@pytest.fixture
def chain() -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    """Return a root, intermediate and leaf certificate forming a valid chain."""
    root, root_key = CertificateGenerator.create_root_ca('Chain Root', path_length=2)
    intermediate, intermediate_key = CertificateGenerator.create_issuing_ca(
        root_key, 'Chain Root', 'Chain Intermediate', path_length=1
    )
    leaf, _ = CertificateGenerator.create_issuing_ca(
        intermediate_key, 'Chain Intermediate', 'Chain Leaf', path_length=0
    )
    return root, intermediate, leaf


class TestTruststoreAddFormValidation:
    """Validation behavior of the truststore upload form."""

    def test_duplicate_unique_name_is_rejected(self) -> None:
        """A name already used by another truststore fails field validation."""
        TruststoreModel.objects.create(
            unique_name='taken', intended_usage=TruststoreModel.IntendedUsage.GENERIC
        )
        root, _ = CertificateGenerator.create_root_ca('Dup Root')
        form = TruststoreAddForm(
            data={'unique_name': 'taken', 'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value},
            files={'trust_store_file': SimpleUploadedFile('ts.pem', _pem(root))},
        )

        assert not form.is_valid()
        assert 'unique_name' in form.errors

    def test_malformed_file_is_rejected(self) -> None:
        """Data that is neither a collection nor a single certificate is rejected."""
        form = TruststoreAddForm(
            data={'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value},
            files={'trust_store_file': SimpleUploadedFile('ts.pem', b'definitely-not-a-certificate')},
        )

        assert not form.is_valid()
        assert 'malformed' in str(form.errors).lower()

    def test_unreadable_file_reports_error(self) -> None:
        """A file object that cannot be read produces a validation error."""

        class Unreadable:
            name = 'broken.pem'
            size = 10

            def read(self) -> bytes:
                msg = 'cannot read'
                raise OSError(msg)

        form = TruststoreAddForm(data={'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value})
        form.cleaned_data = {
            'unique_name': '',
            'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value,
            'trust_store_file': Unreadable(),
        }
        with pytest.raises(ValidationError, match='Unexpected error'):
            form.clean()

    def test_missing_file_reports_error(self) -> None:
        """Absent file content is rejected during cross-field validation."""
        form = TruststoreAddForm(data={'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value})
        form.cleaned_data = {
            'unique_name': '',
            'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value,
            'trust_store_file': None,
        }
        with pytest.raises(ValidationError, match='required'):
            form.clean()

    def test_single_pem_certificate_derives_name_and_saves(self) -> None:
        """A single certificate is stored and named after its subject."""
        root, _ = CertificateGenerator.create_root_ca('Derived Name Root')
        form = TruststoreAddForm(
            data={'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value},
            files={'trust_store_file': SimpleUploadedFile('ts.pem', _pem(root))},
        )

        assert form.is_valid(), form.errors
        truststore = form.cleaned_data['truststore']
        assert truststore.number_of_certificates == 1
        assert truststore.unique_name

    def test_existing_certificate_is_reused_not_duplicated(self, chain: tuple[x509.Certificate, ...]) -> None:
        """Certificates already stored are linked rather than saved twice."""
        from pki.models.certificate import CertificateModel

        root, intermediate, _ = chain
        CertificateModel.save_certificate(root)
        before = CertificateModel.objects.count()

        truststore = TruststoreAddForm.save_trust_store(
            unique_name='reuse-store',
            intended_usage=TruststoreModel.IntendedUsage.GENERIC,
            certificates=[root, intermediate],
        )

        assert truststore.number_of_certificates == 2
        assert CertificateModel.objects.count() == before + 1

    def test_name_collision_detected_after_parsing(self) -> None:
        """A derived name that already exists is reported as a duplicate."""
        root, _ = CertificateGenerator.create_root_ca('Collision Root')
        first = TruststoreAddForm(
            data={'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value},
            files={'trust_store_file': SimpleUploadedFile('ts.pem', _pem(root))},
        )
        assert first.is_valid(), first.errors

        second = TruststoreAddForm(
            data={'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value},
            files={'trust_store_file': SimpleUploadedFile('ts.pem', _pem(root))},
        )
        assert not second.is_valid()
        assert 'already exists' in str(second.errors)


class TestValidateAndCreateCaChain:
    """Chain validation performed for issuing-CA-chain truststores."""

    def test_non_chain_usage_skips_validation(self) -> None:
        """Only the issuing-CA-chain usage triggers chain construction."""
        assert validate_and_create_ca_chain([], TruststoreModel.IntendedUsage.GENERIC) is None

    def test_empty_chain_is_rejected(self) -> None:
        """An empty issuing-CA chain is invalid."""
        with pytest.raises(ValidationError, match='cannot be empty'):
            validate_and_create_ca_chain([], TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN)

    def test_unrelated_certificates_do_not_form_a_chain(self) -> None:
        """Certificates from different hierarchies cannot be ordered into a chain."""
        first, first_key = CertificateGenerator.create_root_ca('Unrelated A')
        leaf_a, _ = CertificateGenerator.create_issuing_ca(first_key, 'Unrelated A', 'Leaf A')
        _second, second_key = CertificateGenerator.create_root_ca('Unrelated B')
        leaf_b, _ = CertificateGenerator.create_issuing_ca(second_key, 'Unrelated B', 'Leaf B')

        with pytest.raises(ValidationError, match='do not form a valid chain'):
            validate_and_create_ca_chain([leaf_a, leaf_b], TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN)

    def test_single_non_self_signed_certificate_is_incomplete(self) -> None:
        """A lone intermediate without its root is an incomplete chain."""
        _root, root_key = CertificateGenerator.create_root_ca('Incomplete Root')
        intermediate, _ = CertificateGenerator.create_issuing_ca(
            root_key, 'Incomplete Root', 'Incomplete Intermediate'
        )

        with pytest.raises(ValidationError, match='Incomplete certificate chain'):
            validate_and_create_ca_chain([intermediate], TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN)

    def test_chain_missing_its_root_is_rejected(self) -> None:
        """A chain whose root is absent cannot be ordered and is rejected."""
        _root, root_key = CertificateGenerator.create_root_ca('Missing Root')
        intermediate, intermediate_key = CertificateGenerator.create_issuing_ca(
            root_key, 'Missing Root', 'Missing Intermediate'
        )
        leaf, _ = CertificateGenerator.create_issuing_ca(
            intermediate_key, 'Missing Intermediate', 'Missing Leaf'
        )

        with pytest.raises(ValidationError, match='do not form a valid chain'):
            validate_and_create_ca_chain([leaf, intermediate], TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN)

    def test_valid_chain_creates_keyless_ca_hierarchy(self, chain: tuple[x509.Certificate, ...]) -> None:
        """A full chain creates keyless CAs for every issuer above the leaf."""
        root, intermediate, leaf = chain

        validate_and_create_ca_chain([leaf, intermediate, root], TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN)

        keyless = CaModel.objects.filter(ca_type=CaModel.CaTypeChoice.KEYLESS)
        assert {ca.certificate.common_name for ca in keyless} == {'Chain Root', 'Chain Intermediate'}
        root_ca = keyless.get(certificate__common_name='Chain Root')
        intermediate_ca = keyless.get(certificate__common_name='Chain Intermediate')
        assert root_ca.parent_ca is None
        assert intermediate_ca.parent_ca == root_ca

    def test_self_signed_root_only_chain_creates_no_parent_cas(self) -> None:
        """A single self-signed root is a valid chain with no issuer above it."""
        root, _ = CertificateGenerator.create_root_ca('Solo Root')

        assert validate_and_create_ca_chain([root], TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN) is None


class TestChainSorting:
    """Ordering and integrity helpers used during chain validation."""

    def test_single_certificate_is_returned_unchanged(self) -> None:
        """A one-element chain requires no sorting."""
        root, _ = CertificateGenerator.create_root_ca('Single')
        assert _sort_certificate_chain([root]) == [root]

    def test_shuffled_chain_is_sorted_leaf_to_root(self, chain: tuple[x509.Certificate, ...]) -> None:
        """Certificates are ordered from leaf up to the self-signed root."""
        root, intermediate, leaf = chain

        assert _sort_certificate_chain([root, leaf, intermediate]) == [leaf, intermediate, root]

    def test_broken_chain_returns_empty_list(self) -> None:
        """A chain with a missing issuer cannot be sorted."""
        _root, root_key = CertificateGenerator.create_root_ca('Broken Root')
        intermediate, intermediate_key = CertificateGenerator.create_issuing_ca(
            root_key, 'Broken Root', 'Broken Intermediate'
        )
        leaf, _ = CertificateGenerator.create_issuing_ca(intermediate_key, 'Broken Intermediate', 'Broken Leaf')

        assert _sort_certificate_chain([leaf, intermediate]) == []

    def test_chain_integrity_detects_mismatched_issuer(self, chain: tuple[x509.Certificate, ...]) -> None:
        """Integrity checking compares issuer and subject of adjacent entries."""
        root, intermediate, leaf = chain

        assert _validate_chain_integrity([leaf, intermediate, root]) is True
        assert _validate_chain_integrity([leaf, root]) is False


class TestCreateOrGetKeylessCa:
    """Keyless CA creation from trust anchor certificates."""

    def test_creates_ca_named_after_common_name(self) -> None:
        """A new keyless CA takes its name from the certificate common name."""
        root, _ = CertificateGenerator.create_root_ca('Keyless Root')

        ca = _create_or_get_keyless_ca(root)

        assert ca.unique_name == 'Keyless Root'
        assert ca.ca_type == CaModel.CaTypeChoice.KEYLESS
        assert ca.certificate.sha256_fingerprint == root.fingerprint(hashes.SHA256()).hex().upper()

    def test_existing_ca_is_reused_and_parent_backfilled(self, chain: tuple[x509.Certificate, ...]) -> None:
        """An existing CA is returned and gains a parent link when missing."""
        root, intermediate, _ = chain
        parent = _create_or_get_keyless_ca(root)
        first = _create_or_get_keyless_ca(intermediate)
        assert first.parent_ca is None

        second = _create_or_get_keyless_ca(intermediate, parent)

        assert second.pk == first.pk
        assert second.parent_ca == parent
        assert CaModel.objects.filter(ca_type=CaModel.CaTypeChoice.KEYLESS).count() == 2

    def test_name_conflict_is_resolved_with_suffix(self) -> None:
        """A conflicting CA name is disambiguated with a numeric suffix."""
        first, _ = CertificateGenerator.create_root_ca('Same Name')
        second, _ = CertificateGenerator.create_root_ca('Same Name')

        _create_or_get_keyless_ca(first)
        duplicate = _create_or_get_keyless_ca(second)

        assert duplicate.unique_name == 'Same Name-1'
