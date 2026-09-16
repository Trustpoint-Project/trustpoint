# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for Issuing CA import, request and configuration forms."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from crypto.domain.specs import EcKeySpec, MlDsaKeySpec, RsaKeySpec
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from pki.forms.issuing_cas import (
    MAX_PKCS12_UPLOAD_BYTES,
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddFileImportSeparateFilesForm,
    IssuingCaAddRequestCmpForm,
    IssuingCaAddRequestEstForm,
    IssuingCaAddRequestMixin,
    IssuingCaCrlCycleForm,
    IssuingCaImportMixin,
    IssuingCaTruststoreAssociationForm,
)
from pki.models import CaModel
from pki.models.truststore import TruststoreModel
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db

TEST_KEY_PASSWORD = 'unit-test-secret-password'  # noqa: S105
MAX_PEM_UPLOAD_BYTES = 1024 * 64


@pytest.fixture(autouse=True)
def permissive_security_config() -> None:
    """Allow self-signed CA imports and manual protocols for these tests."""
    from management.models import SecurityConfig
    from onboarding.enums import NoOnboardingPkiProtocol

    SecurityConfig.objects.all().delete()
    SecurityConfig.objects.create(
        security_mode=True,
        rsa_minimum_key_size=2048,
        allow_self_signed_ca=True,
        allow_imported_private_keys=True,
        allow_ca_issuance=True,
        permitted_no_onboarding_pki_protocols=list(NoOnboardingPkiProtocol.values),
    )


def _ca_pair(cn: str = 'Import CA') -> tuple[x509.Certificate, Any]:
    """Return a self-signed CA certificate and its private key."""
    return CertificateGenerator.create_root_ca(cn)


def _pkcs12_bytes(
    certificate: x509.Certificate, private_key: Any, password: bytes | None = None, chain: list | None = None
) -> bytes:
    """Serialize a credential into a PKCS#12 container."""
    encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    return pkcs12.serialize_key_and_certificates(
        name=b'ca', key=private_key, cert=certificate, cas=chain, encryption_algorithm=encryption
    )


def _key_pem(private_key: Any, password: str | None = None) -> bytes:
    """Serialize a private key to PEM, optionally encrypted."""
    encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    return private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


class TestIssuingCaCertificateValidation:
    """Shared CA certificate validation rules."""

    def test_end_entity_certificate_is_rejected(self) -> None:
        """A certificate without the CA basic constraint is rejected."""
        root, root_key = _ca_pair('EE Issuer')
        leaf, _ = CertificateGenerator.create_ee(root_key, root.subject, 'leaf')

        with pytest.raises(ValidationError, match='not a CA certificate'):
            IssuingCaImportMixin()._validate_ca_certificate(leaf)

    def test_missing_key_usage_extension_is_rejected(self) -> None:
        """CA certificates must carry a KeyUsage extension."""
        root, root_key = _ca_pair('No KU Root')
        builder = (
            x509.CertificateBuilder()
            .subject_name(root.subject)
            .issuer_name(root.subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(root.not_valid_before_utc)
            .not_valid_after(root.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        )
        certificate = builder.sign(root_key, root.signature_hash_algorithm)

        with pytest.raises(ValidationError, match='KeyUsage extension is required'):
            IssuingCaImportMixin()._validate_ca_certificate(certificate)

    @pytest.mark.parametrize(
        ('key_cert_sign', 'crl_sign', 'message'),
        [(False, True, 'keyCertSign'), (True, False, 'cRLSign')],
    )
    def test_required_key_usages_are_enforced(
        self, key_cert_sign: bool, crl_sign: bool, message: str
    ) -> None:
        """CA certificates must permit certificate and CRL signing."""
        root, root_key = _ca_pair('KU Root')
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=key_cert_sign,
            crl_sign=crl_sign,
            encipher_only=False,
            decipher_only=False,
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(root.subject)
            .issuer_name(root.subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(root.not_valid_before_utc)
            .not_valid_after(root.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(key_usage, critical=True)
            .sign(root_key, root.signature_hash_algorithm)
        )

        with pytest.raises(ValidationError, match=message):
            IssuingCaImportMixin()._validate_ca_certificate(certificate)

    def test_chain_verification_is_skipped_without_chain(self) -> None:
        """Self-signed imports without a chain skip path verification."""
        root, _ = _ca_pair('Skip Root')

        assert IssuingCaImportMixin()._verify_ca_cert_with_chain(root, []) is None

    def test_mismatched_key_and_certificate_are_rejected(self) -> None:
        """A private key that does not match the certificate is rejected."""
        from trustpoint_core.serializer import CredentialSerializer

        certificate, _ = _ca_pair('Mismatch CA')
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with pytest.raises(ValidationError, match='does not match'):
            IssuingCaImportMixin()._validate_credential_components(
                CredentialSerializer(
                    private_key=other_key, certificate=certificate, additional_certificates=[]
                )
            )


class TestIssuingCaPkcs12Import:
    """PKCS#12 based Issuing CA import."""

    def test_valid_pkcs12_creates_issuing_ca(self) -> None:
        """A valid PKCS#12 container creates an issuing CA."""
        certificate, key = _ca_pair('P12 CA')
        form = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'p12-ca'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', _pkcs12_bytes(certificate, key))},
        )

        assert form.is_valid(), form.errors
        ca = CaModel.objects.get(unique_name='p12-ca')
        assert ca.credential is not None
        assert ca.chain_truststore is not None
        assert ca.no_onboarding_config is not None

    def test_encrypted_pkcs12_requires_correct_password(self) -> None:
        """A wrong PKCS#12 password is reported without leaking the secret."""
        certificate, key = _ca_pair('Encrypted CA')
        container = _pkcs12_bytes(certificate, key, password=TEST_KEY_PASSWORD.encode())
        form = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'enc-ca', 'pkcs12_password': 'wrong-password'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', container)},
        )

        assert not form.is_valid()
        assert 'wrong password' in str(form.errors).lower()
        assert TEST_KEY_PASSWORD not in str(form.errors)

    def test_encrypted_pkcs12_is_accepted_with_correct_password(self) -> None:
        """The correct PKCS#12 password unlocks the container."""
        certificate, key = _ca_pair('Unlock CA')
        container = _pkcs12_bytes(certificate, key, password=TEST_KEY_PASSWORD.encode())
        form = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'unlock-ca', 'pkcs12_password': TEST_KEY_PASSWORD},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', container)},
        )

        assert form.is_valid(), form.errors
        assert CaModel.objects.filter(unique_name='unlock-ca').exists()

    def test_name_is_derived_from_certificate_when_omitted(self) -> None:
        """An omitted unique name is derived from the certificate."""
        certificate, key = _ca_pair('Derived CA')
        form = IssuingCaAddFileImportPkcs12Form(
            data={},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', _pkcs12_bytes(certificate, key))},
        )

        assert form.is_valid(), form.errors
        assert CaModel.objects.count() == 1

    def test_duplicate_certificate_is_rejected(self) -> None:
        """The same CA certificate cannot be imported twice."""
        certificate, key = _ca_pair('Duplicate CA')
        container = _pkcs12_bytes(certificate, key)
        first = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'dup-one'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', container)},
        )
        assert first.is_valid(), first.errors

        second = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'dup-two'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', container)},
        )

        assert not second.is_valid()
        assert 'already configured' in str(second.errors)

    def test_duplicate_unique_name_is_rejected(self) -> None:
        """An already used CA name is rejected."""
        first_cert, first_key = _ca_pair('First CA')
        assert IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'taken-ca'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', _pkcs12_bytes(first_cert, first_key))},
        ).is_valid()

        second_cert, second_key = _ca_pair('Second CA')
        form = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'taken-ca'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', _pkcs12_bytes(second_cert, second_key))},
        )

        assert not form.is_valid()
        assert 'already taken' in str(form.errors)

    def test_corrupt_container_is_rejected(self) -> None:
        """Unparsable PKCS#12 content is rejected."""
        form = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'broken-ca'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', b'not-a-container')},
        )

        assert not form.is_valid()
        assert not CaModel.objects.exists()

    def test_end_entity_container_is_rejected(self) -> None:
        """A PKCS#12 holding an end-entity certificate cannot become a CA."""
        root, root_key = _ca_pair('EE Container Root')
        leaf, leaf_key = CertificateGenerator.create_ee(root_key, root.subject, 'leaf')
        form = IssuingCaAddFileImportPkcs12Form(
            data={'unique_name': 'ee-ca'},
            files={'pkcs12_file': SimpleUploadedFile('ca.p12', _pkcs12_bytes(leaf, leaf_key))},
        )

        assert not form.is_valid()
        assert 'not a CA certificate' in str(form.errors)


class TestIssuingCaSeparateFilesImport:
    """Separate certificate and key based Issuing CA import."""

    def test_valid_files_create_issuing_ca(self) -> None:
        """Matching certificate and key files create an issuing CA."""
        certificate, key = _ca_pair('Separate CA')
        form = IssuingCaAddFileImportSeparateFilesForm(
            data={'unique_name': 'separate-ca'},
            files={
                'ca_certificate': SimpleUploadedFile(
                    'ca.pem', certificate.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(key)),
            },
        )

        assert form.is_valid(), form.errors
        assert CaModel.objects.filter(unique_name='separate-ca').exists()

    def test_encrypted_key_is_accepted_with_password(self) -> None:
        """An encrypted CA key is unlocked with the supplied password."""
        certificate, key = _ca_pair('Encrypted Separate CA')
        form = IssuingCaAddFileImportSeparateFilesForm(
            data={'unique_name': 'enc-separate-ca', 'private_key_file_password': TEST_KEY_PASSWORD},
            files={
                'ca_certificate': SimpleUploadedFile(
                    'ca.pem', certificate.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(key, TEST_KEY_PASSWORD)),
            },
        )

        assert form.is_valid(), form.errors

    def test_oversized_uploads_are_rejected(self) -> None:
        """Oversized certificate and key uploads are rejected early."""
        certificate, key = _ca_pair('Oversized CA')
        oversized = b'x' * (MAX_PEM_UPLOAD_BYTES + 1)

        key_form = IssuingCaAddFileImportSeparateFilesForm(
            data={},
            files={
                'ca_certificate': SimpleUploadedFile(
                    'ca.pem', certificate.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', oversized),
            },
        )
        assert not key_form.is_valid()
        assert 'too large' in str(key_form.errors['private_key_file'])

        cert_form = IssuingCaAddFileImportSeparateFilesForm(
            data={},
            files={
                'ca_certificate': SimpleUploadedFile('ca.pem', oversized),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(key)),
            },
        )
        assert not cert_form.is_valid()
        assert 'too large' in str(cert_form.errors['ca_certificate'])

    def test_corrupt_inputs_are_rejected(self) -> None:
        """Unparsable certificate, key and chain files are rejected."""
        certificate, key = _ca_pair('Corrupt CA')
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

        bad_key = IssuingCaAddFileImportSeparateFilesForm(
            data={},
            files={
                'ca_certificate': SimpleUploadedFile('ca.pem', certificate_pem),
                'private_key_file': SimpleUploadedFile('key.pem', b'broken'),
            },
        )
        assert not bad_key.is_valid()
        assert 'private_key_file' in bad_key.errors

        bad_cert = IssuingCaAddFileImportSeparateFilesForm(
            data={},
            files={
                'ca_certificate': SimpleUploadedFile('ca.pem', b'broken'),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(key)),
            },
        )
        assert not bad_cert.is_valid()
        assert 'ca_certificate' in bad_cert.errors

        bad_chain = IssuingCaAddFileImportSeparateFilesForm(
            data={},
            files={
                'ca_certificate': SimpleUploadedFile('ca.pem', certificate_pem),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(key)),
                'ca_certificate_chain': SimpleUploadedFile('chain.pem', b'broken'),
            },
        )
        assert not bad_chain.is_valid()
        assert 'ca_certificate_chain' in bad_chain.errors

    def test_key_certificate_mismatch_is_rejected(self) -> None:
        """A key that belongs to a different certificate is rejected."""
        certificate, _ = _ca_pair('Mismatch Import CA')
        _other_cert, other_key = _ca_pair('Other CA')
        form = IssuingCaAddFileImportSeparateFilesForm(
            data={'unique_name': 'mismatch-ca'},
            files={
                'ca_certificate': SimpleUploadedFile(
                    'ca.pem', certificate.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(other_key)),
            },
        )

        assert not form.is_valid()
        assert 'does not match' in str(form.errors)
        assert not CaModel.objects.filter(unique_name='mismatch-ca').exists()

    def test_chain_is_stored_with_the_issuing_ca(self) -> None:
        """A supplied chain is verified and stored with the CA."""
        root, root_key = CertificateGenerator.create_root_ca('Chain Import Root', path_length=2)
        issuing, issuing_key = CertificateGenerator.create_issuing_ca(
            root_key, 'Chain Import Root', 'Chain Import Issuing'
        )
        form = IssuingCaAddFileImportSeparateFilesForm(
            data={'unique_name': 'chain-ca'},
            files={
                'ca_certificate': SimpleUploadedFile(
                    'ca.pem', issuing.public_bytes(serialization.Encoding.PEM)
                ),
                'ca_certificate_chain': SimpleUploadedFile(
                    'chain.pem', root.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(issuing_key)),
            },
        )

        assert form.is_valid(), form.errors
        ca = CaModel.objects.get(unique_name='chain-ca')
        assert ca.chain_truststore is not None

    def test_chain_creates_ca_hierarchy_for_imported_issuing_ca(self) -> None:
        """A supplied chain creates parent CA rows and links the imported CA below them."""
        root, root_key = CertificateGenerator.create_root_ca('Import Tree Root', path_length=2)
        intermediate, intermediate_key = CertificateGenerator.create_issuing_ca(
            root_key, 'Import Tree Root', 'Import Tree Intermediate', path_length=1
        )
        issuing, issuing_key = CertificateGenerator.create_issuing_ca(
            intermediate_key, 'Import Tree Intermediate', 'Import Tree Issuing'
        )
        form = IssuingCaAddFileImportSeparateFilesForm(
            data={'unique_name': 'import-tree-ca'},
            files={
                'ca_certificate': SimpleUploadedFile(
                    'ca.pem', issuing.public_bytes(serialization.Encoding.PEM)
                ),
                'ca_certificate_chain': SimpleUploadedFile(
                    'chain.pem',
                    intermediate.public_bytes(serialization.Encoding.PEM)
                    + root.public_bytes(serialization.Encoding.PEM),
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(issuing_key)),
            },
        )

        assert form.is_valid(), form.errors
        imported_ca = CaModel.objects.get(unique_name='import-tree-ca')
        root_ca = CaModel.objects.get(certificate__common_name='Import Tree Root')
        intermediate_ca = CaModel.objects.get(certificate__common_name='Import Tree Intermediate')
        assert root_ca.parent_ca is None
        assert intermediate_ca.parent_ca == root_ca
        assert imported_ca.parent_ca == intermediate_ca

    def test_untrusted_chain_is_rejected(self) -> None:
        """A chain that does not sign the CA certificate is rejected."""
        _root, root_key = CertificateGenerator.create_root_ca('Real Root', path_length=2)
        issuing, issuing_key = CertificateGenerator.create_issuing_ca(root_key, 'Real Root', 'Real Issuing')
        unrelated, _ = CertificateGenerator.create_root_ca('Unrelated Root')
        form = IssuingCaAddFileImportSeparateFilesForm(
            data={'unique_name': 'bad-chain-ca'},
            files={
                'ca_certificate': SimpleUploadedFile(
                    'ca.pem', issuing.public_bytes(serialization.Encoding.PEM)
                ),
                'ca_certificate_chain': SimpleUploadedFile(
                    'chain.pem', unrelated.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(issuing_key)),
            },
        )

        assert not form.is_valid()
        assert 'verification failed' in str(form.errors)
        assert not CaModel.objects.filter(unique_name='bad-chain-ca').exists()


class TestIssuingCaRequestForms:
    """Remote Issuing CA request forms."""

    @pytest.mark.parametrize(
        ('key_type', 'expected'),
        [
            ('RSA-3072', RsaKeySpec),
            ('ECC-SECP384R1', EcKeySpec),
            ('MLDSA-65', MlDsaKeySpec),
        ],
    )
    def test_key_type_maps_to_backend_spec(self, key_type: str, expected: type) -> None:
        """Each offered key type maps to the matching backend specification."""
        spec = IssuingCaAddRequestMixin._key_spec_for_key_type(key_type)

        assert isinstance(spec, expected)

    def test_rsa_key_size_is_taken_from_choice(self) -> None:
        """The RSA key size is parsed from the selected choice."""
        spec = IssuingCaAddRequestMixin._key_spec_for_key_type('RSA-4096')

        assert spec.key_size == 4096

    def test_est_form_defaults_target_est_endpoint(self) -> None:
        """The EST request form pre-fills the EST endpoint defaults."""
        form = IssuingCaAddRequestEstForm()

        assert form.fields['remote_port'].initial == 443
        assert form.fields['remote_path'].initial == '/.well-known/est/simpleenroll'
        assert form.fields['ca_type'].initial == CaModel.CaTypeChoice.REMOTE_ISSUING_EST

    def test_cmp_form_defaults_target_cmp_endpoint(self) -> None:
        """The CMP request form pre-fills the CMP endpoint defaults."""
        form = IssuingCaAddRequestCmpForm()

        assert form.fields['remote_path'].initial == '/.well-known/cmp/p/certification'
        assert form.fields['ca_type'].initial == CaModel.CaTypeChoice.REMOTE_ISSUING_CMP

    def test_unsupported_key_type_is_rejected(self) -> None:
        """A key type the backend cannot generate is rejected."""
        form = IssuingCaAddRequestEstForm(
            data={
                'unique_name': 'remote-est-ca',
                'remote_host': 'ca.example.com',
                'remote_port': 443,
                'remote_path': '/.well-known/est/simpleenroll',
                'est_username': 'operator',
                'est_password': TEST_KEY_PASSWORD,
                'key_type': 'RSA-1024',
                'ca_type': CaModel.CaTypeChoice.REMOTE_ISSUING_EST,
            }
        )

        assert not form.is_valid()
        assert 'key_type' in form.errors

    def test_supported_choices_are_offered(self) -> None:
        """Only backend-supported key types are offered in the form."""
        choices = IssuingCaAddRequestMixin._supported_key_type_choices()

        assert choices
        assert all(value for value, _label in choices)


class TestIssuingCaTruststoreAssociationForm:
    """Truststore selection rules per CA type."""

    def _ca(self, ca_type: CaModel.CaTypeChoice, *, with_certificate: bool = False) -> CaModel:
        certificate, _key = _ca_pair(f'Assoc {ca_type}')
        from pki.models.certificate import CertificateModel

        ca = CaModel(unique_name=f'assoc-{int(ca_type)}', ca_type=ca_type)
        if with_certificate:
            ca.certificate = CertificateModel.save_certificate(certificate)
        ca.remote_host = 'ca.example.com'
        ca.remote_port = 443
        ca.remote_path = '/path'
        return ca

    def test_est_ra_first_step_requires_issuing_ca_chain(self) -> None:
        """An EST RA without a certificate first imports the issuing CA chain."""
        chain_store = TruststoreModel.objects.create(
            unique_name='chain-store', intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
        )
        TruststoreModel.objects.create(
            unique_name='tls-store', intended_usage=TruststoreModel.IntendedUsage.TLS
        )

        form = IssuingCaTruststoreAssociationForm(
            instance=self._ca(CaModel.CaTypeChoice.REMOTE_EST_RA)
        )

        assert list(form.fields['trust_store'].queryset) == [chain_store]
        assert 'Step 1/2' in str(form.fields['trust_store'].help_text)

    def test_est_ra_second_step_requires_tls_truststore(self) -> None:
        """An EST RA that already has a certificate imports the TLS anchor."""
        TruststoreModel.objects.create(
            unique_name='chain-store', intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
        )
        tls_store = TruststoreModel.objects.create(
            unique_name='tls-store', intended_usage=TruststoreModel.IntendedUsage.TLS
        )

        form = IssuingCaTruststoreAssociationForm(
            instance=self._ca(CaModel.CaTypeChoice.REMOTE_EST_RA, with_certificate=True)
        )

        assert list(form.fields['trust_store'].queryset) == [tls_store]
        assert 'Step 2/2' in str(form.fields['trust_store'].help_text)

    @pytest.mark.parametrize(
        'ca_type', [CaModel.CaTypeChoice.REMOTE_ISSUING_CMP, CaModel.CaTypeChoice.REMOTE_CMP_RA]
    )
    def test_cmp_requires_issuing_ca_chain(self, ca_type: CaModel.CaTypeChoice) -> None:
        """CMP CAs and RAs only accept issuing CA chain truststores."""
        chain_store = TruststoreModel.objects.create(
            unique_name='chain-store', intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
        )
        TruststoreModel.objects.create(
            unique_name='tls-store', intended_usage=TruststoreModel.IntendedUsage.TLS
        )

        form = IssuingCaTruststoreAssociationForm(instance=self._ca(ca_type))

        assert list(form.fields['trust_store'].queryset) == [chain_store]

    def test_save_without_config_raises(self) -> None:
        """A CA without a no-onboarding config cannot store a truststore."""
        tls_store = TruststoreModel.objects.create(
            unique_name='tls-store', intended_usage=TruststoreModel.IntendedUsage.TLS
        )
        form = IssuingCaTruststoreAssociationForm(
            data={'trust_store': tls_store.pk},
            instance=self._ca(CaModel.CaTypeChoice.REMOTE_ISSUING_EST),
        )
        assert form.is_valid(), form.errors

        with pytest.raises(ValidationError):
            form.save()


class TestIssuingCaCrlCycleForm:
    """CRL cycle configuration validation."""

    def test_interval_below_minimum_is_rejected(self, issuing_ca_instance: dict[str, Any]) -> None:
        """CRL cycle intervals shorter than five minutes are rejected."""
        form = IssuingCaCrlCycleForm(
            data={
                'crl_cycle_enabled': True,
                'crl_cycle_interval_hours': 0.01,
                'crl_validity_hours': 24,
            },
            instance=issuing_ca_instance['issuing_ca'],
        )

        assert not form.is_valid()
        assert 'crl_cycle_interval_hours' in form.errors

    def test_valid_settings_are_saved(self, issuing_ca_instance: dict[str, Any]) -> None:
        """Valid CRL cycle settings are persisted on the CA."""
        form = IssuingCaCrlCycleForm(
            data={
                'crl_cycle_enabled': True,
                'crl_cycle_interval_hours': 6,
                'crl_validity_hours': 24,
                'auto_crl_on_revocation_enabled': True,
            },
            instance=issuing_ca_instance['issuing_ca'],
        )

        assert form.is_valid(), form.errors
        ca = form.save()
        assert ca.crl_cycle_enabled is True
        assert ca.crl_cycle_interval_hours == 6
        assert ca.auto_crl_on_revocation_enabled is True

    def test_deactivated_ca_cannot_be_configured(self, issuing_ca_instance: dict[str, Any]) -> None:
        """CRL settings cannot be changed on a deactivated CA."""
        ca = issuing_ca_instance['issuing_ca']
        ca.is_active = False
        ca.save()

        form = IssuingCaCrlCycleForm(
            data={'crl_cycle_interval_hours': 6, 'crl_validity_hours': 24}, instance=ca
        )

        assert not form.is_valid()
        assert 'deactivated' in str(form.errors)

    def test_validity_beyond_security_policy_is_rejected(
        self, issuing_ca_instance: dict[str, Any]
    ) -> None:
        """CRL validity above the configured policy maximum is rejected."""
        from management.models import SecurityConfig

        SecurityConfig.objects.all().delete()
        SecurityConfig.objects.create(security_mode=True, max_crl_validity_days=1)

        form = IssuingCaCrlCycleForm(
            data={'crl_cycle_interval_hours': 6, 'crl_validity_hours': 48},
            instance=issuing_ca_instance['issuing_ca'],
        )

        assert not form.is_valid()
        assert 'crl_validity_hours' in form.errors
