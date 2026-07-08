"""Tests for the Import CA rollover strategy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import NoEncryption, pkcs12
from django import forms
from django.core.files.uploadedfile import SimpleUploadedFile

from crypto.domain.errors import ProviderConfigurationError
from management.models.security import SecurityConfig
from pki.models import CaModel
from pki.models.ca_rollover import CaRolloverStrategyType
from pki.rollover.import_ca import ImportCaRolloverForm, ImportCaRolloverStrategy
from pki.rollover.registry import rollover_registry


@pytest.fixture(autouse=True)
def allow_imported_keys():
    """Ensure imported private keys are allowed for these tests."""
    security_config, _created = SecurityConfig.objects.get_or_create(
        id=1,
        defaults={'allow_imported_private_keys': True},
    )
    security_config.allow_imported_private_keys = True
    security_config.save()
    return security_config


@pytest.fixture
def sample_ca_pkcs12():
    """Create a sample CA PKCS#12 file for testing."""
    # Generate RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test Rollover CA'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Test Organization'),
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'US'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(dt_timezone.utc))
        .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Create PKCS#12
    password = b'test_password'
    pkcs12_data = pkcs12.serialize_key_and_certificates(
        name=b'Test Rollover CA',
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption()
    )

    return {
        'pkcs12_data': pkcs12_data,
        'password': password,
        'private_key': private_key,
        'certificate': cert,
    }


@pytest.fixture
def sample_ec_ca_pkcs12():
    """Create a sample EC CA PKCS#12 file for testing."""
    # Generate EC key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Create CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test EC CA'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Test Organization'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(dt_timezone.utc))
        .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Create PKCS#12
    pkcs12_data = pkcs12.serialize_key_and_certificates(
        name=b'Test EC CA',
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption()
    )

    return {
        'pkcs12_data': pkcs12_data,
        'private_key': private_key,
        'certificate': cert,
    }


@pytest.fixture
def sample_non_ca_pkcs12():
    """Create a sample non-CA PKCS#12 file for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Not a CA'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(dt_timezone.utc))
        .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    pkcs12_data = pkcs12.serialize_key_and_certificates(
        name=b'Not a CA',
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption()
    )

    return {
        'pkcs12_data': pkcs12_data,
        'private_key': private_key,
        'certificate': cert,
    }


class TestImportCaRolloverForm:
    """Test cases for ImportCaRolloverForm."""

    def test_form_has_required_fields(self):
        """Test that the form has all required fields."""
        form = ImportCaRolloverForm()
        assert 'unique_name' in form.fields
        assert 'pkcs12_file' in form.fields
        assert 'pkcs12_password' in form.fields
        assert 'transition_scheduled_at' in form.fields
        assert 'notes' in form.fields

    def test_form_field_requirements(self):
        """Test that field requirements are correct."""
        form = ImportCaRolloverForm()
        assert form.fields['pkcs12_file'].required is True
        assert form.fields['unique_name'].required is False
        assert form.fields['pkcs12_password'].required is False
        assert form.fields['transition_scheduled_at'].required is False
        assert form.fields['notes'].required is False

    def test_clean_missing_pkcs12_file(self):
        """Test validation fails when PKCS#12 file is missing."""
        form = ImportCaRolloverForm(data={})
        assert not form.is_valid()
        assert 'pkcs12_file' in form.errors

    def test_clean_with_valid_ca_certificate(self, sample_ca_pkcs12):
        """Test form validation with valid CA certificate."""
        pkcs12_file = SimpleUploadedFile(
            'test_ca.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={'unique_name': 'test-rollover-ca'},
            files={'pkcs12_file': pkcs12_file}
        )

        assert form.is_valid()
        assert hasattr(form, '_new_issuing_ca')
        assert form.new_issuing_ca is not None
        assert isinstance(form.new_issuing_ca, CaModel)

    def test_clean_with_ec_ca_certificate(self, sample_ec_ca_pkcs12):
        """Test form validation with EC CA certificate."""
        pkcs12_file = SimpleUploadedFile(
            'test_ec_ca.p12',
            sample_ec_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={'unique_name': 'test-ec-ca'},
            files={'pkcs12_file': pkcs12_file}
        )

        assert form.is_valid()
        assert hasattr(form, '_new_issuing_ca')

    def test_clean_without_unique_name(self, sample_ca_pkcs12):
        """Test form generates unique name when not provided."""
        pkcs12_file = SimpleUploadedFile(
            'test_ca.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={},
            files={'pkcs12_file': pkcs12_file}
        )

        assert form.is_valid()
        assert form.new_issuing_ca.unique_name is not None
        assert 'Test Rollover CA' in form.new_issuing_ca.unique_name

    def test_clean_invalid_pkcs12_file(self):
        """Test validation fails with invalid PKCS#12 file."""
        pkcs12_file = SimpleUploadedFile(
            'invalid.p12',
            b'invalid data',
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={},
            files={'pkcs12_file': pkcs12_file}
        )

        assert not form.is_valid()
        assert any('parse' in str(error).lower() for errors in form.errors.values() for error in errors)

    def test_clean_wrong_password(self, sample_ca_pkcs12):
        """Test validation fails with wrong password."""
        # Create password-protected PKCS#12
        password = b'correct_password'
        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=b'Test CA',
            key=sample_ca_pkcs12['private_key'],
            cert=sample_ca_pkcs12['certificate'],
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )

        pkcs12_file = SimpleUploadedFile(
            'test_ca.p12',
            pkcs12_data,
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={'pkcs12_password': 'wrong_password'},
            files={'pkcs12_file': pkcs12_file}
        )

        assert not form.is_valid()

    def test_clean_non_ca_certificate(self, sample_non_ca_pkcs12):
        """Test validation fails with non-CA certificate."""
        pkcs12_file = SimpleUploadedFile(
            'not_ca.p12',
            sample_non_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={},
            files={'pkcs12_file': pkcs12_file}
        )

        assert not form.is_valid()
        assert any('CA certificate' in str(error) for errors in form.errors.values() for error in errors)

    def test_clean_duplicate_ca(self, sample_ca_pkcs12, issuing_ca_model):
        """Test validation fails when CA certificate already exists."""
        # First, import the CA
        pkcs12_file1 = SimpleUploadedFile(
            'test_ca1.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form1 = ImportCaRolloverForm(
            data={'unique_name': 'first-ca'},
            files={'pkcs12_file': pkcs12_file1}
        )
        assert form1.is_valid()

        # Try to import the same certificate again
        pkcs12_file2 = SimpleUploadedFile(
            'test_ca2.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form2 = ImportCaRolloverForm(
            data={'unique_name': 'second-ca'},
            files={'pkcs12_file': pkcs12_file2}
        )

        assert not form2.is_valid()
        assert any('already configured' in str(error).lower() for errors in form2.errors.values() for error in errors)

    def test_clean_with_provider_configuration_error(self, sample_ca_pkcs12):
        """Test validation handles ProviderConfigurationError gracefully."""
        pkcs12_file = SimpleUploadedFile(
            'test_ca.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        with patch('pki.rollover.import_ca.TrustpointCryptoBackend') as mock_backend:
            mock_backend.return_value.import_managed_private_key.side_effect = ProviderConfigurationError(
                'Imported private keys are disabled.'
            )

            form = ImportCaRolloverForm(
                data={'unique_name': 'test-ca'},
                files={'pkcs12_file': pkcs12_file}
            )

            assert not form.is_valid()
            assert any('disabled' in str(error).lower() for errors in form.errors.values() for error in errors)

    def test_clean_with_transition_scheduled_at(self, sample_ca_pkcs12):
        """Test form accepts transition_scheduled_at field."""
        pkcs12_file = SimpleUploadedFile(
            'test_ca.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        transition_time = datetime.now(dt_timezone.utc) + timedelta(days=7)
        form = ImportCaRolloverForm(
            data={
                'unique_name': 'test-ca',
                'transition_scheduled_at': transition_time.strftime('%Y-%m-%dT%H:%M'),
            },
            files={'pkcs12_file': pkcs12_file}
        )

        assert form.is_valid()

    def test_clean_with_notes(self, sample_ca_pkcs12):
        """Test form accepts notes field."""
        pkcs12_file = SimpleUploadedFile(
            'test_ca.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={
                'unique_name': 'test-ca',
                'notes': 'Test rollover notes',
            },
            files={'pkcs12_file': pkcs12_file}
        )

        assert form.is_valid()
        assert form.cleaned_data['notes'] == 'Test rollover notes'

    def test_new_issuing_ca_property(self, sample_ca_pkcs12):
        """Test new_issuing_ca property returns the created CA."""
        pkcs12_file = SimpleUploadedFile(
            'test_ca.p12',
            sample_ca_pkcs12['pkcs12_data'],
            content_type='application/x-pkcs12'
        )

        form = ImportCaRolloverForm(
            data={'unique_name': 'test-ca'},
            files={'pkcs12_file': pkcs12_file}
        )

        assert form.is_valid()
        ca = form.new_issuing_ca
        assert isinstance(ca, CaModel)
        assert ca.unique_name == 'test-ca'


class TestImportCaRolloverStrategy:
    """Test cases for ImportCaRolloverStrategy."""

    def test_strategy_registered(self):
        """Test that the strategy is registered in the registry."""
        strategy = rollover_registry.get(CaRolloverStrategyType.IMPORT_CA)
        assert isinstance(strategy, ImportCaRolloverStrategy)

    def test_strategy_type(self):
        """Test strategy_type property returns correct value."""
        strategy = ImportCaRolloverStrategy()
        assert strategy.strategy_type == CaRolloverStrategyType.IMPORT_CA

    def test_display_name(self):
        """Test display_name property returns a non-empty string."""
        strategy = ImportCaRolloverStrategy()
        assert isinstance(strategy.display_name, str)
        assert len(strategy.display_name) > 0
        assert 'import' in strategy.display_name.lower()

    def test_get_plan_form(self, issuing_ca_model):
        """Test get_plan_form returns an ImportCaRolloverForm."""
        strategy = ImportCaRolloverStrategy()
        form = strategy.get_plan_form(old_ca=issuing_ca_model)
        assert isinstance(form, ImportCaRolloverForm)

    def test_get_plan_form_with_data(self, issuing_ca_model):
        """Test get_plan_form passes data to the form."""
        strategy = ImportCaRolloverStrategy()
        data = {'unique_name': 'test-ca'}
        form = strategy.get_plan_form(old_ca=issuing_ca_model, data=data)
        assert form.data == data

    def test_create_new_ca(self, issuing_ca_model, second_issuing_ca_model):
        """Test create_new_ca returns the CA from the form."""
        strategy = ImportCaRolloverStrategy()
        form = Mock(spec=ImportCaRolloverForm)
        form.new_issuing_ca = second_issuing_ca_model

        result = strategy.create_new_ca(form, issuing_ca_model)
        assert result == second_issuing_ca_model

    def test_create_new_ca_wrong_form_type(self, issuing_ca_model):
        """Test create_new_ca raises TypeError with wrong form type."""
        strategy = ImportCaRolloverStrategy()
        wrong_form = Mock(spec=forms.Form)

        with pytest.raises(TypeError, match='Expected ImportCaRolloverForm'):
            strategy.create_new_ca(wrong_form, issuing_ca_model)

    def test_on_complete_reassigns_domains(self, issuing_ca_model, second_issuing_ca_model):
        """Test on_complete reassigns domains from old CA to new CA."""
        from pki.models import DomainModel

        # Create a domain assigned to the old CA
        domain = DomainModel.objects.create(
            unique_name='test-domain',
            issuing_ca=issuing_ca_model
        )

        # Create a mock rollover
        rollover = Mock()
        rollover.old_issuing_ca = issuing_ca_model
        rollover.new_issuing_ca = second_issuing_ca_model

        strategy = ImportCaRolloverStrategy()
        strategy.on_complete(rollover)

        # Verify domain was reassigned
        domain.refresh_from_db()
        assert domain.issuing_ca == second_issuing_ca_model

    def test_on_complete_deactivates_old_ca(self, issuing_ca_model, second_issuing_ca_model):
        """Test on_complete deactivates the old CA."""
        rollover = Mock()
        rollover.old_issuing_ca = issuing_ca_model
        rollover.new_issuing_ca = second_issuing_ca_model

        assert issuing_ca_model.is_active is True

        strategy = ImportCaRolloverStrategy()
        strategy.on_complete(rollover)

        issuing_ca_model.refresh_from_db()
        assert issuing_ca_model.is_active is False

    def test_on_complete_with_no_new_ca(self, issuing_ca_model):
        """Test on_complete handles case where new CA is None."""
        rollover = Mock()
        rollover.old_issuing_ca = issuing_ca_model
        rollover.new_issuing_ca = None

        strategy = ImportCaRolloverStrategy()
        strategy.on_complete(rollover)

        issuing_ca_model.refresh_from_db()
        assert issuing_ca_model.is_active is False

    def test_get_template_name(self):
        """Test get_template_name returns the correct template path."""
        strategy = ImportCaRolloverStrategy()
        template_name = strategy.get_template_name()
        assert isinstance(template_name, str)
        assert 'rollover' in template_name
        assert 'import' in template_name
        assert template_name.endswith('.html')
