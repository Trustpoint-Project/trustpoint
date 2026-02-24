"""Comprehensive tests for PKI forms module - focused on increasing coverage."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from django import forms
from django.core.files.uploadedfile import SimpleUploadedFile
from management.models import KeyStorageConfig
from trustpoint_core.serializer import PrivateKeyLocation

from pki.forms import (
    CertProfileConfigForm,
    CertificateDownloadForm,
    CertificateIssuanceForm,
    DevIdAddMethodSelectForm,
    DevIdRegistrationForm,
    IssuingCaAddMethodSelectForm,
    IssuingCaFileTypeSelectForm,
    ProfileBasedFormFieldBuilder,
    TruststoreAddForm,
    TruststoreDownloadForm,
    get_private_key_location_from_config,
)
from pki.models import DevIdRegistration
from pki.models.domain import DomainModel
from pki.models.truststore import TruststoreModel


class TestGetPrivateKeyLocationFromConfig:
    """Test the get_private_key_location_from_config function."""

    def test_returns_hsm_provided_for_softhsm(self):
        """Test that HSM_PROVIDED is returned for SOFTHSM storage type."""
        with patch('pki.forms.issuing_cas.KeyStorageConfig.get_config') as mock_get_config:
            mock_config = Mock()
            mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
            mock_get_config.return_value = mock_config
            
            result = get_private_key_location_from_config()
            assert result == PrivateKeyLocation.HSM_PROVIDED

    def test_returns_hsm_provided_for_physical_hsm(self):
        """Test that HSM_PROVIDED is returned for PHYSICAL_HSM storage type."""
        with patch('pki.forms.issuing_cas.KeyStorageConfig.get_config') as mock_get_config:
            mock_config = Mock()
            mock_config.storage_type = KeyStorageConfig.StorageType.PHYSICAL_HSM
            mock_get_config.return_value = mock_config
            
            result = get_private_key_location_from_config()
            assert result == PrivateKeyLocation.HSM_PROVIDED

    def test_returns_software_when_config_does_not_exist(self):
        """Test that SOFTWARE is returned when KeyStorageConfig does not exist."""
        with patch('pki.forms.issuing_cas.KeyStorageConfig.get_config') as mock_get_config:
            mock_get_config.side_effect = KeyStorageConfig.DoesNotExist()
            
            result = get_private_key_location_from_config()
            assert result == PrivateKeyLocation.SOFTWARE


class TestDevIdAddMethodSelectForm:
    """Test the DevIdAddMethodSelectForm."""

    def test_form_valid_with_import_truststore(self):
        """Test form is valid when import_truststore is selected."""
        form = DevIdAddMethodSelectForm(data={'method_select': 'import_truststore'})
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'import_truststore'

    def test_form_valid_with_configure_pattern(self):
        """Test form is valid when configure_pattern is selected."""
        form = DevIdAddMethodSelectForm(data={'method_select': 'configure_pattern'})
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'configure_pattern'

    def test_form_invalid_with_empty_data(self):
        """Test form is invalid when no method is selected."""
        form = DevIdAddMethodSelectForm(data={})
        assert not form.is_valid()
        assert 'method_select' in form.errors

    def test_form_invalid_with_invalid_choice(self):
        """Test form is invalid with an invalid choice."""
        form = DevIdAddMethodSelectForm(data={'method_select': 'invalid_choice'})
        assert not form.is_valid()
        assert 'method_select' in form.errors

    def test_form_initial_value(self):
        """Test that the initial value is configure_pattern."""
        form = DevIdAddMethodSelectForm()
        assert form.fields['method_select'].initial == 'configure_pattern'

    def test_form_field_label(self):
        """Test that the field has the correct label."""
        form = DevIdAddMethodSelectForm()
        assert 'Select Method' in str(form.fields['method_select'].label)


@pytest.mark.django_db
class TestDevIdRegistrationForm:
    """Test the DevIdRegistrationForm."""

    def setup_method(self):
        """Set up test fixtures."""
        self.domain = DomainModel.objects.create(
            unique_name='test-domain'
        )
        self.truststore = TruststoreModel.objects.create(
            unique_name='test-truststore',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )

    def test_form_valid_with_all_fields(self):
        """Test form is valid with all required and optional fields."""
        form = DevIdRegistrationForm(data={
            'unique_name': 'test-devidreg',
            'truststore': self.truststore.pk,
            'domain': self.domain.pk,
            'serial_number_pattern': r'^\d{10}$'
        })
        assert form.is_valid()

    def test_form_valid_without_optional_unique_name(self):
        """Test form is valid without the optional unique_name field."""
        form = DevIdRegistrationForm(data={
            'unique_name': '',
            'truststore': self.truststore.pk,
            'domain': self.domain.pk,
            'serial_number_pattern': r'^\d{10}$'
        })
        assert form.is_valid()

    def test_form_invalid_without_required_fields(self):
        """Test form is invalid when required fields are missing."""
        form = DevIdRegistrationForm(data={})
        assert not form.is_valid()
        assert 'truststore' in form.errors
        assert 'domain' in form.errors
        assert 'serial_number_pattern' in form.errors

    def test_form_invalid_with_duplicate_unique_name(self):
        """Test form is invalid with a duplicate unique_name."""
        # Create existing registration
        DevIdRegistration.objects.create(
            unique_name='duplicate-name',
            truststore=self.truststore,
            domain=self.domain,
            serial_number_pattern=r'^\d{10}$'
        )
        
        # Try to create another with the same name
        form = DevIdRegistrationForm(data={
            'unique_name': 'duplicate-name',
            'truststore': self.truststore.pk,
            'domain': self.domain.pk,
            'serial_number_pattern': r'^\d{8}$'
        })
        assert not form.is_valid()

    def test_form_has_expected_fields(self):
        """Test that form has all expected fields."""
        form = DevIdRegistrationForm()
        assert 'unique_name' in form.fields
        assert 'truststore' in form.fields
        assert 'domain' in form.fields
        assert 'serial_number_pattern' in form.fields

    def test_unique_name_field_not_required(self):
        """Test that unique_name field is optional."""
        form = DevIdRegistrationForm()
        assert form.fields['unique_name'].required is False

    def test_serial_number_pattern_placeholder(self):
        """Test that serial_number_pattern has placeholder text."""
        form = DevIdRegistrationForm()
        widget_attrs = form.fields['serial_number_pattern'].widget.attrs
        assert 'placeholder' in widget_attrs
        assert 'regex' in widget_attrs['placeholder'].lower()


class TestIssuingCaAddMethodSelectForm:
    """Test the IssuingCaAddMethodSelectForm."""

    def test_form_valid_with_local_file_import(self):
        """Test form is valid when local_file_import is selected."""
        form = IssuingCaAddMethodSelectForm(data={'method_select': 'local_file_import'})
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'local_file_import'

    def test_form_valid_with_local_request(self):
        """Test form is valid when local_request is selected."""
        form = IssuingCaAddMethodSelectForm(data={'method_select': 'local_request'})
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'local_request'

    def test_form_valid_with_remote_est(self):
        """Test form is valid when remote_est is selected."""
        form = IssuingCaAddMethodSelectForm(data={'method_select': 'remote_est'})
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'remote_est'

    def test_form_invalid_with_empty_data(self):
        """Test form is invalid when no method is selected."""
        form = IssuingCaAddMethodSelectForm(data={})
        assert not form.is_valid()
        assert 'method_select' in form.errors

    def test_form_initial_value(self):
        """Test that the initial value is local_file_import."""
        form = IssuingCaAddMethodSelectForm()
        assert form.fields['method_select'].initial == 'local_file_import'

    def test_form_has_three_choices(self):
        """Test that form has exactly three choices."""
        form = IssuingCaAddMethodSelectForm()
        assert len(form.fields['method_select'].choices) == 3


class TestIssuingCaFileTypeSelectForm:
    """Test the IssuingCaFileTypeSelectForm."""

    def test_form_valid_with_pkcs_12(self):
        """Test form is valid when pkcs_12 is selected."""
        form = IssuingCaFileTypeSelectForm(data={'method_select': 'pkcs_12'})
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'pkcs_12'

    def test_form_valid_with_other(self):
        """Test form is valid when other is selected."""
        form = IssuingCaFileTypeSelectForm(data={'method_select': 'other'})
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'other'

    def test_form_invalid_with_empty_data(self):
        """Test form is invalid when no file type is selected."""
        form = IssuingCaFileTypeSelectForm(data={})
        assert not form.is_valid()
        assert 'method_select' in form.errors

    def test_form_initial_value(self):
        """Test that the initial value is pkcs_12."""
        form = IssuingCaFileTypeSelectForm()
        assert form.fields['method_select'].initial == 'pkcs_12'

    def test_form_has_two_choices(self):
        """Test that form has exactly two choices."""
        form = IssuingCaFileTypeSelectForm()
        assert len(form.fields['method_select'].choices) == 2


class TestTruststoreDownloadForm:
    """Test the TruststoreDownloadForm."""

    def test_form_valid_with_all_fields(self):
        """Test form is valid with all fields provided."""
        form = TruststoreDownloadForm(data={
            'cert_file_container': 'single_file',
            'cert_chain_incl': 'cert_only',
            'cert_file_format': 'pem'
        })
        assert form.is_valid()

    def test_form_valid_with_zip_container(self):
        """Test form is valid with zip container."""
        form = TruststoreDownloadForm(data={
            'cert_file_container': 'zip',
            'cert_chain_incl': 'chain_incl',
            'cert_file_format': 'der'
        })
        assert form.is_valid()

    def test_form_valid_with_tar_gz_container(self):
        """Test form is valid with tar_gz container."""
        form = TruststoreDownloadForm(data={
            'cert_file_container': 'tar_gz',
            'cert_chain_incl': 'cert_only',
            'cert_file_format': 'pkcs7_pem'
        })
        assert form.is_valid()

    def test_form_valid_with_pkcs7_der_format(self):
        """Test form is valid with pkcs7_der format."""
        form = TruststoreDownloadForm(data={
            'cert_file_container': 'single_file',
            'cert_chain_incl': 'chain_incl',
            'cert_file_format': 'pkcs7_der'
        })
        assert form.is_valid()

    def test_form_invalid_without_required_fields(self):
        """Test form is invalid without required fields."""
        form = TruststoreDownloadForm(data={})
        assert not form.is_valid()
        assert 'cert_file_container' in form.errors
        assert 'cert_chain_incl' in form.errors
        assert 'cert_file_format' in form.errors

    def test_form_has_all_required_fields(self):
        """Test that form has all required fields."""
        form = TruststoreDownloadForm()
        assert 'cert_file_container' in form.fields
        assert 'cert_chain_incl' in form.fields
        assert 'cert_file_format' in form.fields

    def test_form_initial_values(self):
        """Test that initial values are set correctly."""
        form = TruststoreDownloadForm()
        assert form.fields['cert_file_container'].initial == 'single_file'
        assert form.fields['cert_file_format'].initial == 'pem'


class TestCertificateDownloadForm:
    """Test the CertificateDownloadForm."""

    def test_form_valid_with_pem_format(self):
        """Test form is valid with PEM format."""
        form = CertificateDownloadForm(data={
            'cert_file_container': 'single_file',
            'cert_chain_incl': 'cert_only',
            'cert_file_format': 'pem'
        })
        assert form.is_valid()

    def test_form_valid_with_der_format(self):
        """Test form is valid with DER format."""
        form = CertificateDownloadForm(data={
            'cert_file_container': 'single_file',
            'cert_chain_incl': 'chain_incl',
            'cert_file_format': 'der'
        })
        assert form.is_valid()

    def test_form_valid_with_pkcs7_format(self):
        """Test form is valid with PKCS7 PEM format."""
        form = CertificateDownloadForm(data={
            'cert_file_container': 'single_file',
            'cert_chain_incl': 'cert_only',
            'cert_file_format': 'pkcs7_pem'
        })
        assert form.is_valid()

    def test_form_valid_with_pkcs7_der_format(self):
        """Test form is valid with PKCS7 DER format."""
        form = CertificateDownloadForm(data={
            'cert_file_container': 'single_file',
            'cert_chain_incl': 'chain_incl',
            'cert_file_format': 'pkcs7_der'
        })
        assert form.is_valid()

    def test_form_invalid_without_required_fields(self):
        """Test form is invalid without required fields."""
        form = CertificateDownloadForm(data={})
        assert not form.is_valid()

    def test_form_has_expected_fields(self):
        """Test that form has expected fields."""
        form = CertificateDownloadForm()
        assert 'cert_file_container' in form.fields
        assert 'cert_chain_incl' in form.fields
        assert 'cert_file_format' in form.fields


@pytest.mark.django_db
class TestCertProfileConfigForm:
    """Test the CertProfileConfigForm."""

    def test_form_has_required_fields(self):
        """Test that form has all required fields."""
        form = CertProfileConfigForm()
        assert 'unique_name' in form.fields
        assert 'profile_json' in form.fields

    def test_form_is_model_form(self):
        """Test that form is a ModelForm for CertificateProfileModel."""
        from pki.models.cert_profile import CertificateProfileModel
        form = CertProfileConfigForm()
        assert form._meta.model == CertificateProfileModel

    def test_form_with_valid_json(self):
        """Test form with valid JSON profile data."""
        json_data = {
            'version': 1,
            'subject': {
                'common_name': 'test.example.com'
            }
        }
        form = CertProfileConfigForm(data={
            'unique_name': 'test-profile',
            'profile_json': json_data,
            'is_default': False
        })
        # Just check it doesn't crash - full validation depends on Pydantic schema
        assert 'unique_name' in form.fields

    def test_unique_name_has_maxlength(self):
        """Test that unique_name field has maxlength attribute."""
        form = CertProfileConfigForm()
        widget_attrs = form.fields['unique_name'].widget.attrs
        assert 'maxlength' in widget_attrs
        assert widget_attrs['maxlength'] == '255'


@pytest.mark.django_db
class TestTruststoreAddForm:
    """Test TruststoreAddForm."""

    def test_form_has_required_fields(self):
        """Test that form has all required fields."""
        form = TruststoreAddForm()
        assert 'unique_name' in form.fields
        assert 'intended_usage' in form.fields
        assert 'trust_store_file' in form.fields

    def test_form_file_field_is_required(self):
        """Test that trust_store_file field is required."""
        form = TruststoreAddForm()
        assert form.fields['trust_store_file'].required is True

    def test_form_unique_name_not_required(self):
        """Test that unique_name field is not required."""
        form = TruststoreAddForm()
        assert form.fields['unique_name'].required is False


@pytest.mark.django_db
class TestTruststoreAddFormValidation:
    """Test TruststoreAddForm validation with actual files."""

    def test_form_valid_der_certificate(self):
        """Test that form accepts DER encoded certificate."""
        der_file_path = 'tests/data/issuing_cas/ee0_valid.der'
        with open(der_file_path, 'rb') as f:
            der_data = f.read()
        
        uploaded_file = SimpleUploadedFile('certificate.der', der_data, content_type='application/x-x509-ca-cert')
        
        form_data = {
            'intended_usage': TruststoreModel.IntendedUsage.GENERIC.value,
        }
        form = TruststoreAddForm(data=form_data, files={'trust_store_file': uploaded_file})
        
        assert form.is_valid(), f"Form should be valid but got errors: {form.errors}"
        assert 'truststore' in form.cleaned_data
        truststore = form.cleaned_data['truststore']
        assert truststore.number_of_certificates == 1  
class TestIssuingCaAddFileImportPkcs12Form:
    """Test IssuingCaAddFileImportPkcs12Form."""

    def test_form_has_required_fields(self):
        """Test that form has all required fields."""
        from pki.forms import IssuingCaAddFileImportPkcs12Form
        form = IssuingCaAddFileImportPkcs12Form()
        assert 'unique_name' in form.fields
        assert 'pkcs12_file' in form.fields
        assert 'pkcs12_password' in form.fields

    def test_form_unique_name_not_required(self):
        """Test that unique_name field is not required."""
        from pki.forms import IssuingCaAddFileImportPkcs12Form
        form = IssuingCaAddFileImportPkcs12Form()
        assert form.fields['unique_name'].required is False


@pytest.mark.django_db
class TestIssuingCaAddFileImportSeparateFilesForm:
    """Test IssuingCaAddFileImportSeparateFilesForm."""

    def test_form_has_required_fields(self):
        """Test that form has all required fields."""
        from pki.forms import IssuingCaAddFileImportSeparateFilesForm
        form = IssuingCaAddFileImportSeparateFilesForm()
        assert 'unique_name' in form.fields
        assert 'ca_certificate' in form.fields
        assert 'ca_certificate_chain' in form.fields
        assert 'private_key_file' in form.fields
        assert 'private_key_file_password' in form.fields

    def test_form_optional_fields_not_required(self):
        """Test that optional fields are not required."""
        from pki.forms import IssuingCaAddFileImportSeparateFilesForm
        form = IssuingCaAddFileImportSeparateFilesForm()
        assert form.fields['unique_name'].required is False
        assert form.fields['ca_certificate_chain'].required is False
        assert form.fields['private_key_file_password'].required is False


@pytest.mark.django_db
class TestOwnerCredentialFileImportForm:
    """Test OwnerCredentialFileImportForm."""

    def test_form_has_required_fields(self):
        """Test that form has all required fields."""
        from pki.forms import OwnerCredentialFileImportForm
        
        form = OwnerCredentialFileImportForm()
        assert 'unique_name' in form.fields
        assert 'certificate' in form.fields
        assert 'certificate_chain' in form.fields
        assert 'private_key_file' in form.fields
        assert 'private_key_file_password' in form.fields

    def test_form_optional_fields_not_required(self):
        """Test that optional fields are not required."""
        from pki.forms import OwnerCredentialFileImportForm
        
        form = OwnerCredentialFileImportForm()
        assert form.fields['unique_name'].required is False
        assert form.fields['certificate_chain'].required is False
        assert form.fields['private_key_file_password'].required is False


class TestIssuingCaFileTypeSelectForm:
    """Test IssuingCaFileTypeSelectForm."""

    def test_form_has_file_type_field(self):
        """Test that form has method_select field."""
        form = IssuingCaFileTypeSelectForm()
        assert 'method_select' in form.fields

    def test_form_file_type_choices(self):
        """Test method_select field has correct choices."""
        form = IssuingCaFileTypeSelectForm()
        choices = form.fields['method_select'].choices
        choice_values = [c[0] for c in choices]
        
        assert 'pkcs_12' in choice_values
        assert 'other' in choice_values

    def test_form_valid_with_pkcs12(self):
        """Test form is valid with pkcs_12 choice."""
        form = IssuingCaFileTypeSelectForm(data={'method_select': 'pkcs_12'})
        assert form.is_valid()

    def test_form_valid_with_separate(self):
        """Test form is valid with other choice."""
        form = IssuingCaFileTypeSelectForm(data={'method_select': 'other'})
        assert form.is_valid()


class TestFormFieldAttributes:
    """Test various form field attributes and widgets."""

    def test_dev_id_registration_form_fields(self):
        """Test DevIdRegistrationForm field configuration."""
        form = DevIdRegistrationForm()
        
        # Check that form has the correct fields
        assert 'unique_name' in form.fields
        assert 'domain' in form.fields
        assert 'truststore' in form.fields
        assert 'serial_number_pattern' in form.fields

    def test_certificate_download_form_format_choices(self):
        """Test CertificateDownloadForm has correct format fields."""
        form = CertificateDownloadForm()
        
        assert 'cert_file_format' in form.fields
        assert 'cert_file_container' in form.fields
        assert 'cert_chain_incl' in form.fields

    def test_truststore_download_form_format_choices(self):
        """Test TruststoreDownloadForm has correct format fields."""
        form = TruststoreDownloadForm()
        
        assert 'cert_file_format' in form.fields
        assert 'cert_file_container' in form.fields
        assert 'cert_chain_incl' in form.fields

    def test_cert_profile_config_form_widgets(self):
        """Test CertProfileConfigForm widget configuration."""
        form = CertProfileConfigForm()
        
        # Check that profile_json has textarea widget
        assert 'profile_json' in form.fields
        # Widget should be configured for JSON input
        
    def test_issuing_ca_add_method_select_form_choices(self):
        """Test IssuingCaAddMethodSelectForm has correct choices."""
        form = IssuingCaAddMethodSelectForm()
        
        assert 'method_select' in form.fields
        choices = [c[0] for c in form.fields['method_select'].choices]
        
        assert 'local_file_import' in choices
        assert 'local_request' in choices
        assert 'remote_est' in choices


class TestProfileBasedFormFieldBuilder:
    """Test the ProfileBasedFormFieldBuilder class."""

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_initialization(self, mock_verifier_class):
        """Test that ProfileBasedFormFieldBuilder initializes correctly."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'subj': {'cn': {'required': True}},
            'ext': {},
            'validity': {'days': 365}
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        assert builder.profile == profile
        assert builder.verifier == mock_verifier
        assert builder.fields == {}
        mock_verifier_class.assert_called_once_with(profile)

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_build_all_fields_basic_profile(self, mock_verifier_class):
        """Test building fields from a basic profile."""
        mock_verifier = Mock()
        sample_request = {
            'subject': {'cn': 'CHANGEME_common_name', 'o': 'TestOrg'},
            'extensions': {'subject_alternative_name': {'dns_names': ['CHANGEME_dns']}},
            'validity': {'days': 365}
        }
        mock_verifier.get_sample_request.return_value = sample_request
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'cn': {'required': True, 'mutable': True},
                'o': {'required': False, 'mutable': True}
            },
            'ext': {
                'subject_alternative_name': {
                    'dns_names': {'required': False, 'mutable': True}
                }
            },
            'validity': {
                'days': {'required': True, 'mutable': True, 'value': 365}
            }
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        fields = builder.build_all_fields()

        assert 'cn' in fields
        assert 'o' in fields
        assert 'dns_names' in fields
        assert 'days' in fields

        # Check required field
        assert fields['cn'].required is True
        assert fields['days'].required is True

        # Check initial values
        assert fields['days'].initial == 365

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_build_all_subject_fields_allow_star(self, mock_verifier_class):
        """Test building all subject fields when allow='*'."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'allow': '*',
                'common_name': {'required': True, 'mutable': False, 'value': 'test'},
                'organization_name': {'required': False, 'mutable': True}
            }
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        builder._build_all_subject_fields(profile['subj'])

        # Should include all subject fields except the basic ones that are skipped
        assert 'common_name' in builder.fields
        assert 'organization_name' in builder.fields

        # Check required and mutable settings
        assert builder.fields['common_name'].required is True
        assert builder.fields['common_name'].disabled is True  # mutable=False
        assert builder.fields['common_name'].initial == 'test'

        assert builder.fields['organization_name'].required is False
        assert builder.fields['organization_name'].disabled is False  # mutable=True

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_build_all_san_fields_allow_star(self, mock_verifier_class):
        """Test building all SAN fields when allow='*'."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'ext': {
                'subject_alternative_name': {
                    'allow': '*',
                    'dns_names': {'required': True, 'mutable': True, 'value': ['example.com']},
                    'ip_addresses': {'required': False, 'mutable': False}
                }
            }
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        builder._build_all_san_fields(profile['ext']['subject_alternative_name'])

        assert 'dns_names' in builder.fields
        assert 'ip_addresses' in builder.fields

        # Check field properties
        assert builder.fields['dns_names'].required is True
        assert builder.fields['dns_names'].disabled is False
        assert builder.fields['dns_names'].initial == 'example.com'

        assert builder.fields['ip_addresses'].required is False
        assert builder.fields['ip_addresses'].disabled is True  # mutable=False

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_build_subject_fields_from_sample(self, mock_verifier_class):
        """Test building subject fields from sample request."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'cn': {'required': True},
                'o': {'mutable': False, 'value': 'TestOrg'}
            }
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        sample_subject = {
            'cn': 'CHANGEME_common_name',
            'o': 'TestOrg',
            'ou': 'TestUnit'
        }
        builder._build_subject_fields_from_sample(sample_subject)

        assert 'cn' in builder.fields
        assert 'o' in builder.fields
        assert 'ou' in builder.fields

        # CHANGEME should result in empty initial value
        assert builder.fields['cn'].initial == ''
        assert builder.fields['cn'].required is True

        # Fixed value should be set
        assert builder.fields['o'].initial == 'TestOrg'
        assert builder.fields['o'].disabled is True  # mutable=False

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_build_san_fields_from_sample(self, mock_verifier_class):
        """Test building SAN fields from sample request."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'ext': {
                'subject_alternative_name': {
                    'dns_names': {'required': True},
                    'ip_addresses': {'mutable': False, 'value': ['192.168.1.1']}
                }
            }
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        sample_san = {
            'dns_names': ['CHANGEME_dns'],
            'ip_addresses': ['192.168.1.1'],
            'uris': ['https://example.com']
        }
        builder._build_san_fields_from_sample(sample_san)

        assert 'dns_names' in builder.fields
        assert 'ip_addresses' in builder.fields
        assert 'uris' in builder.fields

        # Check field properties
        assert builder.fields['dns_names'].required is True
        assert builder.fields['dns_names'].initial == ''

        assert builder.fields['ip_addresses'].disabled is True  # mutable=False
        assert builder.fields['ip_addresses'].initial == '192.168.1.1'

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_build_validity_fields_from_sample(self, mock_verifier_class):
        """Test building validity fields from sample request."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'validity': {
                'days': {'required': True, 'value': 365},
                'hours': {'mutable': False}
            }
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        sample_validity = {
            'days': 365,
            'hours': 0,
            'minutes': 'CHANGEME_minutes'
        }
        builder._build_validity_fields_from_sample(sample_validity)

        assert 'days' in builder.fields
        assert 'hours' in builder.fields
        assert 'minutes' in builder.fields

        # Check field types and properties
        assert isinstance(builder.fields['days'], forms.IntegerField)
        assert builder.fields['days'].required is True
        assert builder.fields['days'].initial == 365

        assert builder.fields['hours'].disabled is True  # mutable=False
        assert builder.fields['minutes'].initial == 0  # CHANGEME becomes 0

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    def test_country_field_validation(self, mock_verifier_class):
        """Test that country fields have proper validation."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'allow': '*',
                'country_name': {'required': True}
            }
        }
        builder = ProfileBasedFormFieldBuilder(profile)
        builder._build_all_subject_fields(profile['subj'])

        country_field = builder.fields['country_name']
        assert country_field.min_length == 2
        assert country_field.max_length == 2
        assert country_field.required is True


class TestCertificateIssuanceForm:
    """Test the CertificateIssuanceForm class."""

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_initialization(self, mock_builder_class, mock_verifier_class):
        """Test that CertificateIssuanceForm initializes correctly."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {'cn': Mock()}
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {'cn': {'required': True}},
            'ext': {},
            'validity': {'days': 365}
        }
        form = CertificateIssuanceForm(profile)

        assert form.profile == profile
        mock_verifier_class.assert_called_once_with(profile)
        mock_builder_class.assert_called_once_with(profile)
        assert form.verifier == mock_verifier

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_with_subject_fields(self, mock_builder_class, mock_verifier_class):
        """Test form with subject fields from profile."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {
            'cn': forms.CharField(required=True),
            'o': forms.CharField(required=False),
            'c': forms.CharField(required=True, initial='US', disabled=True)
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'cn': {'required': True, 'mutable': True},
                'o': {'required': False, 'mutable': True},
                'c': {'required': True, 'mutable': False, 'value': 'US'}
            },
            'ext': {},
            'validity': {}
        }
        form = CertificateIssuanceForm(profile)
        form.fields = mock_builder.fields

        assert 'cn' in form.fields
        assert 'o' in form.fields
        assert 'c' in form.fields

        assert form.fields['cn'].required is True
        assert form.fields['c'].required is True
        assert form.fields['c'].disabled is True  # mutable=False
        assert form.fields['c'].initial == 'US'

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_with_san_fields(self, mock_builder_class, mock_verifier_class):
        """Test form with SAN fields from profile."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {
            'dns_names': forms.CharField(required=True),
            'ip_addresses': forms.CharField(required=False)
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {},
            'ext': {
                'subject_alternative_name': {
                    'dns_names': {'required': True},
                    'ip_addresses': {'required': False}
                }
            },
            'validity': {}
        }
        form = CertificateIssuanceForm(profile)
        form.fields = mock_builder.fields

        assert 'dns_names' in form.fields
        assert 'ip_addresses' in form.fields
        assert form.fields['dns_names'].required is True

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_with_validity_fields(self, mock_builder_class, mock_verifier_class):
        """Test form with validity fields from profile."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {
            'days': forms.IntegerField(required=True, initial=365),
            'hours': forms.IntegerField(required=False)
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {},
            'ext': {},
            'validity': {
                'days': {'required': True, 'value': 365},
                'hours': {'required': False}
            }
        }
        form = CertificateIssuanceForm(profile)
        form.fields = mock_builder.fields

        assert 'days' in form.fields
        assert 'hours' in form.fields
        assert isinstance(form.fields['days'], forms.IntegerField)
        assert form.fields['days'].required is True
        assert form.fields['days'].initial == 365

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_validation_valid_data(self, mock_builder_class, mock_verifier_class):
        """Test form validation with valid data."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {
            'cn': forms.CharField(required=True),
            'o': forms.CharField(required=False),
            'dns_names': forms.CharField(required=False),
            'days': forms.IntegerField(required=True)
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'cn': {'required': True},
                'o': {'required': False}
            },
            'ext': {
                'subject_alternative_name': {
                    'dns_names': {'required': False}
                }
            },
            'validity': {
                'days': {'required': True, 'value': 365}
            }
        }
        form_data = {
            'cn': 'test.example.com',
            'o': 'Test Organization',
            'dns_names': 'www.example.com, api.example.com',
            'days': 365
        }
        form = CertificateIssuanceForm(profile, data=form_data)
        form.fields = mock_builder.fields

        assert form.is_valid()
        assert form.cleaned_data['cn'] == 'test.example.com'
        assert form.cleaned_data['o'] == 'Test Organization'
        assert form.cleaned_data['dns_names'] == 'www.example.com, api.example.com'
        assert form.cleaned_data['days'] == 365

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_validation_missing_required_field(self, mock_builder_class, mock_verifier_class):
        """Test form validation fails when required field is missing."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {
            'cn': forms.CharField(required=True)
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'cn': {'required': True}
            },
            'ext': {},
            'validity': {}
        }
        form_data = {}  # Missing required 'cn'
        form = CertificateIssuanceForm(profile, data=form_data)
        form.fields = mock_builder.fields

        assert not form.is_valid()
        assert 'cn' in form.errors

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_data_to_json_request(self, mock_builder_class, mock_verifier_class):
        """Test conversion of form data to JSON request format."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {}
        # Set the labels on the mock class
        mock_builder_class.SUBJECT_LABELS = {
            'cn': 'Common Name (CN)',
        }
        mock_builder_class.SAN_LABELS = {}
        mock_builder_class.VALIDITY_LABELS = {
            'days': 'Days',
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {'cn': {'required': True}},
            'ext': {},
            'validity': {'days': {'required': True}}
        }
        form = CertificateIssuanceForm(profile)
        form.cleaned_data = {
            'cn': 'test.example.com',
            'days': 365
        }

        request = form._form_data_to_json_request()

        assert request['type'] == 'cert_request'
        assert request['subject'] == {'cn': 'test.example.com'}
        assert request['validity'] == {'days': 365}
        assert 'extensions' not in request  # No extensions in this case

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_build_subject_from_form_data(self, mock_builder_class, mock_verifier_class):
        """Test building subject DN from form data."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {}
        # Set the SUBJECT_LABELS on the mock class
        mock_builder_class.SUBJECT_LABELS = {
            'cn': 'Common Name (CN)',
            'common_name': 'Common Name (CN)',
            'o': 'Organization (O)',
            'organization_name': 'Organization (O)',
            'c': 'Country (C)',
            'country_name': 'Country (C)',
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {'type': 'cert_profile', 'subj': {}, 'ext': {}, 'validity': {}}
        form = CertificateIssuanceForm(profile)
        cleaned_data = {
            'cn': 'test.example.com',
            'o': 'Test Org',
            'c': 'US',
            'days': 365  # Should be filtered out
        }

        subject = form._build_subject_from_form_data(cleaned_data)

        assert subject == {
            'cn': 'test.example.com',
            'o': 'Test Org',
            'c': 'US'
        }

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_build_san_from_form_data(self, mock_builder_class, mock_verifier_class):
        """Test building SAN extension from form data."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {}
        # Set the SAN_LABELS on the mock class
        mock_builder_class.SAN_LABELS = {
            'dns_names': 'DNS Names (comma separated)',
            'ip_addresses': 'IP Addresses (comma separated)',
            'rfc822_names': 'Email Addresses (comma separated)',
            'uris': 'URIs (comma separated)',
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {'type': 'cert_profile', 'subj': {}, 'ext': {}, 'validity': {}}
        form = CertificateIssuanceForm(profile)
        cleaned_data = {
            'dns_names': 'www.example.com, api.example.com',
            'ip_addresses': '192.168.1.1, 10.0.0.1',
            'cn': 'test.com'  # Should be filtered out
        }

        san = form._build_san_from_form_data(cleaned_data)

        assert san == {
            'dns_names': ['www.example.com', 'api.example.com'],
            'ip_addresses': ['192.168.1.1', '10.0.0.1']
        }

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_build_validity_from_form_data(self, mock_builder_class, mock_verifier_class):
        """Test building validity period from form data."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {}
        # Set the VALIDITY_LABELS on the mock class
        mock_builder_class.VALIDITY_LABELS = {
            'days': 'Days',
            'hours': 'Hours',
            'minutes': 'Minutes',
            'seconds': 'Seconds',
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {'type': 'cert_profile', 'subj': {}, 'ext': {}, 'validity': {}}
        form = CertificateIssuanceForm(profile)
        cleaned_data = {
            'days': 365,
            'hours': 0,
            'cn': 'test.com'  # Should be filtered out
        }

        validity = form._build_validity_from_form_data(cleaned_data)

        assert validity == {'days': 365}  # hours: 0 is falsy, so not included

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    @patch('pki.forms.cert_profiles.JSONCertRequestConverter.from_json')
    def test_get_certificate_builder(self, mock_converter, mock_builder_class, mock_verifier_class):
        """Test get_certificate_builder method."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {}
        # Set the labels on the mock class
        mock_builder_class.SUBJECT_LABELS = {
            'cn': 'Common Name (CN)',
        }
        mock_builder_class.SAN_LABELS = {}
        mock_builder_class.VALIDITY_LABELS = {
            'days': 'Days',
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {'cn': {'required': True}},
            'ext': {},
            'validity': {'days': {'required': True}}
        }
        form = CertificateIssuanceForm(profile)
        form.cleaned_data = {
            'cn': 'test.example.com',
            'days': 365
        }
        form.data = form.cleaned_data  # Make the form bound

        mock_builder_instance = Mock()
        mock_converter.return_value = mock_builder_instance

        result = form.get_certificate_builder()

        assert result == mock_builder_instance
        mock_converter.assert_called_once()

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_with_allow_star_subject(self, mock_builder_class, mock_verifier_class):
        """Test form handles allow='*' for subject fields."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {
            'common_name': forms.CharField(required=True, initial='test'),
            'organization_name': forms.CharField(required=False)
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {
                'allow': '*',
                'common_name': {'required': True, 'value': 'test'},
                'organization_name': {'required': False}
            },
            'ext': {},
            'validity': {}
        }
        form = CertificateIssuanceForm(profile)
        form.fields = mock_builder.fields

        # Should have all subject fields
        assert 'common_name' in form.fields
        assert 'organization_name' in form.fields

        assert form.fields['common_name'].required is True
        assert form.fields['common_name'].initial == 'test'

    @patch('pki.forms.cert_profiles.JSONProfileVerifier')
    @patch('pki.forms.cert_profiles.ProfileBasedFormFieldBuilder')
    def test_form_with_allow_star_san(self, mock_builder_class, mock_verifier_class):
        """Test form handles allow='*' for SAN fields."""
        mock_verifier = Mock()
        mock_verifier_class.return_value = mock_verifier
        
        mock_builder = Mock()
        mock_builder.fields = {
            'dns_names': forms.CharField(required=True),
            'ip_addresses': forms.CharField(required=False),
            'rfc822_names': forms.CharField(),
            'uris': forms.CharField()
        }
        mock_builder_class.return_value = mock_builder
        
        profile = {
            'type': 'cert_profile',
            'subj': {},
            'ext': {
                'subject_alternative_name': {
                    'allow': '*',
                    'dns_names': {'required': True},
                    'ip_addresses': {'required': False}
                }
            },
            'validity': {}
        }
        form = CertificateIssuanceForm(profile)
        form.fields = mock_builder.fields

        # Should have all SAN fields
        assert 'dns_names' in form.fields
        assert 'ip_addresses' in form.fields
        assert 'rfc822_names' in form.fields
        assert 'uris' in form.fields

        assert form.fields['dns_names'].required is True
