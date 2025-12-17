"""Tests for pki.serializer.truststore module."""

from __future__ import annotations

import pytest
from io import BytesIO
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from pki.models.truststore import TruststoreModel
from pki.serializer.truststore import TruststoreSerializer


@pytest.mark.django_db
class TestTruststoreSerializer:
    """Test the TruststoreSerializer class."""

    def create_test_pem_data(self) -> bytes:
        """Create mock PEM certificate data."""
        return b"""-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8RfFNKUxDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJE
-----END CERTIFICATE-----"""

    def test_validate_trust_store_file_valid_pem(self):
        """Test validation accepts valid PEM file."""
        file_data = self.create_test_pem_data()
        uploaded_file = SimpleUploadedFile('truststore.pem', file_data, content_type='application/x-pem-file')
        
        serializer = TruststoreSerializer()
        result = serializer.validate_trust_store_file(uploaded_file)
        
        assert result == file_data

    def test_validate_trust_store_file_valid_p7b(self):
        """Test validation accepts .p7b file."""
        file_data = self.create_test_pem_data()
        uploaded_file = SimpleUploadedFile('truststore.p7b', file_data, content_type='application/pkcs7-mime')
        
        serializer = TruststoreSerializer()
        result = serializer.validate_trust_store_file(uploaded_file)
        
        assert result == file_data

    def test_validate_trust_store_file_valid_p7c(self):
        """Test validation accepts .p7c file."""
        file_data = self.create_test_pem_data()
        uploaded_file = SimpleUploadedFile('truststore.p7c', file_data, content_type='application/pkcs7-mime')
        
        serializer = TruststoreSerializer()
        result = serializer.validate_trust_store_file(uploaded_file)
        
        assert result == file_data

    def test_validate_trust_store_file_invalid_extension(self):
        """Test validation rejects invalid file extension."""
        file_data = self.create_test_pem_data()
        uploaded_file = SimpleUploadedFile('truststore.txt', file_data, content_type='text/plain')
        
        serializer = TruststoreSerializer()
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_trust_store_file(uploaded_file)
        
        assert 'PEM or PKCS#7 format' in str(exc_info.value)

    def test_validate_trust_store_file_no_file(self):
        """Test validation rejects missing file."""
        serializer = TruststoreSerializer()
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_trust_store_file(None)
        
        assert 'required' in str(exc_info.value)

    def test_validate_trust_store_file_empty_filename(self):
        """Test validation rejects file with empty name."""
        # Create a file object that simulates empty filename
        class MockFile:
            name = ''
            
            def read(self):
                return b'data'
        
        serializer = TruststoreSerializer()
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_trust_store_file(MockFile())
        
        assert 'required' in str(exc_info.value)

    def test_validate_trust_store_file_case_insensitive_extension(self):
        """Test validation accepts uppercase file extensions."""
        file_data = self.create_test_pem_data()
        uploaded_file = SimpleUploadedFile('truststore.PEM', file_data, content_type='application/x-pem-file')
        
        serializer = TruststoreSerializer()
        result = serializer.validate_trust_store_file(uploaded_file)
        
        assert result == file_data

    def test_serializer_fields(self):
        """Test that serializer has correct fields defined."""
        serializer = TruststoreSerializer()
        
        assert 'unique_name' in serializer.fields
        assert 'intended_usage' in serializer.fields
        assert 'trust_store_file' in serializer.fields
        assert 'id' in serializer.fields
        assert 'created_at' in serializer.fields

    def test_serializer_read_only_fields(self):
        """Test that id is read-only."""
        serializer = TruststoreSerializer()
        
        assert serializer.fields['id'].read_only is True

    def test_serializer_write_only_fields(self):
        """Test that trust_store_file is write-only."""
        serializer = TruststoreSerializer()
        
        assert serializer.fields['trust_store_file'].write_only is True

    def test_unique_name_not_required(self):
        """Test that unique_name field is not required."""
        serializer = TruststoreSerializer()
        
        assert serializer.fields['unique_name'].required is False
        assert serializer.fields['unique_name'].allow_blank is True

    def test_intended_usage_required(self):
        """Test that intended_usage field is required."""
        serializer = TruststoreSerializer()
        
        assert serializer.fields['intended_usage'].required is True

    def test_intended_usage_choices(self):
        """Test that intended_usage has correct choices."""
        serializer = TruststoreSerializer()
        
        field = serializer.fields['intended_usage']
        # field.choices is an OrderedDict, so just check the keys match
        assert list(field.choices.keys()) == [choice[0] for choice in TruststoreModel.IntendedUsage.choices]

    def test_serializer_model_meta(self):
        """Test that serializer Meta specifies correct model."""
        assert TruststoreSerializer.Meta.model == TruststoreModel


class TestTruststoreSerializerIntegration:
    """Integration tests for TruststoreSerializer with database."""

    def create_test_pem_data(self) -> bytes:
        """Create mock PEM certificate data."""
        return b"""-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8RfFNKUxDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJE
-----END CERTIFICATE-----"""

    @pytest.mark.django_db
    def test_serialize_existing_truststore(self):
        """Test serializing an existing truststore model."""
        truststore = TruststoreModel.objects.create(
            unique_name='test-truststore',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )
        
        serializer = TruststoreSerializer(truststore)
        data = serializer.data
        
        assert data['unique_name'] == 'test-truststore'
        assert data['intended_usage'] == TruststoreModel.IntendedUsage.IDEVID
        assert 'id' in data
        assert 'created_at' in data
        # trust_store_file should not be in serialized data (write-only)
        assert 'trust_store_file' not in data

    @pytest.mark.django_db
    def test_serialize_multiple_truststores(self):
        """Test serializing multiple truststore instances."""
        TruststoreModel.objects.create(
            unique_name='truststore-1',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )
        TruststoreModel.objects.create(
            unique_name='truststore-2',
            intended_usage=TruststoreModel.IntendedUsage.TLS
        )
        
        truststores = TruststoreModel.objects.all()
        serializer = TruststoreSerializer(truststores, many=True)
        data = serializer.data
        
        assert len(data) == 2
        assert any(t['unique_name'] == 'truststore-1' for t in data)
        assert any(t['unique_name'] == 'truststore-2' for t in data)
