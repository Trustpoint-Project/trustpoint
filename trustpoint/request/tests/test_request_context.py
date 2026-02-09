"""Unit tests for the BaseRequestContext class."""

from dataclasses import fields
from unittest.mock import Mock

from cryptography import x509
from cryptography.x509 import CertificateSigningRequest
from devices.models import DeviceModel
from django.http import HttpRequest
from pki.models import DomainModel
from pyasn1_modules.rfc4210 import PKIMessage

from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext, HttpBaseRequestContext


class TestRequestContext:
    """Test cases for the BaseRequestContext class."""

    def test_init_with_defaults(self):
        """Test that BaseRequestContext initializes with all None values by default."""
        context = BaseRequestContext()

        # Check that all fields are initialized to None
        for field in fields(context):
            assert getattr(context, field.name) is None

    def test_init_with_values(self):
        """Test that BaseRequestContext can be initialized with specific values."""
        domain_str = 'example.com'
        operation = 'certificate_request'
        protocol = 'est'

        context = BaseRequestContext(
            domain_str=domain_str,
            operation=operation,
            protocol=protocol
        )

        assert context.domain_str == domain_str
        assert context.operation == operation
        assert context.protocol == protocol
        assert context.parsed_message is None
        assert context.device is None

    def test_to_dict(self):
        """Test that to_dict returns a dictionary representation of the context."""
        context = BaseRequestContext(
            operation='test_operation',
            protocol='test_protocol',
            domain_str='test.domain.com'
        )

        result = context.to_dict()

        assert isinstance(result, dict)
        assert result['operation'] == 'test_operation'
        assert result['protocol'] == 'test_protocol'
        assert result['domain_str'] == 'test.domain.com'
        # Check that None values are also included
        assert result['parsed_message'] is None
        assert result['device'] is None

    def test_to_dict_with_complex_objects(self):
        """Test to_dict with complex objects like mocks."""
        mock_device = Mock(spec=DeviceModel)
        mock_domain = Mock(spec=DomainModel)

        context = BaseRequestContext(
            device=mock_device,
            domain=mock_domain
        )

        result = context.to_dict()

        assert 'device' in result
        assert 'domain' in result

        assert isinstance(result['device'], Mock)
        assert isinstance(result['domain'], Mock)

        assert context.device is mock_device
        assert context.domain is mock_domain


    def test_clear(self):
        """Test that clear() resets all attributes to None."""
        context = BaseRequestContext(
            operation='test_operation',
            protocol='est',
            domain_str='example.com'
        )

        # Verify some fields are set
        assert context.operation == 'test_operation'
        assert context.protocol == 'est'
        assert context.domain_str == 'example.com'

        # Clear all fields
        context.clear()

        # Verify all fields are None
        for field in fields(context):
            assert getattr(context, field.name) is None

    def test_all_field_types(self):
        """Test that all field types can be set and retrieved correctly."""
        # Create mock objects for complex types
        mock_csr = Mock(spec=CertificateSigningRequest)
        mock_domain = Mock(spec=DomainModel)
        mock_device = Mock(spec=DeviceModel)
        mock_cert = Mock(spec=x509.Certificate)
        mock_cert_list = [Mock(spec=x509.Certificate), Mock(spec=x509.Certificate)]

        context = BaseRequestContext(
            parsed_message=mock_csr,
            operation='enroll',
            protocol='est',
            domain_str='test.example.com',
            domain=mock_domain,
            device=mock_device,
            client_certificate=mock_cert,
            client_intermediate_certificate=mock_cert_list
        )

        # Verify all fields are set correctly
        assert context.parsed_message == mock_csr
        assert context.operation == 'enroll'
        assert context.protocol == 'est'
        assert context.domain_str == 'test.example.com'
        assert context.domain == mock_domain
        assert context.device == mock_device
        assert context.client_certificate == mock_cert
        assert context.client_intermediate_certificate == mock_cert_list

    def test_parsed_message_with_pki_message(self):
        """Test that parsed_message can hold a PKIMessage object."""
        mock_pki_message = Mock(spec=PKIMessage)

        context = BaseRequestContext(parsed_message=mock_pki_message)

        assert context.parsed_message == mock_pki_message

    def test_dataclass_immutability_after_creation(self):
        """Test that fields can be modified after creation (dataclass is mutable)."""
        context = BaseRequestContext()

        # Modify fields after creation
        context.operation = 'new_operation'
        context.protocol = 'cmp'
        context.domain_str = 'new_operation'

        assert context.operation == 'new_operation'
        assert context.protocol == 'cmp'
        assert context.domain_str == 'new_operation'

    def test_field_count(self):
        """Test that the expected number of fields are present in BaseRequestContext."""
        context = BaseRequestContext()
        field_names = [field.name for field in fields(context)]

        expected_fields = [
            'operation', 'protocol', 'parsed_message',
            'domain_str', 'domain', 'device',
            'owner_credential', 'issuer_credential',
            'client_certificate', 'client_intermediate_certificate',
            'event'
        ]

        assert len(field_names) == len(expected_fields)
        assert set(field_names) == set(expected_fields)

    def test_to_dict_after_clear(self):
        """Test that to_dict works correctly after clear()."""
        context = BaseRequestContext(
            operation='test',
            protocol='est',
            domain_str='domain'
        )

        context.clear()
        result = context.to_dict()

        # All values should be None
        for value in result.values():
            assert value is None

    def test_field_count(self):
        """Test that the expected number of fields are present."""
        context = EstCertificateRequestContext()
        field_names = [field.name for field in fields(context)]

        expected_fields = [
            'raw_message', 'parsed_message', 'operation', 'protocol',
            'cert_profile_str', 'est_encoding',
            'domain_str', 'domain', 'device', 'certificate_profile_model', 'cert_requested',
            'est_username', 'est_password',
            'client_certificate', 'client_intermediate_certificate',
            'cert_requested_profile_validated', 'issued_certificate',
            'owner_credential', 'issuer_credential',
            'http_response_status', 'http_response_content',
            'http_response_content_type',
            'enrollment_request', 'event',  # These two should be refactored into the overall Req Context
            'allow_ca_certificate_request', 'request_data', 'validated_request_data',
            'est_server_host', 'est_server_port', 'est_server_path', 'est_server_truststore'
        ]

        assert len(field_names) == len(expected_fields)
        assert set(field_names) == set(expected_fields)