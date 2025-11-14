"""Tests for authorization components."""
from unittest.mock import Mock

import pytest
from devices.models import DeviceModel
from pki.models.domain import DomainModel

from request.authorization import (
    AuthorizationComponent,
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DomainScopeValidation,
    EstAuthorization,
    EstOperationAuthorization,  # Changed from OperationAuthorization
    ManualAuthorization,
    ProtocolAuthorization,
)
from request.request_context import RequestContext


class TestProtocolAuthorization:
    """Test cases for ProtocolAuthorization."""

    def test_protocol_authorization_success(self) -> None:
        """Test successful protocol authorization."""
        allowed_protocols = ['est', 'cmp']
        auth = ProtocolAuthorization(allowed_protocols)

        context = Mock(spec=RequestContext)
        context.protocol = 'est'

        # Should not raise an exception
        auth.authorize(context)

    def test_protocol_authorization_failure_invalid_protocol(self) -> None:
        """Test protocol authorization failure with invalid protocol."""
        allowed_protocols = ['est', 'cmp']
        auth = ProtocolAuthorization(allowed_protocols)

        context = Mock(spec=RequestContext)
        context.protocol = 'invalid_protocol'

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert "Unauthorized protocol: 'invalid_protocol'" in str(exc_info.value)
        assert 'Allowed protocols: est, cmp' in str(exc_info.value)

    def test_protocol_authorization_failure_missing_protocol(self) -> None:
        """Test protocol authorization failure with missing protocol."""
        allowed_protocols = ['est', 'cmp']
        auth = ProtocolAuthorization(allowed_protocols)

        context = Mock(spec=RequestContext)
        context.protocol = None

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Protocol information is missing. Authorization denied.' in str(exc_info.value)

    def test_protocol_authorization_failure_empty_protocol(self) -> None:
        """Test protocol authorization failure with empty protocol string."""
        allowed_protocols = ['est', 'cmp']
        auth = ProtocolAuthorization(allowed_protocols)

        context = Mock(spec=RequestContext)
        context.protocol = ''

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Protocol information is missing. Authorization denied.' in str(exc_info.value)

    def test_protocol_authorization_single_allowed_protocol(self) -> None:
        """Test protocol authorization with single allowed protocol."""
        allowed_protocols = ['est']
        auth = ProtocolAuthorization(allowed_protocols)

        context = Mock(spec=RequestContext)
        context.protocol = 'est'

        # Should not raise an exception
        auth.authorize(context)

    def test_protocol_authorization_case_sensitive(self) -> None:
        """Test that protocol authorization is case sensitive."""
        allowed_protocols = ['est']
        auth = ProtocolAuthorization(allowed_protocols)

        context = Mock(spec=RequestContext)
        context.protocol = 'EST'

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert "Unauthorized protocol: 'EST'" in str(exc_info.value)


class TestEstOperationAuthorization:  # Changed from TestOperationAuthorization
    """Test cases for EstOperationAuthorization."""

    def test_operation_authorization_success(self) -> None:
        """Test successful operation authorization."""
        allowed_operations = ['simpleenroll', 'simplereenroll']
        auth = EstOperationAuthorization(allowed_operations)  # Changed class name

        context = Mock(spec=RequestContext)
        context.operation = 'simpleenroll'

        # Should not raise an exception
        auth.authorize(context)

    def test_operation_authorization_failure_invalid_operation(self) -> None:
        """Test operation authorization failure with invalid operation."""
        allowed_operations = ['simpleenroll', 'simplereenroll']
        auth = EstOperationAuthorization(allowed_operations)  # Changed class name

        context = Mock(spec=RequestContext)
        context.operation = 'invalid_operation'

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert "Unauthorized operation: 'invalid_operation'" in str(exc_info.value)

    def test_operation_authorization_failure_missing_operation(self) -> None:
        """Test operation authorization failure with missing operation."""
        allowed_operations = ['simpleenroll']
        auth = EstOperationAuthorization(allowed_operations)  # Changed class name

        context = Mock(spec=RequestContext)
        context.operation = None

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Operation information is missing. Authorization denied.' in str(exc_info.value)

    def test_operation_authorization_failure_empty_operation(self) -> None:
        """Test operation authorization failure with empty operation string."""
        allowed_operations = ['simpleenroll']
        auth = EstOperationAuthorization(allowed_operations)  # Changed class name

        context = Mock(spec=RequestContext)
        context.operation = ''

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Operation information is missing. Authorization denied.' in str(exc_info.value)

    def test_operation_authorization_single_allowed_operation(self) -> None:
        """Test operation authorization with single allowed operation."""
        allowed_operations = ['simpleenroll']
        auth = EstOperationAuthorization(allowed_operations)  # Changed class name

        context = Mock(spec=RequestContext)
        context.operation = 'simpleenroll'

        # Should not raise an exception
        auth.authorize(context)


class TestCertificateProfileAuthorization:
    """Test cases for CertificateProfileAuthorization."""

    def test_cert_profile_authorization_success(self, domain_instance, cert_profile_instance) -> None:
        """Test successful certificate template authorization."""
        auth = CertificateProfileAuthorization()

        context = Mock(spec=RequestContext)
        context.cert_profile_str = 'domain_credential'
        context.domain = domain_instance['domain']

        # Should not raise an exception
        auth.authorize(context)

    def test_cert_profile_authorization_failure_invalid_profile(self, domain_instance, cert_profile_instance) -> None:
        """Test certificate profile authorization failure with invalid profile."""
        auth = CertificateProfileAuthorization()

        context = Mock(spec=RequestContext)
        context.cert_profile_str = 'invalid_profile'
        context.domain = domain_instance['domain']

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert "Unauthorized certificate profile: 'invalid_profile'" in str(exc_info.value)
        assert 'Allowed profiles:' in str(exc_info.value)
        assert 'domain_credential' in str(exc_info.value)

    def test_cert_profile_str_authorization_failure_missing_profile(self, domain_instance, cert_profile_instance) -> None:
        """Test certificate profile authorization failure with missing profile string."""
        auth = CertificateProfileAuthorization()
        context = Mock(spec=RequestContext)
        context.cert_profile_str = None

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Certificate profile is missing in the context. Authorization denied.' in str(exc_info.value)

    def test_cert_profile_str_authorization_failure_empty_profile(self) -> None:
        """Test certificate profile authorization failure with empty profile string."""
        auth = CertificateProfileAuthorization()

        context = Mock(spec=RequestContext)
        context.cert_profile_str = ''

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Certificate profile is missing in the context. Authorization denied.' in str(exc_info.value)

    def test_cert_profile_str_authorization_alias(self, domain_instance, cert_profile_instance) -> None:
        """Test certificate profile authorization with single allowed profile."""
        auth = CertificateProfileAuthorization()
        context = Mock(spec=RequestContext)
        context.cert_profile_str = 'test_profile_alias' # Using alias for profile 'domain_credential'
        context.domain = domain_instance['domain']

        # Should not raise an exception
        auth.authorize(context)


class TestDomainScopeValidation:
    """Test cases for DomainScopeValidation."""

    def test_domain_scope_validation_success(self, domain_instance) -> None:
        """Test successful domain scope validation."""
        domain = domain_instance['domain']
        device = Mock(spec=DeviceModel)
        device.domain = domain

        auth = DomainScopeValidation()
        context = Mock(spec=RequestContext)
        context.device = device
        context.domain = domain

        # Should not raise an exception
        auth.authorize(context)

    def test_domain_scope_validation_failure_device_domain_mismatch(self, domain_instance) -> None:
        """Test domain scope validation failure when device domain doesn't match requested domain."""
        domain = domain_instance['domain']
        different_domain = Mock(spec=DomainModel)
        different_domain.unique_name = 'different_domain'

        device = Mock(spec=DeviceModel)
        device.domain = different_domain

        auth = DomainScopeValidation()
        context = Mock(spec=RequestContext)
        context.device = device
        context.domain = domain

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert f"Unauthorized requested domain: '{domain}'" in str(exc_info.value)
        assert f"Device domain: '{different_domain}'" in str(exc_info.value)

    def test_domain_scope_validation_failure_missing_device(self, domain_instance) -> None:
        """Test domain scope validation failure with missing device."""
        domain = domain_instance['domain']

        auth = DomainScopeValidation()
        context = Mock(spec=RequestContext)
        context.device = None
        context.domain = domain

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Authenticated device is missing in the context. Authorization denied.' in str(exc_info.value)

    def test_domain_scope_validation_failure_missing_domain(self, domain_instance) -> None:
        """Test domain scope validation failure with missing domain."""
        domain = domain_instance['domain']
        device = Mock(spec=DeviceModel)
        device.domain = domain

        auth = DomainScopeValidation()
        context = Mock(spec=RequestContext)
        context.device = device
        context.domain = None

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Requested domain is missing in the context. Authorization denied.' in str(exc_info.value)

    def test_domain_scope_validation_failure_device_has_no_domain(self, domain_instance) -> None:
        """Test domain scope validation failure when device has no associated domain."""
        domain = domain_instance['domain']
        device = Mock(spec=DeviceModel)
        device.domain = None

        auth = DomainScopeValidation()
        context = Mock(spec=RequestContext)
        context.device = device
        context.domain = domain

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert f"Unauthorized requested domain: '{domain}'" in str(exc_info.value)
        assert "Device domain: 'None'" in str(exc_info.value)


class TestManualAuthorization:
    """Test cases for ManualAuthorization."""

    def test_manual_authorization_success(self) -> None:
        """Test that manual authorization always succeeds (no implementation)."""
        auth = ManualAuthorization()
        context = Mock(spec=RequestContext)

        # Should not raise an exception since authorize method is empty
        auth.authorize(context=context)


class TestCompositeAuthorization:
    """Test cases for CompositeAuthorization."""

    def test_composite_authorization_empty_components(self) -> None:
        """Test composite authorization with no components."""
        auth = CompositeAuthorization()
        context = Mock(spec=RequestContext)

        # Should not raise an exception
        auth.authorize(context)

    def test_composite_authorization_single_component_success(self) -> None:
        """Test composite authorization with single successful component."""
        auth = CompositeAuthorization()

        mock_component = Mock(spec=AuthorizationComponent)
        auth.add(mock_component)

        context = Mock(spec=RequestContext)
        auth.authorize(context)

        mock_component.authorize.assert_called_once_with(context)

    def test_composite_authorization_single_component_failure(self) -> None:
        """Test composite authorization with single failing component."""
        auth = CompositeAuthorization()

        mock_component = Mock(spec=AuthorizationComponent)
        mock_component.authorize.side_effect = ValueError('Authorization failed')
        auth.add(mock_component)

        context = Mock(spec=RequestContext)

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Authorization failed' in str(exc_info.value)
        mock_component.authorize.assert_called_once_with(context)

    def test_composite_authorization_multiple_components_success(self) -> None:
        """Test composite authorization with multiple successful components."""
        auth = CompositeAuthorization()

        mock_component1 = Mock(spec=AuthorizationComponent)
        mock_component2 = Mock(spec=AuthorizationComponent)
        auth.add(mock_component1)
        auth.add(mock_component2)

        context = Mock(spec=RequestContext)
        auth.authorize(context)

        mock_component1.authorize.assert_called_once_with(context)
        mock_component2.authorize.assert_called_once_with(context)

    def test_composite_authorization_multiple_components_first_fails(self) -> None:
        """Test composite authorization where first component fails."""
        auth = CompositeAuthorization()

        mock_component1 = Mock(spec=AuthorizationComponent)
        mock_component1.authorize.side_effect = ValueError('First component failed')
        mock_component2 = Mock(spec=AuthorizationComponent)

        auth.add(mock_component1)
        auth.add(mock_component2)

        context = Mock(spec=RequestContext)

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'First component failed' in str(exc_info.value)
        mock_component1.authorize.assert_called_once_with(context)
        # Second component should not be called since first one failed
        mock_component2.authorize.assert_not_called()

    def test_composite_authorization_multiple_components_second_fails(self) -> None:
        """Test composite authorization where second component fails."""
        auth = CompositeAuthorization()

        mock_component1 = Mock(spec=AuthorizationComponent)
        mock_component2 = Mock(spec=AuthorizationComponent)
        mock_component2.authorize.side_effect = ValueError('Second component failed')

        auth.add(mock_component1)
        auth.add(mock_component2)

        context = Mock(spec=RequestContext)

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Second component failed' in str(exc_info.value)
        mock_component1.authorize.assert_called_once_with(context)
        mock_component2.authorize.assert_called_once_with(context)

    def test_composite_authorization_add_component(self) -> None:
        """Test adding components to composite authorization."""
        auth = CompositeAuthorization()
        mock_component = Mock(spec=AuthorizationComponent)

        assert len(auth.components) == 0
        auth.add(mock_component)
        assert len(auth.components) == 1
        assert auth.components[0] == mock_component

    def test_composite_authorization_remove_component(self) -> None:
        """Test removing components from composite authorization."""
        auth = CompositeAuthorization()
        mock_component = Mock(spec=AuthorizationComponent)

        auth.add(mock_component)
        assert len(auth.components) == 1

        auth.remove(mock_component)
        assert len(auth.components) == 0

    def test_composite_authorization_remove_nonexistent_component(self) -> None:
        """Test removing non-existent component raises ValueError."""
        auth = CompositeAuthorization()
        mock_component = Mock(spec=AuthorizationComponent)

        with pytest.raises(ValueError) as exc_info:
            auth.remove(mock_component)

        assert 'Attempted to remove non-existent authorization component' in str(exc_info.value)


class TestEstAuthorization:
    """Test cases for EstAuthorization."""

    def test_est_authorization_initialization(self) -> None:
        """Test EST authorization initialization with default components."""
        auth = EstAuthorization()

        # Should have 5 components by default
        assert len(auth.components) == 5

        # Check component types
        component_types = [type(comp).__name__ for comp in auth.components]
        expected_types = [
            'DomainScopeValidation', 
            'CertificateProfileAuthorization',
            'ManualAuthorization',
            'ProtocolAuthorization',
            'EstOperationAuthorization'
        ]
        assert component_types == expected_types

    def test_est_authorization_protocol_component_configuration(self) -> None:
        """Test that EST authorization configures protocol component correctly."""
        auth = EstAuthorization()

        # Find the protocol authorization component
        protocol_component = None
        for component in auth.components:
            if isinstance(component, ProtocolAuthorization):
                protocol_component = component
                break

        assert protocol_component is not None
        assert protocol_component.allowed_protocols == ['est']

    def test_est_authorization_operation_component_configuration(self) -> None:
        """Test that EST authorization configures operation component correctly."""
        auth = EstAuthorization()

        # Find the operation authorization component
        operation_component = None
        for component in auth.components:
            if isinstance(component, EstOperationAuthorization):
                operation_component = component
                break

        assert operation_component is not None
        assert operation_component.allowed_operations == ['simpleenroll', 'simplereenroll']

    def test_est_authorization_cert_profile_str_component_configuration(self) -> None:
        """Test that EST authorization configures certificate template component correctly."""
        auth = EstAuthorization()

        # Find the certificate template authorization component
        template_component = None
        for component in auth.components:
            if isinstance(component, CertificateProfileAuthorization):
                template_component = component
                break

        assert template_component is not None

    def test_est_authorization_full_success(self, domain_credential_est_onboarding) -> None:
        """Test full EST authorization success."""
        auth = EstAuthorization()

        # Create a context that should pass all authorization checks
        context = Mock(spec=RequestContext)
        context.protocol = 'est'
        context.operation = 'simpleenroll'
        context.cert_profile_str = 'tls_server'
        context.device = Mock()
        context.device.domain = domain_credential_est_onboarding['domain']
        context.device.common_name = 'test-device'
        context.domain = domain_credential_est_onboarding['domain']

        # Should not raise an exception
        auth.authorize(context)

    def test_est_authorization_protocol_failure(self, domain_credential_est_onboarding) -> None:
        """Test EST authorization failure due to wrong protocol."""
        auth = EstAuthorization()

        context = Mock(spec=RequestContext)
        context.protocol = 'cmp'  # Wrong protocol
        context.operation = 'simpleenroll'
        context.cert_profile_str = 'tls_server'
        context.device = Mock()
        context.device.domain = domain_credential_est_onboarding['domain']
        context.domain = domain_credential_est_onboarding['domain']

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert "Unauthorized protocol: 'cmp'" in str(exc_info.value)

    def test_est_authorization_operation_failure(self, domain_credential_est_onboarding) -> None:
        """Test EST authorization failure due to wrong operation."""
        auth = EstAuthorization()

        context = Mock(spec=RequestContext)
        context.protocol = 'est'
        context.operation = 'invalid_operation'  # Wrong operation
        context.cert_profile_str = 'tls_server'
        context.device = Mock()
        context.device.domain = domain_credential_est_onboarding['domain']
        context.domain = domain_credential_est_onboarding['domain']

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert "Unauthorized operation: 'invalid_operation'" in str(exc_info.value)

    def test_est_authorization_cert_profile_str_failure(self, domain_credential_est_onboarding) -> None:
        """Test EST authorization failure due to wrong certificate template."""
        auth = EstAuthorization()

        context = Mock(spec=RequestContext)
        context.protocol = 'est'
        context.operation = 'simpleenroll'
        context.cert_profile_str = 'invalid_template'  # Wrong template
        context.device = Mock()
        context.device.domain = domain_credential_est_onboarding['domain']
        context.domain = domain_credential_est_onboarding['domain']

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert "Unauthorized certificate profile: 'invalid_template'" in str(exc_info.value)

    def test_est_authorization_domain_scope_failure(self, domain_credential_est_onboarding) -> None:
        """Test EST authorization failure due to domain scope mismatch."""
        auth = EstAuthorization()

        different_domain = Mock()
        different_domain.unique_name = 'different_domain'

        context = Mock(spec=RequestContext)
        context.protocol = 'est'
        context.operation = 'simpleenroll'
        context.cert_profile_str = 'tls_server'
        context.device = Mock()
        context.device.domain = different_domain  # Different domain
        context.domain = domain_credential_est_onboarding['domain']

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert f"Unauthorized requested domain: '{domain_credential_est_onboarding['domain']}'" in str(exc_info.value)

    def test_est_authorization_missing_device(self, domain_credential_est_onboarding) -> None:
        """Test EST authorization failure due to missing device."""
        auth = EstAuthorization()

        context = Mock(spec=RequestContext)
        context.protocol = 'est'
        context.operation = 'simpleenroll'
        context.cert_profile_str = 'tls_server'
        context.device = None  # Missing device
        context.domain = domain_credential_est_onboarding['domain']

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Authenticated device is missing in the context. Authorization denied.' in str(exc_info.value)

    def test_est_authorization_missing_domain(self, domain_credential_est_onboarding) -> None:
        """Test EST authorization failure due to missing domain."""
        auth = EstAuthorization()

        context = Mock(spec=RequestContext)
        context.protocol = 'est'
        context.operation = 'simpleenroll'
        context.cert_profile_str = 'tls_server'
        context.device = Mock()
        context.device.domain = domain_credential_est_onboarding['domain']
        context.domain = None  # Missing domain

        with pytest.raises(ValueError) as exc_info:
            auth.authorize(context)

        assert 'Requested domain is missing in the context. Authorization denied.' in str(exc_info.value)


class TestAuthorizationComponentInterface:
    """Test the abstract base class interface."""

    def test_authorization_component_is_abstract(self) -> None:
        """Test that AuthorizationComponent cannot be instantiated directly."""
        with pytest.raises(TypeError):
            AuthorizationComponent()

    def test_authorization_component_subclass_must_implement_authorize(self) -> None:
        """Test that subclasses must implement the authorize method."""

        class IncompleteAuthorization(AuthorizationComponent):
            pass

        with pytest.raises(TypeError):
            IncompleteAuthorization()

    def test_authorization_component_subclass_with_authorize_method(self) -> None:
        """Test that subclasses with authorize method can be instantiated."""

        class CompleteAuthorization(AuthorizationComponent):
            def authorize(self, context: RequestContext) -> None:
                pass

        # Should not raise an exception
        auth = CompleteAuthorization()
        assert isinstance(auth, AuthorizationComponent)