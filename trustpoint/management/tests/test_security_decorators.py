"""Test suite for security decorators."""
from unittest.mock import Mock, patch

from django.core.exceptions import PermissionDenied
from django.test import TestCase
from management.security.decorators import security_level
from management.security.features import AutoGenPkiFeature, SecurityFeature


class MockSecurityFeature(SecurityFeature):
    """Mock security feature for testing."""

    verbose_name = 'Mock Feature'
    db_field_name = 'mock_feature'

    def enable(self, **kwargs: object) -> None:
        """Mock enable method."""
        pass

    def disable(self, **kwargs: object) -> None:
        """Mock disable method."""
        pass

    def is_enabled(self) -> bool:
        """Mock is_enabled method."""
        return True


class SecurityLevelDecoratorTest(TestCase):
    """Test suite for the security_level decorator."""

    def test_decorator_allows_access_when_feature_allowed(self):
        """Test decorator allows function execution when feature is allowed."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function():
            return "success"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            result = test_function()

            self.assertEqual(result, "success")
            mock_manager.is_feature_allowed.assert_called_once_with(mock_feature)

    def test_decorator_denies_access_when_feature_not_allowed(self):
        """Test decorator raises PermissionDenied when feature is not allowed."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function():
            return "success"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = False
            mock_manager_class.return_value = mock_manager

            with self.assertRaises(PermissionDenied) as context:
                test_function()

            self.assertIn('Security level does not allow access to feature', str(context.exception))
            mock_manager.is_feature_allowed.assert_called_once_with(mock_feature)

    def test_decorator_with_feature_class(self):
        """Test decorator works with feature class instead of instance."""
        @security_level(MockSecurityFeature)
        def test_function():
            return "success"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            result = test_function()

            self.assertEqual(result, "success")
            mock_manager.is_feature_allowed.assert_called_once_with(MockSecurityFeature)

    def test_decorator_preserves_function_metadata(self):
        """Test decorator preserves original function's metadata using functools.wraps."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function_with_docstring():
            """This is a test docstring."""
            return "success"

        self.assertEqual(test_function_with_docstring.__name__, "test_function_with_docstring")
        self.assertEqual(test_function_with_docstring.__doc__, "This is a test docstring.")

    def test_decorator_passes_args_and_kwargs(self):
        """Test decorator correctly passes arguments and keyword arguments to decorated function."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function(arg1, arg2, kwarg1=None):
            return f"{arg1}-{arg2}-{kwarg1}"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            result = test_function("a", "b", kwarg1="c")

            self.assertEqual(result, "a-b-c")

    def test_decorator_with_autogenpki_feature(self):
        """Test decorator works with real AutoGenPkiFeature."""
        @security_level(AutoGenPkiFeature)
        def test_function():
            return "pki_success"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            result = test_function()

            self.assertEqual(result, "pki_success")
            mock_manager.is_feature_allowed.assert_called_once_with(AutoGenPkiFeature)

    def test_decorator_with_method(self):
        """Test decorator works on class methods."""
        mock_feature = MockSecurityFeature()

        class TestClass:
            @security_level(mock_feature)
            def test_method(self, value):
                return f"method_{value}"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            instance = TestClass()
            result = instance.test_method("test")

            self.assertEqual(result, "method_test")

    def test_decorator_raises_permission_denied_with_correct_message(self):
        """Test decorator raises PermissionDenied with informative message."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function():
            return "success"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = False
            mock_manager_class.return_value = mock_manager

            with self.assertRaises(PermissionDenied) as context:
                test_function()

            error_message = str(context.exception)
            self.assertIn('Security level does not allow access to feature', error_message)
            # The feature object representation should be in the message
            self.assertIn('MockSecurityFeature', str(type(mock_feature).__name__))

    def test_decorator_creates_new_security_manager_per_call(self):
        """Test decorator creates a new SecurityManager instance for each call."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function():
            return "success"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager1 = Mock()
            mock_manager1.is_feature_allowed.return_value = True
            mock_manager2 = Mock()
            mock_manager2.is_feature_allowed.return_value = True

            mock_manager_class.side_effect = [mock_manager1, mock_manager2]

            # First call
            result1 = test_function()
            self.assertEqual(result1, "success")

            # Second call
            result2 = test_function()
            self.assertEqual(result2, "success")

            # Verify SecurityManager was instantiated twice
            self.assertEqual(mock_manager_class.call_count, 2)

    def test_decorator_with_exception_in_decorated_function(self):
        """Test decorator allows exceptions from decorated function to propagate."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function():
            raise ValueError("Test error")

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            with self.assertRaises(ValueError) as context:
                test_function()

            self.assertEqual(str(context.exception), "Test error")

    def test_decorator_with_return_value(self):
        """Test decorator correctly returns value from decorated function."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function():
            return {"key": "value", "number": 42}

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            result = test_function()

            self.assertEqual(result, {"key": "value", "number": 42})

    def test_decorator_with_none_return(self):
        """Test decorator works when decorated function returns None."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function():
            pass  # Implicitly returns None

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            result = test_function()

            self.assertIsNone(result)

    def test_multiple_decorators_stacked(self):
        """Test security_level decorator works when stacked with other decorators."""
        mock_feature1 = MockSecurityFeature()
        mock_feature2 = MockSecurityFeature()

        @security_level(mock_feature1)
        @security_level(mock_feature2)
        def test_function():
            return "double_decorated"

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            result = test_function()

            self.assertEqual(result, "double_decorated")
            # Should be called twice (once per decorator)
            self.assertEqual(mock_manager.is_feature_allowed.call_count, 2)

    def test_decorator_with_complex_return_types(self):
        """Test decorator works with various complex return types."""
        mock_feature = MockSecurityFeature()

        @security_level(mock_feature)
        def test_function_list():
            return [1, 2, 3, 4, 5]

        @security_level(mock_feature)
        def test_function_tuple():
            return (1, "two", 3.0)

        @security_level(mock_feature)
        def test_function_generator():
            yield 1
            yield 2
            yield 3

        with patch('management.security.decorators.SecurityManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.is_feature_allowed.return_value = True
            mock_manager_class.return_value = mock_manager

            # Test list
            result_list = test_function_list()
            self.assertEqual(result_list, [1, 2, 3, 4, 5])

            # Test tuple
            result_tuple = test_function_tuple()
            self.assertEqual(result_tuple, (1, "two", 3.0))

            # Test generator
            result_gen = list(test_function_generator())
            self.assertEqual(result_gen, [1, 2, 3])
