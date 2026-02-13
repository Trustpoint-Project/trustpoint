"""Test suite for CommandOutputWrapper."""

from unittest.mock import Mock

from django.test import TestCase
from management.util.output_wrapper import CommandOutputWrapper


class CommandOutputWrapperTest(TestCase):
    """Test suite for CommandOutputWrapper class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_stdout = Mock()
        self.mock_style = Mock()
        self.wrapper = CommandOutputWrapper(self.mock_stdout, self.mock_style)

    def test_init(self):
        """Test initialization stores stdout and style."""
        self.assertEqual(self.wrapper._stdout, self.mock_stdout)
        self.assertEqual(self.wrapper._style, self.mock_style)

    def test_write(self):
        """Test write method delegates to stdout."""
        test_message = 'Test message'

        self.wrapper.write(test_message)

        self.mock_stdout.write.assert_called_once_with(test_message)

    def test_write_empty_string(self):
        """Test write method with empty string."""
        self.wrapper.write('')

        self.mock_stdout.write.assert_called_once_with('')

    def test_write_multiline(self):
        """Test write method with multiline string."""
        multiline = 'Line 1\nLine 2\nLine 3'

        self.wrapper.write(multiline)

        self.mock_stdout.write.assert_called_once_with(multiline)

    def test_success(self):
        """Test success method formats with SUCCESS style."""
        test_message = 'Success message'
        expected_result = 'styled success message'
        self.mock_style.SUCCESS.return_value = expected_result

        result = self.wrapper.success(test_message)

        self.mock_style.SUCCESS.assert_called_once_with(test_message)
        self.assertEqual(result, expected_result)

    def test_success_empty_string(self):
        """Test success method with empty string."""
        self.mock_style.SUCCESS.return_value = ''

        result = self.wrapper.success('')

        self.mock_style.SUCCESS.assert_called_once_with('')
        self.assertEqual(result, '')

    def test_error(self):
        """Test error method formats with ERROR style."""
        test_message = 'Error message'
        expected_result = 'styled error message'
        self.mock_style.ERROR.return_value = expected_result

        result = self.wrapper.error(test_message)

        self.mock_style.ERROR.assert_called_once_with(test_message)
        self.assertEqual(result, expected_result)

    def test_error_empty_string(self):
        """Test error method with empty string."""
        self.mock_style.ERROR.return_value = ''

        result = self.wrapper.error('')

        self.mock_style.ERROR.assert_called_once_with('')
        self.assertEqual(result, '')

    def test_warning(self):
        """Test warning method formats with WARNING style."""
        test_message = 'Warning message'
        expected_result = 'styled warning message'
        self.mock_style.WARNING.return_value = expected_result

        result = self.wrapper.warning(test_message)

        self.mock_style.WARNING.assert_called_once_with(test_message)
        self.assertEqual(result, expected_result)

    def test_warning_empty_string(self):
        """Test warning method with empty string."""
        self.mock_style.WARNING.return_value = ''

        result = self.wrapper.warning('')

        self.mock_style.WARNING.assert_called_once_with('')
        self.assertEqual(result, '')

    def test_multiple_operations(self):
        """Test multiple operations in sequence."""
        self.mock_style.SUCCESS.return_value = 'success'
        self.mock_style.ERROR.return_value = 'error'
        self.mock_style.WARNING.return_value = 'warning'

        # Perform multiple operations
        self.wrapper.write('Starting')
        success_msg = self.wrapper.success('Done')
        error_msg = self.wrapper.error('Failed')
        warning_msg = self.wrapper.warning('Caution')
        self.wrapper.write('Ending')

        # Verify all calls
        self.assertEqual(self.mock_stdout.write.call_count, 2)
        self.assertEqual(success_msg, 'success')
        self.assertEqual(error_msg, 'error')
        self.assertEqual(warning_msg, 'warning')
