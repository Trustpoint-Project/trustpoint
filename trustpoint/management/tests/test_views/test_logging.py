"""Test suite for logging views."""
import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.http import Http404
from django.test import RequestFactory, TestCase
from management.views.logging import (
    IndexView,
    LoggingFilesDetailsView,
    LoggingFilesDownloadMultipleView,
    LoggingFilesDownloadView,
    LoggingFilesTableView,
    language,
)


class IndexViewTest(TestCase):
    """Test suite for IndexView."""

    def test_redirect_is_permanent(self):
        """Test that IndexView redirects permanently."""
        view = IndexView()
        self.assertTrue(view.permanent)

    def test_pattern_name(self):
        """Test that IndexView redirects to management:language."""
        view = IndexView()
        self.assertEqual(view.pattern_name, 'management:language')


class LanguageViewTest(TestCase):
    """Test suite for language view function."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('management.views.logging.render')
    def test_language_view_returns_response(self, mock_render):
        """Test language view returns HttpResponse."""
        mock_render.return_value = Mock(status_code=200)
        request = self.factory.get('/language/')
        response = language(request)
        self.assertEqual(response.status_code, 200)
        mock_render.assert_called_once()

    @patch('management.views.logging.render')
    def test_language_view_context_has_page_category(self, mock_render):
        """Test language view context includes page_category."""
        request = self.factory.get('/language/')
        language(request)
        # Check render was called with correct context
        call_args = mock_render.call_args
        context = call_args[1]['context']
        self.assertEqual(context['page_category'], 'management')
        self.assertEqual(context['page_name'], 'language')


class LoggingFilesTableViewTest(TestCase):
    """Test suite for LoggingFilesTableView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = LoggingFilesTableView()
        self.view.request = self.factory.get('/logging/')

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/logging/logging_files.html')

    def test_context_object_name(self):
        """Test correct context object name."""
        self.assertEqual(self.view.context_object_name, 'log_files')

    def test_default_sort_param(self):
        """Test default sort parameter."""
        self.assertEqual(self.view.default_sort_param, 'filename')

    def test_page_category_and_name(self):
        """Test page category and name are set correctly."""
        self.assertEqual(self.view.page_category, 'management')
        self.assertEqual(self.view.page_name, 'logging')

    def test_http_method_names(self):
        """Test only GET method is allowed."""
        self.assertEqual(self.view.http_method_names, ('get',))

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_queryset_with_valid_log_files(self, mock_log_dir):
        """Test get_queryset returns list of valid log files."""
        # Mock log directory with valid log files - use proper name attribute
        mock_file1 = Mock(spec=Path)
        mock_file1.name = 'trustpoint.log'
        mock_file2 = Mock(spec=Path)
        mock_file2.name = 'trustpoint.log.1'
        mock_file3 = Mock(spec=Path)
        mock_file3.name = 'trustpoint.log.2'
        mock_file4 = Mock(spec=Path)
        mock_file4.name = 'other.log'  # Invalid pattern
        
        mock_log_dir.iterdir.return_value = [mock_file1, mock_file2, mock_file3, mock_file4]

        def mock_get_log_file_data(filename):
            # Return data only for valid filenames
            if filename.startswith('trustpoint.log'):
                return {'filename': filename}
            return {}  # Invalid filename

        with patch.object(LoggingFilesTableView, '_get_log_file_data', side_effect=mock_get_log_file_data):
            queryset = self.view.get_queryset()
            self.assertIsInstance(queryset, list)
            # Should have 3 valid files (excluding 'other.log')
            self.assertEqual(len(queryset), 3)

    @patch('management.views.logging.LOG_DIR_PATH')
    @patch.object(LoggingFilesTableView, '_get_first_and_last_entry_date')
    def test_get_log_file_data_with_valid_dates(self, mock_get_dates, mock_log_dir):
        """Test _get_log_file_data with valid datetime entries."""
        from datetime import datetime

        mock_file = Mock(spec=Path)
        mock_file.exists.return_value = True
        mock_file.is_file.return_value = True
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        first_date = datetime(2024, 1, 1, 10, 0, 0)
        last_date = datetime(2024, 1, 2, 15, 30, 0)
        mock_get_dates.return_value = (first_date, last_date)

        result = LoggingFilesTableView._get_log_file_data('trustpoint.log')

        self.assertIn('filename', result)
        self.assertEqual(result['filename'], 'trustpoint.log')
        self.assertIn('created_at', result)
        self.assertIn('updated_at', result)

    @patch('management.views.logging.LOG_DIR_PATH')
    @patch.object(LoggingFilesTableView, '_get_first_and_last_entry_date')
    def test_get_log_file_data_with_none_dates(self, mock_get_dates, mock_log_dir):
        """Test _get_log_file_data when no dates are found in log file."""
        mock_file = Mock(spec=Path)
        mock_file.exists.return_value = True
        mock_file.is_file.return_value = True
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        mock_get_dates.return_value = (None, None)

        result = LoggingFilesTableView._get_log_file_data('trustpoint.log')

        self.assertIn('created_at', result)
        self.assertIn('updated_at', result)
        # Should contain translation for 'None'

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_log_file_data_with_nonexistent_file(self, mock_log_dir):
        """Test _get_log_file_data with non-existent file."""
        mock_file = Mock(spec=Path)
        mock_file.exists.return_value = False
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        result = LoggingFilesTableView._get_log_file_data('nonexistent.log')

        self.assertEqual(result, {})

    def test_get_first_and_last_entry_date_with_valid_log(self):
        """Test _get_first_and_last_entry_date with valid log entries."""
        mock_log_content = """2024-01-01 10:00:00 INFO First entry
2024-01-01 11:00:00 DEBUG Middle entry
2024-01-02 15:30:00 ERROR Last entry"""

        mock_path = Mock(spec=Path)
        mock_path.read_text.return_value = mock_log_content

        first_date, last_date = LoggingFilesTableView._get_first_and_last_entry_date(mock_path)

        self.assertIsNotNone(first_date)
        self.assertIsNotNone(last_date)
        self.assertEqual(first_date.year, 2024)
        self.assertEqual(last_date.year, 2024)

    def test_get_first_and_last_entry_date_with_no_dates(self):
        """Test _get_first_and_last_entry_date with log containing no dates."""
        mock_log_content = "No dates in this log file"

        mock_path = Mock(spec=Path)
        mock_path.read_text.return_value = mock_log_content

        first_date, last_date = LoggingFilesTableView._get_first_and_last_entry_date(mock_path)

        self.assertIsNone(first_date)
        self.assertIsNone(last_date)


class LoggingFilesDetailsViewTest(TestCase):
    """Test suite for LoggingFilesDetailsView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = LoggingFilesDetailsView()
        self.view.request = self.factory.get('/logging/details/')
        self.view.kwargs = {}

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/logging/logging_files_details.html')

    def test_page_category_and_name(self):
        """Test page category and name are set correctly."""
        self.assertEqual(self.view.page_category, 'settings')
        self.assertEqual(self.view.page_name, 'logging')

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_context_data_with_existing_file(self, mock_log_dir):
        """Test get_context_data with existing log file."""
        mock_file = Mock(spec=Path)
        mock_file.exists.return_value = True
        mock_file.is_file.return_value = True
        mock_file.read_text.return_value = "Log file content here"
        mock_file.resolve.return_value = mock_file
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        self.view.kwargs = {'filename': 'trustpoint.log'}
        context = self.view.get_context_data()

        self.assertIn('log_content', context)
        self.assertEqual(context['log_content'], "Log file content here")

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_context_data_with_nonexistent_file(self, mock_log_dir):
        """Test get_context_data with non-existent log file."""
        mock_file = Mock(spec=Path)
        mock_file.exists.return_value = False
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        self.view.kwargs = {'filename': 'nonexistent.log'}
        context = self.view.get_context_data()

        self.assertIn('log_content', context)
        self.assertIn('not found', context['log_content'].lower())


class LoggingFilesDownloadViewTest(TestCase):
    """Test suite for LoggingFilesDownloadView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = LoggingFilesDownloadView()
        self.view.request = self.factory.get('/logging/download/')

    def test_page_category_and_name(self):
        """Test page category and name are set correctly."""
        self.assertEqual(self.view.page_category, 'settings')
        self.assertEqual(self.view.page_name, 'logging')

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_with_existing_file(self, mock_log_dir):
        """Test GET method with existing file."""
        mock_file = Mock(spec=Path)
        mock_file.exists.return_value = True
        mock_file.is_file.return_value = True
        mock_file.read_text.return_value = "Log content"
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        response = self.view.get(self.view.request, filename='trustpoint.log')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('trustpoint.log', response['Content-Disposition'])

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_with_nonexistent_file(self, mock_log_dir):
        """Test GET method with non-existent file raises Http404."""
        mock_file = Mock(spec=Path)
        mock_file.exists.return_value = False
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        with self.assertRaises(Http404):
            self.view.get(self.view.request, filename='nonexistent.log')

    def test_get_without_filename(self):
        """Test GET method without filename raises Http404."""
        with self.assertRaises(Http404):
            self.view.get(self.view.request, filename=None)


class LoggingFilesDownloadMultipleViewTest(TestCase):
    """Test suite for LoggingFilesDownloadMultipleView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = LoggingFilesDownloadMultipleView()
        self.view.request = self.factory.get('/logging/download-multiple/')

    def test_page_category_and_name(self):
        """Test page category and name are set correctly."""
        self.assertEqual(self.view.page_category, 'settings')
        self.assertEqual(self.view.page_name, 'logging')

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_with_zip_format(self, mock_log_dir):
        """Test GET method creating ZIP archive."""
        mock_file = Mock(spec=Path)
        mock_file.read_bytes.return_value = b'log content'
        mock_file.resolve.return_value = mock_file
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        response = self.view.get(
            self.view.request,
            archive_format='zip',
            filenames='trustpoint.log/trustpoint.log.1'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/zip')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('trustpoint-logs.zip', response['Content-Disposition'])

        # Verify it's a valid ZIP
        zip_data = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_data, 'r') as zf:
            self.assertGreater(len(zf.namelist()), 0)

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_with_tar_gz_format(self, mock_log_dir):
        """Test GET method creating tar.gz archive."""
        mock_file = Mock(spec=Path)
        mock_file.read_bytes.return_value = b'log content'
        mock_file.resolve.return_value = mock_file
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        response = self.view.get(
            self.view.request,
            archive_format='tar.gz',
            filenames='trustpoint.log/trustpoint.log.1'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/gzip')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('trustpoint-logs.tar.gz', response['Content-Disposition'])

        # Verify it's a valid tar.gz
        tar_data = io.BytesIO(response.content)
        with tarfile.open(fileobj=tar_data, mode='r:gz') as tf:
            self.assertGreater(len(tf.getnames()), 0)

    def test_get_without_archive_format(self):
        """Test GET method without archive format raises Http404."""
        with self.assertRaises(Http404):
            self.view.get(
                self.view.request,
                archive_format=None,
                filenames='trustpoint.log'
            )

    def test_get_without_filenames(self):
        """Test GET method without filenames raises Http404."""
        with self.assertRaises(Http404):
            self.view.get(
                self.view.request,
                archive_format='zip',
                filenames=None
            )

    def test_get_with_invalid_archive_format(self):
        """Test GET method with invalid archive format raises Http404."""
        with self.assertRaises(Http404):
            self.view.get(
                self.view.request,
                archive_format='invalid',
                filenames='trustpoint.log'
            )

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_with_empty_filenames_string(self, mock_log_dir):
        """Test GET method with empty filenames string."""
        mock_log_dir.__truediv__ = Mock(
            return_value=Mock(read_bytes=Mock(return_value=b''))
        )

        # Should not raise error with empty filename list
        response = self.view.get(
            self.view.request,
            archive_format='zip',
            filenames='///'  # Will result in empty list after filtering
        )

        self.assertEqual(response.status_code, 200)

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_with_multiple_files_zip(self, mock_log_dir):
        """Test GET method with multiple files in ZIP."""
        mock_file = Mock(spec=Path)
        mock_file.read_bytes.return_value = b'content'
        mock_file.resolve.return_value = mock_file
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        response = self.view.get(
            self.view.request,
            archive_format='zip',
            filenames='trustpoint.log/trustpoint.log.1/trustpoint.log.2'
        )

        zip_data = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_data, 'r') as zf:
            # Should have 3 files
            self.assertEqual(len(zf.namelist()), 3)

    @patch('management.views.logging.LOG_DIR_PATH')
    def test_get_with_multiple_files_tar_gz(self, mock_log_dir):
        """Test GET method with multiple files in tar.gz."""
        mock_file = Mock(spec=Path)
        mock_file.read_bytes.return_value = b'content'
        mock_file.resolve.return_value = mock_file
        mock_log_dir.__truediv__ = Mock(return_value=mock_file)

        response = self.view.get(
            self.view.request,
            archive_format='tar.gz',
            filenames='trustpoint.log/trustpoint.log.1/trustpoint.log.2'
        )

        tar_data = io.BytesIO(response.content)
        with tarfile.open(fileobj=tar_data, mode='r:gz') as tf:
            # Should have 3 files
            self.assertEqual(len(tf.getnames()), 3)
