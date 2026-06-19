"""Tests for LoggingViewSet API endpoints.

The LoggingViewSet provides three custom actions (no standard CRUD):
  GET  /api/logging/list_files/              — list all trustpoint log files
  GET  /api/logging/download/<file_name>/    — download a log file
  DELETE /api/logging/delete/<file_name>/   — delete a log file

Filename validation in the delete action enforces the pattern
^trustpoint\\.log(?:\\.\\d+)?$ to prevent path traversal and arbitrary
file deletion.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient


LIST_URL = '/api/logging/list_files/'


def _download_url(filename: str) -> str:
    return f'/api/logging/download/{filename}/'


def _delete_url(filename: str) -> str:
    return f'/api/logging/delete/{filename}/'


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def user():
    """Create a test user."""
    User = get_user_model()
    return User.objects.create_user(username='log_testuser', password='testpass123')


@pytest.fixture
def authenticated_client(api_client: APIClient, user) -> APIClient:
    """Return an API client authenticated as a regular user."""
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def log_dir(tmp_path: Path) -> Path:
    """Create a temporary directory containing two fake log files."""
    log = tmp_path / 'trustpoint.log'
    log.write_text('2025-01-01 10:00:00 INFO First log entry\n', encoding='utf-8')
    rotated = tmp_path / 'trustpoint.log.1'
    rotated.write_text('2024-12-31 23:59:59 INFO Old log entry\n', encoding='utf-8')
    return tmp_path


@pytest.mark.django_db
class TestLoggingViewSetAuthentication:
    """Verify that unauthenticated requests are rejected."""

    def test_list_files_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated GET /api/logging/list_files/ returns 401."""
        response = api_client.get(LIST_URL)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_download_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated GET /api/logging/download/<file>/ returns 401."""
        response = api_client.get(_download_url('trustpoint.log'))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_delete_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated DELETE /api/logging/delete/<file>/ returns 401."""
        response = api_client.delete(_delete_url('trustpoint.log'))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestLoggingViewSetListFiles:
    """Tests for GET /api/logging/list_files/."""

    def test_list_files_returns_200(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """list_files action returns 200 when the log directory exists."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.get(LIST_URL)
        assert response.status_code == status.HTTP_200_OK

    def test_list_files_returns_log_filenames(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Response contains entries for all trustpoint.log* files in the directory."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.get(LIST_URL)
        assert response.status_code == status.HTTP_200_OK
        names = {item['name'] for item in response.data}
        assert 'trustpoint.log' in names
        assert 'trustpoint.log.1' in names

    def test_list_files_response_has_expected_fields(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Each item in the response has name, size, and modified fields."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.get(LIST_URL)
        assert response.status_code == status.HTTP_200_OK
        for item in response.data:
            assert 'name' in item
            assert 'size' in item
            assert 'modified' in item

    def test_list_files_returns_404_when_directory_missing(self, authenticated_client: APIClient, tmp_path: Path) -> None:
        """list_files returns 404 when LOG_DIR_PATH does not exist."""
        missing_dir = tmp_path / 'nonexistent'
        with patch('management.views.logging.LOG_DIR_PATH', missing_dir):
            response = authenticated_client.get(LIST_URL)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_files_excludes_non_log_files(self, authenticated_client: APIClient, tmp_path: Path) -> None:
        """Files that don't match the trustpoint.log pattern are excluded."""
        (tmp_path / 'trustpoint.log').write_text('entry', encoding='utf-8')
        (tmp_path / 'other.txt').write_text('noise', encoding='utf-8')
        with patch('management.views.logging.LOG_DIR_PATH', tmp_path):
            response = authenticated_client.get(LIST_URL)
        names = {item['name'] for item in response.data}
        assert 'other.txt' not in names
        assert 'trustpoint.log' in names


class TestLoggingViewSetDownload:
    """Tests for GET /api/logging/download/<file_name>/."""

    def test_download_existing_file_returns_200(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Downloading an existing log file returns 200."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.get(_download_url('trustpoint.log'))
        assert response.status_code == status.HTTP_200_OK

    def test_download_returns_file_content(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Downloaded content matches the actual file content."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.get(_download_url('trustpoint.log'))
        assert response.status_code == status.HTTP_200_OK
        content = b''.join(response.streaming_content) if hasattr(response, 'streaming_content') else response.content
        assert b'First log entry' in content

    def test_download_missing_file_returns_404(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Downloading a file that does not exist returns 404."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.get(_download_url('trustpoint.log.9'))
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_download_rotated_log_returns_200(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Rotated log files (trustpoint.log.N) can also be downloaded."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.get(_download_url('trustpoint.log.1'))
        assert response.status_code == status.HTTP_200_OK


class TestLoggingViewSetDelete:
    """Tests for DELETE /api/logging/delete/<file_name>/.

    The delete action enforces strict filename validation to prevent
    path traversal and deletion of arbitrary files.
    """

    def test_delete_valid_log_file_returns_200(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Deleting an existing trustpoint.log returns 200."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.delete(_delete_url('trustpoint.log'))
        assert response.status_code == status.HTTP_200_OK

    def test_delete_removes_file_from_filesystem(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """After a successful delete, the file no longer exists on disk."""
        log_file = log_dir / 'trustpoint.log'
        assert log_file.exists()
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            authenticated_client.delete(_delete_url('trustpoint.log'))
        assert not log_file.exists()

    def test_delete_rotated_log_returns_200(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Rotated log file trustpoint.log.1 can be deleted."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.delete(_delete_url('trustpoint.log.1'))
        assert response.status_code == status.HTTP_200_OK

    def test_delete_missing_file_returns_404(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Deleting a filename that matches the pattern but doesn't exist returns 404."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.delete(_delete_url('trustpoint.log.99'))
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_rejects_arbitrary_filename(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Filenames not matching trustpoint.log* are rejected with 400."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.delete(_delete_url('malicious.sh'))
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_delete_path_traversal_with_slash_returns_404(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Paths containing slashes don't match the URL pattern and are rejected by the router with 404.

        The url_path regex [^/]+ prevents any filename containing slashes from
        reaching the view — they never get past URL resolution.
        """
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.delete(_delete_url('etc/passwd'))
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_rejects_dotdot_without_slash(self, authenticated_client: APIClient, log_dir: Path) -> None:
        """Filenames containing '..' but no slash fail the regex pattern with 400."""
        with patch('management.views.logging.LOG_DIR_PATH', log_dir):
            response = authenticated_client.delete(_delete_url('trustpoint.log..evil'))
        assert response.status_code == status.HTTP_400_BAD_REQUEST
