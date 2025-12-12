"""Tests for the LoggedHttpResponse class."""
from django.test import TestCase

from trustpoint.views.base import THRESHOLD_LOGGER_HTTP_STATUS, LoggedHttpResponse


class TestLoggedHttpResponse(TestCase):
    """Test cases for LoggedHttpResponse."""

    def test_logged_response_success_status(self) -> None:
        """Test LoggedHttpResponse with success status code."""
        response = LoggedHttpResponse(content='Success', status=200)
        assert response.status_code == 200
        assert response.content == b'Success'

    def test_logged_response_error_status_string(self) -> None:
        """Test LoggedHttpResponse with error status and string content."""
        response = LoggedHttpResponse(content='Error message', status=400)
        assert response.status_code == 400
        assert response.content == b'Error message'

    def test_logged_response_error_status_bytes(self) -> None:
        """Test LoggedHttpResponse with error status and bytes content."""
        response = LoggedHttpResponse(content=b'Error bytes', status=500)
        assert response.status_code == 500
        assert response.content == b'Error bytes'

    def test_logged_response_threshold(self) -> None:
        """Test LoggedHttpResponse at threshold status."""
        response = LoggedHttpResponse(
            content='Threshold error', 
            status=THRESHOLD_LOGGER_HTTP_STATUS
        )
        assert response.status_code == THRESHOLD_LOGGER_HTTP_STATUS
        assert response.content == b'Threshold error'

    def test_logged_response_below_threshold(self) -> None:
        """Test LoggedHttpResponse below threshold status."""
        response = LoggedHttpResponse(
            content='Below threshold', 
            status=THRESHOLD_LOGGER_HTTP_STATUS - 1
        )
        assert response.status_code == THRESHOLD_LOGGER_HTTP_STATUS - 1

    def test_logged_response_no_status(self) -> None:
        """Test LoggedHttpResponse without explicit status."""
        response = LoggedHttpResponse(content='No status')
        assert response.content == b'No status'

    def test_logged_response_empty_content(self) -> None:
        """Test LoggedHttpResponse with empty content."""
        response = LoggedHttpResponse(status=404)
        assert response.status_code == 404
        assert response.content == b''
