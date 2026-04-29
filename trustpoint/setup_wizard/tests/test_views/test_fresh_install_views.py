"""Tests for the redesigned fresh-install wizard views."""

from unittest.mock import Mock

from django.test import SimpleTestCase

from setup_wizard.views import FreshInstallFormBaseView, FreshInstallSummaryTruststoreDownloadView, FreshInstallTlsConfigView


class FreshInstallTlsConfigViewTests(SimpleTestCase):
    """Small unit tests for current fresh-install helpers."""

    def test_format_csv_initial_with_values(self) -> None:
        self.assertEqual(FreshInstallTlsConfigView._format_csv_initial(['a', 'b']), 'a, b, ')

    def test_format_csv_initial_without_values(self) -> None:
        self.assertEqual(FreshInstallTlsConfigView._format_csv_initial([]), '')

    def test_get_step_state_active(self) -> None:
        step = Mock()
        self.assertEqual(
            FreshInstallFormBaseView._get_step_state(step, step, Mock(), is_submitted=False),
            FreshInstallFormBaseView.StepState.ACTIVE,
        )


class FreshInstallSummaryTruststoreDownloadViewTests(SimpleTestCase):
    """Tests for summary truststore download helper behavior."""

    def setUp(self) -> None:
        self.root_ca_serializer = Mock()
        self.root_ca_serializer.as_pem.return_value = b'pem'
        self.root_ca_serializer.as_der.return_value = b'der'

        self.tls_credential = Mock()
        self.tls_credential.get_root_ca_certificate_serializer.return_value = self.root_ca_serializer

    def test_get_root_ca_certificate_and_content_type_for_pem(self) -> None:
        content, content_type = FreshInstallSummaryTruststoreDownloadView._get_root_ca_certificate_and_content_type(
            self.tls_credential,
            'pem',
        )

        self.assertEqual(content, b'pem')
        self.assertEqual(content_type, 'application/x-pem-file')

    def test_get_root_ca_certificate_and_content_type_for_der(self) -> None:
        content, content_type = FreshInstallSummaryTruststoreDownloadView._get_root_ca_certificate_and_content_type(
            self.tls_credential,
            'der',
        )

        self.assertEqual(content, b'der')
        self.assertEqual(content_type, 'application/pkix-cert')
