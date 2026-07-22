"""Unit tests for the discovery network scanner."""

from __future__ import annotations

import concurrent.futures
from threading import Event
from unittest.mock import MagicMock, Mock, patch

from discovery.scanner import OTScanner


def _context_manager(value: object) -> MagicMock:
    """Build a simple context manager mock that yields the given value."""
    manager = MagicMock()
    manager.__enter__.return_value = value
    manager.__exit__.return_value = False
    return manager


class TestOTScanner:
    """Tests for OTScanner."""

    def test_get_ips_from_range_is_inclusive_and_handles_invalid_input(self) -> None:
        """IP ranges should include both endpoints and reject invalid addresses."""
        scanner = OTScanner(target_ports=[])

        assert scanner._get_ips_from_range('192.168.10.1', '192.168.10.3') == [
            '192.168.10.1',
            '192.168.10.2',
            '192.168.10.3',
        ]
        assert scanner._get_ips_from_range('invalid', '192.168.10.3') == []

    def test_resolve_hostname_prefers_reverse_lookup_and_falls_back_to_fqdn(self) -> None:
        """Hostname resolution should use reverse DNS first, then FQDN fallback."""
        scanner = OTScanner(target_ports=[])

        with patch('discovery.scanner.socket.getnameinfo', return_value=('host.example', None)):
            assert scanner._resolve_hostname('192.168.10.2') == 'host.example'

        with (
            patch('discovery.scanner.socket.getnameinfo', side_effect=OSError),
            patch('discovery.scanner.socket.getfqdn', return_value='fallback.example'),
        ):
            assert scanner._resolve_hostname('192.168.10.2') == 'fallback.example'

        with (
            patch('discovery.scanner.socket.getnameinfo', side_effect=OSError),
            patch('discovery.scanner.socket.getfqdn', return_value='192.168.10.2'),
        ):
            assert scanner._resolve_hostname('192.168.10.2') == ''

    def test_resolve_hostname_returns_empty_when_stop_is_requested(self) -> None:
        """Resolution should abort immediately once shutdown is requested."""
        scanner = OTScanner(target_ports=[])
        scanner.stop_requested.set()

        assert scanner._resolve_hostname('192.168.10.2') == ''

    def test_get_ssl_info_returns_certificate_metadata(self) -> None:
        """Successful TLS handshakes should expose certificate details."""
        scanner = OTScanner(target_ports=[])
        socket_mock = Mock()
        ssl_socket = Mock()
        ssl_socket.getpeercert.return_value = b'binary-cert'
        ssl_context = Mock()
        ssl_context.wrap_socket.return_value = _context_manager(ssl_socket)

        issuer = Mock()
        issuer.rfc4514_string.return_value = 'CN=issuer'
        subject = Mock()
        subject.rfc4514_string.return_value = 'CN=subject'
        cert = Mock()
        cert.issuer = issuer
        cert.subject = subject

        with (
            patch('discovery.scanner.socket.create_connection', return_value=_context_manager(socket_mock)),
            patch('discovery.scanner.ssl.create_default_context', return_value=ssl_context),
            patch('discovery.scanner.x509.load_der_x509_certificate', return_value=cert),
        ):
            result = scanner._get_ssl_info('192.168.10.2', 443)

        assert result == {
            'ssl_open': True,
            'cert_object': cert,
            'is_self_signed': False,
            'issuer': 'CN=issuer',
            'subject': 'CN=subject',
        }
        assert ssl_context.check_hostname is False
        assert ssl_context.verify_mode == 0

    def test_get_ssl_info_returns_closed_on_handshake_failure(self) -> None:
        """TLS probe failures should be reported as a closed SSL endpoint."""
        scanner = OTScanner(target_ports=[])

        with patch('discovery.scanner.socket.create_connection', side_effect=OSError):
            assert scanner._get_ssl_info('192.168.10.2', 443) == {'ssl_open': False}

    def test_scan_host_collects_open_ports_hostname_and_ssl_info(self) -> None:
        """Host scans should aggregate open ports and attach TLS metadata."""
        scanner = OTScanner(target_ports=[443, 502, 8888])

        def create_connection(address: tuple[str, int], timeout: float) -> MagicMock:
            assert timeout == scanner.timeout
            if address[1] in {443, 502}:
                return _context_manager(Mock())
            raise OSError

        with (
            patch('discovery.scanner.socket.create_connection', side_effect=create_connection),
            patch.object(
                scanner,
                '_get_ssl_info',
                side_effect=[
                    {'ssl_open': True, 'subject': 'CN=device', 'issuer': 'CN=device'},
                    {'ssl_open': False},
                ],
            ) as mock_ssl_info,
            patch.object(scanner, '_resolve_hostname', return_value='plc-01.local') as mock_hostname,
        ):
            result = scanner._scan_host('192.168.10.20')

        assert result == {
            'ip': '192.168.10.20',
            'hostname': 'plc-01.local',
            'ports': [443, 502],
            'ssl_info': {'ssl_open': True, 'subject': 'CN=device', 'issuer': 'CN=device'},
        }
        assert mock_ssl_info.call_count == 2
        mock_hostname.assert_called_once_with('192.168.10.20')

    def test_scan_host_returns_none_when_no_ports_open_or_stop_requested(self) -> None:
        """Host scans should produce no result if nothing is reachable or shutdown starts."""
        scanner = OTScanner(target_ports=[443])

        with patch('discovery.scanner.socket.create_connection', side_effect=OSError):
            assert scanner._scan_host('192.168.10.20') is None

        scanner.stop_requested.set()
        assert scanner._scan_host('192.168.10.20') is None

    def test_scan_network_collects_results_and_ignores_cancelled_or_failed_futures(self) -> None:
        """Network scans should keep successful results and skip cancelled or broken futures."""
        scanner = OTScanner(target_ports=[443])
        future_ok = Mock()
        future_ok.result.return_value = {'ip': '192.168.10.10', 'ports': [443], 'hostname': '', 'ssl_info': {}}
        future_none = Mock()
        future_none.result.return_value = None
        future_cancelled = Mock()
        future_cancelled.result.side_effect = concurrent.futures.CancelledError()
        future_error = Mock()
        future_error.result.side_effect = RuntimeError('boom')

        executor = MagicMock()
        executor.__enter__.return_value = executor
        executor.__exit__.return_value = False
        executor.submit.side_effect = [future_ok, future_none, future_cancelled, future_error]

        with (
            patch.object(scanner, '_get_ips_from_range', return_value=['.10', '.11', '.12', '.13']),
            patch('discovery.scanner.concurrent.futures.ThreadPoolExecutor', return_value=executor),
            patch(
                'discovery.scanner.concurrent.futures.as_completed',
                return_value=[future_ok, future_none, future_cancelled, future_error],
            ),
        ):
            results = scanner.scan_network('192.168.10.10', '192.168.10.13')

        assert results == [{'ip': '192.168.10.10', 'ports': [443], 'hostname': '', 'ssl_info': {}}]

    def test_scan_network_requests_executor_shutdown_after_stop_signal(self) -> None:
        """Network scans should stop consuming futures after a stop request."""
        scanner = OTScanner(target_ports=[443])
        future = Mock()
        future.result.return_value = {'ip': '192.168.10.10'}

        executor = MagicMock()
        executor.__enter__.return_value = executor
        executor.__exit__.return_value = False
        executor.submit.return_value = future

        def stopped_iterator(_future_map: dict[Mock, str]):
            scanner.stop_requested.set()
            yield future

        with (
            patch.object(scanner, '_get_ips_from_range', return_value=['192.168.10.10']),
            patch('discovery.scanner.concurrent.futures.ThreadPoolExecutor', return_value=executor),
            patch('discovery.scanner.concurrent.futures.as_completed', side_effect=stopped_iterator),
        ):
            results = scanner.scan_network('192.168.10.10', '192.168.10.10')

        assert results == []
        executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_scan_network_clears_previous_stop_request_before_scanning(self) -> None:
        """A new scan should always clear an earlier stop request."""
        scanner = OTScanner(target_ports=[443])
        scanner.stop_requested = Event()
        scanner.stop_requested.set()

        executor = MagicMock()
        executor.__enter__.return_value = executor
        executor.__exit__.return_value = False

        with (
            patch.object(scanner, '_get_ips_from_range', return_value=[]),
            patch('discovery.scanner.concurrent.futures.ThreadPoolExecutor', return_value=executor),
        ):
            assert scanner.scan_network('192.168.10.10', '192.168.10.10') == []

        assert scanner.stop_requested.is_set() is False
