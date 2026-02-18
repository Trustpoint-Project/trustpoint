"""CMP Mock Server that integrates CMP factory and key generation factory."""

import binascii
import logging
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from django.test.client import RequestFactory
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc4210

from trustpoint.logger import LoggerMixin


class CMPMockRequestHandler(BaseHTTPRequestHandler, LoggerMixin):
    """HTTP handler that captures and analyzes CMP requests."""

    def do_POST(self):
        """Handle POST requests (CMP messages)."""
        self.logger.info('=== CMP Request Captured ===')
        self.logger.info(f'Path: {self.path}')
        self.logger.info(f'Headers: {dict(self.headers)}')

        content_length = int(self.headers.get('Content-Length', 0))
        raw_data = self.rfile.read(content_length)

        self.logger.info(f'Body size: {len(raw_data)} bytes')
        self.logger.debug(f'Raw data (hex): {binascii.hexlify(raw_data).decode()}')

        request_factory = RequestFactory()

        extra_headers = {}
        for key, value in self.headers.items():
            if key.lower() not in ['content-type', 'content-length']:
                header_key = f'HTTP_{key.upper().replace("-", "_")}'
                extra_headers[header_key] = value

        django_request = request_factory.post(
            path=self.path,
            data=raw_data,
            content_type=self.headers.get('Content-Type', 'application/pkixcmp'),
            **extra_headers,
        )

        try:
            cmp_message, _ = decoder.decode(raw_data, asn1Spec=rfc4210.PKIMessage())
            self.logger.info('Successfully decoded CMP message')
        except Exception as e:
            self.logger.error(f'Failed to decode CMP message: {e}')
            cmp_message = None

        if hasattr(self.server, 'test_runner'):
            self.server.test_runner.captured_request = django_request
            self.server.test_runner.captured_cmp_message = cmp_message
            self.server.test_runner.captured_path = self.path
            self.server.test_runner.captured_headers = dict(self.headers)
            self.server.test_runner.captured_content_length = content_length
            self.server.test_runner.capture_complete_event.set()

        error_response = b'test'
        self.send_response(200)
        self.send_header('Content-Type', 'application/pkixcmp')
        self.send_header('Content-Length', str(len(error_response)))
        self.end_headers()
        self.wfile.write(error_response)

        threading.Thread(target=self._shutdown_server, daemon=True).start()

    def _shutdown_server(self):
        """Shutdown the server after a short delay."""
        time.sleep(0.5)
        if hasattr(self.server, 'test_runner') and self.server.test_runner.server:
            self.server.test_runner.server.shutdown()

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        self.logger.info(format % args)


class CMPMockServer(LoggerMixin):
    """Mock CMP server that integrates with CMP and key generation factories."""

    def __init__(self, cmp_factory=None, keygen_factory=None, host: str = 'localhost', port: int = 8443):
        """Initialize the mock CMP server.

        Args:
            cmp_factory: CMP command factory (CompositeCMPCommand)
            keygen_factory: Key generation factory (CompositeKeyGenerator)
            host: Server host
            port: Server port
        """
        self.cmp_factory = cmp_factory
        self.keygen_factory = keygen_factory
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None

        self.captured_request = None
        self.captured_cmp_message = None
        self.captured_path = None
        self.captured_headers = None
        self.captured_content_length = None
        self.capture_complete_event = threading.Event()

    def generate_key_if_needed(self, temp_dir: str, context: dict[str, Any]) -> bool:
        """Generate key using the key generation factory if provided."""
        if not self.keygen_factory:
            self.logger.info('No key generation factory provided, skipping key generation')
            return True

        try:
            self.logger.info(f'Generating key using: {self.keygen_factory.get_description()}')

            context['temp_dir'] = temp_dir

            key_gen_command = self.keygen_factory.build_command(context)
            self.logger.info(f'Key generation command: {" ".join(key_gen_command)}')

            result = subprocess.run(
                key_gen_command, capture_output=True, text=True, timeout=30, cwd=temp_dir, check=False
            )

            if result.returncode == 0:
                self.logger.info('Key generation successful')
                return True
            self.logger.error(f'Key generation failed: {result.stderr}')
            return False

        except Exception as e:
            self.logger.error(f'Key generation error: {e}')
            return False

    def execute_cmp_command(self, temp_dir: str, context: dict[str, Any]) -> bool:
        """Execute CMP command using the CMP factory."""
        if not self.cmp_factory:
            self.logger.error('No CMP factory provided')
            return False

        try:
            prepared_files = self.cmp_factory.prepare_files(temp_dir, context)
            self.logger.info(f'Prepared CMP files: {prepared_files}')

            cmp_command = self.cmp_factory.build_args(context)
            self.logger.info(f'CMP command: {" ".join(cmp_command)}')

            result = subprocess.run(cmp_command, capture_output=True, text=True, timeout=30, cwd=temp_dir, check=False)

            self.logger.info(f'CMP command exit code: {result.returncode}')
            if result.stdout:
                self.logger.debug(f'CMP stdout: {result.stdout}')
            if result.stderr:
                self.logger.warning(f'CMP stderr: {result.stderr}')

            return result.returncode == 0

        except Exception as e:
            self.logger.error(f'CMP command execution error: {e}')
            return False

    def start_server(self):
        """Start the mock HTTP server."""

        class CustomHandler(CMPMockRequestHandler):
            pass

        self.server = HTTPServer((self.host, self.port), CustomHandler)
        self.server.test_runner = self  # Attach reference to self

        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

        self.logger.info(f'Mock CMP server started on http://{self.host}:{self.port}')
        time.sleep(1)  # Give server time to start

    def stop_server(self):
        """Stop the mock HTTP server."""
        if self.server:
            self.server.shutdown()
            self.logger.info('Mock CMP server stopped')

        if self.server_thread:
            self.server_thread.join(timeout=5)

    def run_test(self) -> tuple[Any, Any, Any, Any, Any] | tuple[None, None, None, None, None]:
        """Run the complete test workflow.

        Returns:
            Tuple of (captured_cmp_message, captured_path, captured_headers, captured_content_length)
        """
        temp_dir = tempfile.mkdtemp()
        context = {}

        try:
            self.logger.info('Starting CMP mock server test workflow')

            self.start_server()

            if not self.generate_key_if_needed(temp_dir, context):
                self.logger.error('Key generation failed, aborting test')
                return None, None, None, None, None

            success = self.execute_cmp_command(temp_dir, context)

            if success:
                if self.capture_complete_event.wait(timeout=30):
                    self.logger.info('CMP request captured successfully')
                else:
                    self.logger.warning('Timeout waiting for CMP request capture')
            else:
                self.logger.warning('CMP command failed, but may have sent request')
                self.capture_complete_event.wait(timeout=10)

            return (
                self.captured_request,
                self.captured_cmp_message,
                self.captured_path,
                self.captured_headers,
                self.captured_content_length,
            )

        finally:
            self.stop_server()
            self._cleanup_temp_dir(temp_dir)

    def _cleanup_temp_dir(self, temp_dir: str):
        """Clean up temporary directory."""
        try:
            import shutil

            shutil.rmtree(temp_dir)
            self.logger.debug(f'Cleaned up temporary directory: {temp_dir}')
        except Exception as e:
            self.logger.warning(f'Could not clean up temporary directory {temp_dir}: {e}')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    try:
        from openssl_cmp_factory import (
            BasicCMPArgs,
            CertificateRequest,
            CompositeCMPCommand,
            ServerConfig,
            SharedSecretAuth,
        )
        from openssl_keygen_factory import CompositeKeyGenerator, KeyFileOutput, RSAKeyGenerator

        cmp_factory = (
            CompositeCMPCommand('test_cmp', 'Test CMP command')
            .add_component(BasicCMPArgs(cmd='cr'))
            .add_component(ServerConfig('http://localhost:8443/.well-known/cmp/test2'))
            .add_component(SharedSecretAuth('33', 'pass:Qj7yJEh6D6BYBXKMhrp1wQ'))
            .add_component(CertificateRequest('/CN=Test-Certificate', 10, '127.0.0.1,localhost'))
        )

        keygen_factory = (
            CompositeKeyGenerator('RSA').add_component(RSAKeyGenerator(4096)).add_component(KeyFileOutput())
        )

        mock_server = CMPMockServer(cmp_factory, keygen_factory, 'localhost', 8443)

        request, cmp_message, path, headers, content_length = mock_server.run_test()

        print('\n=== Test Results ===')
        print(f'Captured CMP message: {cmp_message}')
        print(f'Captured path: {path}')
        print(f'Captured headers: {headers}')
        print(f'Captured content length: {content_length}')

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            mock_server.stop_server()
            print('\nServer stopped')

    except Exception as e:
        print(f'Error: {e}')
