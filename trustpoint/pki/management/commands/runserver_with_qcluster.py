"""Management command to run the development server and Django-Q2 qcluster together."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """Run the Django development server and Django-Q2 qcluster in parallel.

    This command starts both processes and handles shutdown gracefully when Ctrl+C is pressed.
    """

    help = 'Run the Django development server and Django-Q2 qcluster together'

    def add_arguments(self, parser: Any) -> None:
        """Add command line arguments."""
        parser.add_argument(
            '--port',
            type=int,
            default=None,
            help='Port for the development server (default: 8000 for HTTP, 443 for HTTPS)'
        )
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Host for the development server (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--https',
            action='store_true',
            help='Run HTTPS server using test certificates from tests/data/x509/'
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command."""
        use_https = options['https']
        host = options['host']

        # Set default port based on HTTPS option
        if options['port'] is None:
            port = 443 if use_https else 8000
        else:
            port = options['port']

        protocol = 'https' if use_https else 'http'
        self.stdout.write(self.style.SUCCESS('Starting Django development server and Django-Q2 qcluster...'))
        self.stdout.write(f'Server will be available at: {protocol}://{host}:{port}')
        if use_https:
            self.stdout.write(self.style.WARNING('Using test certificates from tests/data/x509/'))
        self.stdout.write('Press Ctrl+C to stop both processes\n')

        processes = []
        
        # Get the directory where manage.py is located
        manage_py_dir = Path(__file__).resolve().parents[4] / 'trustpoint'
        os.chdir(manage_py_dir)

        try:
            # Start qcluster
            self.stdout.write(self.style.WARNING('[qcluster] Starting...'))
            qcluster_process = subprocess.Popen(
                [sys.executable, '-m', 'django', 'qcluster'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(manage_py_dir)
            )
            processes.append(('qcluster', qcluster_process))

            # Build runserver command
            if use_https:
                # Find the project root (where tests/ directory is)
                project_root = Path(__file__).resolve().parents[4]
                cert_path = project_root / 'tests' / 'data' / 'x509' / 'https_server.crt'
                key_path = project_root / 'tests' / 'data' / 'x509' / 'https_server.pem'

                if not cert_path.exists() or not key_path.exists():
                    self.stdout.write(self.style.ERROR(f'Certificate files not found:'))
                    self.stdout.write(self.style.ERROR(f'  Cert: {cert_path}'))
                    self.stdout.write(self.style.ERROR(f'  Key: {key_path}'))
                    raise FileNotFoundError('HTTPS certificates not found')

                self.stdout.write(self.style.WARNING(f'[runserver_plus] Starting HTTPS server on {host}:{port}...'))
                runserver_cmd = [
                    sys.executable, '-m', 'django', 'runserver_plus',
                    f'{host}:{port}',
                    '--cert-file', str(cert_path),
                    '--key-file', str(key_path)
                ]
            else:
                self.stdout.write(self.style.WARNING(f'[runserver] Starting on {host}:{port}...'))
                runserver_cmd = [sys.executable, '-m', 'django', 'runserver', f'{host}:{port}']

            runserver_process = subprocess.Popen(
                runserver_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(manage_py_dir)
            )
            processes.append(('runserver', runserver_process))

            # Monitor output from both processes
            import select

            readable = [qcluster_process.stdout, runserver_process.stdout]

            while True:
                # Check if processes are still running
                if qcluster_process.poll() is not None:
                    self.stdout.write(self.style.ERROR('[qcluster] Process terminated unexpectedly'))
                    break
                if runserver_process.poll() is not None:
                    self.stdout.write(self.style.ERROR('[runserver] Process terminated unexpectedly'))
                    break

                # Read output from whichever process has data ready
                ready, _, _ = select.select(readable, [], [], 0.1)

                for stream in ready:
                    line = stream.readline()
                    if line:
                        if stream == qcluster_process.stdout:
                            self.stdout.write(f'[qcluster] {line.rstrip()}')
                        elif stream == runserver_process.stdout:
                            self.stdout.write(f'[runserver] {line.rstrip()}')

        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\n\nShutting down...'))

        finally:
            # Terminate all processes gracefully
            for name, process in processes:
                if process.poll() is None:  # Process is still running
                    self.stdout.write(f'[{name}] Stopping...')
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                        self.stdout.write(self.style.SUCCESS(f'[{name}] Stopped'))
                    except subprocess.TimeoutExpired:
                        self.stdout.write(self.style.ERROR(f'[{name}] Force killing...'))
                        process.kill()
                        process.wait()

            self.stdout.write(self.style.SUCCESS('\nAll processes stopped successfully'))
