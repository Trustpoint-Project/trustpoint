"""Django management command to auto-configure Trustpoint from environment variables."""

import ipaddress
import os
import sys
from pathlib import Path
from typing import Any

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, transaction
from django.db.models import ProtectedError

from management.models import KeyStorageConfig
from management.nginx_paths import NGINX_CERT_CHAIN_PATH, NGINX_CERT_PATH, NGINX_KEY_PATH
from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.models import SetupWizardCompletedModel
from setup_wizard.tls_credential import TlsServerCredentialGenerator
from setup_wizard.views import execute_shell_script


UPDATE_TLS_NGINX = Path('/etc/trustpoint/wizard/update_tls_nginx.sh')


class Command(BaseCommand):
    """Auto-configure Trustpoint from environment variables."""

    help = 'Auto-configure Trustpoint from environment variables, bypassing the setup wizard'

    def _env_value(self, name: str, *, required: bool = True, default: str | None = None) -> str | None:
        """Get an environment variable value."""
        value = os.getenv(name)
        if value is None or value.strip() == '':
            if required:
                err_msg = f'Required environment variable {name} is not set'
                raise CommandError(err_msg)
            return default
        return value.strip()

    def _env_bool(self, name: str, *, default: bool = False) -> bool:
        """Get a boolean environment variable."""
        raw_value = os.getenv(name)
        if raw_value is None or raw_value.strip() == '':
            return default
        return raw_value.strip().lower() in {'1', 'true', 'yes', 'on'}

    def _create_superuser(self, username: str, password: str, email: str) -> None:
        """Create the superuser account."""
        self.stdout.write('Creating superuser...')
        try:
            if User.objects.filter(username=username).exists():
                self.stdout.write(self.style.WARNING(f'User {username} already exists, skipping creation'))
                return

            call_command('createsuperuser', interactive=False, username=username, email=email)
            user = User.objects.get(username=username)
            user.set_password(password)
            user.save()
            self.stdout.write(self.style.SUCCESS(f'Superuser {username} created successfully'))
        except Exception as e:
            err_msg = f'Failed to create superuser: {e}'
            raise CommandError(err_msg) from e

    def _configure_storage(self) -> None:
        """Configure cryptographic storage (currently only SOFTWARE supported)."""
        self.stdout.write('Configuring crypto storage...')
        try:
            key_storage_config = KeyStorageConfig.get_or_create_default()
            key_storage_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
            key_storage_config.save(update_fields=['storage_type'])
            self.stdout.write(self.style.SUCCESS('Crypto storage configured'))
        except Exception as e:
            err_msg = f'Failed to configure storage: {e}'
            raise CommandError(err_msg) from e

    def _parse_csv_list(self, value: str | None) -> list[str]:
        """Parse comma-separated values into a list."""
        if not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    def _generate_tls_credential(
        self,
        ipv4_addresses: list[str],
        ipv6_addresses: list[str],
        dns_names: list[str],
    ) -> CredentialModel:
        """Generate TLS server credential."""
        self.stdout.write('Generating TLS server credential...')
        try:
            parsed_ipv4 = [ipaddress.IPv4Address(addr) for addr in ipv4_addresses]
            parsed_ipv6 = [ipaddress.IPv6Address(addr) for addr in ipv6_addresses]

            generator = TlsServerCredentialGenerator(
                ipv4_addresses=parsed_ipv4,
                ipv6_addresses=parsed_ipv6,
                domain_names=dns_names,
            )
            tls_credential_serializer = generator.generate_tls_server_credential()

            with transaction.atomic():
                credential_model = CredentialModel.save_credential_serializer(
                    credential_serializer=tls_credential_serializer,
                    credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
                )

            self.stdout.write(self.style.SUCCESS('TLS server credential generated'))
            return credential_model

        except (ValueError, DjangoValidationError, ProtectedError, TypeError) as e:
            err_msg = f'Failed to generate TLS credential: {e}'
            raise CommandError(err_msg) from e

    def _apply_tls_credential(self, credential_model: CredentialModel) -> None:
        """Apply TLS credential to nginx."""
        self.stdout.write('Applying TLS credential...')
        try:
            active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
            active_tls.credential = credential_model
            active_tls.save()

            self._write_pem_files(credential_model)
            execute_shell_script(UPDATE_TLS_NGINX, 'no_hsm')

            self.stdout.write(self.style.SUCCESS('TLS credential applied'))
        except Exception as e:
            err_msg = f'Failed to apply TLS credential: {e}'
            raise CommandError(err_msg) from e

    def _write_pem_files(self, credential_model: CredentialModel) -> None:
        """Write TLS certificate and key files to disk."""
        private_key_pem = credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
        certificate_pem = credential_model.get_certificate_serializer().as_pem().decode()
        trust_store_pem = credential_model.get_certificate_chain_serializer().as_pem().decode()

        NGINX_KEY_PATH.write_text(private_key_pem)
        NGINX_CERT_PATH.write_text(certificate_pem)

        if trust_store_pem.strip():
            NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)
        elif NGINX_CERT_CHAIN_PATH.exists():
            NGINX_CERT_CHAIN_PATH.unlink()

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the auto-setup command."""
        del args
        del options

        self.stdout.write(self.style.WARNING('=== Trustpoint Auto-Setup from Environment Variables ==='))

        if SetupWizardCompletedModel.setup_wizard_completed():
            self.stdout.write(self.style.WARNING('Setup wizard already completed, skipping auto-setup'))
            return

        try:
            username = self._env_value('TP_ADMIN_USERNAME', required=True)
            password = self._env_value('TP_ADMIN_PASSWORD', required=True)
            email = self._env_value('TP_ADMIN_EMAIL', required=False, default='') or ''

            inject_demo_data = self._env_bool('TP_INJECT_DEMO_DATA', default=False)

            tls_ipv4_raw = self._env_value('TP_TLS_IPV4_ADDRESSES', required=False, default='') or ''
            tls_ipv6_raw = self._env_value('TP_TLS_IPV6_ADDRESSES', required=False, default='') or ''
            tls_dns_raw = self._env_value('TP_TLS_DNS_NAMES', required=False, default='') or ''
            
            tls_ipv4 = self._parse_csv_list(tls_ipv4_raw)
            tls_ipv6 = self._parse_csv_list(tls_ipv6_raw)
            tls_dns = self._parse_csv_list(tls_dns_raw)

            if not tls_ipv4 and not tls_ipv6 and not tls_dns:
                tls_ipv4 = ['127.0.0.1']
                tls_ipv6 = ['::1']
                tls_dns = ['localhost']

            with transaction.atomic():
                if not isinstance(username, str) or not isinstance(password, str):
                    err_msg = 'Username and password must be strings'
                    raise CommandError(err_msg)
                self._create_superuser(username, password, email)

                self._configure_storage()

                self.stdout.write('Creating default certificate profiles...')
                call_command('create_default_cert_profiles')
                self.stdout.write(self.style.SUCCESS('Certificate profiles created'))

                if inject_demo_data:
                    self.stdout.write('Injecting demo data...')
                    call_command('add_domains_and_devices')
                    self.stdout.write(self.style.SUCCESS('Demo data injected'))

                self.stdout.write('Executing notifications...')
                call_command('execute_all_notifications')
                self.stdout.write(self.style.SUCCESS('Notifications executed'))

                credential_model = self._generate_tls_credential(tls_ipv4, tls_ipv6, tls_dns)
                self._apply_tls_credential(credential_model)

                SetupWizardCompletedModel.mark_setup_complete_once()
                self.stdout.write(self.style.SUCCESS('Setup marked as complete'))

            self.stdout.write(self.style.SUCCESS('=== Auto-setup completed successfully ==='))

        except CommandError:
            raise
        except (DatabaseError, FileNotFoundError, OSError, ProtectedError, RuntimeError, TypeError, ValueError) as e:
            err_msg = f'Auto-setup failed: {e}'
            raise CommandError(err_msg) from e
