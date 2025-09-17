"""Management command to test KEK loading and DEK unwrapping for PKCS11Token.

Usage:
    python manage.py unwrap_dek [--token-label <label>]
"""


import argparse
from typing import TYPE_CHECKING

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from management.models import PKCS11Token


DEK_EXPECTED_LENGTH = 32

class Command(BaseCommand, LoggerMixin):
    """A Django management command to test KEK loading and DEK unwrapping for PKCS11Token.

    This command allows testing of Key Encryption Key (KEK) loading and Data Encryption Key (DEK)
    unwrapping for a specified PKCS11 token. It supports specifying a token label or defaults to
    the first available token.
    """
    help = 'Test KEK loading and DEK unwrapping for PKCS11Token'

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-line arguments to the parser.

        Parameters
        ----------
        parser : ArgumentParser
            The argument parser instance to which arguments are added.
        """
        parser.add_argument(
            '--token-label',
            type=str,
            help='Specific token label to test (uses first token if not specified)',
        )

    def handle(self, *args: str, **options: dict) -> None:
        """Handle the management command execution.

        This method retrieves the specified PKCS11 token (or the first available one),
        tests the Key Encryption Key (KEK) loading, and attempts to unwrap the Data Encryption Key (DEK).

        Parameters
        ----------
        *args : tuple
            Positional arguments passed to the command.
        **options : dict
            Keyword arguments passed to the command, including 'token_label'.

        Raises:
        ------
        Exception
            If any error occurs during KEK loading or DEK unwrapping.
        """
        del args  # Unused
        token_label = options.get('token_label')
        from settings.models import PKCS11Token

        try:
            # Get the token
            if token_label:
                try:
                    token = PKCS11Token.objects.get(label=token_label)
                except ObjectDoesNotExist:
                    self.log_and_stdout(
                        f'Token with label "{token_label}" not found. '
                        f'This may be expected behavior if the token is not yet created.',
                        level='error'
                    )
                    return
            else:
                token = PKCS11Token.objects.first()
                if not token:
                    self.log_and_stdout(
                        'No PKCS11 tokens found. This may be expected behavior if no tokens are created yet.',
                        level='error'
                    )
                    return

            self.log_and_stdout(f'Testing KEK and DEK for token: {token.label}')

            # Test 1: Load KEK
            self._test_kek_loading(token)

            # Test 2: Unwrap DEK (only if we have one)
            if token.encrypted_dek:
                self._test_dek_unwrapping(token)
            else:
                self.log_and_stdout(f'No encrypted DEK found for token "{token.label}"', level='warning')

        except Exception as e:
            self.log_and_stdout(f'KEK/DEK testing failed: {e}', level='error')
            raise

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout.

        Parameters
        ----------
        message : str
            The message to log and print.
        level : str
            The logging level ('info', 'warning', 'error', etc.).
        """
        # Log the message
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(message)

        # Write to stdout
        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'info':
            self.stdout.write(self.style.INFO(message))
        else:
            self.stdout.write(self.style.SUCCESS(message))

    def _test_kek_loading(self, token: 'PKCS11Token') -> None:
        """Test loading the KEK (Key Encryption Key)."""
        self.log_and_stdout('Testing KEK loading...')

        from pki.models import PKCS11Key

        try:
            # Get the KEK record
            if token.kek:
                kek_record = token.kek
            else:
                try:
                    kek_record = PKCS11Key.objects.get(
                        token_label=token.label,
                        key_label=token.KEK_ENCRYPTION_KEY_LABEL,
                        key_type=PKCS11Key.KeyType.AES
                    )
                except ObjectDoesNotExist:
                    self.log_and_stdout(f'KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" not found in database', level='error')
                    return

            # Get the AES key instance
            aes_key = kek_record.get_pkcs11_key_instance(
                lib_path=token.module_path,
                user_pin=token.get_pin()
            )

            try:
                aes_key.load_aes_key()
                self.log_and_stdout(f'KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" loaded successfully')
            finally:
                aes_key.close()

        except Exception as e:
            if 'no such key' in str(e).lower():
                self.log_and_stdout(f'KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" not found in HSM', level='error')
            else:
                self.log_and_stdout('KEK loading failed', level='error')
            raise

    def _test_dek_unwrapping(self, token: 'PKCS11Token') -> None:
        """Test unwrapping the DEK."""
        self.log_and_stdout('Testing DEK unwrapping...')

        try:
            # Clear any cached DEK to force unwrapping
            token.clear_dek_cache()

            dek = token.get_dek()

            # Unwrap the DEK
            if dek and len(dek) == DEK_EXPECTED_LENGTH:

                self.log_and_stdout(f'DEK unwrapped successfully ({len(dek)} bytes)')
            else:
                self.log_and_stdout(f'Invalid DEK (expected {DEK_EXPECTED_LENGTH} bytes, '
                                     f'got {len(dek) if dek else 0})', level='error')

        except Exception:
            self.log_and_stdout('DEK unwrapping failed', level='error')
            raise
