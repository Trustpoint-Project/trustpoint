"""Bootstrap-phase startup preparation for Trustpoint."""

from __future__ import annotations

import io
import logging
import os
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand
from django.db import connection
from packaging.version import InvalidVersion, Version

from management.util.output_wrapper import CommandOutputWrapper
from management.util.startup_strategies import BootstrapTlsMaterialStrategy, StartupContext, WizardState
from setup_wizard.models import SetupWizardCompletedModel, SetupWizardConfigModel
from setup_wizard.tls_credential import load_staged_tls_credential

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Prepare the isolated bootstrap runtime without operational dependencies."""

    help = 'Prepare Trustpoint bootstrap mode using the bootstrap SQLite database.'

    def handle(self, **_options: dict[str, object]) -> None:
        """Entrypoint for the command."""
        if not getattr(settings, 'TRUSTPOINT_IS_BOOTSTRAP', False):
            msg = 'bootstrap_manager may only run with TRUSTPOINT_PHASE=bootstrap.'
            raise CommandError(msg)

        output = CommandOutputWrapper(self.stdout, self.style)
        output.write('=== Starting Trustpoint Bootstrap Sequence ===')
        output.write(f"Bootstrap database: {settings.DATABASES['default']['NAME']}")

        output.write('Preparing bootstrap database schema...')
        self._prepare_bootstrap_database()
        self._create_bootstrap_login(output)

        completed_row, _ = SetupWizardCompletedModel.objects.get_or_create(
            singleton_id=SetupWizardCompletedModel.SINGLETON_ID
        )
        config = SetupWizardConfigModel.get_singleton()
        self._seed_operational_database_defaults(config, output)
        current_step = config.FreshInstallCurrentStep(config.fresh_install_current_step)
        output.write(f'Bootstrap wizard completed: {completed_row.setup_completed_at is not None}')
        output.write(f'Bootstrap wizard current step: {current_step.name}')

        context = StartupContext(
            current_version=self._parse_version(settings.APP_VERSION),
            db_version=None,
            wizard_state_enum=WizardState.INCOMPLETE,
            wizard_current_step=current_step,
            backend_kind=None,
            appsecrets_configured=False,
            has_staged_tls=self._has_staged_tls(),
            output=output,
        )
        BootstrapTlsMaterialStrategy().apply(context)

        self._collect_static_files(output)
        self._compile_messages(output)
        output.write(output.success('=== Bootstrap Sequence Completed Successfully ==='))

    @staticmethod
    def _prepare_bootstrap_database() -> None:
        """Prepare only the schema needed by the bootstrap web surface."""
        for app_label in ('contenttypes', 'auth', 'sessions'):
            call_command('migrate', app_label, interactive=False, verbosity=0)

        existing_tables = set(connection.introspection.table_names())
        bootstrap_models = (SetupWizardCompletedModel, SetupWizardConfigModel)
        with connection.schema_editor() as schema_editor:
            for model in bootstrap_models:
                if model._meta.db_table not in existing_tables:
                    schema_editor.create_model(model)
                else:
                    Command._add_missing_bootstrap_columns(schema_editor, model)

    @staticmethod
    def _add_missing_bootstrap_columns(schema_editor: object, model: type[object]) -> None:
        """Add newly introduced bootstrap columns without running operational migrations."""
        with connection.cursor() as cursor:
            existing_columns = {
                column.name
                for column in connection.introspection.get_table_description(cursor, model._meta.db_table)
            }
        for field in model._meta.local_fields:
            if field.primary_key or field.column in existing_columns:
                continue
            schema_editor.add_field(model, field)

    @staticmethod
    def _create_bootstrap_login(output: CommandOutputWrapper) -> None:
        """Create or rotate the temporary bootstrap login and log the password."""
        username = getattr(settings, 'TRUSTPOINT_BOOTSTRAP_USERNAME', 'tp-admin')
        password = secrets.token_urlsafe(8)
        user_model = get_user_model()
        user, _created = user_model.objects.get_or_create(
            username=username,
            defaults={
                'email': '',
                'is_staff': True,
                'is_superuser': True,
            },
        )
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.set_password(password)
        user.save()

        messages = (
            'Trustpoint bootstrap login generated.',
            f'Trustpoint bootstrap username: {username}',
            f'Trustpoint bootstrap password: {password}',
        )
        for message in messages:
            logger.warning(message)
            output.write(message)

    @staticmethod
    def _seed_operational_database_defaults(config: SetupWizardConfigModel, output: CommandOutputWrapper) -> None:
        """Seed the wizard DB step from container env without making bootstrap use PostgreSQL."""
        if config.fresh_install_database_submitted or config.operational_config_applied:
            return

        env_defaults = {
            'operational_db_host': os.getenv('DATABASE_HOST'),
            'operational_db_port': os.getenv('DATABASE_PORT'),
            'operational_db_name': os.getenv('POSTGRES_DB'),
            'operational_db_user': os.getenv('DATABASE_USER'),
            'operational_db_password': os.getenv('DATABASE_PASSWORD'),
        }
        update_fields = []
        for field_name, env_value in env_defaults.items():
            if env_value in (None, ''):
                continue

            field = config._meta.get_field(field_name)
            default_value = field.get_default()
            current_value = getattr(config, field_name)
            if current_value not in ('', None, default_value):
                continue

            if field_name == 'operational_db_port':
                try:
                    value = int(env_value)
                except ValueError:
                    continue
            else:
                value = env_value

            setattr(config, field_name, value)
            update_fields.append(field_name)

        if update_fields:
            config.save(update_fields=update_fields)
            output.write('Seeded operational database defaults from container environment.')

    @staticmethod
    def _parse_version(version_str: str) -> Version:
        """Parse and validate the application version."""
        try:
            return Version(version_str)
        except InvalidVersion as exc:
            msg = f'Invalid version format: {version_str}'
            raise CommandError(msg) from exc

    @staticmethod
    def _has_staged_tls() -> bool:
        """Return whether the bootstrap wizard already staged TLS material."""
        try:
            return load_staged_tls_credential() is not None
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _collect_static_files(output: CommandOutputWrapper) -> None:
        """Collect static files for nginx."""
        output.write('Collecting static files...')
        with io.StringIO() as fake_out:
            call_command('collectstatic', '--noinput', stdout=fake_out)

    @staticmethod
    def _compile_messages(output: CommandOutputWrapper) -> None:
        """Compile translation messages."""
        output.write('Compiling translation messages...')
        with io.StringIO() as fake_out:
            call_command('compilemessages', '-l', 'de', '-l', 'en', stdout=fake_out)
