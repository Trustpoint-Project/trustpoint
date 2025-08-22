"""Django backup view."""
import datetime
import io
import logging
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import Http404, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import ListView, View
from util.sftp import SftpClient, SftpError

from settings.forms import BackupOptionsForm
from settings.models import BackupOptions
from trustpoint.views.base import SortableTableMixin

logger = logging.getLogger(__name__)


def get_backup_file_data(filename: str) -> dict[str, Any]:
    """Retrieve metadata for a single backup file.

    Args:
        filename: Name of the backup file.

    Returns:
        A dict with keys:
          - filename: str
          - created_at: str (formatted 'YYYY-MM-DD HH:MM:SS' in UTC)
          - modified_at: str (formatted 'YYYY-MM-DD HH:MM:SS' in UTC)
          - size_kb: str (size in KB to one decimal place)

        Returns an empty dict if the file does not exist or is not a regular file.
    """
    backup_dir: Path = settings.BACKUP_FILE_PATH
    file_path = backup_dir / filename
    if not file_path.exists() or not file_path.is_file():
        return {}
    stat = file_path.stat()
    created_dt = datetime.datetime.fromtimestamp(stat.st_ctime, datetime.UTC)
    modified_dt = datetime.datetime.fromtimestamp(stat.st_mtime, datetime.UTC)
    size_kb = stat.st_size / 1024
    return {
        'filename': filename,
        'created_at': created_dt.strftime('%Y-%m-%d %H:%M:%S'),
        'modified_at': modified_dt.strftime('%Y-%m-%d %H:%M:%S'),
        'size_kb': f'{size_kb:.1f}',
    }


def create_db_backup(path: Path) -> str:
    """Create a compressed database backup file in the given directory.

    The command `manage.py dbbackup -o <filename> -z` is used, producing a `.dump.gz` file under `path`.

    Args:
        path: Directory where backups should be stored.

    Returns:
        The filename of the created backup file.

    Raises:
        OSError: If `path` cannot be created.
        CalledProcessError: If the `dbbackup` command fails.
    """
    path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d_%H-%M-%S')
    filename = f'backup_{timestamp}'
    call_command('trustpointbackup', filename=filename)
    return filename


class BackupManageView(SortableTableMixin, ListView[Any]):
    """Display existing backups and handle backup-related actions.

    GET:
      - Renders a table of existing backup files.
      - Includes a form for editing SFTP/backup settings.

    POST:
      Depending on which button was clicked, performs one of:
        - create_backup: Creates a new database backup (and optionally uploads via SFTP).
        - test_sftp_connection: Validates SFTP credentials without saving them.
        - save_backup_settings: Saves or updates BackupOptions.
        - reset_backup_settings: Deletes existing BackupOptions, reverting to defaults.
    """
    template_name = 'settings/backups/manage_backups.html'
    context_object_name = 'backup_files'
    paginate_by = 20
    default_sort_param = 'filename'
    success_url = reverse_lazy('settings:backups')

    def get_queryset(self) -> Any: # list[dict[str, Any]]
        """Collect metadata for all backup_*.dump.gz files under BACKUP_FILE_PATH."""
        backup_dir: Path = settings.BACKUP_FILE_PATH
        try:
            files = [p.name for p in backup_dir.iterdir() if p.is_file()]
        except (FileNotFoundError, NotADirectoryError):
            return []
        backups = [
            f for f in files if f.startswith('backup_') and f.endswith('.dump.gz')
        ]
        data: list[dict[str, Any]] = [get_backup_file_data(f) for f in backups]
        self.object_list = data
        return data

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the BackupOptions form to the template context."""
        context = super().get_context_data(**kwargs)
        instance, _ = BackupOptions.objects.get_or_create(pk=1)
        context['backup_options_form'] = BackupOptionsForm(instance=instance)
        return context

    def post(self, request: Any, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle form submissions for backup or SFTP settings."""
        if 'create_backup' in request.POST:
            return self._handle_create_backup(request)

        if 'test_sftp_connection' in request.POST:
            return self._handle_test_sftp(request)

        if 'save_backup_settings' in request.POST:
            return self._handle_save_settings(request)

        if 'reset_backup_settings' in request.POST:
            return self._handle_reset_settings(request)

        return redirect(self.success_url)

    def _handle_create_backup(self, request: Any) -> HttpResponse:
        """Logic for creating a new backup and possibly uploading via SFTP."""
        try:
            filename = create_db_backup(settings.BACKUP_FILE_PATH)
            messages.success(request, f'Database backup created successfully: {filename}')
        except (OSError, CommandError) as exc:
            msg = f'Error creating database backup: {exc}'
            messages.error(request, msg)
            return redirect(self.success_url)

        try:
            opts = BackupOptions.objects.get(pk=1)
        except BackupOptions.DoesNotExist:
            messages.warning(request, 'Backup created locally; no SFTP settings found.')
            return redirect(self.success_url)

        overrides = {
            'local_storage': opts.local_storage,
            'sftp_storage': opts.sftp_storage,
            'host': opts.host,
            'port': opts.port,
            'user': opts.user,
            'auth_method': opts.auth_method,
            'password': opts.password or '',
            'private_key': opts.private_key or '',
            'key_passphrase': opts.key_passphrase or '',
            'remote_directory': opts.remote_directory or '',
        }

        try:
            client = SftpClient(overrides=overrides)
        except SftpError as exc:
            messages.warning(request, f'Backup created locally; SFTP cannot be used: {exc}')
            return redirect(self.success_url)

        local_file = settings.BACKUP_FILE_PATH / filename
        if client.auth_method:
            rd = client.remote_directory or ''
            if rd.endswith('/'):
                remote_path = f'{rd}{filename}'
            elif rd:
                remote_path = f'{rd}/{filename}'
            else:
                remote_path = filename

            try:
                client.upload_file(local_file, remote_path)
                messages.success(
                    request, f'Uploaded {filename} via SFTP to {remote_path}.'
                )
            except SftpError as exc:
                messages.error(
                    request, f'Backup created locally; SFTP upload failed: {exc}'
                )

        if not client.store_locally:
            try:
                local_file.unlink()
            except OSError:
                messages.warning(request, f'Could not delete local file {filename}.')

        return redirect(self.success_url)

    def _handle_test_sftp(self, request: Any) -> HttpResponse:
        """Logic for testing SFTP connection without saving settings."""
        instance, _ = BackupOptions.objects.get_or_create(pk=1)
        form = BackupOptionsForm(request.POST, instance=instance)
        if form.is_valid():
            cd = form.cleaned_data
            overrides = {
                'host': cd['host'],
                'port': cd['port'],
                'user': cd['user'],
                'auth_method': cd['auth_method'],
                'password': cd.get('password', ''),
                'private_key': cd.get('private_key', ''),
                'key_passphrase': cd.get('key_passphrase', ''),
                'local_storage': cd.get('local_storage', False),
                'remote_directory': cd.get('remote_directory', ''),
            }
            try:
                client = SftpClient(overrides=overrides)
                client.test_connection()
                messages.success(request, 'SFTP connection successful.')
            except SftpError as exc:
                messages.error(request, f'SFTP connection failed: {exc}')

        self.object_list = self.get_queryset()
        context = self.get_context_data()
        context['backup_options_form'] = form
        return self.render_to_response(context)

    def _handle_save_settings(self, request: Any) -> HttpResponse:
        """Logic for saving or updating backup/SFTP settings."""
        instance, _ = BackupOptions.objects.get_or_create(pk=1)
        form = BackupOptionsForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, 'Backup settings saved successfully.')
            return redirect(self.success_url)

        error_messages = []
        for field, errors in form.errors.items():
            if field == '__all__':
                error_messages.extend(errors)
            else:
                error_messages.extend([f'{field.capitalize()}: {error}' for error in errors])

        for err_msg in error_messages:
            messages.error(request, err_msg)

        self.object_list = self.get_queryset()
        context = self.get_context_data()
        context['backup_options_form'] = form
        return self.render_to_response(context)

    def _handle_reset_settings(self, request: Any) -> HttpResponse:
        """Logic for resetting (deleting) backup/SFTP settings."""
        BackupOptions.objects.filter(pk=1).delete()
        messages.warning(request, 'Backup settings have been reset.')
        self.object_list = self.get_queryset()
        context = self.get_context_data()
        context['backup_options_form'] = BackupOptionsForm()
        return self.render_to_response(context)


class BackupFileDownloadView(View):
    """Serve a single backup file for download."""

    def get(self, _request: Any, filename: str) -> HttpResponse:
        """Return the requested backup file as an attachment.

        Args:
            _request: The HTTP request (unused).
            filename: Name of the backup file to download.

        Returns:
            An HttpResponse with the file contents.

        Raises:
            Http404: If the requested file does not exist.
        """
        backup_dir: Path = settings.BACKUP_FILE_PATH
        file_path = backup_dir / filename
        if not file_path.exists() or not file_path.is_file():
            msg = f'Backup file not found: {filename}'
            raise Http404(msg)

        content = file_path.read_bytes()
        response = HttpResponse(content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


class BackupFilesDownloadMultipleView(View):
    """Download multiple selected backup files as a ZIP or tar.gz archive."""

    def post(self, request: Any, archive_format: str) -> HttpResponse:
        """Bundle selected backups into an archive.

        Args:
            request: The HTTP request, containing POST data 'selected' (a list of filenames).
            archive_format: Either 'zip' or 'tar.gz'.

        Returns:
            An HttpResponse containing the archive.

        Raises:
            Redirect to settings:backups with an error if no valid files are selected.
        """
        filenames: list[str] = request.POST.getlist('selected')
        if not filenames:
            messages.error(request, 'No files selected for download.')
            return redirect('settings:backups')

        backup_dir: Path = settings.BACKUP_FILE_PATH
        valid: list[str] = [f for f in filenames if (backup_dir / f).is_file()]
        if not valid:
            messages.error(request, 'No valid files to download.')
            return redirect('settings:backups')

        buffer = io.BytesIO()
        ext = archive_format.lower()

        if ext == 'zip':
            with zipfile.ZipFile(buffer, 'w') as zip_archive:
                for fname in valid:
                    data = (backup_dir / fname).read_bytes()
                    zip_archive.writestr(fname, data)
        else:
            with tarfile.open(fileobj=buffer, mode='w:gz') as tar_archive:
                for fname in valid:
                    path = backup_dir / fname
                    data = path.read_bytes()
                    info = tarfile.TarInfo(name=fname)
                    info.size = len(data)
                    tar_archive.addfile(info, io.BytesIO(data))

        buffer.seek(0)
        archive_name = f'backups.{ext}'
        response = HttpResponse(buffer.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename={archive_name}'
        return response


class BackupFilesDeleteMultipleView(View):
    """Delete multiple selected backup files and notify the user."""

    def post(self, request: Any) -> HttpResponse:
        """Delete the selected backup files.

        Args:
            request: The HTTP request, containing POST data 'selected' (list of filenames).

        Returns:
            An HttpResponse redirecting back to the backups page.
        """
        filenames: list[str] = request.POST.getlist('selected')
        if not filenames:
            messages.error(request, 'No files selected for deletion.')
            return redirect('settings:backups')

        backup_dir: Path = settings.BACKUP_FILE_PATH
        deleted: list[str] = []
        errors: list[str] = []

        for fname in filenames:
            path = backup_dir / fname
            if not path.is_file():
                errors.append(fname)
                continue
            try:
                path.unlink()
                deleted.append(fname)
            except OSError:
                errors.append(fname)

        if deleted:
            messages.success(request, f"Deleted: {', '.join(deleted)}")
        if errors:
            messages.error(request, f"Errors deleting: {', '.join(errors)}")

        return redirect('settings:backups')
