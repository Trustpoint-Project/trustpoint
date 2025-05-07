import datetime
import io
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any, ClassVar

from django.conf import settings
from django.contrib import messages
from django.core.management import call_command
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views.generic import ListView, View

from trustpoint.views.base import SortableTableMixin


def get_backup_file_data(filename: str) -> dict[str, Any]:
    """Retrieve metadata for a single backup file.

    Args:
        filename (str): Name of the backup file.

    Returns:
        dict: A dictionary containing filename, creation time, modification time, and size in KB.
              Returns an empty dict if the file does not exist or is not a file.
    """
    backup_dir = settings.BACKUP_FILE_PATH
    file_path = backup_dir / filename
    if not file_path.exists() or not file_path.is_file():
        return {}
    stat = file_path.stat()
    created = datetime.datetime.fromtimestamp(stat.st_ctime, datetime.UTC)
    modified = datetime.datetime.fromtimestamp(stat.st_mtime, datetime.UTC)
    size_kb = stat.st_size / 1024
    return {
        'filename': filename,
        'created_at': created.strftime('%Y-%m-%d %H:%M:%S'),
        'modified_at': modified.strftime('%Y-%m-%d %H:%M:%S'),
        'size_kb': f'{size_kb:.1f}',
    }


def create_db_backup(path: Path) -> str:
    """Create a compressed database backup file in the given directory.

    Args:
        path (Path): The directory path where backups should be stored.

    Returns:
        str: The filename of the created backup file.

    Raises:
        OSError: If the directory cannot be created.
        CalledProcessError: If the dbbackup command fails.
    """
    path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d_%H%M%S')
    filename = f'backup_{timestamp}.dump.gz'
    call_command('dbbackup', '-o', filename, '-z')
    return filename


class BackupManageView(SortableTableMixin, ListView[dict[str, Any]]):
    """View to manage backups: list existing backups and create new ones.

    GET:
        Renders a table of existing backup files with pagination and sorting.
    POST:
        Generates a new database backup and redirects back to the list view.

    Attributes:
        template_name (str): Template path for rendering.
        context_object_name (str): Context name for the backup list.
        paginate_by (int): Number of items per page.
        default_sort_param (str): Default field to sort by.
    """
    template_name = 'settings/backups/manage_backups.html'
    context_object_name = 'backup_files'
    paginate_by = 20
    default_sort_param = 'filename'

    def get_queryset(self) -> Any:
        """Collect metadata for all backup files in the backup directory.

        Returns:
            list: A list of dicts, each containing metadata for one backup file.
        """
        backup_dir = settings.BACKUP_FILE_PATH
        try:
            all_files = os.listdir(backup_dir)
        except (FileNotFoundError, NotADirectoryError):
            return []
        backups = [f for f in all_files if f.startswith('backup_') and f.endswith('.dump.gz')]
        data = [get_backup_file_data(f) for f in backups]
        self.queryset = data
        return super().get_queryset()

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST request to create a new database backup.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            HttpResponse: A redirection to the backup list view.
        """
        try:
            filename = create_db_backup(settings.BACKUP_FILE_PATH)
            messages.success(request, f'Database backup created successfully: {filename}')
        except Exception as e:
            messages.error(request, f'Error creating database backup: {e}')
        return redirect('settings:backups')


class BackupFileDownloadView(View):
    """View to download a single backup file."""

    def get(self, request: HttpRequest, filename: str) -> HttpResponse:
        """Serve the requested backup file for download.

        Args:
            request (HttpRequest): The incoming HTTP request.
            filename (str): The name of the backup file to download.

        Returns:
            HttpResponse: A response with the file content and appropriate headers.

        Raises:
            Http404: If the requested file does not exist.
        """
        backup_dir = settings.BACKUP_FILE_PATH
        file_path = backup_dir / filename
        if not file_path.exists() or not file_path.is_file():
            msg = f'Backup file not found: {filename}'
            raise Http404(msg)
        content = file_path.read_bytes()
        response = HttpResponse(content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


class BackupFilesDownloadMultipleView(View):
    """View to download multiple selected backup files as an archive.

    Supported formats: zip, tar.gz
    """

    def post(self, request: HttpRequest, archive_format: str) -> HttpResponse:
        """Bundle selected backups into an archive and return it.

        Args:
            request (HttpRequest): The incoming HTTP request.
            archive_format (str): The archive format ('zip' or 'tar.gz').

        Returns:
            HttpResponse: A response with the archive content.

        Raises:
            Http404: If no valid files are selected.
        """
        filenames = request.POST.getlist('selected')
        if not filenames:
            messages.error(request, 'No files selected for download.')
            return redirect('settings:backups')
        valid = [f for f in filenames if (settings.BACKUP_FILE_PATH / f).is_file()]
        if not valid:
            messages.error(request, 'No valid files to download.')
            return redirect('settings:backups')
        buffer = io.BytesIO()
        if archive_format.lower() == 'zip':
            archive = zipfile.ZipFile(buffer, 'w')
            ext = 'zip'
        else:
            archive = tarfile.open(fileobj=buffer, mode='w:gz')
            ext = 'tar.gz'
        for fname in valid:
            path = settings.BACKUP_FILE_PATH / fname
            data = path.read_bytes()
            if ext == 'zip':
                archive.writestr(fname, data)
            else:
                info = tarfile.TarInfo(name=fname)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        archive.close()
        buffer.seek(0)
        response = HttpResponse(buffer.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename=backups.{ext}'
        return response


class BackupFilesDeleteMultipleView(View):
    """View to delete multiple selected backup files."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Delete the selected backup files and report results via messages.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            HttpResponse: A redirection to the backup list view.
        """
        filenames = request.POST.getlist('selected')
        if not filenames:
            messages.error(request, 'No files selected for deletion.')
            return redirect('settings:backups')
        deleted, errors = [], []
        for fname in filenames:
            path = settings.BACKUP_FILE_PATH / fname
            try:
                if path.is_file():
                    path.unlink()
                    deleted.append(fname)
                else:
                    errors.append(fname)
            except Exception:
                errors.append(fname)
        if deleted:
            messages.success(request, f'Deleted: {", ".join(deleted)}')
        if errors:
            messages.error(request, f'Errors deleting: {", ".join(errors)}')
        return redirect('settings:backups')
