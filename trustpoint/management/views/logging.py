"""Logging setting specific views."""

from __future__ import annotations

import datetime
import io
import os
import re
import tarfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.generic import TemplateView, View
from django.views.generic.base import RedirectView
from django.views.generic.list import ListView
from drf_spectacular.utils import extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from management.serializer.logging import LoggingSerializer
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin
from trustpoint.settings import DATE_FORMAT, LOG_DIR_PATH
from trustpoint.views.base import SortableTableFromListMixin

if TYPE_CHECKING:

    from django.http import HttpRequest
    from rest_framework.request import Request


_LOG_FILENAME_RE = re.compile(r'^trustpoint\.log(?:\.\d+)?$')

_CONTROL_CHAR_THRESHOLD = 32


def _secure_log_filename(filename: str) -> str:
    """Secure a log filename by removing any potentially dangerous characters.

    Args:
        filename: The filename to secure

    Returns:
        The secured filename with dangerous characters removed

    Raises:
        Http404: If the filename is invalid
    """
    if not isinstance(filename, str) or not filename:
        exc_msg = f'Invalid filename: {filename}'
        raise Http404(exc_msg)

    if '\x00' in filename or any(ord(c) < _CONTROL_CHAR_THRESHOLD for c in filename):
        exc_msg = f'Invalid filename: {filename}'
        raise Http404(exc_msg)

    for sep in (os.sep, os.path.altsep, '/', '\\'):
        if sep:
            filename = filename.replace(sep, '')

    filename = filename.replace('..', '').replace('~', '').replace(':', '')

    if not filename:
        exc_msg = 'Invalid filename after sanitization'
        raise Http404(exc_msg)

    return filename


def _validate_log_filename(filename: str) -> Path:
    """Validate a log filename and return the resolved path if valid.

    Args:
        filename: The filename to validate

    Returns:
        The resolved Path object if valid

    Raises:
        Http404: If the filename is invalid or not found
    """
    secured_filename = _secure_log_filename(filename)

    if not _LOG_FILENAME_RE.match(secured_filename):
        exc_msg = 'Invalid filename.'
        raise Http404(exc_msg)

    resolved_log_dir = LOG_DIR_PATH.resolve()

    for file_path in resolved_log_dir.iterdir():
        if file_path.is_file() and file_path.name == secured_filename:
            return file_path

    exc_msg = 'Log file not found.'
    raise Http404(exc_msg)


class IndexView(RedirectView):
    """Index view."""

    permanent = True
    pattern_name = 'management:language'


def language(request: HttpRequest) -> HttpResponse:
    """Handle language Configuration.

    Returns: HTTPResponse
    """
    context = {'page_category': 'management', 'page_name': 'language'}
    return render(request, 'management/language.html', context=context)


# ------------------------------------------------------- Logging ------------------------------------------------------


class LoggingFilesTableView(PageContextMixin, LoggerMixin, SortableTableFromListMixin, ListView):  # type: ignore[type-arg,misc]
    """View to display all log files in the log directory in a table."""

    http_method_names = ('get',)

    template_name = 'management/logging/logging_files.html'
    context_object_name = 'log_files'
    default_sort_param = 'updated_at'
    paginate_by = None

    page_category = 'management'
    page_name = 'logging'

    @staticmethod
    def _get_first_and_last_entry_date(
        log_file_path: Path,
    ) -> tuple[None | datetime.datetime, None | datetime.datetime]:
        log_file = log_file_path.read_text(encoding='utf-8', errors='backslashreplace')

        date_regex = re.compile(r'\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b')
        matches = re.findall(date_regex, log_file)
        if matches:
            first_date = datetime.datetime.strptime(matches[0], DATE_FORMAT).replace(tzinfo=datetime.UTC)
            last_date = datetime.datetime.strptime(matches[-1], DATE_FORMAT).replace(tzinfo=datetime.UTC)
        else:
            first_date = None
            last_date = None

        return first_date, last_date

    @classmethod
    def _get_log_file_data(cls, log_filename: str) -> dict[str, str]:
        try:
            log_file_path = _validate_log_filename(log_filename)
        except Http404:
            return {}

        first_date, last_date = cls._get_first_and_last_entry_date(log_file_path)
        if isinstance(first_date, datetime.datetime):
            created_at = first_date.strftime(f'{DATE_FORMAT} UTC')
        else:
            created_at = _('None')

        if isinstance(last_date, datetime.datetime):  # noqa: SIM108
            updated_at = last_date.strftime(f'{DATE_FORMAT} UTC')
        else:
            updated_at = _('None')

        return {'filename': log_filename, 'created_at': created_at, 'updated_at': updated_at}

    def get_queryset(self) -> list[dict[str, str]]:  # type: ignore[override]
        """Gets a queryset of all valid Trustpoint log files in the log directory."""
        all_files = [file.name for file in LOG_DIR_PATH.iterdir()]

        file_data_list = [self._get_log_file_data(log_file_name) for log_file_name in all_files]

        self.queryset = [data for data in file_data_list if data]

        def sort_key(item: dict[str, str]) -> datetime.datetime:
            if item['updated_at'] == _('None'):
                return datetime.datetime.min.replace(tzinfo=datetime.UTC)
            date_str = item['updated_at'][:-4]
            return datetime.datetime.strptime(date_str, DATE_FORMAT).replace(tzinfo=datetime.UTC)

        self.queryset.sort(key=sort_key, reverse=True)
        return self.queryset




class LoggingFilesDetailsView(PageContextMixin, LoggerMixin, TemplateView):
    """Log file detail view, allows to view the content of a single log file without download."""

    http_method_names = ('get',)

    template_name = 'management/logging/logging_files_details.html'
    log_directory = LOG_DIR_PATH

    page_category = 'settings'
    page_name = 'logging'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the view."""
        context = super().get_context_data(**kwargs)
        log_filename = self.kwargs.get('filename')

        try:
            resolved_path = _validate_log_filename(log_filename)
            context['log_content'] = resolved_path.read_text(encoding='utf-8', errors='backslashreplace')
        except Http404:
            context['log_content'] = 'Log-File not found.'

        return context


class LoggingFilesDownloadView(PageContextMixin, LoggerMixin, TemplateView):
    """View to download a single log file."""

    http_method_names = ('get',)

    page_category = 'settings'
    page_name = 'logging'

    def get(self, *_args: Any, **kwargs: Any) -> HttpResponse:
        """The HTTP GET method for the view."""
        filename = kwargs.get('filename')
        if not filename:
            msg = 'Filename not provided.'
            raise Http404(msg)

        resolved_path = _validate_log_filename(filename)

        response = HttpResponse(
            resolved_path.read_text(encoding='utf-8', errors='backslashreplace'), content_type='text/plain'
        )
        # Use the validated filename from the resolved path in the response header.
        response['Content-Disposition'] = f'attachment; filename={resolved_path.name}'
        return response


class LoggingFilesDownloadMultipleView(PageContextMixin, LoggerMixin, View):
    """View to download multiple log files as a single archive."""

    http_method_names = ('get',)

    page_category = 'settings'
    page_name = 'logging'

    @classmethod
    def get(cls, *_args: Any, **kwargs: Any) -> HttpResponse:
        """The HTTP GET method for the view."""
        archive_format = kwargs.get('archive_format')
        filenames = kwargs.get('filenames')

        # These should never happen, due to the regex in the urls.py (re_path). ----------------------------------------
        if not archive_format or not filenames:
            exc_msg = 'Log files not found.'
            raise Http404(exc_msg)
        if archive_format not in ['zip', 'tar.gz']:
            exc_msg = 'Invalid archive format specified.'
            raise Http404(exc_msg)
        # --------------------------------------------------------------------------------------------------------------

        filenames = [filename for filename in filenames.split('/') if filename]

        valid_log_files: list[tuple[str, Path]] = []
        for filename in filenames:
            try:
                resolved_path = _validate_log_filename(filename)
                valid_log_files.append((filename, resolved_path))
            except Http404 as exc:
                exc_msg = f'Invalid filename: {filename}'
                raise Http404(exc_msg) from exc

        file_collection = [(filename, resolved_path.read_bytes()) for filename, resolved_path in valid_log_files]

        if archive_format.lower() == 'zip':
            bytes_io = io.BytesIO()
            zip_file = zipfile.ZipFile(bytes_io, 'w')
            for filename, data in file_collection:
                zip_file.writestr(filename, data)
            zip_file.close()

            response = HttpResponse(bytes_io.getvalue(), content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename=trustpoint-logs.zip'
            return response

        bytes_io = io.BytesIO()
        with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
            for filename, data in file_collection:
                file_io_bytes = io.BytesIO(data)
                file_io_bytes_info = tarfile.TarInfo(filename)
                file_io_bytes_info.size = len(data)
                tar.addfile(file_io_bytes_info, file_io_bytes)

        response = HttpResponse(bytes_io.getvalue(), content_type='application/gzip')
        response['Content-Disposition'] = 'attachment; filename=trustpoint-logs.tar.gz'
        return response

@extend_schema(tags=['Logging'])
class LoggingViewSet(viewsets.GenericViewSet[Any]):
    """ViewSet for managing Backup instances.

    Supports standard CRUD operations such as list, retrieve,
    create, update, and delete.
    """
    serializer_class = LoggingSerializer
    filter_backends = ()

    @action(detail=False, methods=['get'])
    def list_files(self, _request: Request) -> Response:
        """Retrieve detailed info for all log files."""
        if not LOG_DIR_PATH.exists():
            return Response({'error': 'Log files not found'}, status=status.HTTP_404_NOT_FOUND)

        files_info = []
        all_files = [file.name for file in LOG_DIR_PATH.iterdir()]
        valid_log_files = [f for f in all_files if re.compile(r'^trustpoint\.log(?:\.\d+)?$').match(f)]
        for filename in valid_log_files:
            file_path = LOG_DIR_PATH / Path(filename)
            if file_path.is_file():
                stat = file_path.stat()
                files_info.append({
                    'name': filename,
                    'size': stat.st_size,
                    'modified': datetime.datetime.fromtimestamp(stat.st_mtime, tz=datetime.UTC)
                })

        serializer = self.get_serializer(files_info, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path=r'download/(?P<file_name>[^/]+)')
    def download(self, _request: Request, file_name: str) -> FileResponse | Response:
        """Download a log file by name.

        /logs/download/trustpoint.log/
        """
        if not file_name:
            return Response(
                {'error': "Missing 'file_name' path parameter"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prevent path traversal
        safe_file_name = Path(file_name)
        file_path = LOG_DIR_PATH / safe_file_name
        if not file_path.exists() or not file_path.is_file():
            return Response(
                {'error': 'File not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        return FileResponse(
            file_path.read_text(encoding='utf-8', errors='backslashreplace'),
            as_attachment=True,
            filename=file_name
        )

    @action(
        detail=False,
        methods=['delete'],
        url_path=r'delete/(?P<file_name>[^/]+)'
    )
    def delete(self, _request: Request, file_name: str) -> Response:
        """Delete a log file by name.

        DELETE /logs/delete/trustpoint.log/
        """
        if not file_name:
            return Response(
                {'error': 'File name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate file name against allowed log file pattern
        if not re.compile(r'^trustpoint\.log(?:\.\d+)?$').match(file_name):
            return Response(
                {'error': 'Invalid file name'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prevent path traversal by restricting to a filename within LOG_DIR_PATH
        safe_file_name = Path(file_name).name
        log_root = LOG_DIR_PATH.resolve()
        file_path = (log_root / safe_file_name).resolve()

        # Ensure the resolved file path is within the log directory
        if log_root not in file_path.parents:
            return Response(
                {'error': 'Invalid file name'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not file_path.exists() or not file_path.is_file():
            return Response(
                {'error': 'File not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            file_path.unlink()
            return Response(
                {'message': f"File '{safe_file_name}' deleted successfully"},
                status=status.HTTP_200_OK
            )
        except Exception: # noqa: BLE001
            return Response(
                {'error': 'An internal error occurred while deleting the file.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
