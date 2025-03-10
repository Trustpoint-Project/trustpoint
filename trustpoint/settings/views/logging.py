"""Logging setting specific views."""

from __future__ import annotations

import datetime
import io
import os
import re
import tarfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from django.http import Http404, HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.generic import TemplateView, View
from django.views.generic.base import RedirectView
from django.views.generic.list import ListView

from trustpoint.settings import DATE_FORMAT, LOG_DIR_PATH, UIConfig
from trustpoint.views.base import LoggerMixin, SortableTableMixin

if TYPE_CHECKING:
    from typing import Any, ClassVar

    from django.http import HttpRequest


class IndexView(RedirectView):
    """Index view"""

    permanent = True
    pattern_name = 'settings:language'


def language(request: HttpRequest) -> HttpResponse:
    """Handle language Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'settings', 'page_name': 'language'}
    return render(request, 'settings/language.html', context=context)


# ------------------------------------------------------- Logging ------------------------------------------------------


class LoggingContextMixin:
    """Mixin which adds extra menu context for the Logging Views."""

    extra_context: ClassVar[dict] = {'page_category': 'settings', 'page_name': 'logging'}


class LoggingFilesTableView(LoggerMixin, LoggingContextMixin, SortableTableMixin, ListView):
    """View to display all log files in the log directory in a table."""

    http_method_names = ('get',)

    template_name = 'settings/logging/logging_files.html'
    context_object_name = 'log_files'
    default_sort_param = 'filename'
    paginate_by = UIConfig.paginate_by

    @staticmethod
    @LoggerMixin.log_exceptions
    def _get_first_and_last_entry_date(
        log_file_path: Path,
    ) -> tuple[None | datetime.datetime, None | datetime.datetime]:
        log_file = log_file_path.read_text(encoding='utf-8', errors='backslashreplace')

        date_regex = re.compile(r'\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b')
        matches = re.findall(date_regex, log_file)
        if matches:
            first_date = datetime.datetime.strptime(matches[0], DATE_FORMAT).replace(tzinfo=datetime.timezone.utc)
            last_date = datetime.datetime.strptime(matches[-1], DATE_FORMAT).replace(tzinfo=datetime.timezone.utc)
        else:
            first_date = None
            last_date = None

        return first_date, last_date

    @classmethod
    @LoggerMixin.log_exceptions
    def _get_log_file_data(cls, log_filename: str) -> dict[str, str]:
        log_file_path = LOG_DIR_PATH / Path(log_filename)
        if not log_file_path.exists() or not log_file_path.is_file():
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

    @LoggerMixin.log_exceptions
    def get_queryset(self) -> list[dict[str, str]]:
        """Gets a queryset of all valid Trustpoint log files in the log directory."""
        all_files = os.listdir(LOG_DIR_PATH)
        valid_log_files = [f for f in all_files if re.compile(r'^trustpoint\.log(?:\.\d+)?$').match(f)]

        self.queryset = [self._get_log_file_data(log_file_name) for log_file_name in valid_log_files]
        return super().get_queryset()


class LoggingFilesDetailsView(LoggerMixin, LoggingContextMixin, TemplateView):
    """Log file detail view, allows to view the content of a single log file without download."""

    http_method_names = ('get',)

    template_name = 'settings/logging/logging_files_details.html'
    log_directory = LOG_DIR_PATH

    @LoggerMixin.log_exceptions
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the view."""
        context = super().get_context_data(**kwargs)
        log_filename = self.kwargs.get('filename')

        log_file_path = LOG_DIR_PATH / Path(log_filename)

        if not log_file_path.exists() or not log_file_path.is_file():
            context['log_content'] = 'Log-File not found.'
        else:
            context['log_content'] = log_file_path.read_text(encoding='utf-8', errors='backslashreplace')

        return context


class LoggingFilesDownloadView(LoggerMixin, LoggingContextMixin, TemplateView):
    """View to download a single log file"""

    http_method_names = ('get',)

    @LoggerMixin.log_exceptions
    def get(self, *_args: Any, **kwargs: Any) -> HttpResponse:
        """The HTTP GET method for the view."""
        filename = kwargs.get('filename')
        log_file_path = LOG_DIR_PATH / Path(filename)

        if not log_file_path.exists() or not log_file_path.is_file():
            exc_msg = 'Log file not found.'
            raise Http404(exc_msg)

        response = HttpResponse(
            log_file_path.read_text(encoding='utf-8', errors='backslashreplace'), content_type='text/plain'
        )
        response['Content-Disposition'] = f'attachment; filename={filename}'
        return response


class LoggingFilesDownloadMultipleView(LoggerMixin, LoggingContextMixin, View):
    """View to download multiple log files as a single archive."""

    http_method_names = ('get',)

    @classmethod
    @LoggerMixin.log_exceptions
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

        file_collection = [(filename, (LOG_DIR_PATH / Path(filename)).read_bytes()) for filename in filenames]

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
