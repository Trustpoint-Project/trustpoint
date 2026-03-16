import mimetypes
import time
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.management import call_command
from django.http import FileResponse, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.views import View


class ServeLocalDocsView(LoginRequiredMixin, View):
    """View to serve local Sphinx documentation or fallback to ReadTheDocs."""

    def get(self, request: HttpRequest, path: str = 'index.html') -> HttpResponse:
        if not path or path.endswith('/'):
            path += 'index.html'

        docs_dir = settings.BASE_DIR.parent / 'docs' / 'build' / 'html'
        file_path = (docs_dir / path).resolve()

        if docs_dir in file_path.parents and file_path.exists() and file_path.is_file():
            content_type, _ = mimetypes.guess_type(str(file_path))
            return FileResponse(open(file_path, 'rb'), content_type=content_type or 'application/octet-stream')

        return redirect(f"https://trustpoint.readthedocs.io/en/latest/{path}")


class BuildDocsTriggerView(LoginRequiredMixin, View):
    """It triggers documentation build directly."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        lock_file = settings.BASE_DIR.parent / 'docs' / '.building'


        if lock_file.exists() and (time.time() - lock_file.stat().st_mtime < 300):
            return JsonResponse({'status': 'running'})

        try:
            lock_file.touch()  # Create the lock
            call_command('build_docs', force_env=True, clean=True)  # clean=True ensures old docs are wiped!
            return JsonResponse({'status': 'finished'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
        finally:
            if lock_file.exists():
                lock_file.unlink()

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        """It checks poll if the page is refreshed during a build."""
        lock_file = settings.BASE_DIR.parent / 'docs' / '.building'
        if lock_file.exists() and (time.time() - lock_file.stat().st_mtime < 300):
            return JsonResponse({'status': 'running'})
        return JsonResponse({'status': 'finished'})