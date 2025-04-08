import datetime
import glob
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.core.management import call_command
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views import View

from settings.forms import BackupForm, RestoreForm
from settings.models import BackupRecord


def create_combined_backup(db_backup_path: str, config_paths: list[str], output_zip_path: str) -> None:
    """Create a zip archive containing the database backup and configuration files/folders.

    Args:
        db_backup_path: The path to the database backup file.
        config_paths: A list of file or directory paths to include.
        output_zip_path: The path where the combined zip file will be created.
    """
    db_backup = Path(db_backup_path)
    output_zip = Path(output_zip_path)
    with zipfile.ZipFile(output_zip, 'w') as zf:
        zf.write(str(db_backup), arcname=db_backup.name)
        for path_str in config_paths:
            p = Path(path_str)
            if p.is_file():
                zf.write(str(p), arcname=p.name)
            elif p.is_dir():
                for file in p.rglob('*'):
                    if file.is_file():
                        arcname = file.relative_to(p.parent)
                        zf.write(str(file), arcname=str(arcname))


class BackupRestoreView(View):
    """View to handle both backup and restore functionality on one page."""
    template_name: str = 'settings/backup_restore.html'

    def get(self, request: HttpRequest, *_args: object, **_kwargs: object) -> HttpResponse:
        """Handle GET requests by displaying the backup and restore forms and listing backup records."""
        backup_form = BackupForm()
        restore_form = RestoreForm()
        backup_records = BackupRecord.objects.all().order_by('-created_at')
        return render(request, self.template_name, {
            'backup_form': backup_form,
            'restore_form': restore_form,
            'backup_records': backup_records,
        })

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle POST requests for backup creation and database restoration."""
        if 'backup_submit' in request.POST:
            backup_form = BackupForm(request.POST)
            restore_form = RestoreForm()
            if backup_form.is_valid():
                backup_app_config: bool = backup_form.cleaned_data.get('backup_app_config', False)
                backup_apache_config: bool = backup_form.cleaned_data.get('backup_apache_config', False)

                try:
                    call_command('dbbackup')
                    backup_dir = getattr(settings, 'BACKUP_FILE_PATH', '')
                    list_of_files = glob.glob(os.path.join(backup_dir, '*.sql'))
                    latest_file = max(list_of_files, key=os.path.getmtime) if list_of_files else None
                    if not latest_file:
                        messages.error(request, 'Database backup file not found.')
                        return redirect(reverse('settings:backup_restore'))
                except Exception as e:
                    messages.error(request, f'Error during database backup: {str(e)}')
                    return redirect(reverse('settings:backup_restore'))

                config_paths = []
                items_list = ['Database']
                if backup_app_config:
                    config_paths.append('/etc/trustpoint')
                    items_list.append('Application Config')
                if backup_apache_config:
                    config_paths.append('/etc/apache2')
                    items_list.append('Apache Config')

                timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
                backup_name = f'backup-{timestamp}.zip'
                output_zip_path = os.path.join(backup_dir, backup_name)
                try:
                    create_combined_backup(latest_file, config_paths, output_zip_path)
                    os.remove(latest_file)
                    BackupRecord.objects.create(
                        name=backup_name,
                        created_by=request.user,
                        items=', '.join(items_list),
                        backup_file=output_zip_path
                    )
                    messages.success(request, 'Backup created successfully.')
                except Exception as e:
                    messages.error(request, f'Error creating combined backup: {str(e)}')
                    return redirect(reverse('settings:backup_restore'))

                backup_records_ordered = BackupRecord.objects.all().order_by("created_at")
                total_records = backup_records_ordered.count()
                if total_records > 10:
                    BackupRecord.objects.first().delete()
                return redirect(reverse('settings:backup_restore'))

        elif 'restore_submit' in request.POST:
            restore_form = RestoreForm(request.POST, request.FILES)
            backup_form = BackupForm()
            if restore_form.is_valid():
                backup_file = restore_form.cleaned_data['backup_file']
                with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
                    for chunk in backup_file.chunks():
                        tmp.write(chunk)
                    tmp_path = tmp.name
                try:
                    # Step 5: Extract the zip and locate the database backup file.
                    with tempfile.TemporaryDirectory() as extract_dir:
                        with zipfile.ZipFile(tmp_path, 'r') as zf:
                            zf.extractall(path=extract_dir)
                        # Assume the database backup file has a .dump or .sql extension.
                        db_backup_files = [
                            os.path.join(extract_dir, f)
                            for f in os.listdir(extract_dir)
                            if f.endswith(('.dump', '.sql'))
                        ]
                        if not db_backup_files:
                            messages.error(request, 'No database backup file found in the uploaded backup.')
                            return redirect(reverse('settings:backup_restore'))
                        db_backup_file = db_backup_files[0]
                        print(db_backup_file)
                        call_command('dbrestore', input_path=db_backup_file)
                        messages.success(request, 'Database restored successfully.')
                except Exception as e:
                    messages.error(request, f'Error during restore: {str(e)}')
                return redirect(reverse('settings:backup_restore'))
        else:
            backup_form = BackupForm()
            restore_form = RestoreForm()

        backup_records = BackupRecord.objects.all().order_by("-created_at")
        return render(request, self.template_name, {
            'backup_form': backup_form,
            'restore_form': restore_form,
            'backup_records': backup_records,
        })



class BackupDeleteView(View):
    """View to handle deletion of a backup record."""

    def post(self, request: HttpRequest, pk: int, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Delete the specified backup record and its associated file."""
        record = BackupRecord.objects.get(pk=pk)
        record.delete()
        messages.success(request, 'Backup deleted successfully.')
        return redirect(reverse('settings:backup_restore'))
