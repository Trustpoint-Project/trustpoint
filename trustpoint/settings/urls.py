"""Routing configuration"""

from django.urls import path, re_path

from .views import IndexView, backup_restore, language, logging, security

app_name = 'settings'
urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    path('language/', language.language, name='language'),
    path('logging/files/', logging.LoggingFilesTableView.as_view(), name='logging-files'),
    re_path(
        r'^logging/files/details/(?P<filename>trustpoint\.log(?:\.\d{1,5})?)/?$',
        logging.LoggingFilesDetailsView.as_view(),
        name='logging-files-details',
    ),
    re_path(
        r'^logging/files/download/(?P<filename>trustpoint\.log(?:\.\d{1,5})?)/?$',
        logging.LoggingFilesDownloadView.as_view(),
        name='logging-files-download',
    ),
    re_path(
        r'^logging/files/download/(?P<archive_format>tar\.gz|zip)(?P<filenames>(?:/trustpoint\.log(\.\d{1,5})?)+)/?$',
        logging.LoggingFilesDownloadMultipleView.as_view(),
        name='logging-files-download-multiple',
    ),
    path('security/', security.SecurityView.as_view(), name='security'),
    path('backup-restore/', backup_restore.BackupRestoreView.as_view(), name='backup_restore'),
    path('backup/delete/<int:pk>/', backup_restore.BackupDeleteView.as_view(), name='backup_delete'),
]
