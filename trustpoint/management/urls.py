"""URL configuration for the management application."""

from django.urls import path, re_path

from .views import IndexView, backup, logging, settings, tls

app_name = 'management'
urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    # path('settings/', settings.settings, name='settings'),
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
    path('loglevel/set', settings.ChangeLogLevelView.as_view(), name='set-loglevel'),
    path('settings/', settings.SettingsView.as_view(), name='settings'),
    path('tls/', tls.TlsView.as_view(), name='tls'),
    path(
        'backups/',
        backup.BackupManageView.as_view(extra_context={'page_category': 'management', 'page_name': 'backup'}),
        name='backups'
    ),
    path('backups/download/<str:filename>/', backup.BackupFileDownloadView.as_view(), name='backup-download'),
    path(
        'backups/download-multiple/<str:archive_format>/',
        backup.BackupFilesDownloadMultipleView.as_view(),
        name='backup-download-multiple'
    ),
    path('backups/delete-multiple/', backup.BackupFilesDeleteMultipleView.as_view(), name='backup-delete-multiple'),
]
