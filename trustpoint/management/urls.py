"""URL configuration for the management application."""

from django.urls import path, re_path

from .views import (
    IndexView,
    audit_log,
    backup,
    docs,
    help_support,
    key_storage,
    logging,
    notifications,
    settings,
    tls,
)

app_name = 'management'
urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    # Settings URLs
    path('settings/', settings.SettingsTabView.as_view(), name='settings'),
    path('settings/internationalization/',settings.InternationalizationSettingsView.as_view(),name='settings-internationalization'),
    path('settings/security/', settings.SecuritySettingsView.as_view(), name='settings-security'),
    path('settings/logging/', settings.LoggingSettingsView.as_view(), name='settings-logging'),
    path('settings/notifications/', settings.NotificationSettingsView.as_view(), name='settings-notifications'),
    # Backward compatibility for log level change
    path('loglevel/change', settings.ChangeLogLevelView.as_view(), name='change-loglevel'),
    # Logging file views
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
    # TLS views
    path('tls/', tls.TlsView.as_view(), name='tls'),
    path('tls/add/method-select/', tls.TlsAddMethodSelectView.as_view(),
        name='tls-add-method_select',
    ),
    path('tls/add/generate-tls', tls.GenerateTlsCertificateView.as_view(),
        name='tls-generate',
    ),
    path(
        'tls/add/file-import/pkcs12',
        tls.TlsAddFileImportPkcs12View.as_view(),
        name='tls-add-file_import-pkcs12',
    ),
    path(
        'tls/add/file-import/separate-files',
        tls.TlsAddFileImportSeparateFilesView.as_view(),
        name='tls-add-file_import-separate_files',
    ),
    re_path(
        r'^tls/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        tls.TlsBulkDeleteConfirmView.as_view(),
        name='tls-delete_confirm',
    ),
    path('tls/activate/<int:pk>', tls.ActivateTlsServerView.as_view(), name='activate-tls'),
    # Backup views
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
    # Other views
    path('help/', help_support.HelpView.as_view(), name='help'),
    path('docs/build/trigger/', docs.BuildDocsTriggerView.as_view(), name='trigger_build_docs'),
    path('docs/', docs.ServeLocalDocsView.as_view(), name='local_docs'),
    path('docs/<path:path>', docs.ServeLocalDocsView.as_view(), name='local_docs_path'),
    path('key_storage/', key_storage.KeyStorageConfigView.as_view(), name='key_storage'),
    path('notifications/refresh/', notifications.RefreshNotificationsView.as_view(), name='refresh_notifications'),
    path('notifications/<int:pk>/delete/', notifications.NotificationDeleteView.as_view(), name='notification_delete'),
    # Audit log
    path('audit-log/', audit_log.AuditLogListView.as_view(), name='audit-log'),
]
