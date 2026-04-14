"""URL configuration for the management application."""

from django.urls import path, re_path

from .views import (
    IndexView,
    backup,
    help_support,
    key_storage,
    logging,
    notifications,
    role_management,
    settings,
    tls,
    user_management,
)

app_name = 'management'
urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    # path('settings/', settings.settings, name='settings'),  # noqa: ERA001
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
    path('loglevel/change', settings.ChangeLogLevelView.as_view(), name='change-loglevel'),
    path('settings/', settings.SettingsView.as_view(), name='settings'),
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
    path('tls/activate/<int:pk>', tls.ActivateTlsServerView.as_view(), name='activate-tls'),
    path(
        'backups/',
        backup.BackupManageView.as_view(extra_context={'page_category': 'management', 'page_name': 'backup'}),
        name='backups'
    ),
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
    path('help/', help_support.HelpView.as_view(), name='help'),
    path('key_storage/', key_storage.KeyStorageConfigView.as_view(), name='key_storage'),
    path('notifications/refresh/', notifications.RefreshNotificationsView.as_view(), name='refresh_notifications'),
    path('notifications/<int:pk>/delete/', notifications.NotificationDeleteView.as_view(), name='notification_delete'),
    path('user_management/', user_management.UserTableView.as_view(), name='user_management'),
    path('user_management/add_user/', user_management.UserCreateView.as_view(), name='add_user'),
    path('user_management/<int:pk>/delete/', user_management.UserDeleteView.as_view(), name='delete_user'),
    path('user_management/<int:pk>/change_role/', user_management.UserChangeRoleView.as_view(), name='change_role'),
    path('role_management/', role_management.RoleTableView.as_view(), name='role_management'),
    path('role_management/add/', role_management.RoleCreateView.as_view(), name='add_role'),
    path('role_management/<int:pk>/edit/', role_management.RoleEditView.as_view(), name='edit_role'),
    path('role_management/<int:pk>/delete/', role_management.RoleDeleteView.as_view(), name='delete_role'),
]
