"""URL configuration for the users application."""

from django.urls import path

from setup_wizard import views

app_name = 'setup_wizard'
urlpatterns = [
    path('', views.SetupWizardIndexView.as_view(), name='index'),
    path(
        'restore-backup/',
        views.SetupWizardRestoreBackupView.as_view(),
        name='restore_backup',
    ),
    path(
        'restore-backup/database/',
        views.RestoreBackupDatabaseView.as_view(),
        name='restore_backup_database',
    ),
    path(
        'restore-backup/crypto-storage/',
        views.RestoreBackupCryptoStorageView.as_view(),
        name='restore_backup_crypto_storage',
    ),
    path(
        'restore-backup/backend-config/',
        views.RestoreBackupBackendConfigView.as_view(),
        name='restore_backup_backend_config',
    ),
    path(
        'restore-backup/import/',
        views.RestoreBackupImportView.as_view(),
        name='restore_backup_import',
    ),
    path(
        'restore-backup/summary/',
        views.RestoreBackupSummaryView.as_view(),
        name='restore_backup_summary',
    ),
    path(
        'connect-existing/',
        views.SetupWizardConnectExistingView.as_view(),
        name='connect_existing',
    ),
    path(
        'connect-existing/database/',
        views.ConnectExistingDatabaseView.as_view(),
        name='connect_existing_database',
    ),
    path(
        'connect-existing/crypto-storage/',
        views.ConnectExistingCryptoStorageView.as_view(),
        name='connect_existing_crypto_storage',
    ),
    path(
        'connect-existing/backend-config/',
        views.ConnectExistingBackendConfigView.as_view(),
        name='connect_existing_backend_config',
    ),
    path(
        'connect-existing/summary/',
        views.ConnectExistingSummaryView.as_view(),
        name='connect_existing_summary',
    ),
    path(
        'fresh-install/admin-user/',
        views.FreshInstallAdminUserView.as_view(),
        name='fresh_install_admin_user',
    ),
    path(
        'fresh-install/database/',
        views.FreshInstallDatabaseView.as_view(),
        name='fresh_install_database',
    ),
    path(
        'fresh-install/crypto-storage/',
        views.FreshInstallCryptoStorageView.as_view(),
        name='fresh_install_crypto_storage',
    ),
    path(
        'fresh-install/backend-config/',
        views.FreshInstallBackendConfigView.as_view(),
        name='fresh_install_backend_config',
    ),
    path(
        'fresh-install/demo-data/',
        views.FreshInstallDemoDataView.as_view(),
        name='fresh_install_demo_data',
    ),
    path(
        'fresh-install/tls-config/',
        views.FreshInstallTlsConfigView.as_view(),
        name='fresh_install_tls_config',
    ),
    path('fresh-install/summary/', views.FreshInstallSummaryView.as_view(), name='fresh_install_summary'),
    path(
        'fresh-install/summary/truststore/<str:file_format>/',
        views.FreshInstallSummaryTruststoreDownloadView.as_view(),
        name='fresh_install_summary_truststore_download',
    ),
    path(
        'fresh-install/cancel/',
        views.FreshInstallCancelView.as_view(),
        name='fresh_install_cancel',
    ),
]
