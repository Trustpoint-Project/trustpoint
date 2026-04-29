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
    # path(
    #     'backup-password/', # noqa: ERA001
    #     SetupWizardBackupPasswordView.as_view(), # noqa: ERA001
    #     name='backup_password', # noqa: ERA001
    # ),
    path('restore/', views.BackupRestoreView.as_view(), name='restore'),
    # path('auto_restore_password/', BackupAutoRestorePasswordView.as_view(),
    # name='auto_restore_password'),
]
