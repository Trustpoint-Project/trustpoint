"""URL configuration for the users application."""

from django.urls import path

from setup_wizard import views
from setup_wizard.views import (
    AutoRestoreHsmSetupView,
    BackupAutoRestorePasswordView,
    BackupRestoreView,
    SetupWizardBackupPasswordView,
    SetupWizardCreateSuperUserView,
    SetupWizardCryptoStorageView,
    SetupWizardDemoDataView,
    SetupWizardGenerateTlsServerCredentialView,
    SetupWizardHsmSetupView,
    SetupWizardImportTlsServerCredentialMethodSelectView,
    SetupWizardImportTlsServerCredentialPkcs12View,
    SetupWizardImportTlsServerCredentialSeparateFilesView,
    SetupWizardSelectTlsServerCredentialView,
    SetupWizardSetupModeView,
    SetupWizardTlsServerCredentialApplyCancelView,
    SetupWizardTlsServerCredentialApplyView,
)

app_name = 'setup_wizard'
urlpatterns = [
    path('', views.SetupWizardIndexView.as_view(), name='index'),
    path('create-super-user', views.SetupWizardCreateSuperUserView.as_view(), name='create_super_user'),
    path(
        'restore-backup/',
        views.SetupWizardRestoreBackupView.as_view(),
        name='restore_backup',
    ),
    # path('restore/', BackupRestoreView.as_view(), name='restore'),
    # path(
    #     'crypto-storage-setup/',
    #     SetupWizardCryptoStorageView.as_view(),
    #     name='crypto_storage_setup',
    # ),
    # path(
    #     'hsm-setup/<str:hsm_type>/',
    #     SetupWizardHsmSetupView.as_view(),
    #     name='hsm_setup',
    # ),
    # path(
    #     'auto-restore-hsm-setup/<str:hsm_type>/',
    #     AutoRestoreHsmSetupView.as_view(),
    #     name='auto_restore_hsm_setup',
    # ),
    # path('setup_mode/', SetupWizardSetupModeView.as_view(), name='setup_mode'),
    path(
        'fresh-install/crypto-storage/',
        views.FreshInstallCryptoStorageView.as_view(),
        name='fresh_install_crypto_storage',
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
    # path(
    #     'fresh-install/select_tls_server_credential/',
    #     SetupWizardSelectTlsServerCredentialView.as_view(),
    #     name='select_tls_server_credential',
    # ),
    # path(
    #     'fresh-install/import-tls-server-credential/',
    #     SetupWizardImportTlsServerCredentialMethodSelectView.as_view(),
    #     name='import_tls_server_credential',
    # ),
    # path(
    #     'fresh-install/import-tls-server-credential/pkcs12/',
    #     SetupWizardImportTlsServerCredentialPkcs12View.as_view(),
    #     name='import_tls_server_credential_pkcs12',
    # ),
    # path(
    #     'fresh-install/import-tls-server-credential/separate-files/',
    #     SetupWizardImportTlsServerCredentialSeparateFilesView.as_view(),
    #     name='import_tls_server_credential_separate_files',
    # ),
    # path(
    #     'backup-password/',
    #     SetupWizardBackupPasswordView.as_view(),
    #     name='backup_password',
    # ),
    path(
        'fresh-install/generate-tls-server-credential/',
        SetupWizardGenerateTlsServerCredentialView.as_view(),
        name='generate_tls_server_credential',
    ),
    path(
        'fresh-install/tls-server-credential-apply/',
        SetupWizardTlsServerCredentialApplyView.as_view(),
        name='tls_server_credential_apply',
    ),
    path(
        'fresh-install/tls-server-credential-apply/<str:file_format>/',
        SetupWizardTlsServerCredentialApplyView.as_view(),
        name='tls_server_credential_apply',
    ),
    path(
        'fresh-install/tls-server-credential-apply-cancel/',
        SetupWizardTlsServerCredentialApplyCancelView.as_view(),
        name='tls_server_credential_apply_cancel',
    ),
    # path('demo-data/', SetupWizardDemoDataView.as_view(), name='demo_data'),
    # path('create-super-user', SetupWizardCreateSuperUserView.as_view(), name='create_super_user'),
    # path('restore/', BackupRestoreView.as_view(), name='restore'),
    # path('auto_restore_password/', BackupAutoRestorePasswordView.as_view(), name='auto_restore_password'),
]
