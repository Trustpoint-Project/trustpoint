"""URL configuration for the users application."""

from django.urls import path

from setup_wizard.views import (
    BackupAutoRestoreHsmView,
    BackupAutoRestorePasswordView,
    BackupRestoreView,
    SetupWizardBackupPasswordView,
    SetupWizardCreateSuperUserView,
    SetupWizardDemoDataView,
    SetupWizardGenerateTlsServerCredentialView,
    SetupWizardHsmSetupView,
    SetupWizardImportTlsServerCredentialView,
    SetupWizardRestoreOptionsView,
    SetupWizardSelectTlsServerCredentialView,
    SetupWizardSetupModeView,
    SetupWizardTlsServerCredentialApplyCancelView,
    SetupWizardTlsServerCredentialApplyView,
)

app_name = 'setup_wizard'
urlpatterns = [
    path(
        'hsm-setup/',
        SetupWizardHsmSetupView.as_view(),
        name='hsm_setup',
    ),
    path('setup_mode/', SetupWizardSetupModeView.as_view(), name='setup_mode'),
    path('select_tls_server_credential/', SetupWizardSelectTlsServerCredentialView.as_view(), name='select_tls_server_credential'),
    path(
        'backup-password/',
        SetupWizardBackupPasswordView.as_view(),
        name='backup_password',
    ),
    path(
        'generate-tls-server-credential/',
        SetupWizardGenerateTlsServerCredentialView.as_view(),
        name='generate_tls_server_credential',
    ),
    path(
        'import-tls-server-credential/',
        SetupWizardImportTlsServerCredentialView.as_view(),
        name='import_tls_server_credential',
    ),
    path(
        'restore_options/',
        SetupWizardRestoreOptionsView.as_view(),
        name='restore_options',
    ),
    path(
        'tls-server-credential-apply/',
        SetupWizardTlsServerCredentialApplyView.as_view(),
        name='tls_server_credential_apply',
    ),
    path(
        'tls-server-credential-apply/<str:file_format>/',
        SetupWizardTlsServerCredentialApplyView.as_view(),
        name='tls_server_credential_apply',
    ),
    path(
        'tls-server-credential-apply-cancel/',
        SetupWizardTlsServerCredentialApplyCancelView.as_view(),
        name='tls_server_credential_apply_cancel',
    ),
    path('demo-data/', SetupWizardDemoDataView.as_view(), name='demo_data'),
    path('create-super-user', SetupWizardCreateSuperUserView.as_view(), name='create_super_user'),
    path('restore/', BackupRestoreView.as_view(), name='restore'),
    path('auto_restore_hsm/', BackupAutoRestoreHsmView.as_view(), name='auto_restore_hsm'),
    path('auto_restore_password/', BackupAutoRestorePasswordView.as_view(), name='auto_restore_password'),

]
