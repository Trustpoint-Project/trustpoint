"""URL configuration for the users application."""

from django.urls import path

from setup_wizard.views import (
    SetupWizardCreateSuperUserView,
    SetupWizardDemoDataView,
    SetupWizardGenerateTlsServerCredentialView,
    SetupWizardImportTlsServerCredentialView,
    SetupWizardInitialView,
    SetupWizardTlsServerCredentialApplyCancelView,
    SetupWizardTlsServerCredentialApplyView,
)

app_name = 'setup_wizard'
urlpatterns = [
    path('', SetupWizardInitialView.as_view(), name='initial'),
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
]
