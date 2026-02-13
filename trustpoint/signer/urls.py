"""Contains Routes of URls for Signer App at App level."""

from django.urls import path, re_path

from signer import views

app_name = 'signer'

urlpatterns = [
    # Signer list view
    path('', views.SignerTableView.as_view(), name='signer_list'),
    # Signer add workflow
    path('add/method-select/', views.SignerAddMethodSelectView.as_view(), name='signer-add-method_select'),
    path(
        'add/file-import/file-type-select/',
        views.SignerAddFileImportFileTypeSelectView.as_view(),
        name='signer-add-file_import-file_type_select',
    ),
    path(
        'add/file-import/pkcs12',
        views.SignerAddFileImportPkcs12View.as_view(),
        name='signer-add-file_import-pkcs12',
    ),
    path(
        'add/file-import/separate-files',
        views.SignerAddFileImportSeparateFilesView.as_view(),
        name='signer-add-file_import-separate_files',
    ),
    # Signer configuration view
    path('config/<int:pk>/', views.SignerConfigView.as_view(), name='signer-config'),
    # Signed messages
    path('signed-messages/<int:pk>/', views.SignedMessagesListView.as_view(), name='signer-signed_messages'),
    # Signer delete
    re_path(
        r'^delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        views.SignerBulkDeleteConfirmView.as_view(),
        name='signer-delete_confirm',
    ),
    # Sign hash view
    path('sign-hash/', views.SignHashView.as_view(), name='sign_hash'),
    path('sign-hash/success/', views.SignHashSuccessView.as_view(), name='sign_hash_success'),
    # API endpoint for signing
    # path('api/sign/', views.SignHashAPIView.as_view(), name='sign_hash_api'),  # noqa: ERA001
]
