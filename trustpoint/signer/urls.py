"""Contains Routes of URls for Signer App at App level."""

from django.urls import path

from . import views

app_name = 'signer'

urlpatterns = [
    path('add-signer/', views.SignerCreateView.as_view(), name='addSigner'),
    path('', views.SignerListView.as_view(), name='signerList'),
    path('delete-signer/<int:pk>/', views.SignerDeleteView.as_view(), name='deleteSigner'),
    path('edit-signer/<int:pk>/', views.SignerEditView.as_view(), name='editSigner'),
    path('signer/<int:pk>/', views.SignerDetailView.as_view(), name='signerDetail'),
    path('api/sign/', views.SignHashAPIView.as_view(), name='sign_hash_api'),
]