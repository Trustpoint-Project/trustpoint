"""Contains Routes of URls for Signer App at App level."""

from django.urls import path

from trustpoint.signer.views import SignerCreateView, SignerListView, SignerDeleteView, SignerEditView, \
    SignerDetailView, SignHashAPIView

urlpatterns = [
    path('add-signer/', SignerCreateView.as_view(), name='addSigner'),
    path('', SignerListView.as_view(), name='signerList'),
    path('delete-signer/<int:pk>/', SignerDeleteView.as_view(), name='deleteSigner'),
    path('edit-signer/<int:pk>/', SignerEditView.as_view(), name='editSigner'),
    path('signer/<int:pk>/', SignerDetailView.as_view(), name='signerDetail'),
    path('api/sign/', SignHashAPIView.as_view(), name='sign_hash_api'),
]