"""URL configuration for Signer API endpoints.

Defines routes that map API requests to their corresponding viewsets and views.
"""

from rest_framework.routers import DefaultRouter

from signer.api_views import SignedMessageViewSet, SignerViewSet

router = DefaultRouter()
router.register(r'signers', SignerViewSet, basename='signer')
router.register(r'signed-messages', SignedMessageViewSet, basename='signed-message')

urlpatterns = router.urls
