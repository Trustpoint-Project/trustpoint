"""URL configuration for Device API endpoints.

Defines routes that map API requests to their corresponding viewsets and views.
"""
from rest_framework.routers import DefaultRouter

from .views import DeviceViewSet

router = DefaultRouter()
router.register(r'devices', DeviceViewSet, basename='device')

urlpatterns = router.urls
