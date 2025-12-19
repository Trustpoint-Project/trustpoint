"""URL configuration for Management App API endpoints.

Defines routes that map API requests to their corresponding viewsets and views.
"""
from rest_framework.routers import DefaultRouter

from management.views.backup import BackupViewSet

router = DefaultRouter()
router.register(r'backups', BackupViewSet, basename='backup')

urlpatterns = router.urls
