"""URL configuration for Management App API endpoints.

Defines routes that map API requests to their corresponding viewsets and views.
"""
from rest_framework.routers import DefaultRouter

from management.views.backup import BackupViewSet
from management.views.logging import LoggingViewSet
from management.views.role_management import RoleViewSet
from management.views.tls import TlsViewSet
from management.views.user_management import UserViewSet

router = DefaultRouter()
router.register(r'backups', BackupViewSet, basename='backup')
router.register(r'logging', LoggingViewSet, basename='logging')
router.register(r'tls', TlsViewSet, basename='tls')
router.register(r'users', UserViewSet, basename='users')
router.register(r'roles', RoleViewSet, basename='roles')

urlpatterns = router.urls
