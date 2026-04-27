"""API routes for Workflow 2 DRF endpoints."""

from rest_framework.routers import DefaultRouter

from workflows2.api_views import Workflow2DefinitionViewSet

router = DefaultRouter()
router.register(r'workflow2-definitions', Workflow2DefinitionViewSet, basename='workflow2-definition')

urlpatterns = router.urls
