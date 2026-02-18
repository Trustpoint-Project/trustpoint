"""URL configuration for Certificate API endpoints.

Defines routes that map API requests to their corresponding viewsets and views.
"""

from rest_framework.routers import DefaultRouter

from pki.views.cert_profiles import CertProfileViewSet
from pki.views.certificates import CertificateViewSet
from pki.views.domains import DomainViewSet
from pki.views.issuing_cas import IssuingCaViewSet
from pki.views.truststores import TruststoreViewSet

router = DefaultRouter()
router.register(r'certificates', CertificateViewSet, basename='certificate')
router.register(r'cert-profiles', CertProfileViewSet, basename='cert-profiles')
router.register(r'issuing-cas', IssuingCaViewSet, basename='issuing-ca')
router.register(r'truststores', TruststoreViewSet, basename='truststore')
router.register(r'domains', DomainViewSet, basename='domain')

urlpatterns = router.urls
