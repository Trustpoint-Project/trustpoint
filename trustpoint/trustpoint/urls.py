"""URL configuration for trustpoint project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/

Examples:
---------
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))

"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.utils import timezone
from django.views.decorators.http import last_modified
from django.views.decorators.vary import vary_on_cookie
from django.views.i18n import JavaScriptCatalog
from drf_spectacular.utils import extend_schema, extend_schema_view
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from pki.views.issuing_cas import CrlDownloadView

from .views import base

last_modified_date = timezone.now()

@extend_schema_view(
    post=extend_schema(tags=['Auth'])
)
class CustomTokenObtainPairView(TokenObtainPairView):
    """For Access Token."""

@extend_schema_view(
    post=extend_schema(tags=['Auth'])
)
class CustomTokenRefreshView(TokenRefreshView):
    """For Refresh Token."""


if settings.DEBUG:
    urlpatterns = [
        path('admin/', admin.site.urls),
        *static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT),
    ]
else:
    urlpatterns = []

urlpatterns += [
    path('users/', include('users.urls')),
    path('signer/', include('signer.urls')),
    path('setup-wizard/', include('setup_wizard.urls')),
    path('pki/', include('pki.urls')),
    path('crl/<int:pk>/', CrlDownloadView.as_view(), name='crl-download'),
    path('.well-known/cmp/', include('cmp.urls')),
    path('.well-known/est/', include('est.urls')),
    path('aoki/', include('aoki.urls')),
    path('home/', include('home.urls')),
    path('devices/', include('devices.urls')),
    path('management/', include('management.urls')),
    path('notifications/', include('notifications.urls')),
    path('i18n/', include('django.conf.urls.i18n')),
    path(
        'jsi18n/',
        vary_on_cookie(last_modified(lambda _req, **_kw: last_modified_date)(JavaScriptCatalog.as_view())),
        name='javascript-catalog',
    ),
    path('', base.IndexView.as_view()),
    path('workflows/', include('workflows.urls', namespace='workflows')),

    # API URLs
    path('api/', include('devices.api_urls')),
    path('api/', include('pki.api_urls')),
    path('api/', include('signer.api_urls')),
    path('api/', include('management.api_urls')),

    # JWT endpoints
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),

    # Swagger & Redoc
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc')
]
