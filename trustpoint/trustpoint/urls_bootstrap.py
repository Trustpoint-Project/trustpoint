"""URL configuration for Trustpoint bootstrap mode.

Bootstrap intentionally exposes only setup-oriented routes. Operational APIs,
workers, device endpoints, and PKI management views are available only after the
container is started in the operational phase.
"""

from __future__ import annotations

from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path
from django.utils import timezone
from django.views.decorators.http import last_modified
from django.views.decorators.vary import vary_on_cookie
from django.views.generic import RedirectView
from django.views.i18n import JavaScriptCatalog

last_modified_date = timezone.now()

urlpatterns = [
    path('', RedirectView.as_view(pattern_name='setup_wizard:index', permanent=False)),
    path('users/', include('users.urls')),
    path('setup-wizard/', include('setup_wizard.urls')),
    path('i18n/', include('django.conf.urls.i18n')),
    path(
        'jsi18n/',
        vary_on_cookie(last_modified(lambda _req, **_kw: last_modified_date)(JavaScriptCatalog.as_view())),
        name='javascript-catalog',
    ),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
