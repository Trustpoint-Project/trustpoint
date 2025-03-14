"""Package that contains all Django Views of the settings App."""

from __future__ import annotations

from django.views.generic.base import RedirectView


class IndexView(RedirectView):
    """Index view."""

    permanent = True
    pattern_name = 'settings:language'
