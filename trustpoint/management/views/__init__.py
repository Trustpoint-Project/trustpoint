"""Package that contains all Django Views of the management App."""

from __future__ import annotations

from django.views.generic.base import RedirectView


class IndexView(RedirectView):
    """Index view."""

    permanent = True
    pattern_name = 'management:settings'
