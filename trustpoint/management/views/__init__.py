"""Package that contains all Django Views of the management App."""

from __future__ import annotations

from django.utils.translation import gettext as _
from django.views.generic.base import RedirectView


class IndexView(RedirectView):
    """Index view."""

    permanent = True
    pattern_name = 'management:settings'
