"""Django Views"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.http import HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.generic.base import RedirectView

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest, HttpResponse


def language(request: HttpRequest) -> HttpResponse:
    """Handle language Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'settings', 'page_name': 'language'}
    return render(request, 'settings/language.html', context=context)
