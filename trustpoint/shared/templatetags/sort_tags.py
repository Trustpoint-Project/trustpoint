"""This module contains template tags for sorting lists or columns in a table."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django import template

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest, QueryDict


register = template.Library()


@register.simple_tag(takes_context=True)
def url_sort(context: dict[str, Any], field_name: str) -> str:
    """_Builds a querystring ?sort=... which toggles the field_name between asc / dsc.

    Args:
        context: The context of the request.
        field_name: The field name to toggle.

    Returns:
        The querystring ?sort=...
    """
    request: HttpRequest = context['request']
    params: QueryDict = request.GET.copy()
    current: list[str] = params.getlist('sort')

    rest: list[str] = [s for s in current if s.lstrip('-') != field_name]
    new: str = field_name if f'-{field_name}' in current else f'-{field_name}'

    params.setlist('sort', [new, *rest])
    qs: str = params.urlencode()
    return f'?{qs}'


@register.filter
def sort_icon(request: HttpRequest, field_name: str) -> str:
    """Return ↑ if `field_name` is sorted ascending, ↓ if descending, or '' otherwise.

    Args:
        request: The HttpRequest object.
        field_name: The corresponding field name.

    Returns:
        Return ↑ if `field_name` is sorted ascending, ↓ if descending, or '' otherwise.
    """
    sorts: list[str] = request.GET.getlist('sort')
    return '↓' if f'-{field_name}' in sorts else '↑'
