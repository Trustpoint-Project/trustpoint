"""View for the help page."""

from typing import Any

from django.views.generic import TemplateView


class HelpView(TemplateView):
    """View for rendering the help page."""

    template_name = 'management/help.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add context data for the help page."""
        context = super().get_context_data(**kwargs)
        context.update(
            {
                'page_category': 'settings',
                'page_name': 'help',
            }
        )
        return context
