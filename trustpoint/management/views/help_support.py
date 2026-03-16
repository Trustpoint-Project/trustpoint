import time
from typing import Any
from django.conf import settings
from django.views.generic import TemplateView

class HelpView(TemplateView):
    """View for rendering the help page."""
    template_name = 'management/help.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        
        docs_dir = settings.BASE_DIR.parent / 'docs'
        docs_index = docs_dir / 'build' / 'html' / 'index.html'
        lock_file = docs_dir / '.building'


        is_building = False
        if lock_file.exists():
            if time.time() - lock_file.stat().st_mtime < 300:
                is_building = True
            else:
                lock_file.unlink()

        context.update({
            'page_category': 'settings',
            'page_name': 'help',
            'local_docs_available': docs_index.exists(),
            'build_in_progress': is_building,
        })
        return context