# trustpoint/context_processors.py
from pathlib import Path
import os
from django.conf import settings

def docs_flags(_request):
    """
    Expose des flags pour savoir si la doc locale est disponible.
    Priorité : static/docs/index.html (copie prête à servir).
    Fallback dev : docs/_build/html/index.html si jamais on sert autrement.
    Toggleable via USE_LOCAL_DOCS=0 pour forcer le mode online.
    """
    base = Path(settings.BASE_DIR)

    candidates = [
        base / "static" / "docs" / "index.html",          # chemin recommandé (Phase 1)
        base / "docs" / "build" / "html" / "index.html", # build dev si utilisée
    ]

    use_local = os.getenv("USE_LOCAL_DOCS", "1") == "1"
    available = use_local and any(p.exists() for p in candidates)

    return {
        "LOCAL_DOCS_AVAILABLE": available,
        "DOCS_MODE": "local" if available else "online",
    }
