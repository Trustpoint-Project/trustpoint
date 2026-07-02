"""Generate Trustpoint architecture documentation automatically."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# Add trustpoint to path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
TRUSTPOINT_DIR = PROJECT_ROOT / 'trustpoint'
sys.path.insert(0, str(TRUSTPOINT_DIR))

import os

import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trustpoint.settings')
django.setup()

from django.apps import apps as django_apps
from django.conf import settings
from django.urls import get_resolver


def get_installed_apps() -> list[str]:
    """Get list of Trustpoint apps (exclude Django contrib and third-party)."""
    trustpoint_apps = []
    for app in settings.INSTALLED_APPS:
        if not app.startswith(('django.', 'rest_framework', 'drf_', 'crispy', 'dbbackup', 'django_')):
            if app != 'trustpoint_core':  # External dependency
                app_label = app.split('.')[0]
                trustpoint_apps.append(app_label)
    return trustpoint_apps


def analyze_models() -> dict[str, Any]:
    """Analyze Django models and their relationships."""
    model_data = {}
    
    trustpoint_apps = get_installed_apps()

    for app_config in django_apps.get_app_configs():
        if app_config.name not in trustpoint_apps:
            continue

        app_models = {}
        for model in app_config.get_models():
            model_name = model.__name__
            fields = []

            for field in model._meta.get_fields():
                field_info = {
                    'name': field.name,
                    'type': field.__class__.__name__,
                }

                if hasattr(field, 'related_model') and field.related_model:
                    field_info['related_to'] = f"{field.related_model._meta.app_label}.{field.related_model.__name__}"

                fields.append(field_info)

            app_models[model_name] = {
                'fields': fields,
                'verbose_name': str(model._meta.verbose_name),
                'table_name': model._meta.db_table,
            }

        if app_models:
            model_data[app_config.name] = app_models

    return model_data


def analyze_urls() -> dict[str, Any]:
    """Analyze URL patterns and their views."""
    url_data = {}
    resolver = get_resolver()

    def _extract_patterns(patterns, prefix=''):
        """Recursively extract URL patterns."""
        routes = []
        for pattern in patterns:
            if hasattr(pattern, 'url_patterns'):
                new_prefix = prefix + str(pattern.pattern)
                routes.extend(_extract_patterns(pattern.url_patterns, new_prefix))
            else:
                route_info = {
                    'pattern': prefix + str(pattern.pattern),
                }
                if hasattr(pattern, 'callback'):
                    callback = pattern.callback
                    if callback:
                        route_info['view'] = f"{callback.__module__}.{callback.__name__}"
                if hasattr(pattern, 'name') and pattern.name:
                    route_info['name'] = pattern.name
                routes.append(route_info)
        return routes

    url_data['routes'] = _extract_patterns(resolver.url_patterns)
    return url_data


def generate_app_dependency_rst(output_dir: Path) -> None:
    """Generate RST file with application dependency graph using pydeps."""
    print("Generating application dependency graph...")

    svg_path = output_dir / 'app_dependencies.svg'
    try:
        subprocess.run(
            [
                'uv',
                'run',
                'pydeps',
                str(TRUSTPOINT_DIR),
                '--max-bacon=2',
                '--cluster',
                '--noshow',
                '-o',
                str(svg_path),
                '--exclude=django.*,rest_framework.*,crispy.*',
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Warning: pydeps failed: {e}")
        print(f"stderr: {e.stderr}")
        # Continue anyway

    rst_content = """Application Dependencies
========================

This diagram shows the dependency relationships between Trustpoint applications.

.. image:: app_dependencies.svg
   :alt: Application Dependency Graph
   :align: center

**Legend:**

- **Arrows** indicate import dependencies (A → B means A imports from B)
- **Clusters** group related applications
- **Colors** indicate different application modules

Key Applications
----------------

"""

    for app in get_installed_apps():
        app_name = app.split('.')[-1] if '.' in app else app
        rst_content += f"- **{app_name}**: "

        try:
            app_config = django_apps.get_app_config(app_name)
            if hasattr(app_config, '__doc__') and app_config.__doc__:
                rst_content += app_config.__doc__.split('\n')[0]
            else:
                rst_content += f"{app_name.title()} application"
        except LookupError:
            rst_content += f"{app_name.title()} application"

        rst_content += '\n'

    (output_dir / 'app_dependencies.rst').write_text(rst_content)
    print(f"✓ Generated {output_dir / 'app_dependencies.rst'}")


def generate_model_diagram_rst(output_dir: Path, model_data: dict) -> None:
    """Generate RST file with Django model diagrams using django-extensions."""
    print("Generating model relationship diagram...")

    dot_path = output_dir / 'model_relationships.dot'
    svg_path = output_dir / 'model_relationships.svg'
    
    try:
        subprocess.run(
            [
                'uv',
                'run',
                'python',
                str(TRUSTPOINT_DIR / 'manage.py'),
                'graph_models',
                '-a',  # All apps
                '--dot',
                '-o',
                str(dot_path),
                '--exclude-models',
                'Session,ContentType,Permission,Group,LogEntry',
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        
        try:
            subprocess.run(
                ['dot', '-Tsvg', str(dot_path), '-o', str(svg_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            print(f"✓ Generated SVG diagram at {svg_path}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Note: graphviz 'dot' command not found. SVG not generated.")
            print(f"DOT file available at: {dot_path}")
            
    except subprocess.CalledProcessError as e:
        print(f"Warning: graph_models failed: {e}")
        print(f"stderr: {e.stderr}")

    rst_content = """Model Relationships
===================

Complete Model Diagram
----------------------

This diagram shows all Django models and their relationships across the Trustpoint application.

"""

    # Check if SVG was generated
    svg_path = output_dir / 'model_relationships.svg'
    dot_path = output_dir / 'model_relationships.dot'
    
    if svg_path.exists():
        rst_content += """.. image:: model_relationships.svg
   :alt: Complete Model Relationship Diagram
   :align: center
   :width: 100%

"""
    elif dot_path.exists():
        rst_content += f""".. note::
   
   Model diagram is available as a DOT file. To generate SVG, install graphviz and run:
   
   .. code-block:: bash
   
      dot -Tsvg {dot_path.name} -o model_relationships.svg

"""
    else:
        rst_content += """.. note::
   
   Model diagram generation requires django-extensions. 
   Run the architecture generator to create diagrams.

"""

    rst_content += """
**Legend:**

- **Boxes** represent Django models
- **Solid arrows** indicate ForeignKey relationships
- **Dashed arrows** indicate ManyToMany relationships
- **Colors** group models by application

Model Index by Application
---------------------------

"""

    # Add model index
    for app_name, models in sorted(model_data.items()):
        app_display = app_name.split('.')[-1]
        rst_content += f"\n{app_display}\n"
        rst_content += "^" * len(app_display) + "\n\n"

        for model_name, model_info in sorted(models.items()):
            rst_content += f"**{model_name}**\n\n"
            rst_content += f"   *{model_info['verbose_name']}*\n\n"
            rst_content += f"   Database table: ``{model_info['table_name']}``\n\n"

            # List relationships
            relationships = [
                f for f in model_info['fields'] if 'related_to' in f
            ]
            if relationships:
                rst_content += "   Relationships:\n\n"
                for rel in relationships:
                    rst_content += f"   - ``{rel['name']}`` ({rel['type']}) → {rel['related_to']}\n"
                rst_content += "\n"

    (output_dir / 'model_relationships.rst').write_text(rst_content)
    print(f"✓ Generated {output_dir / 'model_relationships.rst'}")


def generate_url_routing_rst(output_dir: Path, url_data: dict) -> None:
    """Generate RST file documenting URL routing."""
    print("Generating URL routing documentation...")

    rst_content = """URL Routing Map
===============

This document maps URL patterns to their corresponding views across the Trustpoint application.

URL Patterns by App
-------------------

"""

    # Group routes by app
    routes_by_app: dict[str, list] = {}
    for route in url_data['routes']:
        pattern = route['pattern']
        # Try to extract app from pattern or view
        app_name = 'other'

        if 'view' in route:
            view_module = route['view'].split('.')[0]
            app_name = view_module

        # Try to get from pattern
        parts = pattern.strip('^$/').split('/')
        if parts and parts[0]:
            potential_app = parts[0]
            if potential_app in get_installed_apps():
                app_name = potential_app

        if app_name not in routes_by_app:
            routes_by_app[app_name] = []
        routes_by_app[app_name].append(route)

    # Write routes by app
    for app_name in sorted(routes_by_app.keys()):
        routes = routes_by_app[app_name]
        app_display = app_name.replace('_', ' ').title()

        rst_content += f"\n{app_display}\n"
        rst_content += "^" * len(app_display) + "\n\n"

        rst_content += ".. list-table::\n"
        rst_content += "   :header-rows: 1\n"
        rst_content += "   :widths: 40 30 30\n\n"
        rst_content += "   * - URL Pattern\n"
        rst_content += "     - View\n"
        rst_content += "     - Name\n"

        for route in sorted(routes, key=lambda x: x['pattern']):
            pattern = route['pattern'].replace('|', r'\|')
            view = route.get('view', '').rsplit('.', 1)[-1] if 'view' in route else '-'
            name = route.get('name', '-')

            rst_content += f"   * - ``{pattern}``\n"
            rst_content += f"     - ``{view}``\n"
            rst_content += f"     - ``{name}``\n"

        rst_content += "\n"

    (output_dir / 'url_routing.rst').write_text(rst_content)
    print(f"✓ Generated {output_dir / 'url_routing.rst'}")


def generate_app_overview_rst(output_dir: Path, model_data: dict, url_data: dict) -> None:
    """Generate overview RST file."""
    print("Generating application overview...")

    apps = get_installed_apps()

    rst_content = """Application Overview
====================

This document provides an automatically generated overview of the Trustpoint architecture.

**Generated sections:**

.. toctree::
   :maxdepth: 2

   app_dependencies
   model_relationships
   url_routing

Statistics
----------

"""

    # Count stats
    total_models = sum(len(models) for models in model_data.values())
    total_routes = len(url_data['routes'])

    rst_content += f"- **Applications**: {len(apps)}\n"
    rst_content += f"- **Models**: {total_models}\n"
    rst_content += f"- **URL Routes**: {total_routes}\n\n"

    rst_content += """
Applications
------------

"""

    for app in sorted(apps):
        app_name = app.split('.')[-1] if '.' in app else app
        model_count = len(model_data.get(app, {}))

        rst_content += f"**{app_name}**\n\n"

        try:
            app_config = django_apps.get_app_config(app_name)
            rst_content += f"   - Models: {model_count}\n"
            rst_content += f"   - Path: ``{app_config.path}``\n"
        except LookupError:
            pass

        rst_content += "\n"

    (output_dir / 'index.rst').write_text(rst_content)
    print(f"✓ Generated {output_dir / 'index.rst'}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate Trustpoint architecture documentation'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=PROJECT_ROOT / 'docs' / 'source' / 'development' / 'architecture' / 'generated',
        help='Output directory for generated documentation',
    )

    args = parser.parse_args()
    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    print("="* 60)
    print("Trustpoint Architecture Documentation Generator")
    print("="* 60)

    print("\nAnalyzing project structure...")
    model_data = analyze_models()
    url_data = analyze_urls()

    print(f"Found {len(model_data)} apps with models")
    print(f"Found {len(url_data['routes'])} URL routes")

    print("\nGenerating documentation files...")
    generate_app_overview_rst(output_dir, model_data, url_data)
    generate_app_dependency_rst(output_dir)
    generate_model_diagram_rst(output_dir, model_data)
    generate_url_routing_rst(output_dir, url_data)

    json_path = output_dir / 'architecture_data.json'
    with json_path.open('w') as f:
        json.dump(
            {
                'models': model_data,
                'urls': url_data,
                'apps': get_installed_apps(),
            },
            f,
            indent=2,
        )
    print(f"✓ Saved raw data to {json_path}")

    print("\n" + "="* 60)
    print("Architecture documentation generated successfully!")
    print(f"Output directory: {output_dir}")
    print("="* 60)


if __name__ == '__main__':
    main()
