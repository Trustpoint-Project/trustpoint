#!/usr/bin/env python
"""Script to toggle simplified view mode."""

import os
import sys
import django

# Add the project directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'trustpoint'))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trustpoint.settings')
django.setup()

from management.models import UIConfig

def toggle_view_mode():
    """Toggle between standard and simplified view modes."""
    config = UIConfig.get_current()
    
    print(f"Current view mode: {config.get_view_mode_display()}")
    
    if config.view_mode == UIConfig.ViewModeChoices.STANDARD:
        config.view_mode = UIConfig.ViewModeChoices.SIMPLIFIED
        print("Switching to Simplified View...")
    else:
        config.view_mode = UIConfig.ViewModeChoices.STANDARD
        print("Switching to Standard View...")
    
    config.save()
    print(f"New view mode: {config.get_view_mode_display()}")
    print("\nRefresh your browser to see the changes.")

if __name__ == '__main__':
    toggle_view_mode()
