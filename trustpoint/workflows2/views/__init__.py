"""Workflow 2 view exports."""

from .definitions import Workflow2DefinitionCreateView as Workflow2DefinitionCreateView
from .definitions import Workflow2DefinitionEditView as Workflow2DefinitionEditView
from .definitions import Workflow2DefinitionListView as Workflow2DefinitionListView
from .triggers import Workflow2TriggerCatalogView as Workflow2TriggerCatalogView

__all__ = [
    'Workflow2DefinitionCreateView',
    'Workflow2DefinitionEditView',
    'Workflow2DefinitionListView',
    'Workflow2TriggerCatalogView',
]
