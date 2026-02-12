"""Provides the base classes for the message building step of the request pipeline."""

from abc import ABC, abstractmethod

from request.request_context import BaseRequestContext
from trustpoint.logger import LoggerMixin


class BuildingComponent(ABC):
    """Abstract base class for components in the composite building pattern.

    This is the building counterpart to ``ParsingComponent`` in ``message_parser/base.py``.
    Each component is responsible for one aspect of constructing a CMP PKI message
    (e.g. header, body, protection preparation) and stores its results in the context.
    """

    @abstractmethod
    def build(self, context: BaseRequestContext) -> None:
        """Execute building logic and store results in the context."""


class CompositeBuilding(BuildingComponent, LoggerMixin):
    """Composite builder to group multiple building components.

    Mirrors the ``CompositeParsing`` class from ``message_parser/base.py``.
    """

    def __init__(self) -> None:
        """Initialize the composite builder with an empty list of components."""
        self.components: list[BuildingComponent] = []

    def add(self, component: BuildingComponent) -> None:
        """Add a building component to the composite builder."""
        self.components.append(component)

    def remove(self, component: BuildingComponent) -> None:
        """Remove a building component from the composite builder."""
        if component in self.components:
            self.components.remove(component)
            self.logger.debug('Removed building component: %(component_name)s',
                              extra={'component_name': component.__class__.__name__})
        else:
            error_message = f'Attempted to remove non-existent building component: {component.__class__.__name__}'
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def build(self, context: BaseRequestContext) -> None:
        """Execute all child builders sequentially."""
        self.logger.debug('Starting composite building with %i components', len(self.components))

        for i, component in enumerate(self.components):
            try:
                component.build(context)
                self.logger.debug('Building component %s completed successfully',
                                  component.__class__.__name__)
            except ValueError as e:
                error_message = f'{component.__class__.__name__}: {e}'
                self.logger.warning('Building component %s failed: %s',
                                    component.__class__.__name__, str(e))
                self.logger.exception(
                    'Composite building failed at component %s/%s: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f'Unexpected error in {component.__class__.__name__}: {e}'
                self.logger.exception('Unexpected error in building component %s',
                                      component.__class__.__name__)
                self.logger.exception(
                    'Composite building failed at component %s/%s: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e

        self.logger.info('Composite building successful. All %i components completed',
                         len(self.components))
