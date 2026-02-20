"""Unit tests for the message builder base classes."""

import pytest

from request.message_builder.base import BuildingComponent, CompositeBuilding
from request.request_context import BaseRequestContext


class MockBuildingComponent(BuildingComponent):
    """Mock building component for testing."""

    def __init__(self, should_fail=False, exception_type=ValueError, return_context=None):
        self.should_fail = should_fail
        self.exception_type = exception_type
        self.return_context = return_context
        self.call_count = 0

    def build(self, context: BaseRequestContext) -> None:
        self.call_count += 1
        if self.should_fail:
            raise self.exception_type("Mock component failure")
        if self.return_context:
            # For components that might modify context, but BuildingComponent doesn't return anything
            pass


class TestBuildingComponent:
    """Test cases for the BuildingComponent abstract base class."""

    def test_building_component_is_abstract(self):
        """Test that BuildingComponent cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            BuildingComponent()


class TestCompositeBuilding:
    """Test cases for the CompositeBuilding class."""

    def test_init(self):
        """Test initialization of CompositeBuilding."""
        composite = CompositeBuilding()
        assert composite.components == []

    def test_add_component(self):
        """Test adding a component to the composite."""
        composite = CompositeBuilding()
        component = MockBuildingComponent()

        composite.add(component)
        assert len(composite.components) == 1
        assert composite.components[0] == component

    def test_add_multiple_components(self):
        """Test adding multiple components."""
        composite = CompositeBuilding()
        component1 = MockBuildingComponent()
        component2 = MockBuildingComponent()
        component3 = MockBuildingComponent()

        composite.add(component1)
        composite.add(component2)
        composite.add(component3)

        assert len(composite.components) == 3
        assert composite.components == [component1, component2, component3]

    def test_remove_component_success(self):
        """Test successful removal of a component."""
        composite = CompositeBuilding()
        component1 = MockBuildingComponent()
        component2 = MockBuildingComponent()

        composite.add(component1)
        composite.add(component2)
        assert len(composite.components) == 2

        composite.remove(component1)
        assert len(composite.components) == 1
        assert composite.components == [component2]

    def test_remove_component_not_found(self):
        """Test removal of a non-existent component raises ValueError."""
        composite = CompositeBuilding()
        component1 = MockBuildingComponent()
        component2 = MockBuildingComponent()

        composite.add(component1)

        with pytest.raises(ValueError, match="Attempted to remove non-existent building component"):
            composite.remove(component2)

    def test_build_empty_composite(self):
        """Test building with no components."""
        composite = CompositeBuilding()
        context = BaseRequestContext()

        # Should not raise any exception
        composite.build(context)

    def test_build_single_component_success(self):
        """Test building with a single successful component."""
        composite = CompositeBuilding()
        component = MockBuildingComponent()
        context = BaseRequestContext()

        composite.add(component)
        composite.build(context)

        assert component.call_count == 1

    def test_build_multiple_components_success(self):
        """Test building with multiple successful components."""
        composite = CompositeBuilding()
        component1 = MockBuildingComponent()
        component2 = MockBuildingComponent()
        component3 = MockBuildingComponent()
        context = BaseRequestContext()

        composite.add(component1)
        composite.add(component2)
        composite.add(component3)

        composite.build(context)

        assert component1.call_count == 1
        assert component2.call_count == 1
        assert component3.call_count == 1

    def test_build_component_fails_with_value_error(self):
        """Test building when a component raises ValueError."""
        composite = CompositeBuilding()
        success_component = MockBuildingComponent()
        fail_component = MockBuildingComponent(should_fail=True, exception_type=ValueError)
        never_called_component = MockBuildingComponent()

        composite.add(success_component)
        composite.add(fail_component)
        composite.add(never_called_component)

        context = BaseRequestContext()

        with pytest.raises(ValueError, match="MockBuildingComponent: Mock component failure"):
            composite.build(context)

        # First component should have been called
        assert success_component.call_count == 1
        # Failing component should have been called
        assert fail_component.call_count == 1
        # Component after failure should not have been called
        assert never_called_component.call_count == 0

    def test_build_component_fails_with_unexpected_error(self):
        """Test building when a component raises an unexpected error."""
        composite = CompositeBuilding()
        success_component = MockBuildingComponent()
        fail_component = MockBuildingComponent(should_fail=True, exception_type=RuntimeError)
        never_called_component = MockBuildingComponent()

        composite.add(success_component)
        composite.add(fail_component)
        composite.add(never_called_component)

        context = BaseRequestContext()

        with pytest.raises(ValueError, match="Unexpected error in MockBuildingComponent: Mock component failure"):
            composite.build(context)

        # First component should have been called
        assert success_component.call_count == 1
        # Failing component should have been called
        assert fail_component.call_count == 1
        # Component after failure should not have been called
        assert never_called_component.call_count == 0

    def test_build_stops_at_first_failure(self):
        """Test that building stops at the first component that fails."""
        composite = CompositeBuilding()
        component1 = MockBuildingComponent()
        component2 = MockBuildingComponent(should_fail=True)
        component3 = MockBuildingComponent()  # Should not be called

        composite.add(component1)
        composite.add(component2)
        composite.add(component3)

        context = BaseRequestContext()

        with pytest.raises(ValueError):
            composite.build(context)

        assert component1.call_count == 1
        assert component2.call_count == 1
        assert component3.call_count == 0

    def test_build_with_context_modification(self):
        """Test that components can modify the context during building."""
        composite = CompositeBuilding()

        class ContextModifyingComponent(BuildingComponent):
            def build(self, context: BaseRequestContext) -> None:
                context.operation = "modified_operation"

        component = ContextModifyingComponent()
        context = BaseRequestContext(operation="original_operation")

        composite.add(component)
        composite.build(context)

        assert context.operation == "modified_operation"
