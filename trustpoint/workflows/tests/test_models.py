"""Tests for workflows models module."""

from __future__ import annotations

import uuid

import pytest
from django.db import models

from workflows.models import (
    BADGE_MAP,
    State,
    WorkflowDefinition,
    WorkflowScope,
    get_status_badge,
)


class TestState:
    """Test the State enum."""

    def test_state_has_all_expected_values(self):
        """Test that State enum has all expected values."""
        assert hasattr(State, 'RUNNING')
        assert hasattr(State, 'AWAITING')
        assert hasattr(State, 'APPROVED')
        assert hasattr(State, 'PASSED')
        assert hasattr(State, 'FINALIZED')
        assert hasattr(State, 'REJECTED')
        assert hasattr(State, 'FAILED')
        assert hasattr(State, 'ABORTED')

    def test_state_values(self):
        """Test that State enum values are correct."""
        assert State.RUNNING == 'Running'
        assert State.AWAITING == 'AwaitingApproval'
        assert State.APPROVED == 'Approved'
        assert State.PASSED == 'Passed'
        assert State.FINALIZED == 'Finalized'
        assert State.REJECTED == 'Rejected'
        assert State.FAILED == 'Failed'
        assert State.ABORTED == 'Aborted'

    def test_state_is_text_choices(self):
        """Test that State is a TextChoices subclass."""
        assert issubclass(State, models.TextChoices)


class TestBadgeMap:
    """Test the BADGE_MAP dictionary."""

    def test_badge_map_has_all_states(self):
        """Test that BADGE_MAP contains all State enum values."""
        for state in State:
            assert state in BADGE_MAP, f'State {state} not in BADGE_MAP'

    def test_badge_map_structure(self):
        """Test that each badge entry is a tuple of (label, css_class)."""
        for state, badge in BADGE_MAP.items():
            assert isinstance(badge, tuple)
            assert len(badge) == 2
            assert isinstance(badge[0], str)  # label
            assert isinstance(badge[1], str)  # CSS class

    def test_badge_map_css_classes(self):
        """Test that badge CSS classes start with 'bg-'."""
        for state, (label, css_class) in BADGE_MAP.items():
            assert css_class.startswith('bg-'), f"CSS class for {state} should start with 'bg-'"

    def test_specific_badge_values(self):
        """Test specific badge values for key states."""
        assert BADGE_MAP[State.RUNNING] == ('Running', 'bg-primary')
        assert BADGE_MAP[State.AWAITING] == ('Awaiting approval', 'bg-warning text-dark')
        assert BADGE_MAP[State.APPROVED] == ('Approved', 'bg-success')
        assert BADGE_MAP[State.REJECTED] == ('Rejected', 'bg-danger')
        assert BADGE_MAP[State.FAILED] == ('Failed', 'bg-danger')
        assert BADGE_MAP[State.ABORTED] == ('Aborted', 'bg-dark')
        assert BADGE_MAP[State.PASSED] == ('Passed', 'bg-success')
        assert BADGE_MAP[State.FINALIZED] == ('Finalized', 'bg-secondary')


class TestGetStatusBadge:
    """Test the get_status_badge function."""

    def test_with_none(self):
        """Test get_status_badge with None returns unknown badge."""
        label, css = get_status_badge(None)
        assert label == 'Unknown'
        assert css == 'bg-light text-muted'

    def test_with_state_enum(self):
        """Test get_status_badge with State enum member."""
        label, css = get_status_badge(State.RUNNING)
        assert label == 'Running'
        assert css == 'bg-primary'

    def test_with_state_string(self):
        """Test get_status_badge with state string."""
        label, css = get_status_badge('Running')
        assert label == 'Running'
        assert css == 'bg-primary'

    def test_with_awaiting_state(self):
        """Test get_status_badge with awaiting state."""
        label, css = get_status_badge(State.AWAITING)
        assert label == 'Awaiting approval'
        assert css == 'bg-warning text-dark'

    def test_with_approved_state(self):
        """Test get_status_badge with approved state."""
        label, css = get_status_badge(State.APPROVED)
        assert label == 'Approved'
        assert css == 'bg-success'

    def test_with_rejected_state(self):
        """Test get_status_badge with rejected state."""
        label, css = get_status_badge(State.REJECTED)
        assert label == 'Rejected'
        assert css == 'bg-danger'

    def test_with_failed_state(self):
        """Test get_status_badge with failed state."""
        label, css = get_status_badge(State.FAILED)
        assert label == 'Failed'
        assert css == 'bg-danger'

    def test_with_aborted_state(self):
        """Test get_status_badge with aborted state."""
        label, css = get_status_badge(State.ABORTED)
        assert label == 'Aborted'
        assert css == 'bg-dark'

    def test_with_passed_state(self):
        """Test get_status_badge with passed state."""
        label, css = get_status_badge(State.PASSED)
        assert label == 'Passed'
        assert css == 'bg-success'

    def test_with_finalized_state(self):
        """Test get_status_badge with finalized state."""
        label, css = get_status_badge(State.FINALIZED)
        assert label == 'Finalized'
        assert css == 'bg-secondary'

    def test_with_normalized_string(self):
        """Test get_status_badge with normalized string (case insensitive)."""
        label, css = get_status_badge('running')
        assert label == 'Running'
        assert css == 'bg-primary'

    def test_with_whitespace_string(self):
        """Test get_status_badge with whitespace in string."""
        label, css = get_status_badge('  Running  ')
        assert label == 'Running'
        assert css == 'bg-primary'

    def test_with_unknown_string(self):
        """Test get_status_badge with unknown string returns fallback."""
        label, css = get_status_badge('UnknownState')
        assert label == 'UnknownState'
        assert css == 'bg-secondary text-light'


@pytest.mark.django_db
class TestWorkflowDefinition:
    """Test the WorkflowDefinition model."""

    def test_create_workflow_definition(self):
        """Test creating a workflow definition."""
        workflow = WorkflowDefinition.objects.create(
            name='Test Workflow', version=1, published=False, definition={'events': [], 'steps': []}
        )
        assert workflow.id is not None
        assert isinstance(workflow.id, uuid.UUID)
        assert workflow.name == 'Test Workflow'
        assert workflow.version == 1
        assert workflow.published is False
        assert workflow.definition == {'events': [], 'steps': []}

    def test_workflow_definition_str(self):
        """Test string representation of workflow definition."""
        workflow = WorkflowDefinition.objects.create(name='My Workflow', version=2, definition={})
        assert str(workflow) == 'My Workflow v2'

    def test_workflow_definition_default_version(self):
        """Test that version defaults to 1."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        assert workflow.version == 1

    def test_workflow_definition_default_published(self):
        """Test that published defaults to False."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        assert workflow.published is False

    def test_workflow_definition_auto_timestamps(self):
        """Test that timestamps are automatically set."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        assert workflow.created_at is not None
        assert workflow.updated_at is not None

    def test_workflow_definition_unique_name(self):
        """Test that workflow names must be unique."""
        WorkflowDefinition.objects.create(name='Unique Workflow', definition={})
        with pytest.raises(Exception):  # IntegrityError or similar
            WorkflowDefinition.objects.create(name='Unique Workflow', definition={})

    def test_workflow_definition_ordering(self):
        """Test that workflows are ordered by created_at descending."""
        workflow1 = WorkflowDefinition.objects.create(name='First Workflow', definition={})
        workflow2 = WorkflowDefinition.objects.create(name='Second Workflow', definition={})

        workflows = list(WorkflowDefinition.objects.all())
        assert workflows[0].id == workflow2.id  # Most recent first
        assert workflows[1].id == workflow1.id

    def test_workflow_definition_with_complex_definition(self):
        """Test workflow with complex definition JSON."""
        complex_def = {
            'events': ['enrollment_request'],
            'steps': [
                {'type': 'approval', 'name': 'Manager Approval'},
                {'type': 'webhook', 'url': 'https://example.com'},
                {'type': 'email', 'to': 'admin@example.com'},
            ],
        }
        workflow = WorkflowDefinition.objects.create(name='Complex Workflow', definition=complex_def)
        assert workflow.definition == complex_def
        assert len(workflow.definition['steps']) == 3


@pytest.mark.django_db
class TestWorkflowScope:
    """Test the WorkflowScope model."""

    def test_create_workflow_scope(self):
        """Test creating a workflow scope."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, ca_id=1, domain_id=2, device_id=3)
        assert scope.id is not None
        assert isinstance(scope.id, uuid.UUID)
        assert scope.workflow == workflow
        assert scope.ca_id == 1
        assert scope.domain_id == 2
        assert scope.device_id == 3

    def test_workflow_scope_with_null_values(self):
        """Test creating scope with NULL values (meaning any)."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, ca_id=None, domain_id=None, device_id=None)
        assert scope.ca_id is None
        assert scope.domain_id is None
        assert scope.device_id is None

    def test_workflow_scope_cascade_delete(self):
        """Test that scope is deleted when workflow is deleted."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, ca_id=1)
        scope_id = scope.id

        workflow.delete()

        assert not WorkflowScope.objects.filter(id=scope_id).exists()

    def test_workflow_scope_related_name(self):
        """Test accessing scopes through workflow's related name."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope1 = WorkflowScope.objects.create(workflow=workflow, ca_id=1)
        scope2 = WorkflowScope.objects.create(workflow=workflow, ca_id=2)

        scopes = list(workflow.scopes.all())
        assert len(scopes) == 2
        assert scope1 in scopes
        assert scope2 in scopes

    def test_workflow_scope_with_only_ca(self):
        """Test scope with only CA specified."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, ca_id=1)
        assert scope.ca_id == 1
        assert scope.domain_id is None
        assert scope.device_id is None

    def test_workflow_scope_with_only_domain(self):
        """Test scope with only domain specified."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, domain_id=5)
        assert scope.ca_id is None
        assert scope.domain_id == 5
        assert scope.device_id is None

    def test_workflow_scope_with_only_device(self):
        """Test scope with only device specified."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, device_id=10)
        assert scope.ca_id is None
        assert scope.domain_id is None
        assert scope.device_id == 10

    def test_multiple_scopes_for_workflow(self):
        """Test that a workflow can have multiple scopes."""
        workflow = WorkflowDefinition.objects.create(name='Multi-Scope Workflow', definition={})

        # Create scopes for different CAs
        scope1 = WorkflowScope.objects.create(workflow=workflow, ca_id=1)
        scope2 = WorkflowScope.objects.create(workflow=workflow, ca_id=2)
        scope3 = WorkflowScope.objects.create(workflow=workflow, ca_id=3)

        assert workflow.scopes.count() == 3

    def test_workflow_scope_str_with_ca(self):
        """Test string representation with CA only."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, ca_id=5)
        assert str(scope) == 'Test Workflow [CA=5]'

    def test_workflow_scope_str_with_domain(self):
        """Test string representation with domain only."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, domain_id=10)
        assert str(scope) == 'Test Workflow [Domain=10]'

    def test_workflow_scope_str_with_device(self):
        """Test string representation with device only."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, device_id=15)
        assert str(scope) == 'Test Workflow [Device=15]'

    def test_workflow_scope_str_with_all(self):
        """Test string representation with all IDs."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow, ca_id=1, domain_id=2, device_id=3)
        assert str(scope) == 'Test Workflow [CA=1, Domain=2, Device=3]'

    def test_workflow_scope_str_with_none(self):
        """Test string representation with no IDs (any)."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        scope = WorkflowScope.objects.create(workflow=workflow)
        assert str(scope) == 'Test Workflow [any]'

    def test_workflow_scope_unique_together(self):
        """Test that unique_together constraint works."""
        workflow = WorkflowDefinition.objects.create(name='Test Workflow', definition={})
        WorkflowScope.objects.create(workflow=workflow, ca_id=1, domain_id=2, device_id=3)

        # Try to create duplicate scope
        with pytest.raises(Exception):  # IntegrityError
            WorkflowScope.objects.create(workflow=workflow, ca_id=1, domain_id=2, device_id=3)
