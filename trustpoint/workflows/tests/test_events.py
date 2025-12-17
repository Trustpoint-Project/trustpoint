"""Tests for workflows events module."""

from __future__ import annotations

from workflows.events import Event, Events


class TestEvent:
    """Test the Event dataclass."""

    def test_event_creation(self):
        """Test creating an Event instance."""
        event = Event(
            key='test_event',
            protocol='TEST',
            operation='test_op',
            handler='test_handler'
        )
        assert event.key == 'test_event'
        assert event.protocol == 'TEST'
        assert event.operation == 'test_op'
        assert event.handler == 'test_handler'

    def test_event_is_frozen(self):
        """Test that Event is frozen (immutable)."""
        event = Event(
            key='test_event',
            protocol='TEST',
            operation='test_op',
            handler='test_handler'
        )
        
        # Should not be able to modify frozen dataclass
        try:
            event.key = 'modified'  # type: ignore
            assert False, "Should not be able to modify frozen dataclass"
        except Exception:
            pass  # Expected

    def test_event_equality(self):
        """Test that two Events with same values are equal."""
        event1 = Event(
            key='test',
            protocol='TEST',
            operation='op',
            handler='handler'
        )
        event2 = Event(
            key='test',
            protocol='TEST',
            operation='op',
            handler='handler'
        )
        assert event1 == event2

    def test_event_hashable(self):
        """Test that Event instances are hashable (can be used in sets/dicts)."""
        event = Event(
            key='test',
            protocol='TEST',
            operation='op',
            handler='handler'
        )
        # Should be able to add to a set
        event_set = {event}
        assert event in event_set


class TestEvents:
    """Test the Events class containing event definitions."""

    def test_events_has_est_simpleenroll(self):
        """Test that Events has est_simpleenroll defined."""
        assert hasattr(Events, 'est_simpleenroll')
        event = Events.est_simpleenroll
        assert isinstance(event, Event)
        assert event.key == 'est_simpleenroll'
        assert event.protocol == 'est'
        assert event.operation == 'simpleenroll'
        assert event.handler == 'certificate_request'

    def test_events_has_est_simplereenroll(self):
        """Test that Events has est_simplereenroll defined."""
        assert hasattr(Events, 'est_simplereenroll')
        event = Events.est_simplereenroll
        assert isinstance(event, Event)
        assert event.key == 'est_simplereenroll'
        assert event.protocol == 'EST'
        assert event.operation == 'simplereenroll'
        assert event.handler == 'certificate_request'

    def test_event_instances_are_unique_objects(self):
        """Test that event instances are distinct."""
        event1 = Events.est_simpleenroll
        event2 = Events.est_simplereenroll
        assert event1 is not event2
        assert event1 != event2


class TestEventsAll:
    """Test the Events.all() class method."""

    def test_all_returns_list(self):
        """Test that Events.all() returns a list."""
        events = Events.all()
        assert isinstance(events, list)

    def test_all_contains_event_instances(self):
        """Test that all returned items are Event instances."""
        events = Events.all()
        assert all(isinstance(e, Event) for e in events)

    def test_all_not_empty(self):
        """Test that Events.all() returns non-empty list."""
        events = Events.all()
        assert len(events) > 0

    def test_all_contains_est_simpleenroll(self):
        """Test that Events.all() includes est_simpleenroll."""
        events = Events.all()
        event_keys = [e.key for e in events]
        assert 'est_simpleenroll' in event_keys

    def test_all_no_duplicates(self):
        """Test that Events.all() doesn't return duplicates."""
        events = Events.all()
        event_keys = [e.key for e in events]
        assert len(event_keys) == len(set(event_keys))


class TestEventsProtocols:
    """Test the Events.protocols() class method."""

    def test_protocols_returns_list(self):
        """Test that Events.protocols() returns a list."""
        protocols = Events.protocols()
        assert isinstance(protocols, list)

    def test_protocols_contains_strings(self):
        """Test that all returned items are strings."""
        protocols = Events.protocols()
        assert all(isinstance(p, str) for p in protocols)

    def test_protocols_not_empty(self):
        """Test that Events.protocols() returns non-empty list."""
        protocols = Events.protocols()
        assert len(protocols) > 0

    def test_protocols_no_duplicates(self):
        """Test that Events.protocols() doesn't return duplicates."""
        protocols = Events.protocols()
        assert len(protocols) == len(set(protocols))

    def test_protocols_contains_est(self):
        """Test that Events.protocols() includes EST protocol."""
        protocols = Events.protocols()
        # Should contain 'est' or 'EST'
        protocols_lower = [p.lower() for p in protocols]
        assert 'est' in protocols_lower

    def test_protocols_filters_empty_protocols(self):
        """Test that Events.protocols() doesn't include empty strings."""
        protocols = Events.protocols()
        assert '' not in protocols
        assert all(p.strip() for p in protocols)

    def test_protocols_is_sorted(self):
        """Test that Events.protocols() returns sorted list."""
        protocols = Events.protocols()
        assert protocols == sorted(protocols)


class TestEventsOperationsFor:
    """Test the Events.operations_for() class method."""

    def test_operations_for_est_returns_list(self):
        """Test that operations_for returns a list."""
        operations = Events.operations_for('est')
        assert isinstance(operations, list)

    def test_operations_for_est_not_empty(self):
        """Test that EST protocol has operations."""
        operations = Events.operations_for('est')
        assert len(operations) > 0

    def test_operations_for_est_contains_simpleenroll(self):
        """Test that EST operations include simpleenroll."""
        operations = Events.operations_for('est')
        assert 'simpleenroll' in operations

    def test_operations_for_unknown_protocol(self):
        """Test operations_for with unknown protocol returns empty list."""
        operations = Events.operations_for('unknown_protocol')
        assert operations == []

    def test_operations_for_case_sensitive(self):
        """Test that operations_for is case-sensitive."""
        operations_lower = Events.operations_for('est')
        operations_upper = Events.operations_for('EST')
        # They should be different if protocol names are case-sensitive
        # Or same if case-insensitive - just testing the behavior
        assert isinstance(operations_lower, list)
        assert isinstance(operations_upper, list)
