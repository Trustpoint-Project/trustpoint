from __future__ import annotations

from unittest.mock import Mock, patch

from workflows2.events.request_events import Events
from workflows2.integrations.devices import on_device_deleted, on_device_saved


@patch('workflows2.integrations.devices.Workflow2Handler')
def test_on_device_saved_emits_created_event(mock_handler) -> None:
    instance = Mock()
    instance.id = 'device-1'
    instance.domain_id = 7
    instance.domain = Mock()

    on_device_saved(type(instance), instance, created=True)

    ctx = mock_handler.return_value.handle.call_args.args[0]
    assert ctx.event == Events.device_created
    assert ctx.operation == Events.device_created.operation


@patch('workflows2.integrations.devices.Workflow2Handler')
def test_on_device_saved_emits_domain_changed_event(mock_handler) -> None:
    instance = Mock()
    instance.id = 'device-1'
    instance.domain_id = 7
    instance.old_domain_id = 3
    instance.domain = Mock()

    on_device_saved(type(instance), instance, created=False)

    ctx = mock_handler.return_value.handle.call_args.args[0]
    assert ctx.event == Events.device_domain_changed
    assert ctx.operation == Events.device_domain_changed.operation


@patch('workflows2.integrations.devices.Workflow2Handler')
def test_on_device_deleted_emits_deleted_event(mock_handler) -> None:
    instance = Mock()
    instance.id = 'device-1'
    instance.domain_id = 7
    instance.domain = Mock()

    on_device_deleted(type(instance), instance)

    ctx = mock_handler.return_value.handle.call_args.args[0]
    assert ctx.event == Events.device_deleted
    assert ctx.operation == Events.device_deleted.operation
