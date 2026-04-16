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
def test_on_device_saved_emits_updated_event(mock_handler) -> None:
    instance = Mock()
    instance.id = 'device-1'
    instance.common_name = 'Device 1'
    instance.serial_number = 'SER-1'
    instance.domain_id = 7
    instance.workflow2_before_snapshot = {
        'id': 'device-1',
        'common_name': 'Device 1',
        'serial_number': 'SER-1',
        'domain_id': 3,
    }
    instance.domain = Mock()

    on_device_saved(type(instance), instance, created=False)

    ctx = mock_handler.return_value.handle.call_args.args[0]
    assert ctx.event == Events.device_updated
    assert ctx.operation == Events.device_updated.operation
    assert ctx.event_payload['device']['before']['domain_id'] == 3
    assert ctx.event_payload['device']['after']['domain_id'] == 7
    assert ctx.event_payload['device']['changes']['domain_id'] == {'before': 3, 'after': 7}


@patch('workflows2.integrations.devices.Workflow2Handler')
def test_on_device_saved_skips_updated_event_without_changes(mock_handler) -> None:
    instance = Mock()
    instance.id = 'device-1'
    instance.common_name = 'Device 1'
    instance.serial_number = 'SER-1'
    instance.domain_id = 7
    instance.workflow2_before_snapshot = {
        'id': 'device-1',
        'common_name': 'Device 1',
        'serial_number': 'SER-1',
        'domain_id': 7,
    }
    instance.domain = Mock()

    on_device_saved(type(instance), instance, created=False)

    mock_handler.return_value.handle.assert_not_called()


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
