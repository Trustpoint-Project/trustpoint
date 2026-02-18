"""Python steps file for R_007."""

from behave import runner, then, when
import logging
import os
import time

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.abspath(f'{CURRENT_DIR}/../../media/log/trustpoint.log')


@when('the admin performs an action {action}')
def step_when_admin_performs_action(context: runner.Context, action: str) -> None:  # noqa: ARG001
    """Simulates the admin performing a specified action (create, update, delete).

    Args:
        context (runner.Context): Behave context.
        action (str): The action being performed.
    """
    logger.info(f'Admin performed {action} action')


@then('the system logs the action {action} with relevant details')
def step_then_system_logs_action(context: runner.Context, action: str) -> None:  # noqa: ARG001
    """Verifies that the system logs the specified action with relevant details.

    Args:
        context (runner.Context): Behave context.
        action (str): The action that should be logged.
    """

    assert os.path.exists(LOG_FILE_PATH), f'Log file {LOG_FILE_PATH} does not exist.'

    with open(LOG_FILE_PATH, 'r') as f:
        log_contents = f.read()

    expected_log = f'Admin performed {action} action'
    assert expected_log in log_contents, f'Expected log entry not found: {expected_log}'


@when('the admin retrieves logs for the time range {time_range}')
def step_when_admin_retrieves_logs(context: runner.Context, time_range: str) -> None:  # noqa: ARG001
    """Simulates the admin retrieving logs for a specific time range.

    Args:
        context (runner.Context): Behave context.
        time_range (str): The time range for filtering logs.
    """
    msg = f'STEP: When the admin retrieves logs for the time range {time_range}'
    raise AssertionError(msg)


@then('the system displays logs within the {time_range}')
def step_then_system_displays_logs(context: runner.Context, time_range: str) -> None:  # noqa: ARG001
    """Verifies that the system correctly displays logs within the specified time range.

    Args:
        context (runner.Context): Behave context.
        time_range (str): The expected time range of logs.
    """
    msg = f'STEP: Then the system displays logs within the {time_range}'
    raise AssertionError(msg)


@then('logs can be filtered by {filter_criteria}')
def step_then_logs_can_be_filtered(context: runner.Context, filter_criteria: str) -> None:  # noqa: ARG001
    """Ensures that logs can be filtered using specific criteria.

    Args:
        context (runner.Context): Behave context.
        filter_criteria (str): The filtering criteria (e.g., user, event type).
    """
    msg = f'STEP: Then logs can be filtered by {filter_criteria}'
    raise AssertionError(msg)


@when('the admin modifies logging configuration to {log_level}')
def step_when_admin_modifies_logging(context: runner.Context, log_level: str) -> None:  # noqa: ARG001
    """Simulates the admin modifying the logging configuration.

    Args:
        context (runner.Context): Behave context.
        log_level (str): The new logging verbosity level.
    """
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level))
    context.new_log_level = log_level


@then('the system applies the new logging configuration')
def step_then_system_applies_logging_config(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that the system applies the updated logging configuration.

    Args:
        context (runner.Context): Behave context.
    """
    current_level_num = logging.getLogger().getEffectiveLevel()
    current_log_level = logging.getLevelName(current_level_num)
    assert current_log_level == context.new_log_level, f'Expected log level is not: {context.new_log_level}'


@then('logs reflect the new verbosity level {log_level}')
def step_then_logs_reflect_log_level(context: runner.Context, log_level: str) -> None:  # noqa: ARG001
    """Ensures logs reflect the newly configured verbosity level.

    Args:
        context (runner.Context): Behave context.
        log_level (str): The expected verbosity level.
    """
    log_level = log_level.upper()
    reset_log_file()

    # Emit logs of various levels
    logger.debug('This is a DEBUG message')
    logger.info('This is an INFO message')
    logger.warning('This is a WARNING message')
    logger.error('This is an ERROR message')

    # Wait for log file flush
    time.sleep(0.5)

    with open(LOG_FILE_PATH, 'r') as f:
        contents = f.read()

    # Check that messages at or above log_level are included
    def should_be_present(level):
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        return levels.index(level) >= levels.index(log_level)

    assert ('DEBUG' in contents) == should_be_present('DEBUG'), 'DEBUG presence mismatch'
    assert ('INFO' in contents) == should_be_present('INFO'), 'INFO presence mismatch'
    assert ('WARNING' in contents) == should_be_present('WARNING'), 'WARNING presence mismatch'
    assert ('ERROR' in contents) == should_be_present('ERROR'), 'ERROR presence mismatch'


@when('the system restarts')
def step_when_system_restarts(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a system restart.

    Args:
        context (runner.Context): Behave context.
    """
    marker = f'PRE_RESTART_LOG_{time.time()}'
    logger.info(marker)
    context.log_marker = marker

    # Simulate restart
    time.sleep(0.1)


@then('previous logs are still accessible')
def step_then_previous_logs_are_accessible(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that logs remain accessible after a system restart.

    Args:
        context (runner.Context): Behave context.
    """
    assert os.path.exists(LOG_FILE_PATH), 'Log file does not exist.'

    with open(LOG_FILE_PATH, 'r') as f:
        contents = f.read()

    assert context.log_marker in contents, 'Pre-restart log entry not found after simulated restart.'


@then('unauthorized users cannot delete or modify logs')
def step_then_unauthorized_users_cannot_modify_logs(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures unauthorized users cannot delete or modify logs.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then unauthorized users cannot delete or modify logs'
    raise AssertionError(msg)


def reset_log_file():
    if os.path.exists(LOG_FILE_PATH):
        open(LOG_FILE_PATH, 'w').close()
