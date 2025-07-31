"""Environment file for behave tests."""

import functools
import traceback
from collections.abc import Callable

from behave import given, runner, step, then, when
#from selenium import webdriver


# Function to wrap steps and enforce failure on any exception
def fail_on_exception(func: Callable) -> Callable:
    """Wrapper that ensures uncaught exceptions fail the scenario and are logged to the HTML report."""

    @functools.wraps(func)
    def wrapper(context: runner.Context, *args: tuple, **kwargs: dict) -> Callable:
        try:
            return func(context, *args, **kwargs)
        except AssertionError:
            raise
        except Exception as e:
            traceback.print_exc()  # Print full traceback for debugging
            exc_msg = f'Step failed due to exception: {e}'
            raise AssertionError(exc_msg) from e

    return wrapper

# def before_all(context):
#     """Initializes browser before all tests."""

#     # Initialize browser (e.g., Chrome, Firefox)
#     context.browser = webdriver.Chrome()  # or webdriver.Firefox()
#     context.browser.implicitly_wait(10)  # optional: wait for elements to load

 
# def after_all(context):
#     """Quit the browser at the end of all tests."""
    
#     context.browser.quit()

# Monkey-patch Behave's step decorators to automatically wrap all steps
original_step = step
original_given = given
original_when = when
original_then = then


def patched_step(*args: tuple, **kwargs: dict) -> Callable:
    """Monkey-patched step decorator that wraps the step function to fail on any exception."""

    def decorator(func: Callable) -> Callable:
        return original_step(*args, **kwargs)(fail_on_exception(func))

    return decorator


def patched_given(*args: tuple, **kwargs: dict) -> Callable:
    """Monkey-patched given decorator that wraps the step function to fail on any exception."""

    def decorator(func: Callable) -> Callable:
        return original_given(*args, **kwargs)(fail_on_exception(func))

    return decorator


def patched_when(*args: tuple, **kwargs: dict) -> Callable:
    """Monkey-patched when decorator that wraps the step function to fail on any exception."""

    def decorator(func: Callable) -> Callable:
        return original_when(*args, **kwargs)(fail_on_exception(func))

    return decorator


def patched_then(*args: tuple, **kwargs: dict) -> Callable:
    """Monkey-patched then decorator that wraps the step function to fail on any exception."""

    def decorator(func: Callable) -> Callable:
        return original_then(*args, **kwargs)(fail_on_exception(func))

    return decorator


# Override Behave's step registration functions
step = patched_step
given = patched_given
when = patched_when
then = patched_then
