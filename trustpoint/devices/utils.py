"""Utility functions for the devices app."""

from django import forms

from util.validation import (
    ValidationError as GeneralValidationError,
)
from util.validation import (
    validate_application_uri as general_validate_application_uri,
)
from util.validation import (
    validate_common_name_characters as general_validate_common_name_characters,
)


def validate_common_name_characters(common_name: str) -> None:
    """Validate that the common name contains only safe characters and no URL-like constructs."""
    try:
        general_validate_common_name_characters(common_name)
    except GeneralValidationError as e:
        raise forms.ValidationError(str(e)) from e


def validate_application_uri(application_uri: str) -> None:
    """Validate that the application URI has a valid scheme and is not HTTP/HTTPS."""
    try:
        general_validate_application_uri(application_uri)
    except GeneralValidationError as e:
        raise forms.ValidationError(str(e)) from e

