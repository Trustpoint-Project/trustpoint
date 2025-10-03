"""This module contains validators that are used in several different apps in the trustpoint project."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from typing import Any


class UniqueNameValidator(RegexValidator):
    """Validates unique names used in the trustpoint."""

    form_label = _('(Must start with a letter. Can only contain letters, digits, umlauts, underscores and hyphens)')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes a UniqueNameValidator object.

        Args:
            args: Positional arguments are discarded.
            kwargs: Keyword arguments are discarded._
        """
        del args
        del kwargs
        msg = f'Enter a valid unique name. {self.form_label}.'
        trans_msg = _(msg)
        super().__init__(
            regex=r'^[a-zA-ZäöüÄÖÜß]+[a-zA-Z0-9äöüÄÖÜß _-]*$',
            message=trans_msg,
            code='invalid_unique_name',
        )
