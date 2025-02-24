from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from typing import Any


class UniqueNameValidator(RegexValidator):
    form_label = _('(Must start with a letter. Can only contain letters, digits, underscores and hyphens)')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            regex=r'^[a-zA-Z]+[a-zA-Z0-9_-]+$',
            message=_(f'Enter a valid unique name. {self.form_label}.'),
            code='invalid_unique_name',
        )
