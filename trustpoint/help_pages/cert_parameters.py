# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Profile-driven, client-side editable parameters for the help page commands.

The server renders one command template per combination of present / omitted optional parameters using the
existing command builders. Parameters are represented by stable placeholder tokens inside these templates. The
client (static/js/help_cert_params.js) only selects the matching template and substitutes the escaped values.
:meth:`CertParameterTemplate.render` is the reference implementation of that client-side logic.
"""

from __future__ import annotations

import copy
import enum
import itertools
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.utils.html import format_html, json_script
from django.utils.safestring import SafeString
from django.utils.translation import gettext as _

from help_pages.help_section import HelpRow, ValueRenderType
from pki.forms.cert_profiles import ProfileBasedFormFieldBuilder

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from pki.util.cert_profile import EditableProfileField

MAX_OPTIONAL_PARAMETERS = 6
_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f]')
_SUBJECT_SPECIAL_CHARS = re.compile(r'([\\/+])')
_DOUBLE_QUOTE_SPECIAL_CHARS = re.compile(r'([\\"$`])')
NON_SUBJECT_VALUE_PATTERN = r'[^\s,]*'

RequestPath = tuple[str | int, ...]


class ShellQuoting(enum.StrEnum):
    """The shell quoting context a placeholder is located in."""

    NONE = 'none'
    SINGLE = 'single'
    DOUBLE = 'double'


@dataclass(frozen=True)
class CertParameter:
    """Metadata of a single editable certificate request parameter."""

    id: str
    label: str
    path: RequestPath
    required: bool
    default: str
    placeholder: str
    quoting: ShellQuoting = ShellQuoting.NONE

    @property
    def is_subject(self) -> bool:
        """Whether the parameter is a subject attribute (OpenSSL subject escaping applies)."""
        return self.path[0] == 'subject'

    @property
    def missing_display(self) -> str:
        """The text displayed in the command while a required value is missing."""
        return f'<{next(p for p in reversed(self.path) if isinstance(p, str))}>'

    def format_value(self, value: str) -> str:
        """Escape a user-provided value for the OpenSSL argument and the shell quoting context."""
        value = _CONTROL_CHARS.sub('', value)
        if self.is_subject:
            value = _SUBJECT_SPECIAL_CHARS.sub(r'\\\1', value)
        if self.quoting == ShellQuoting.DOUBLE:
            return _DOUBLE_QUOTE_SPECIAL_CHARS.sub(r'\\\1', value).replace('!', '"\'!\'"')
        escaped = value.replace("'", "'\\''")
        return escaped if self.quoting == ShellQuoting.SINGLE else f"'{escaped}'"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the metadata for the client side."""
        return {
            'id': self.id,
            'label': self.label,
            'path': list(self.path),
            'required': self.required,
            'default': self.default,
            'placeholder': self.placeholder,
            'quoting': self.quoting.value,
            'is_subject': self.is_subject,
            'missing_display': self.missing_display,
        }


@dataclass(frozen=True)
class CertParameterTemplate:
    """Command templates for all combinations of omitted optional parameters."""

    parameters: list[CertParameter]
    variants: dict[str, str]

    @property
    def optional_ids(self) -> list[str]:
        """Ids of the optional parameters in the order used by the variant keys."""
        return [p.id for p in self.parameters if not p.required]

    def render(self, values: dict[str, str]) -> str:
        """Render the command for the given (unescaped) values; empty optional values are omitted."""
        cleaned = {p.id: values.get(p.id, '').strip() for p in self.parameters}
        key = ''.join('1' if cleaned[pid] else '0' for pid in self.optional_ids)
        command = self.variants[key]
        for param in self.parameters:
            if cleaned[param.id]:
                command = command.replace(param.placeholder, param.format_value(cleaned[param.id]))
            elif param.required:
                command = command.replace(param.placeholder, param.missing_display)
        return command

    @property
    def initial_command(self) -> str:
        """The command using the profile defaults."""
        return self.render({p.id: p.default for p in self.parameters})

    def to_dict(self) -> dict[str, Any]:
        """Serialize the template for the client side."""
        return {
            'parameters': [p.to_dict() for p in self.parameters],
            'optional_ids': self.optional_ids,
            'variants': self.variants,
        }

    @classmethod
    def build(
        cls,
        sample_request: dict[str, Any],
        editable_fields: Iterable[EditableProfileField],
        build_command: Callable[[dict[str, Any]], str],
    ) -> CertParameterTemplate:
        """Build the parameter metadata and command variants using an existing command builder.

        Only parameters whose placeholder can be represented in the generated command are kept.
        """
        candidates = [
            c for c in _expand_candidates(editable_fields) if _is_representable(c, sample_request, build_command)
        ]
        optional = [c for c in candidates if not c.required][:MAX_OPTIONAL_PARAMETERS]
        candidates = [c for c in candidates if c.required or c in optional]
        if not candidates:
            return cls(parameters=[], variants={'': build_command(sample_request)})

        optional_ids = [c.id for c in candidates if not c.required]
        variants: dict[str, str] = {}
        for flags in itertools.product('10', repeat=len(optional_ids)):
            omitted = {pid for pid, flag in zip(optional_ids, flags, strict=True) if flag == '0'}
            variants[''.join(flags)] = build_command(_with_placeholders(sample_request, candidates, omitted))

        full_command = variants['1' * len(optional_ids)]
        parameters = [
            CertParameter(
                id=c.id, label=c.label, path=c.path, required=c.required, default=c.default,
                placeholder=c.placeholder, quoting=_quoting_at(full_command, full_command.index(c.placeholder)),
            )
            for c in candidates
        ]
        return cls(parameters=parameters, variants=variants)


def _label(path: RequestPath) -> str:
    keys = [p for p in path if isinstance(p, str)]
    key = keys[-1]
    label = (
        ProfileBasedFormFieldBuilder.SUBJECT_LABELS.get(key)
        or ProfileBasedFormFieldBuilder.SAN_LABELS.get(key, '').removesuffix(' (comma separated)')
        or key.replace('_', ' ').title()
    )
    index = path[-1]
    return f'{label} {index + 1}' if isinstance(index, int) and index > 0 else label


def _expand_candidates(editable_fields: Iterable[EditableProfileField]) -> list[CertParameter]:
    """Convert editable profile fields into text parameters, expanding list defaults into one parameter each."""
    candidates: list[CertParameter] = []
    for field in editable_fields:
        default = field.default
        entries: list[tuple[RequestPath, str]]
        if default is None or isinstance(default, str):
            entries = [(field.path, default or '')]
        elif isinstance(default, list) and default and all(isinstance(v, str) for v in default):
            entries = [((*field.path, i), v) for i, v in enumerate(default)]
        else:
            continue
        for path, value in entries:
            index = len(candidates)
            candidates.append(CertParameter(
                id='_'.join(str(p) for p in path),
                label=_label(path),
                path=path,
                required=field.required,
                default=value,
                placeholder=f'__TP_PARAM_{index}__',
            ))
    return candidates


def _is_representable(
    candidate: CertParameter, sample_request: dict[str, Any], build_command: Callable[[dict[str, Any]], str]
) -> bool:
    """Whether a text value at the candidate's path ends up in the command (e.g. not a whole extension object)."""
    try:
        return candidate.placeholder in build_command(_with_placeholders(sample_request, [candidate], set()))
    except (AttributeError, TypeError, ValueError):
        return False


def _with_placeholders(
    sample_request: dict[str, Any], parameters: list[CertParameter], omitted: set[str]
) -> dict[str, Any]:
    """Return a copy of the sample request with placeholders set and omitted parameters removed."""
    request = copy.deepcopy(sample_request)
    for param in parameters:
        node: Any = request
        for key in param.path[:-1]:
            if isinstance(key, str) and not isinstance(node.get(key), (dict, list)):
                node[key] = {}
            node = node[key]
        node[param.path[-1]] = param.placeholder
    # Remove back to front to keep list indices valid; drop lists that became empty.
    for param in sorted((p for p in parameters if p.id in omitted), key=lambda p: p.path, reverse=True):
        parent = _get_node(request, param.path[:-1])
        del parent[param.path[-1]]
        if isinstance(param.path[-1], int) and not parent:
            del _get_node(request, param.path[:-2])[param.path[-2]]
    return request


def _get_node(request: dict[str, Any], path: RequestPath) -> Any:
    node: Any = request
    for key in path:
        node = node[key]
    return node


def build_cert_parameter_rows(
    profile_name: str, template: CertParameterTemplate | None, *, hidden: bool
) -> list[HelpRow]:
    """Build the Certificate Parameters rows of one profile; JS toggles them via data-cert-params-profile."""
    if template is None or not template.parameters:
        message = (
            _('No additional parameters required.') if template is not None
            else _('The certificate parameters cannot be determined for this profile.')
        )
        value = format_html('<span data-cert-params-profile="{}">{}</span>', profile_name, message)
        return [HelpRow(_('Parameters'), value, ValueRenderType.HTML, hidden=hidden)]

    rows = []
    for index, param in enumerate(template.parameters):
        input_id = f'cert-param-{profile_name}-{param.id}'
        key = format_html(
            '<label for="{}" class="mb-0">{}{}</label>',
            input_id,
            param.label,
            SafeString(' <span class="text-danger" aria-hidden="true">*</span>') if param.required else '',
        )
        value = format_html(
            '<input type="text" class="form-control cert-param-input" id="{}" value="{}" placeholder="{}" '
            'data-cert-params-profile="{}" data-cert-param-id="{}"{}{}>',
            input_id,
            param.default,
            _('Required') if param.required else _('Optional - omitted from the command if empty'),
            profile_name,
            param.id,
            SafeString(' required aria-required="true"') if param.required else '',
            '' if param.is_subject else format_html(' pattern="{}"', NON_SUBJECT_VALUE_PATTERN),
        )
        if index == 0:
            value = format_html('{}{}', value, json_script(template.to_dict(), f'cert-params-data-{profile_name}'))
        rows.append(HelpRow(key, value, ValueRenderType.HTML, hidden=hidden))

    incomplete = any(p.required and not p.default for p in template.parameters)
    status = format_html(
        '<div data-cert-params-profile="{}" data-cert-params-status>'
        '<div class="alert alert-warning mb-0" data-status="incomplete"{}>{}</div>'
        '<div class="text-success" data-status="complete"{}>{}</div>'
        '</div>',
        profile_name,
        '' if incomplete else SafeString(' hidden'),
        _('The command below is incomplete. Please provide all required (*) and valid parameters.'),
        SafeString(' hidden') if incomplete else '',
        _('All required parameters are provided.'),
    )
    rows.append(HelpRow(_('Command Status'), status, ValueRenderType.HTML, hidden=hidden))
    return rows


def _quoting_at(command: str, index: int) -> ShellQuoting:
    """Determine the shell quoting context at the given position of a command."""
    quoting = ShellQuoting.NONE
    escaped = False
    for char in command[:index]:
        if escaped:
            escaped = False
        elif char == '\\' and quoting != ShellQuoting.SINGLE:
            escaped = True
        elif char == "'" and quoting != ShellQuoting.DOUBLE:
            quoting = ShellQuoting.NONE if quoting == ShellQuoting.SINGLE else ShellQuoting.SINGLE
        elif char == '"' and quoting != ShellQuoting.SINGLE:
            quoting = ShellQuoting.NONE if quoting == ShellQuoting.DOUBLE else ShellQuoting.DOUBLE
    return quoting
