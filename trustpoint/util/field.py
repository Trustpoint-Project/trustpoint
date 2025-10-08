"""This module contains validators that are used in several different apps in the trustpoint project."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.x509.oid import NameOID
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from typing import Any


class UniqueNameValidator(RegexValidator):
    """Validates unique names used in the trustpoint."""

    form_label = _(
        '(All UTF-8 characters are allowed except control characters (e.g., newline, tab).)'
    )

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
            regex=r'^[^\x00-\x1F\x7F-\x9F]+$',
            message=trans_msg,
            code='invalid_unique_name',
        )

    def __call__(self, value: Any) -> None:
        """Trim trailing spaces before validation."""
        if isinstance(value, str):
            value = value.rstrip()
        super().__call__(value)


def get_certificate_name(cert: x509.Certificate) -> str :
    """Extracts a certificate name from x509 certificate.

    Args:
        cert: x509 Certificate.
    Priority:
      1. CN (Common Name) from Subject DN
      2. First SAN entry
    """
    # Try CN from Subject DN
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn:
            return cn
    except IndexError:
        pass

    # Try SAN extension (first entry)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san.value.get_values_for_type(x509.DNSName)
        if san_names:
            return san_names[0]
    except x509.ExtensionNotFound:
        pass  # SAN not present

    raise ValueError('No valid CN or SAN found in the certificate. Unique name is required.')
