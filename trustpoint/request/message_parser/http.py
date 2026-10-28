# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""HTTP Basic Auth header parsing shared by EST and REST."""

import base64
from typing import ClassVar

from request.request_context import BaseRequestContext, HttpBaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import ParsingComponent


class BasicAuthHeaderParsing(ParsingComponent, LoggerMixin):
    """Parse Basic credentials into the fields used by the selected protocol."""

    context_type: ClassVar[type[HttpBaseRequestContext]]
    context_error_message: ClassVar[str]
    protocol: ClassVar[str]

    def parse(self, context: BaseRequestContext) -> None:
        """Validate the HTTP request and decode its optional Basic Auth header."""
        if not isinstance(context, self.context_type):
            raise TypeError(self.context_error_message)
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            self.logger.warning('%s auth header parsing failed: Raw message is missing', self.protocol.upper())
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            msg = 'Raw message is missing headers.'
            self.logger.warning('%s auth header parsing failed: Headers are missing', self.protocol.upper())
            raise ValueError(msg)

        header = context.raw_message.headers.get('Authorization')
        if not header:
            self.logger.debug('%s auth header parsing skipped: No Authorization header present', self.protocol.upper())
            return
        if not header.lower().startswith('basic '):
            msg = "Authorization header must start with 'Basic'."
            self.logger.warning('%s auth header parsing failed: Expected Basic authentication', self.protocol.upper())
            raise ValueError(msg)

        try:
            credentials = base64.b64decode(header.split(' ', 1)[1].strip()).decode('utf-8')
            username, password = credentials.split(':', 1)
            setattr(context, f'{self.protocol}_username', username)
            setattr(context, f'{self.protocol}_password', password)
            self.logger.debug('%s auth header parsing successful: Extracted user %s', self.protocol.upper(), username)
        except Exception as exc:
            msg = "Malformed 'Authorization' header credentials."
            self.logger.warning('%s auth header parsing failed: Malformed credentials - %s', self.protocol.upper(), exc)
            context.error(msg, http_status=401)
            raise ValueError(msg) from exc
