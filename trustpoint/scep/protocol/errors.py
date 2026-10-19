# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exceptions raised by the SCEP protocol layer."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scep.protocol.oids import FailInfo


class ScepMalformedMessageError(ValueError):
    """The request cannot be parsed far enough to build a CertRep; maps to HTTP 400."""


class ScepProtocolError(Exception):
    """A request failure that is reported to the client as CertRep FAILURE."""

    def __init__(self, fail_info: FailInfo, text: str) -> None:
        """Store the failInfo code and a non-sensitive human readable explanation."""
        super().__init__(text)
        self.fail_info = fail_info
        self.text = text
