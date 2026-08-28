# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for PKCS#11 session pooling."""

import pytest
from pkcs11.exceptions import GeneralError

from crypto.adapters.pkcs11.session_pool import Pkcs11SessionPool


class FakeSession:
    """Simple session fake for pooling tests."""

    def __init__(self, *, fail_close: bool = False) -> None:
        """Initialize counters."""
        self.close_calls = 0
        self.fail_close = fail_close

    def close(self) -> None:
        """Track close calls."""
        self.close_calls += 1
        if self.fail_close:
            raise GeneralError


class FakeToken:
    """Token fake that opens in-memory sessions."""

    def __init__(self) -> None:
        """Initialize open-call bookkeeping."""
        self.open_calls = 0

    def open(self, *, user_pin: str, rw: bool) -> FakeSession:
        """Return a new fake session."""
        assert user_pin == '1234'
        assert rw is True
        self.open_calls += 1
        return FakeSession()


def test_session_pool_reuses_idle_sessions() -> None:
    """A returned session should be reused instead of reopening the token."""
    token = FakeToken()
    pool = Pkcs11SessionPool(token=token, user_pin='1234', max_size=2)

    with pool.session() as session_one:
        first_session = session_one

    with pool.session() as session_two:
        second_session = session_two

    assert first_session is second_session
    assert token.open_calls == 1


def test_session_close_failure_does_not_mask_operation_error() -> None:
    """Discard cleanup must preserve the PKCS#11 error raised by the operation."""
    pool = Pkcs11SessionPool(token=FakeToken(), user_pin='1234', max_size=1)
    failing_session = FakeSession(fail_close=True)
    pool._open_session = lambda: failing_session  # type: ignore[method-assign]  # noqa: SLF001

    with pytest.raises(GeneralError):
        with pool.session():
            raise GeneralError


def test_pool_close_continues_after_session_close_failure() -> None:
    """Closing one bad session must not prevent the remaining idle sessions from closing."""
    pool = Pkcs11SessionPool(token=FakeToken(), user_pin='1234', max_size=2)
    failing_session = FakeSession(fail_close=True)
    healthy_session = FakeSession()
    pool._available_sessions.put_nowait(healthy_session)  # noqa: SLF001
    pool._available_sessions.put_nowait(failing_session)  # noqa: SLF001
    pool._created_sessions = 2  # noqa: SLF001

    pool.close()

    assert failing_session.close_calls == 1
    assert healthy_session.close_calls == 1
    assert pool._created_sessions == 0  # noqa: SLF001
