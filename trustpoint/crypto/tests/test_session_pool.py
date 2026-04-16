"""Tests for PKCS#11 session pooling."""

from crypto.adapters.pkcs11.session_pool import Pkcs11SessionPool


class FakeSession:
    """Simple session fake for pooling tests."""

    def __init__(self) -> None:
        """Initialize counters."""
        self.close_calls = 0

    def close(self) -> None:
        """Track close calls."""
        self.close_calls += 1


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
