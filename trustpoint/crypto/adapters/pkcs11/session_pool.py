"""Session-pool management for PKCS#11 tokens."""

from __future__ import annotations

from contextlib import contextmanager
from queue import Empty, LifoQueue
from threading import Lock
from typing import TYPE_CHECKING

from crypto.domain.errors import SessionUnavailableError
from pkcs11 import PKCS11Error
from pkcs11.exceptions import UserAlreadyLoggedIn
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pkcs11 import Session, Token


class Pkcs11SessionPool(LoggerMixin):
    """Thread-safe pool for reusable PKCS#11 sessions.

    This pool is intentionally generic and does not encode vendor-specific
    behavior. It does, however, tolerate the common PKCS#11 behavior where
    login state is token-global and opening a second session with a PIN raises
    UserAlreadyLoggedIn.
    """

    def __init__(
        self,
        *,
        token: Token,
        user_pin: str,
        max_size: int = 8,
        borrow_timeout_seconds: float = 5.0,
        rw: bool = True,
    ) -> None:
        """Initialize the session pool."""
        if max_size < 1:
            msg = 'PKCS#11 session pool size must be at least 1.'
            raise ValueError(msg)

        if borrow_timeout_seconds <= 0:
            msg = 'PKCS#11 borrow timeout must be greater than zero.'
            raise ValueError(msg)

        self._token = token
        self._user_pin = user_pin
        self._rw = rw
        self._borrow_timeout_seconds = borrow_timeout_seconds
        self._available_sessions: LifoQueue[Session] = LifoQueue(maxsize=max_size)
        self._created_sessions = 0
        self._max_size = max_size
        self._lock = Lock()

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Borrow a session from the pool and return it afterwards.

        Any PKCS#11-level failure during use causes the session to be discarded.
        This is conservative and avoids returning potentially bad session state
        to the pool.
        """
        session = self._acquire()
        should_discard = False
        try:
            yield session
        except PKCS11Error:
            should_discard = True
            raise
        finally:
            self._release(session, discard=should_discard)

    def close(self) -> None:
        """Close all currently idle sessions."""
        closed_count = 0
        while True:
            try:
                session = self._available_sessions.get_nowait()
            except Empty:
                break
            try:
                session.close()
            finally:
                closed_count += 1

        with self._lock:
            self._created_sessions = max(0, self._created_sessions - closed_count)

    def _acquire(self) -> Session:
        """Acquire an existing or newly-opened PKCS#11 session."""
        try:
            return self._available_sessions.get_nowait()
        except Empty:
            pass

        with self._lock:
            if self._created_sessions < self._max_size:
                self._created_sessions += 1
                try:
                    return self._open_session()
                except Exception:
                    self._created_sessions = max(0, self._created_sessions - 1)
                    raise

        try:
            return self._available_sessions.get(timeout=self._borrow_timeout_seconds)
        except Empty as exc:
            msg = 'Timed out while waiting for a PKCS#11 session.'
            raise SessionUnavailableError(msg) from exc

    def _open_session(self) -> Session:
        """Open a new PKCS#11 session.

        Some providers treat login as token-global state. In those cases, a
        second `open(..., user_pin=...)` may raise UserAlreadyLoggedIn even
        though opening an unauthenticated session would inherit usable login
        state from the token. Retry without the PIN in that case.
        """
        try:
            return self._token.open(user_pin=self._user_pin, rw=self._rw)
        except UserAlreadyLoggedIn:
            return self._token.open(rw=self._rw)

    def _release(self, session: Session, *, discard: bool) -> None:
        """Return a session to the pool or discard it if it failed."""
        if discard:
            try:
                session.close()
            finally:
                with self._lock:
                    self._created_sessions = max(0, self._created_sessions - 1)
            return

        try:
            self._available_sessions.put_nowait(session)
        except Exception:
            try:
                session.close()
            finally:
                with self._lock:
                    self._created_sessions = max(0, self._created_sessions - 1)
