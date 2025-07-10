"""Provides the `RequestContext` class for managing key-value data specific to a request."""

class RequestContext:
    """Lightweight container for managing request-specific key-value pairs."""

    def __init__(self):
        """Initialize an empty context."""
        self._data = {}

    def set(self, key: str, value: any) -> None:
        """Set a key-value pair in the context."""
        self._data[key] = value

    def get(self, key: str, default=None) -> any:
        """Get the value for a key, or return a default if not found."""
        return self._data.get(key, default)

    def has(self, key: str) -> bool:
        """Check if a key exists in the context."""
        return key in self._data

    def remove(self, key: str) -> None:
        """Remove a key-value pair from the context if it exists."""
        self._data.pop(key, None)

    def to_dict(self) -> dict:
        """Return the context as a dictionary."""
        return dict(self._data)

    def __getitem__(self, key: str) -> any:
        """Get the value for a key using dictionary-style access."""
        return self._data[key]

    def __setitem__(self, key: str, value: any) -> None:
        """Set a key-value pair using dictionary-style access."""
        self._data[key] = value

    def __contains__(self, key: str) -> bool:
        """Check if a key exists using the 'in' operator."""
        return key in self._data