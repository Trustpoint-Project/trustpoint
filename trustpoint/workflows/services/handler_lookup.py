# workflows/services/handler_lookup.py


_handler_registry: dict[str, type] = {}


def register_handler(key: str):
    """Decorator to register an event handler under a given key.

    Usage:
        @register_handler("certificate_request")
        class CertificateRequestHandler: ...
    """

    def decorator(cls: type) -> type:
        _handler_registry[key] = cls
        return cls

    return decorator


def get_handler_by_key(key: str) -> type | None:
    """Lookup a handler class by its registry key."""
    return _handler_registry.get(key)
