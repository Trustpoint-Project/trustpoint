from typing import Any, Dict

# from workflows.services.certificate_issued import CertificateIssuedHandler
from workflows.handlers.certificate_request import CertificateRequestHandler

# from workflows.services.device_created import DeviceCreatedHandler
# from workflows.services.device_deleted import DeviceDeletedHandler


class TriggerDispatcher:
    """Map event‐names to handler instances."""
    _handlers: dict[str, Any] = {
        'certificate_request': CertificateRequestHandler(),
        # 'device_created':      DeviceCreatedHandler(),
        # 'certificate_issued':  CertificateIssuedHandler(),
        # 'device_deleted':      DeviceDeletedHandler(),
    }

    @classmethod
    def dispatch(cls, event: str, **kwargs: Any) -> Dict[str, Any]:
        handler = cls._handlers.get(event)
        if not handler:
            return {'status': 'error', 'msg': f'No handler for event {event!r}'}
        return handler(**kwargs)
