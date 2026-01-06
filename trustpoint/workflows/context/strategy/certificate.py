from __future__ import annotations

from workflows.context.base import ContextStrategy
from workflows.context.strategy.registry import StrategyRegistry


class CertificateRequestContextStrategy(ContextStrategy):
    key = 'certificate_request'
    label = 'Certificate Request Strategy'

    variables = {
        'csr_pem': 'CSR pem',
        'subject': 'CSR Subject',
        'common_name': 'Common Name',
        'sans': 'SubjectAltNames',
        'public_key_type': 'Public Key Type',
        'fingerprint': 'Enrollment request fingerprint',
        'template': 'Template',
    }

    def get_values(self, ctx: dict) -> dict:
        req = ctx.get('request') or {}
        return {
            'csr_pem': req.get('csr_pem'),
            'subject': req.get('subject'),
            'common_name': req.get('common_name'),
            'sans': req.get('sans'),
            'public_key_type': req.get('public_key_type'),
            'fingerprint': req.get('enrollment_request_id'),
            'template': req.get('template'),
        }


StrategyRegistry.register(CertificateRequestContextStrategy)
