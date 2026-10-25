# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Presentation of certificate signature suites."""

from trustpoint_core import oid

_MLDSA_LABELS = {
    oid.AlgorithmIdentifier.ML_DSA_44.dotted_string: 'ML-DSA-44',
    oid.AlgorithmIdentifier.ML_DSA_65.dotted_string: 'ML-DSA-65',
    oid.AlgorithmIdentifier.ML_DSA_87.dotted_string: 'ML-DSA-87',
}


def format_signature_suite(signature_suite: oid.SignatureSuite | None) -> str:
    """Return a readable signature suite, including the ML-DSA variant."""
    if signature_suite is None:
        return '-'
    algorithm = getattr(signature_suite, 'signature_algorithm', None)
    algorithm_value = getattr(algorithm, 'value', None)
    if isinstance(algorithm_value, str):
        label = _MLDSA_LABELS.get(algorithm_value)
        if label:
            return label
    return str(signature_suite)
