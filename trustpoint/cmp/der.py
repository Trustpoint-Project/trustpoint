# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""DER encoding helpers shared by CMP requests and responses."""

_DER_LENGTH_SHORT_FORM_MAX = 0x7F


def der_tlv(tag_byte: int, value: bytes) -> bytes:
    """Construct a DER Tag-Length-Value triplet.

    Handles both short-form (length < 128) and long-form DER lengths.
    """
    length = len(value)
    if length <= _DER_LENGTH_SHORT_FORM_MAX:
        return bytes([tag_byte, length]) + value
    length_payload = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([tag_byte, 0x80 | len(length_payload)]) + length_payload + value
