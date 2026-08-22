from enum import Enum
from typing import Any

__all__ = ['MAX_JSON_SAFE_INTEGER', 'CanonicalIntegerErrorReason', 'CanonicalIntegerError', 'parse_canonical_decimal_integer', 'parse_decimal_integer']

MAX_JSON_SAFE_INTEGER: int

class CanonicalIntegerErrorReason(str, Enum):
    GRAMMAR = 'grammar'
    BELOW_MINIMUM = 'below_minimum'
    ABOVE_MAXIMUM = 'above_maximum'
    BIT_LIMIT = 'bit_limit'

class CanonicalIntegerError(ValueError):
    field: str
    reason: CanonicalIntegerErrorReason
    def __init__(self, message: str, *, field: str, reason: CanonicalIntegerErrorReason) -> None: ...

def parse_canonical_decimal_integer(value: Any, field: str, *, minimum: int | None = None, maximum: int | None = None, max_bits: int | None = None) -> int: ...
def parse_decimal_integer(value: Any, field: str) -> int: ...
