"""Shared typed canonical JSON and stable errors, without ledger storage."""
import json
import math

MAX_JSON_BYTES = 1_048_576
MAX_SEQUENCE = 2**63 - 1


class LedgerError(Exception):
    """Stable, non-secret failure code. Storage errors require reconciliation."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _json(value):
    """Canonical typed JSON: object order is irrelevant; bool/int/float differ."""
    def check(item, depth=0):
        if depth > 32:
            raise LedgerError("INVALID_JSON")
        if item is None or type(item) is bool:
            return
        if type(item) is int and abs(item) <= MAX_SEQUENCE:
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) is str:
            if len(item) > MAX_JSON_BYTES:
                raise LedgerError("INVALID_JSON")
            return
        if type(item) is list and len(item) <= 4096:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict and len(item) <= 4096:
            for key, child in item.items():
                if type(key) is not str:
                    raise LedgerError("INVALID_JSON")
                check(key, depth + 1)
                check(child, depth + 1)
            return
        raise LedgerError("INVALID_JSON")

    check(value)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
            raise LedgerError("INVALID_JSON")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LedgerError("INVALID_JSON") from error
    return encoded
