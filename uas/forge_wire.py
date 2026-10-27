"""Bounded request JSON, distinct from the one-MiB output/audit bound.

Allowed body controls are LF/CR/TAB, so JSON escapes expand at most twofold.
512 KiB body plus bounded argv, Origin and frame envelopes fits MAX_REQUEST.
This serialization never enters canonical audit; only its digest does.
"""
import json
from .ledger import LedgerError, _json

MAX_REQUEST = 1_114_112


def request_json(value):
    def shape(item, depth=0):
        if depth>32: raise LedgerError('INVALID_JSON')
        if type(item) is str: return item[:1024]
        if type(item) is list:
            if len(item)>4096: raise LedgerError('INVALID_JSON')
            return [shape(v,depth+1) for v in item]
        if type(item) is dict:
            if len(item)>4096: raise LedgerError('INVALID_JSON')
            return {k:shape(v,depth+1) for k,v in item.items()}
        return item
    _json(shape(value))  # Same typed, nesting, finite-number and key rules.
    try:
        encoded=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
        if len(encoded.encode('utf-8'))>MAX_REQUEST: raise LedgerError('INVALID_JSON')
        return encoded
    except (ValueError,TypeError,UnicodeError,RecursionError):
        raise LedgerError('INVALID_JSON') from None
