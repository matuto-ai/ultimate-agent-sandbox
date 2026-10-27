"""Bounded source-only hash/parent proof from authenticated advertised tips.

This is not a push object validator or proof that arbitrary writable .git data
is authoritative. Every raw object on the selected chain is SHA-1 verified,
including the requested source. Exceeding a bound refuses the cherry-pick.
"""
import base64
from collections import deque
import time

from .git_provenance import _oid, parse_commit
from .ledger import LedgerError, _json

MAX_TIPS = 32
MAX_NODES = 64
MAX_RAW_BYTES = 512 * 1024
MAX_SECONDS = 5


def _tips(values):
    if type(values) is not list or not 1 <= len(values) <= MAX_TIPS:
        raise LedgerError('GIT_SOURCE_PROOF_BOUND')
    result = [_oid(value) for value in values]
    if result != sorted(set(result)): raise LedgerError('INVALID_GIT_SOURCE_PROOF')
    return result


def build(source_oid, tips, read_commit, *, current=lambda: True):
    """Trusted worker seam. read_commit returns exact native bytes or None."""
    source_oid, tips = _oid(source_oid), _tips(tips)
    queue = deque((tip, None, tip) for tip in tips)
    seen, raw_total = {}, 0
    deadline = time.monotonic() + MAX_SECONDS
    while queue:
        if current() is not True or time.monotonic() >= deadline:
            raise LedgerError('GIT_SOURCE_PROOF_BOUND')
        oid, child, tip = queue.popleft()
        if oid in seen: continue
        if len(seen) >= MAX_NODES: raise LedgerError('GIT_SOURCE_PROOF_BOUND')
        raw = read_commit(oid)
        if current() is not True or time.monotonic() >= deadline:
            raise LedgerError('GIT_SOURCE_PROOF_BOUND')
        if raw is None:
            seen[oid] = None
            continue
        commit = parse_commit(raw)
        if commit.oid != oid: raise LedgerError('GIT_SOURCE_PROOF_MISMATCH')
        raw_total += len(raw)
        if raw_total > MAX_RAW_BYTES: raise LedgerError('GIT_SOURCE_PROOF_BOUND')
        seen[oid] = (raw, child, tip)
        if oid == source_oid:
            chain, cursor = [], oid
            while cursor is not None:
                node = seen[cursor]
                chain.append(base64.b64encode(node[0]).decode('ascii'))
                cursor = node[1]
            chain.reverse()
            return {'source_oid': source_oid, 'tip_oid': tip, 'commits': chain}
        for parent in commit.parents:
            if len(queue) >= MAX_NODES * 32: raise LedgerError('GIT_SOURCE_PROOF_BOUND')
            queue.append((parent, oid, tip))
    raise LedgerError('GIT_SOURCE_UNANCHORED')


def verify(value, *, source_oid, tips):
    """External Supervisor independently verifies worker's bounded raw chain."""
    source_oid, tips = _oid(source_oid), _tips(tips)
    if (type(value) is not dict or set(value) != {'source_oid', 'tip_oid', 'commits'}
            or value['source_oid'] != source_oid or value['tip_oid'] not in tips
            or type(value['commits']) is not list or not 1 <= len(value['commits']) <= MAX_NODES):
        raise LedgerError('INVALID_GIT_SOURCE_PROOF')
    previous, first, seen, total, final_raw = None, None, set(), 0, None
    for encoded in value['commits']:
        if type(encoded) is not str or len(encoded) > MAX_RAW_BYTES * 4 // 3 + 4:
            raise LedgerError('GIT_SOURCE_PROOF_BOUND')
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError):
            raise LedgerError('INVALID_GIT_SOURCE_PROOF') from None
        if base64.b64encode(raw).decode('ascii') != encoded:
            raise LedgerError('INVALID_GIT_SOURCE_PROOF')
        total += len(raw)
        if total > MAX_RAW_BYTES: raise LedgerError('GIT_SOURCE_PROOF_BOUND')
        commit = parse_commit(raw)
        if commit.oid in seen or previous is not None and commit.oid not in previous.parents:
            raise LedgerError('GIT_SOURCE_PROOF_MISMATCH')
        if first is None: first = commit.oid
        seen.add(commit.oid); previous, final_raw = commit, raw
    if first != value['tip_oid'] or previous.oid != source_oid:
        raise LedgerError('GIT_SOURCE_PROOF_MISMATCH')
    return final_raw
