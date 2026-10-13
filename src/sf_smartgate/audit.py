"""Tamper-evident audit log: every decision, approval, kill and fallback is one JSON line, chained by
SHA-256 (spec/SEMANTICS.md, "Audit chain"; vectors: spec/conformance/audit.json).

record = {"seq": n, "ts_ms": t, "event": "...", ...fields, "prev": <hash of record n-1 or 64 zeros>}
hash   = sha256(canonical_json(record)) as lower-case hex; the line written is record + {"hash": hash}.

Fields must be strings, integers, booleans, null, lists or objects of those (no floats).
Editing, removing or reordering a line breaks every later hash; ``verify`` reports the first bad line.
A chain proves the log was not changed after it was written; it does not prove the log is complete
(whoever controls the file can truncate it and write a new tail): ship it to storage you trust.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading

from . import canonical
from .registry import now_ms

GENESIS = '0' * 64


def record_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != 'hash'}
    return hashlib.sha256(canonical.encode(body)).hexdigest()


class AuditLog:
    def __init__(self, path: str | None = None, clock=now_ms):
        self.path = path
        self.clock = clock
        self.records: list[dict] = []
        self._lock = threading.Lock()
        self._prev, self._seq = GENESIS, 0
        if path and os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        r = json.loads(line)
                        self._prev, self._seq = r['hash'], r['seq'] + 1
            # keep only the tail in memory; the file is the log

    def append(self, event: str, ts_ms: int | None = None, **fields) -> dict:
        with self._lock:
            rec = dict(fields)
            rec.update(seq=self._seq, ts_ms=self.clock() if ts_ms is None else ts_ms, event=event, prev=self._prev)
            rec['hash'] = record_hash(rec)
            self._prev, self._seq = rec['hash'], self._seq + 1
            if self.path:
                with open(self.path, 'a', encoding='utf-8', newline='\n') as f:
                    f.write(canonical.dumps(rec) + '\n')
            else:
                self.records.append(rec)
            return rec


def verify(records) -> tuple[bool, int | None, str]:
    """(ok, index of the first bad record or None, message)."""
    prev = GENESIS
    for i, r in enumerate(records):
        if r.get('seq') != i:
            return False, i, f'record {i}: seq is {r.get("seq")!r}, expected {i}'
        if r.get('prev') != prev:
            return False, i, f'record {i}: prev does not match the hash of record {i - 1}'
        h = record_hash(r)
        if r.get('hash') != h:
            return False, i, f'record {i}: hash does not match its content'
        prev = h
    return True, None, f'{len(records)} records, chain intact'


def verify_file(path: str):
    with open(path, encoding='utf-8') as f:
        return verify([json.loads(line) for line in f if line.strip()])
