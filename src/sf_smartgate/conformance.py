"""Conformance: the shared vectors every SmartGate engine (this one and the ports) must pass.

Files (spec/conformance/, also shipped inside the wheel):
    canonical.json   canonical JSON text and its SHA-256 for given values
    scoring.json     one action, fresh engine: score, level, decision, reasons (default policy)
    scoring-custom.json  the same with a custom policy (float band edges, other levels)
    sequences.json   stateful sessions: evaluate / kill / kill_agent / release_agent / start / complete
    audit.json       hash chains, and tampered chains that must fail at a given record
    policies.json    policies that must be accepted or rejected
    policy.default.json  the default policy (input for the scoring and sequence vectors)

A Session is the deterministic core of ``Gate``: the engine plus the kill registry, no clock (every
time comes from the vectors), no approvals, metrics or audit.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import canonical
from .audit import GENESIS, record_hash, verify
from .engine import Engine
from .policy import Policy, PolicyError, validate
from .registry import Registry

FILES = ('canonical.json', 'scoring.json', 'scoring-custom.json', 'sequences.json', 'audit.json', 'policies.json')


def _policy(p):
    return Policy() if p in (None, 'default') else Policy(p)


class Session:
    def __init__(self, policy: Policy):
        self.engine = Engine(policy)
        self.registry = Registry(clock=lambda: 0)

    def apply(self, step: dict):
        op = step['op']
        r = self.registry
        if op == 'evaluate':
            a = step['action']
            state = r.register(a['action_id'], a['agent_id'], a.get('ts_ms', 0))
            return self.engine.decide(a, halted=r.is_halted(a['agent_id']), killed=(state == 'killed')).to_dict()
        if op == 'kill':
            return r.kill(step['action_id'], step.get('reason', ''), step.get('at_ms', 0))
        if op == 'kill_agent':
            return r.kill_agent(step['agent_id'], step.get('reason', ''), step.get('at_ms', 0))
        if op == 'release_agent':
            return r.release_agent(step['agent_id'])
        if op == 'start':
            return {'action_id': step['action_id'], 'started': r.start(step['action_id'])}
        if op == 'complete':
            return {'action_id': step['action_id'], 'state': r.complete(step['action_id'])}
        raise ValueError(f'unknown op {op!r}')


def chain(events):
    """Build the records of an audit chain from [{"event", "ts_ms", "fields"}]."""
    prev, out = GENESIS, []
    for i, e in enumerate(events):
        rec = dict(e.get('fields', {}))
        rec.update(seq=i, ts_ms=e['ts_ms'], event=e['event'], prev=prev)
        rec['hash'] = record_hash(rec)
        prev = rec['hash']
        out.append(rec)
    return out


def run_file(name: str, doc: dict) -> list[str]:
    """Return a list of failures (empty when every case passes)."""
    fails = []
    if name == 'canonical.json':
        for c in doc['cases']:
            got = canonical.dumps(c['value'])
            if got != c['canonical']:
                fails.append(f"canonical/{c['name']}: {got!r} != {c['canonical']!r}")
            elif hashlib.sha256(got.encode()).hexdigest() != c['sha256']:
                fails.append(f"canonical/{c['name']}: sha256 differs")
    elif name in ('scoring.json', 'scoring-custom.json'):
        pol = _policy(doc.get('policy'))
        for c in doc['cases']:
            got = Engine(pol).decide(c['action']).to_dict()
            want = c['expect']
            if any(got[k] != want[k] for k in want):
                fails.append(f"scoring/{c['name']}: got {json.dumps(got)}")
    elif name == 'sequences.json':
        for c in doc['cases']:
            s = Session(_policy(c.get('policy')))
            for i, st in enumerate(c['steps']):
                got = s.apply(st)
                if got != st['expect']:
                    fails.append(f"sequences/{c['name']}[{i}] {st['op']}: got {json.dumps(got, sort_keys=True)}")
                    break
    elif name == 'audit.json':
        for c in doc['chains']:
            recs = chain(c['events'])
            got = [r['hash'] for r in recs]
            if got != c['hashes']:
                fails.append(f"audit/{c['name']}: hashes differ")
            if verify(recs)[0] is not True:
                fails.append(f"audit/{c['name']}: own chain does not verify")
        for c in doc['tampered']:
            ok, idx, _ = verify(c['records'])
            if ok or idx != c['bad_index']:
                fails.append(f"audit/tampered/{c['name']}: got ok={ok} index={idx}")
    elif name == 'policies.json':
        for c in doc['cases']:
            try:
                validate(c['policy'])
                acc = True
            except PolicyError:
                acc = False
            if acc != c['valid']:
                fails.append(f"policies/{c['name']}: valid={acc}, expected {c['valid']}")
    else:
        fails.append(f'unknown vector file {name}')
    return fails


def count(name, doc):
    if name == 'audit.json':
        return len(doc['chains']) + len(doc['tampered'])
    return len(doc['cases'])


def run_dir(path: str):
    total, fails = 0, []
    for n in FILES:
        with open(os.path.join(path, n), encoding='utf-8') as f:
            doc = json.load(f)
        total += count(n, doc)
        fails += run_file(n, doc)
    return total, fails
