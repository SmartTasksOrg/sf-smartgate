"""Action lifecycle and the kill switch.

An action is ``pending`` (registered), ``running`` (started), ``completed`` or ``killed``. A kill is
idempotent: the first kill of an action returns ``first: true``, every later one the same status
with ``first: false``. Killing an action that has not been registered yet leaves a tombstone, so the
action is refused when it registers. Halting an agent kills its unfinished actions and refuses its
new ones until the agent is released. Semantics: spec/SEMANTICS.md, "Session"; vectors:
spec/conformance/sequences.json.

State lives in a store: ``MemoryStore`` (one process) or ``RedisStore`` (several SmartGate servers
share it; every change to one action or agent holds the lock ``smartgate:lock:<key>``, 5 s timeout).
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from contextlib import contextmanager


def now_ms() -> int:
    return int(time.time() * 1000)


class Killed(Exception):
    """Raised inside a gated action when it has been killed (at a checkpoint or before start)."""

    def __init__(self, action_id: str, reason: str = ''):
        super().__init__(f'SmartGate killed action {action_id}' + (f': {reason}' if reason else ''))
        self.action_id = action_id
        self.reason = reason


class LockTimeout(RuntimeError):
    pass


class MemoryStore:
    def __init__(self):
        self._d: dict[str, dict] = {}
        self._sets: dict[str, set] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._meta = threading.Lock()

    def get(self, key):
        v = self._d.get(key)
        return dict(v) if v is not None else None

    def put(self, key, value):
        self._d[key] = dict(value)

    def sadd(self, key, member):
        with self._meta:
            self._sets.setdefault(key, set()).add(member)

    def smembers(self, key):
        with self._meta:
            return set(self._sets.get(key, ()))

    @contextmanager
    def lock(self, key, timeout_ms=5000, metrics=None):
        with self._meta:
            lk = self._locks.setdefault(key, threading.Lock())
        if not lk.acquire(timeout=timeout_ms / 1000):
            raise LockTimeout(key)
        try:
            yield
        finally:
            lk.release()


_RELEASE = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"


class RedisStore:
    """Shared state in Redis (``pip install redis``; pass a ``redis.Redis`` client). Keys:
    ``smartgate:<key>`` (JSON), ``smartgate:set:<key>`` (sets) and ``smartgate:lock:<key>``."""

    def __init__(self, client, prefix='smartgate:'):
        self.r = client
        self.p = prefix

    def get(self, key):
        v = self.r.get(self.p + key)
        return json.loads(v) if v else None

    def put(self, key, value):
        self.r.set(self.p + key, json.dumps(value, sort_keys=True))

    def sadd(self, key, member):
        self.r.sadd(self.p + 'set:' + key, member)

    def smembers(self, key):
        return {m.decode() if isinstance(m, bytes) else m for m in self.r.smembers(self.p + 'set:' + key)}

    @contextmanager
    def lock(self, key, timeout_ms=5000, metrics=None):
        name, token = self.p + 'lock:' + key, uuid.uuid4().hex
        t0 = time.monotonic()
        deadline = t0 + timeout_ms / 1000
        while not self.r.set(name, token, nx=True, px=timeout_ms):
            if time.monotonic() >= deadline:
                raise LockTimeout(key)
            time.sleep(0.002)
        if metrics is not None:
            metrics.lock_wait.observe(time.monotonic() - t0)
        try:
            yield
        finally:
            try:
                self.r.eval(_RELEASE, 1, name, token)
            except Exception:  # lock expires by itself after timeout_ms
                pass


class Registry:
    def __init__(self, store=None, clock=now_ms, lock_timeout_ms=5000, metrics=None):
        self.store = store or MemoryStore()
        self.clock = clock
        self.lock_timeout_ms = lock_timeout_ms
        self.metrics = metrics

    def _lock(self, key):
        return self.store.lock(key, self.lock_timeout_ms, self.metrics)

    # -- agents
    def is_halted(self, agent_id: str) -> bool:
        a = self.store.get('agent:' + agent_id)
        return bool(a and a.get('halted'))

    def kill_agent(self, agent_id: str, reason: str = '', at_ms: int | None = None) -> dict:
        at = self.clock() if at_ms is None else at_ms
        with self._lock('agent:' + agent_id):
            a = self.store.get('agent:' + agent_id) or {}
            first = not a.get('halted')
            if first:
                self.store.put('agent:' + agent_id, {'halted': True, 'reason': reason, 'at_ms': at})
        killed = []
        for aid in sorted(self.store.smembers('agentacts:' + agent_id)):
            r = self.kill(aid, reason or 'agent_halted', at)
            if r['status'] == 'killed' and r['first']:
                killed.append(aid)
        return {'agent_id': agent_id, 'status': 'halted', 'first': first, 'killed': killed}

    def release_agent(self, agent_id: str) -> dict:
        with self._lock('agent:' + agent_id):
            a = self.store.get('agent:' + agent_id) or {}
            first = bool(a.get('halted'))
            self.store.put('agent:' + agent_id, {'halted': False})
        return {'agent_id': agent_id, 'status': 'released', 'first': first}

    # -- actions
    def register(self, action_id: str, agent_id: str, at_ms: int | None = None) -> str:
        at = self.clock() if at_ms is None else at_ms
        with self._lock('action:' + action_id):
            cur = self.store.get('action:' + action_id)
            if cur is not None and cur.get('agent_id'):
                return cur['state']
            if cur is not None:          # tombstone from a kill that came first
                cur['agent_id'] = agent_id
                self.store.put('action:' + action_id, cur)
                self.store.sadd('agentacts:' + agent_id, action_id)
                return cur['state']
            state, reason = 'pending', ''
            if self.is_halted(agent_id):
                state, reason = 'killed', 'agent_halted'
            self.store.put('action:' + action_id, {'action_id': action_id, 'agent_id': agent_id, 'state': state,
                                                   'reason': reason, 'registered_at_ms': at,
                                                   'killed_at_ms': at if state == 'killed' else None})
            self.store.sadd('agentacts:' + agent_id, action_id)
            return state

    def start(self, action_id: str) -> bool:
        with self._lock('action:' + action_id):
            cur = self.store.get('action:' + action_id)
            if cur is None or cur['state'] in ('killed', 'completed'):
                return False
            if cur['state'] == 'pending':
                cur['state'] = 'running'
                self.store.put('action:' + action_id, cur)
            return True

    def complete(self, action_id: str) -> str:
        with self._lock('action:' + action_id):
            cur = self.store.get('action:' + action_id)
            if cur is None:
                return 'unknown'
            if cur['state'] in ('pending', 'running'):
                cur['state'] = 'completed'
                self.store.put('action:' + action_id, cur)
            return cur['state']

    def kill(self, action_id: str, reason: str = '', at_ms: int | None = None) -> dict:
        at = self.clock() if at_ms is None else at_ms
        with self._lock('action:' + action_id):
            cur = self.store.get('action:' + action_id)
            if cur is None:
                self.store.put('action:' + action_id, {'action_id': action_id, 'agent_id': None, 'state': 'killed',
                                                       'reason': reason, 'registered_at_ms': None,
                                                       'killed_at_ms': at})
                if self.metrics is not None:
                    self.metrics.kill_hits.inc()
                return {'action_id': action_id, 'status': 'killed', 'first': True}
            if cur['state'] == 'completed':
                return {'action_id': action_id, 'status': 'completed', 'first': False, 'warning': 'already_completed'}
            if cur['state'] == 'killed':
                return {'action_id': action_id, 'status': 'killed', 'first': False}
            cur.update(state='killed', reason=reason, killed_at_ms=at)
            self.store.put('action:' + action_id, cur)
        if self.metrics is not None:
            self.metrics.kill_hits.inc()
        return {'action_id': action_id, 'status': 'killed', 'first': True}

    def note_decision(self, action_id: str, decision: str, approval_id: str | None) -> None:
        """Remember the last decision for the action (the server refuses to start a blocked or
        unapproved action). Not part of the conformance session."""
        with self._lock('action:' + action_id):
            cur = self.store.get('action:' + action_id)
            if cur is not None:
                cur.update(decision=decision, approval_id=approval_id)
                self.store.put('action:' + action_id, cur)

    def ack(self, action_id: str) -> None:
        """The action has seen its kill: record time to override once."""
        cur = self.store.get('action:' + action_id)
        if cur and cur['state'] == 'killed' and not cur.get('acked'):
            if self.metrics is not None and cur.get('killed_at_ms') is not None:
                self.metrics.time_to_override.observe(max(0, self.clock() - cur['killed_at_ms']))
            cur['acked'] = True
            self.store.put('action:' + action_id, cur)

    def status(self, action_id: str):
        return self.store.get('action:' + action_id)

    def is_killed(self, action_id: str) -> bool:
        cur = self.store.get('action:' + action_id)
        return bool(cur and cur['state'] == 'killed')

    def checkpoint(self, action_id: str) -> None:
        """Call inside a long action: raises Killed once a kill has arrived (and records how long
        the kill took to be acknowledged)."""
        cur = self.store.get('action:' + action_id)
        if cur and cur['state'] == 'killed':
            self.ack(action_id)
            raise Killed(action_id, cur.get('reason', ''))
