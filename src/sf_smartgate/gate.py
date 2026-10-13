"""SmartGate: one object that decides, asks, runs and kills.

    gate = Gate()                                   # default policy, in-memory state
    with gate.guard({"action_id": "a1", "agent_id": "bot", "action_type": "file_write"}) as g:
        ...                                         # runs only if allowed or approved
        g.checkpoint()                              # raises Killed once someone has killed it

How a kill stops an action, honestly:
- before it starts: always (the action is refused);
- a coroutine run with ``arun`` / ``@impact_gate`` on an ``async def``: the task is cancelled at its next
  ``await`` (within ``kill_poll_ms``, default 20 ms);
- a synchronous function: at its next ``checkpoint()``; code that never calls one runs to the end
  (Python cannot stop a thread from outside). Put checkpoints between the steps that do damage, or
  run the risky part as a subprocess you can terminate.
SmartGate only sees actions that go through it; an agent that calls an API directly bypasses it.
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
import time
from contextlib import contextmanager

from .approvals import Approvals, effective
from .audit import AuditLog
from .engine import ActionError, Engine, check_action
from .metrics import Metrics
from .policy import Policy
from .registry import Killed, Registry, now_ms

log = logging.getLogger('sf_smartgate')
_current = contextvars.ContextVar('sf_smartgate_current', default=None)


class Blocked(Exception):
    """The gate refused the action (decision ``block``, or a ``prompt`` that was not approved)."""

    def __init__(self, decision: dict, why: str = ''):
        super().__init__(f"SmartGate blocked {decision.get('action_id')}: {why or decision.get('decision')} "
                         f"(risk {decision.get('score')}/10, {', '.join(decision.get('reasons', []))})")
        self.decision = decision
        self.why = why


class Handle:
    def __init__(self, gate: 'Gate', action: dict, decision: dict):
        self.gate, self.action, self.decision = gate, action, decision
        self.action_id = action['action_id']

    def checkpoint(self):
        self.gate.registry.checkpoint(self.action_id)


def checkpoint():
    """Inside a gated action: raise Killed if the current action has been killed. No-op outside one."""
    h = _current.get()
    if h is not None:
        h.checkpoint()


class Gate:
    def __init__(self, policy: Policy | None = None, store=None, audit: AuditLog | None = None,
                 metrics: Metrics | None = None, notifier=None, clock=now_ms, kill_poll_ms: int = 20):
        self.policy = policy or Policy()
        self.metrics = metrics or Metrics()
        self.registry = Registry(store, clock=clock, metrics=self.metrics)
        self.store = self.registry.store
        self.engine = Engine(self.policy)
        self.audit = audit or AuditLog(clock=clock)
        self.approvals = Approvals(self.store, clock=clock, metrics=self.metrics,
                                   timeout_ms=self.policy.approval_timeout_ms, on_timeout=self.policy.approval_on_timeout)
        self.notifier = notifier
        self.clock = clock
        self.kill_poll_ms = kill_poll_ms

    # -- deciding
    def evaluate(self, action: dict) -> dict:
        t0 = time.perf_counter()
        a = check_action(dict(action))
        a.setdefault('ts_ms', self.clock())
        known = self.registry.status(a['action_id'])
        if known and known.get('agent_id') and known['agent_id'] != a['agent_id']:
            raise ActionError(f"action_id {a['action_id']!r} belongs to another agent")
        if known and known.get('decision') is not None:
            # one decision per action: a second evaluate could otherwise replace a block or a rejected
            # prompt with a milder descriptor and then start the action
            raise ActionError(f"action_id {a['action_id']!r} was already evaluated; use a new action_id")
        state = self.registry.register(a['action_id'], a['agent_id'])
        d = self.engine.decide(a, halted=self.registry.is_halted(a['agent_id']),
                               killed=(state == 'killed')).to_dict()
        if d['decision'] == 'prompt':
            d['approval_id'] = self.approvals.create(d, a)
            if self.notifier is not None:     # in the background: a slow Slack must not delay the decision
                threading.Thread(target=self._notify, args=(self.approvals.get(d['approval_id']),), daemon=True).start()
        self.registry.note_decision(d['action_id'], d['decision'], d.get('approval_id'))
        self.audit.append('decision', action_id=d['action_id'], agent_id=d['agent_id'],
                          action_type=a['action_type'], target=a.get('target'), decision=d['decision'],
                          score=d['score'], level=d['level'], reasons=d['reasons'], cascade=d['cascade'],
                          approval_id=d.get('approval_id'))
        m = self.metrics
        m.decisions.inc(decision=d['decision'], level=d['level'])
        if d['decision'] != 'allow':
            m.friction_triggers.inc()
        if d['decision'] == 'prompt' and d['score'] < 3:
            m.prompts_low_score.inc()
        m.decision_latency.observe((time.perf_counter() - t0) * 1000)
        return d

    def _notify(self, req):
        try:
            self.notifier.notify(req)
        except Exception as e:  # the request still waits; people can answer by REST or CLI
            log.warning('approval notification failed: %s', e)

    def start(self, action_id: str) -> bool:
        """Start an action only if its last decision lets it run: allow, or prompt with an approval
        that is approved (or timed out with on_timeout approve), and it has not been killed."""
        rec = self.registry.status(action_id)
        if rec is None:
            return False
        dec = rec.get('decision')
        if dec == 'block' or dec is None:
            return False
        if dec == 'prompt' and not effective(self.approvals.get(rec.get('approval_id') or '')):
            return False
        return self.registry.start(action_id)

    def score(self, action: dict) -> dict:
        from .engine import level_of, score
        a = check_action(dict(action))
        s = score(self.policy, a)
        return {'score': s, 'level': level_of(self.policy, s)['name']}

    # -- people
    def approve(self, approval_id: str, by: str = '') -> dict | None:
        r = self.approvals.approve(approval_id, by)
        if r:
            self.audit.append('approval', approval_id=approval_id, action_id=r['action_id'], outcome=r['state'], by=by)
        return r

    def reject(self, approval_id: str, by: str = '') -> dict | None:
        r = self.approvals.reject(approval_id, by)
        if r:
            self.audit.append('approval', approval_id=approval_id, action_id=r['action_id'], outcome=r['state'], by=by)
        return r

    def kill(self, action_id: str, reason: str = '', by: str = '') -> dict:
        r = self.registry.kill(action_id, reason)
        self.audit.append('kill', action_id=action_id, status=r['status'], first=r['first'], reason=reason, by=by)
        return r

    def kill_agent(self, agent_id: str, reason: str = '', by: str = '') -> dict:
        r = self.registry.kill_agent(agent_id, reason)
        self.audit.append('agent_halt', agent_id=agent_id, first=r['first'], killed=r['killed'], reason=reason, by=by)
        return r

    def release_agent(self, agent_id: str, by: str = '') -> dict:
        r = self.registry.release_agent(agent_id)
        self.audit.append('agent_release', agent_id=agent_id, first=r['first'], by=by)
        return r

    # -- running
    def _admit(self, action: dict) -> dict:
        d = self.evaluate(action)
        if d['decision'] == 'block':
            raise Blocked(d)
        if d['decision'] == 'prompt':
            out = self.approvals.wait(d['approval_id'], is_killed=lambda: self.registry.is_killed(d['action_id']))
            self.audit.append('approval_result', approval_id=d['approval_id'], action_id=d['action_id'], outcome=out)
            if out not in ('approved', 'timeout-approved'):
                raise Blocked(d, out)
        if not self.start(d['action_id']):
            raise Killed(d['action_id'], 'killed before start')
        return d

    async def _admit_async(self, action: dict) -> dict:
        d = self.evaluate(action)
        if d['decision'] == 'block':
            raise Blocked(d)
        if d['decision'] == 'prompt':
            out = await asyncio.to_thread(self.approvals.wait, d['approval_id'],
                                          lambda: self.registry.is_killed(d['action_id']))
            self.audit.append('approval_result', approval_id=d['approval_id'], action_id=d['action_id'], outcome=out)
            if out not in ('approved', 'timeout-approved'):
                raise Blocked(d, out)
        if not self.start(d['action_id']):
            raise Killed(d['action_id'], 'killed before start')
        return d

    def _finish(self, d, exc):
        aid = d['action_id']
        if isinstance(exc, Killed) or (exc is not None and self.registry.is_killed(aid)):
            self.audit.append('action_killed', action_id=aid)
            return
        state = self.registry.complete(aid)
        self.audit.append('action_end', action_id=aid, state=state, error=type(exc).__name__ if exc else None)

    @contextmanager
    def guard(self, action: dict):
        d = self._admit(action)
        h = Handle(self, action, d)
        tok = _current.set(h)
        exc = None
        try:
            yield h
        except BaseException as e:
            exc = e
            raise
        finally:
            _current.reset(tok)
            self._finish(d, exc)

    def run(self, action: dict, fn, *args, **kwargs):
        with self.guard(action):
            return fn(*args, **kwargs)

    async def arun(self, action: dict, coro_fn, *args, **kwargs):
        """Run ``await coro_fn(*args, **kwargs)`` behind the gate; a kill cancels it at its next await."""
        d = await self._admit_async(action)
        h = Handle(self, action, d)
        tok = _current.set(h)
        task = asyncio.ensure_future(coro_fn(*args, **kwargs))
        killed = False

        async def watch():
            nonlocal killed
            while not task.done():
                if self.registry.is_killed(d['action_id']):
                    killed = True
                    task.cancel()
                    return
                await asyncio.sleep(self.kill_poll_ms / 1000)

        w = asyncio.ensure_future(watch())
        exc = None
        try:
            return await task
        except asyncio.CancelledError as e:
            if killed:
                try:
                    self.registry.checkpoint(d['action_id'])
                except Killed as k:
                    exc = k
                    raise k from None
            exc = e
            raise
        except BaseException as e:
            exc = e
            raise
        finally:
            w.cancel()
            _current.reset(tok)
            self._finish(d, exc)
