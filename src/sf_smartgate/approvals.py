"""Human approval for actions whose friction is ``prompt``.

An approval request is created when the gate decides ``prompt``. A person approves or rejects it (REST,
CLI or the Slack buttons). It expires ``approval.timeout_ms`` after it was created; an expired request has
the state ``timeout`` and counts as approved only when the policy's ``approval.on_timeout`` is
``approve`` (default ``reject``). Expiry is applied whenever the request is read or answered, so it works
the same for in-process waits and for remote agents polling the server. Requests live in the same store
as the kill switch, so every SmartGate server sharing a Redis store sees them.
"""
from __future__ import annotations

import time
import uuid

from .registry import now_ms

PENDING, APPROVED, REJECTED, TIMEOUT = 'pending', 'approved', 'rejected', 'timeout'


def effective(req: dict | None) -> bool:
    """True when the request lets the action run."""
    if not req:
        return False
    return req['state'] == APPROVED or (req['state'] == TIMEOUT and req.get('on_timeout') == 'approve')


def outcome(req: dict | None) -> str:
    if not req:
        return REJECTED
    if req['state'] == TIMEOUT:
        return 'timeout-approved' if req.get('on_timeout') == 'approve' else 'timeout-rejected'
    return req['state']


class Approvals:
    def __init__(self, store, clock=now_ms, poll_s=0.02, metrics=None, timeout_ms=300000, on_timeout='reject'):
        self.store, self.clock, self.poll_s, self.metrics = store, clock, poll_s, metrics
        self.timeout_ms, self.on_timeout = timeout_ms, on_timeout

    def create(self, decision: dict, action: dict) -> str:
        aid = uuid.uuid4().hex
        now = self.clock()
        self.store.put('approval:' + aid, {
            'approval_id': aid, 'state': PENDING, 'action_id': decision['action_id'],
            'agent_id': decision['agent_id'], 'score': decision['score'], 'level': decision['level'],
            'reasons': decision['reasons'], 'action_type': action.get('action_type'),
            'target': action.get('target'), 'created_at_ms': now, 'expires_at_ms': now + self.timeout_ms,
            'on_timeout': self.on_timeout, 'decided_by': None})
        return aid

    def _set(self, approval_id, state, by):
        """Change a pending request; return the request as it is afterwards (or None if unknown)."""
        with self.store.lock('approval:' + approval_id):
            cur = self.store.get('approval:' + approval_id)
            if cur is None:
                return None
            if cur['state'] == PENDING:
                if state != TIMEOUT and self.clock() >= cur.get('expires_at_ms', float('inf')):
                    state, by = TIMEOUT, 'timeout'          # an answer that arrives too late does not count
                cur.update(state=state, decided_by=by, decided_at_ms=self.clock())
                self.store.put('approval:' + approval_id, cur)
                if self.metrics is not None:
                    self.metrics.approvals.inc(outcome=state)
            return cur

    def get(self, approval_id: str):
        cur = self.store.get('approval:' + approval_id)
        if cur and cur['state'] == PENDING and self.clock() >= cur.get('expires_at_ms', float('inf')):
            cur = self._set(approval_id, TIMEOUT, 'timeout')
        return cur

    def approve(self, approval_id: str, by: str = '') -> dict | None:
        return self._set(approval_id, APPROVED, by)

    def reject(self, approval_id: str, by: str = '') -> dict | None:
        return self._set(approval_id, REJECTED, by)

    def wait(self, approval_id: str, is_killed=None) -> str:
        """Block until the request is answered or expires; returns approved | rejected |
        timeout-approved | timeout-rejected | killed."""
        while True:
            cur = self.get(approval_id)
            if cur is None or cur['state'] != PENDING:
                return outcome(cur)
            if is_killed is not None and is_killed():
                self._set(approval_id, REJECTED, 'kill')
                return 'killed'
            time.sleep(self.poll_s)
