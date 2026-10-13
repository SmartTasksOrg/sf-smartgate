"""Client for a SmartGate server (``sf-smartgate serve``), with the fallback the council decided.

    gate = RemoteGate("http://smartgate:8711", agent_token=os.environ["SMARTGATE_AGENT_TOKEN"])
    with gate.guard({"action_id": "a1", "agent_id": "bot", "action_type": "db_write"}) as g:
        ...
        g.checkpoint()          # asks the server whether the action was killed

Fallback when the server cannot be reached (the connection fails; not an HTTP error):
    "allow"       log, count, call ``on_fallback`` and let the action run (the council's default);
    "block"       refuse every action;
    "block_high"  score the action locally with ``policy`` (give it the server's policy file) and refuse
                  it if its level's friction is block.
The mode comes from the ``fallback`` argument, or else from the policy's ``fallback`` field.
"allow" keeps agents running when SmartGate is down, and also means nothing is gated then: alert on the
server being down (SmartGateDown), export this client's ``smartgate_fallback_total`` from your agent, or
choose "block_high".

When the request reached the server but no answer came back in time (a read timeout, a reset), the
decision is unknown and the action may already be registered and waiting for approval: the client then
answers ``block`` (reason GATE-NO-ANSWER), never the fallback. An HTTP error from the server raises
``ServerError``: the action does not run.

An action admitted on the fallback still asks the server at each ``checkpoint()``; if the server is back
and someone killed the action meanwhile (a kill for an id the server never saw is kept), it stops.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager

from .approvals import effective
from .engine import check_action, level_of, score
from .gate import Blocked
from .metrics import Metrics
from .policy import Policy
from .registry import Killed

log = logging.getLogger('sf_smartgate.client')


class ServerError(RuntimeError):
    def __init__(self, status, body):
        super().__init__(f'SmartGate server answered {status}: {body}')
        self.status, self.body = status, body


class RemoteGate:
    def __init__(self, url: str, agent_token: str | None = None, operator_token: str | None = None,
                 timeout_s: float = 2.0, fallback: str | None = None, policy: Policy | None = None,
                 on_fallback=None, metrics: Metrics | None = None, poll_s: float = 0.25):
        self.policy = policy or Policy()
        fallback = fallback or self.policy.fallback
        if fallback not in ('allow', 'block', 'block_high'):
            raise ValueError('fallback must be allow, block or block_high')
        self.url = url.rstrip('/')
        self.agent_token, self.operator_token = agent_token, operator_token
        self.timeout_s, self.fallback = timeout_s, fallback
        self.on_fallback, self.metrics, self.poll_s = on_fallback, metrics or Metrics(), poll_s

    def _call(self, method, path, body=None, token=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {'Content-Type': 'application/json', **(headers or {})}
        if token:
            h['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(self.url + path, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:  # noqa: S310
                return json.loads(r.read() or b'{}')
        except urllib.error.HTTPError as e:
            raise ServerError(e.code, e.read().decode('utf-8', 'replace')) from None

    def _fallback(self, action, err):
        a = check_action(dict(action))
        mode = self.fallback
        s = score(self.policy, a)
        lv = level_of(self.policy, s)
        decision = 'allow'
        if mode == 'block' or (mode == 'block_high' and lv['friction'] == 'block'):
            decision = 'block'
        log.error('SmartGate unreachable (%s); fallback %s -> %s for %s', err, mode, decision, a['action_id'])
        self.metrics.fallback.inc(mode=mode)
        if self.on_fallback is not None:
            try:
                self.on_fallback(a, decision, err)
            except Exception:  # an alert hook must not break the agent
                log.exception('on_fallback hook failed')
        return {'action_id': a['action_id'], 'agent_id': a['agent_id'], 'decision': decision, 'score': s,
                'level': lv['name'], 'reasons': ['GATE-FALLBACK-' + mode.upper().replace('_', '-')],
                'cascade': False, 'fallback': True}

    # -- agent side
    def evaluate(self, action: dict) -> dict:
        try:
            return self._call('POST', '/smartgate/evaluate', action, self.agent_token)
        except urllib.error.URLError as e:          # could not connect or send: the server is down
            return self._fallback(action, e)
        except (TimeoutError, ConnectionError, OSError) as e:   # sent, but no answer: fail closed
            a = check_action(dict(action))
            log.error('SmartGate did not answer (%s); blocking %s', e, a['action_id'])
            return {'action_id': a['action_id'], 'agent_id': a['agent_id'], 'decision': 'block', 'score': None,
                    'level': None, 'reasons': ['GATE-NO-ANSWER'], 'cascade': False}

    @staticmethod
    def _q(x: str) -> str:
        return urllib.parse.quote(x, safe='')

    def approval(self, approval_id: str) -> dict:
        return self._call('GET', f'/smartgate/approvals/{self._q(approval_id)}', token=self.agent_token)

    def status(self, action_id: str) -> dict:
        return self._call('GET', f'/smartgate/actions/{self._q(action_id)}', token=self.agent_token)

    def report(self, action_id: str, what: str) -> dict:
        return self._call('POST', f'/smartgate/actions/{self._q(action_id)}/{what}', {}, self.agent_token)

    def checkpoint(self, action_id: str) -> None:
        try:
            st = self.status(action_id)
        except ServerError as e:
            if e.status == 404:
                return          # the server does not know the action (admitted on the fallback)
            raise
        except (urllib.error.URLError, OSError):
            return              # cannot ask: keep going (same rule as the fallback)
        if st.get('state') == 'killed':
            raise Killed(action_id, st.get('reason', ''))

    @contextmanager
    def guard(self, action: dict, approval_timeout_s: float | None = None):
        d = self.evaluate(action)
        if d['decision'] == 'block':
            raise Blocked(d)
        if d['decision'] == 'prompt':
            # the server expires the request after the policy's timeout; this limit only guards
            # against a server that never answers
            limit = time.monotonic() + (approval_timeout_s or self.policy.approval_timeout_ms / 1000) + 30
            while True:
                ap = self.approval(d['approval_id'])
                if ap['state'] != 'pending':
                    break
                if time.monotonic() > limit:
                    raise Blocked(d, 'timeout')
                time.sleep(self.poll_s)
            if not effective(ap):
                raise Blocked(d, ap['state'])
        fallback = d.get('fallback')
        if not fallback:
            r = self.report(d['action_id'], 'start')
            if not r.get('started'):
                raise Killed(d['action_id'], 'killed before start')
        exc = None

        class _H:
            action_id = d['action_id']
            decision = d
            checkpoint = (lambda _s: self.checkpoint(d['action_id']))
        try:
            yield _H()
        except BaseException as e:
            exc = e
            raise
        finally:
            if not fallback and not isinstance(exc, Killed):
                try:
                    self.report(d['action_id'], 'complete')
                except (urllib.error.URLError, OSError, ServerError):
                    log.warning('could not report completion of %s', d['action_id'])

    # -- operator side
    def kill(self, action_id: str | None = None, agent_id: str | None = None, reason: str = '',
             request_id: str | None = None) -> dict:
        body = {'reason': reason}
        if action_id:
            body['action_id'] = action_id
        if agent_id:
            body['agent_id'] = agent_id
        hdr = {'X-Request-ID': request_id} if request_id else None
        return self._call('POST', '/smartgate/kill', body, self.operator_token, hdr)

    def approve(self, approval_id: str) -> dict:
        return self._call('POST', f'/smartgate/approvals/{self._q(approval_id)}/approve', {}, self.operator_token)

    def reject(self, approval_id: str) -> dict:
        return self._call('POST', f'/smartgate/approvals/{self._q(approval_id)}/reject', {}, self.operator_token)
