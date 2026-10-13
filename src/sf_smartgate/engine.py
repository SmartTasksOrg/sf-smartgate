"""The decision engine: score an action, pick its level and friction, apply cascade, low-confidence,
halt and kill rules. Deterministic: no clock, no randomness; time comes from the action (``ts_ms``).

Action descriptor (spec/SEMANTICS.md, "Action"):
    action_id (str, required), agent_id (str, required), action_type (str, required),
    cost_usd (number >= 0, default 0), reversible (bool, default true),
    confidence_permille (int 0-1000, optional), ts_ms (int, default 0), target (str, optional)
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .policy import FRICTIONS, Policy, stronger


class ActionError(ValueError):
    pass


def check_action(a) -> dict:
    if not isinstance(a, dict):
        raise ActionError('action must be an object')
    for k in ('action_id', 'agent_id', 'action_type'):
        if not isinstance(a.get(k), str) or not a[k]:
            raise ActionError(f'action.{k} must be a non-empty string')
    cost = a.get('cost_usd', 0)
    if isinstance(cost, bool) or not isinstance(cost, (int, float)) or cost < 0:
        raise ActionError('action.cost_usd must be a number >= 0')
    if not isinstance(a.get('reversible', True), bool):
        raise ActionError('action.reversible must be true or false')
    c = a.get('confidence_permille')
    if c is not None and (isinstance(c, bool) or not isinstance(c, int) or not 0 <= c <= 1000):
        raise ActionError('action.confidence_permille must be an integer 0-1000')
    ts = a.get('ts_ms', 0)
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        raise ActionError('action.ts_ms must be an integer >= 0')
    t = a.get('target')
    if t is not None and not isinstance(t, str):
        raise ActionError('action.target must be a string')
    return a


def score(policy: Policy, action: dict) -> int:
    """Risk score 0-10: the cost band's score, raised to the action type's floor (``default_floor``
    for a type the policy does not list), plus the irreversible bonus, clamped to 0-10."""
    d = policy.doc
    cost = action.get('cost_usd', 0)
    s = d['cost_bands'][-1]['score']
    for b in d['cost_bands']:
        if b['max_usd'] is None or cost <= b['max_usd']:
            s = b['score']
            break
    floors = d.get('action_floors', {})
    s = max(s, floors.get(action['action_type'], d.get('default_floor', 0)))
    if action.get('reversible', True) is False:
        s += d.get('irreversible_bonus', 0)
    return max(0, min(10, s))


def level_of(policy: Policy, s: int) -> dict:
    for lv in policy.levels:
        if s <= lv['max_score']:
            return lv
    return policy.levels[-1]


@dataclass
class Decision:
    action_id: str
    agent_id: str
    decision: str            # allow | prompt | block
    score: int
    level: str
    reasons: list = field(default_factory=list)
    cascade: bool = False

    def to_dict(self) -> dict:
        return {'action_id': self.action_id, 'agent_id': self.agent_id, 'decision': self.decision,
                'score': self.score, 'level': self.level, 'reasons': list(self.reasons), 'cascade': self.cascade}


class Engine:
    """Stateful only for the cascade window (per agent) and halted agents/killed actions, which the
    caller feeds in. Thread-safe."""

    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy()
        self._hist: dict[str, list] = {}
        self._lock = threading.Lock()

    def decide(self, action: dict, *, halted: bool = False, killed: bool = False) -> Decision:
        a = check_action(action)
        p = self.policy
        s = score(p, a)
        lv = level_of(p, s)
        friction = lv['friction']
        reasons = ['GATE-LEVEL-' + lv['name'].upper()]
        if a['action_type'] not in p.doc.get('action_floors', {}):
            reasons.append('GATE-UNLISTED-TYPE')
        cascade = False
        c = p.cascade
        ts = a.get('ts_ms', 0)
        if c:
            with self._lock:
                # the window: this agent's earlier actions with ts_ms >= ts - window_ms, plus this one
                h = [e for e in self._hist.get(a['agent_id'], []) if e[0] >= ts - c['window_ms']]
                h.append((ts, s))
                self._hist[a['agent_id']] = h
                if len(h) > c['max_actions'] and sum(x[1] for x in h) > c['max_cumulative_risk']:
                    cascade = True
        if cascade:
            friction = stronger(friction, c['escalate_to'])
            reasons.append('GATE-CASCADE')
        lc = p.doc.get('low_confidence')
        conf = a.get('confidence_permille')
        if lc and conf is not None and conf < lc['below_permille']:
            friction = stronger(friction, lc['escalate_to'])
            reasons.append('GATE-LOW-CONFIDENCE')
        if halted:
            friction = 'block'
            reasons.append('GATE-AGENT-HALTED')
        if killed:
            friction = 'block'
            reasons.append('GATE-KILLED')
        assert friction in FRICTIONS
        return Decision(a['action_id'], a['agent_id'], friction, s, lv['name'], reasons, cascade)

    def reset(self, agent_id: str | None = None) -> None:
        with self._lock:
            if agent_id is None:
                self._hist.clear()
            else:
                self._hist.pop(agent_id, None)
