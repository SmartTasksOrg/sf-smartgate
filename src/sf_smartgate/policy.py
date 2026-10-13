"""Policy: how an action descriptor becomes a risk score (0-10), an impact level and a friction.

A policy is one JSON document (schema: spec/policy.schema.json). Every engine (Python and the ports)
reads the same document and must return the same score, level and friction for the same action
(spec/conformance/scoring.json).
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field

FRICTIONS = ('allow', 'prompt', 'block')            # ordered: a later one is stronger
FALLBACKS = ('allow', 'block', 'block_high')

# The council's cost-to-score bands (USD per action): <=1000 -> 2, <=5000 -> 5, <=20000 -> 8, else 10.
# Levels: low <=3 (allow), medium <=6 (prompt), high <=10 (block).
# Cascade (the council's labelling rule: more than 3 actions from one agent within 5 s, summed score
# above 7) flags the decision (cascade: true, GATE-CASCADE) without adding friction by default: with
# escalate_to "prompt", four ordinary reads in five seconds would already ask a person.
# The action floors are starting values, not measurements: calibrate them for your agents. An action
# type the policy does not list gets default_floor (4: medium, so a person is asked).
DEFAULT_POLICY = {
    'schema': 'smartgate.policy/v1',
    'cost_bands': [
        {'max_usd': 1000, 'score': 2},
        {'max_usd': 5000, 'score': 5},
        {'max_usd': 20000, 'score': 8},
        {'max_usd': None, 'score': 10},
    ],
    'action_floors': {
        'read': 0, 'api_call': 0, 'file_write': 2, 'message_send': 3, 'db_write': 3,
        'code_exec': 6, 'delete': 6,
    },
    'default_floor': 4,
    'irreversible_bonus': 2,
    'levels': [
        {'name': 'low', 'max_score': 3, 'friction': 'allow'},
        {'name': 'medium', 'max_score': 6, 'friction': 'prompt'},
        {'name': 'high', 'max_score': 10, 'friction': 'block'},
    ],
    'cascade': {'window_ms': 5000, 'max_actions': 3, 'max_cumulative_risk': 7, 'escalate_to': 'allow'},
    'low_confidence': {'below_permille': 300, 'escalate_to': 'prompt'},
    'approval': {'timeout_ms': 300000, 'on_timeout': 'reject'},
    'fallback': 'allow',
}


class PolicyError(ValueError):
    pass


def _num(v, what):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise PolicyError(f'{what} must be a number')
    return v


def _int(v, what, lo=None, hi=None):
    if isinstance(v, bool) or not isinstance(v, int):
        raise PolicyError(f'{what} must be an integer')
    if (lo is not None and v < lo) or (hi is not None and v > hi):
        raise PolicyError(f'{what} must be between {lo} and {hi}')
    return v


def _friction(v, what):
    if v not in FRICTIONS:
        raise PolicyError(f'{what} must be one of {", ".join(FRICTIONS)}')
    return v


@dataclass(frozen=True)
class Policy:
    doc: dict = field(default_factory=lambda: copy.deepcopy(DEFAULT_POLICY))

    def __post_init__(self):
        validate(self.doc)

    @classmethod
    def load(cls, path: str) -> 'Policy':
        with open(path, encoding='utf-8') as f:
            return cls(json.load(f))

    @classmethod
    def from_json(cls, text: str) -> 'Policy':
        return cls(json.loads(text))

    # -- convenience views
    @property
    def levels(self):
        return self.doc['levels']

    @property
    def cascade(self):
        return self.doc.get('cascade')

    @property
    def fallback(self):
        return self.doc.get('fallback', 'allow')

    @property
    def approval_timeout_ms(self):
        return self.doc.get('approval', {}).get('timeout_ms', 300000)

    @property
    def approval_on_timeout(self):
        return self.doc.get('approval', {}).get('on_timeout', 'reject')


def validate(doc) -> None:
    """Raise PolicyError when ``doc`` is not a usable policy. Mirrors spec/policy.schema.json."""
    if not isinstance(doc, dict):
        raise PolicyError('policy must be a JSON object')
    if doc.get('schema') != 'smartgate.policy/v1':
        raise PolicyError('policy "schema" must be "smartgate.policy/v1"')
    bands = doc.get('cost_bands')
    if not isinstance(bands, list) or not bands:
        raise PolicyError('cost_bands must be a non-empty list')
    last = None
    for i, b in enumerate(bands):
        if not isinstance(b, dict):
            raise PolicyError(f'cost_bands[{i}] must be an object')
        _int(b.get('score'), f'cost_bands[{i}].score', 0, 10)
        m = b.get('max_usd')
        if m is None:
            if i != len(bands) - 1:
                raise PolicyError('only the last cost band may have max_usd null')
        else:
            _num(m, f'cost_bands[{i}].max_usd')
            if last is not None and m <= last:
                raise PolicyError('cost_bands max_usd must increase')
            last = m
    if bands[-1].get('max_usd') is not None:
        raise PolicyError('the last cost band must have max_usd null (covers every larger cost)')
    floors = doc.get('action_floors', {})
    if not isinstance(floors, dict):
        raise PolicyError('action_floors must be an object')
    for k, v in floors.items():
        _int(v, f'action_floors.{k}', 0, 10)
    _int(doc.get('default_floor', 0), 'default_floor', 0, 10)
    _int(doc.get('irreversible_bonus', 0), 'irreversible_bonus', 0, 10)
    levels = doc.get('levels')
    if not isinstance(levels, list) or not levels:
        raise PolicyError('levels must be a non-empty list')
    prev = -1
    names = set()
    for i, lv in enumerate(levels):
        if not isinstance(lv, dict) or not isinstance(lv.get('name'), str) or not lv['name']:
            raise PolicyError(f'levels[{i}] needs a name')
        if lv['name'] in names:
            raise PolicyError(f'level name {lv["name"]!r} repeated')
        names.add(lv['name'])
        m = _int(lv.get('max_score'), f'levels[{i}].max_score', 0, 10)
        if m <= prev:
            raise PolicyError('levels max_score must increase')
        prev = m
        _friction(lv.get('friction'), f'levels[{i}].friction')
    if prev != 10:
        raise PolicyError('the last level must have max_score 10')
    c = doc.get('cascade')
    if c is not None:
        if not isinstance(c, dict):
            raise PolicyError('cascade must be an object or null')
        _int(c.get('window_ms'), 'cascade.window_ms', 1)
        _int(c.get('max_actions'), 'cascade.max_actions', 1)
        _int(c.get('max_cumulative_risk'), 'cascade.max_cumulative_risk', 0)
        _friction(c.get('escalate_to'), 'cascade.escalate_to')
    lc = doc.get('low_confidence')
    if lc is not None:
        if not isinstance(lc, dict):
            raise PolicyError('low_confidence must be an object or null')
        _int(lc.get('below_permille'), 'low_confidence.below_permille', 0, 1000)
        _friction(lc.get('escalate_to'), 'low_confidence.escalate_to')
    ap = doc.get('approval', {})
    if not isinstance(ap, dict):
        raise PolicyError('approval must be an object')
    _int(ap.get('timeout_ms', 300000), 'approval.timeout_ms', 1)
    if ap.get('on_timeout', 'reject') not in ('reject', 'approve'):
        raise PolicyError('approval.on_timeout must be "reject" or "approve"')
    if doc.get('fallback', 'allow') not in FALLBACKS:
        raise PolicyError(f'fallback must be one of {", ".join(FALLBACKS)}')


def stronger(a: str, b: str) -> str:
    return a if FRICTIONS.index(a) >= FRICTIONS.index(b) else b
