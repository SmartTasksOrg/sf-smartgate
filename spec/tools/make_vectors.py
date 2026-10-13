"""Write spec/conformance/*.json: the inputs below, with the outputs of the Python reference.

    python spec/tools/make_vectors.py            # rewrite the vectors
    python spec/tools/make_vectors.py --check    # fail if the files differ from what this would write

Every expected value comes from the reference engine; review a diff of the vectors before merging a
change to the engine, because the ports are held to these files.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from sf_smartgate import canonical  # noqa: E402
from sf_smartgate.conformance import Session, chain  # noqa: E402
from sf_smartgate.engine import Engine  # noqa: E402
from sf_smartgate.policy import DEFAULT_POLICY, Policy  # noqa: E402

OUT = os.path.join(ROOT, 'spec', 'conformance')


def act(i, agent='agent-a', t='read', **kw):
    a = {'action_id': i, 'agent_id': agent, 'action_type': t}
    a.update(kw)
    return a


def canonical_vectors():
    vals = [
        ('empty object', {}), ('empty array', []), ('null', None), ('true', True), ('false', False),
        ('zero', 0), ('negative', -42), ('max safe integer', 9007199254740991), ('min safe integer', -9007199254740991),
        ('sorted keys', {'b': 1, 'a': 2, 'C': 3, '_': 4, 'aa': 5}),
        ('nested', {'z': [3, {'y': None, 'x': [True, False]}], 'a': {'d': 'e'}}),
        ('quote and backslash', 'say "hi" \\ bye'),
        ('short escapes', 'a\nb\rc\td\be\ff'),
        ('other control characters', 'x\u0001y\u001fz\u0000'),
        ('not escaped', '/ < > & \' \u007f    '),
        ('non-ASCII', 'café · 東京 · \U0001F680'),
        ('string with keys', {'k': 'v', 'list': ['a', 'b'], 'n': 1}),
        ('empty string', ''),
    ]
    cases = []
    for name, v in vals:
        c = canonical.dumps(v)
        cases.append({'name': name, 'value': v, 'canonical': c, 'sha256': hashlib.sha256(c.encode()).hexdigest()})
    return {'description': 'canonical JSON (spec/SEMANTICS.md): the exact text and the SHA-256 of its UTF-8 bytes',
            'cases': cases}


def scoring_vectors():
    A = [
        ('read, no cost', act('s1')),
        ('api call at 1000 USD (band edge)', act('s2', t='api_call', cost_usd=1000)),
        ('api call at 1000.01 USD', act('s3', t='api_call', cost_usd=1000.01)),
        ('api call at 5000 USD', act('s4', t='api_call', cost_usd=5000)),
        ('api call at 5000.5 USD', act('s5', t='api_call', cost_usd=5000.5)),
        ('api call at 20000 USD', act('s6', t='api_call', cost_usd=20000)),
        ('api call at 20001 USD', act('s7', t='api_call', cost_usd=20001)),
        ('file write floor', act('s8', t='file_write')),
        ('message send floor (still low)', act('s9', t='message_send')),
        ('db write floor', act('s10', t='db_write')),
        ('code exec floor', act('s11', t='code_exec')),
        ('delete floor', act('s12', t='delete')),
        ('irreversible delete', act('s13', t='delete', reversible=False)),
        ('irreversible message', act('s14', t='message_send', reversible=False)),
        ('irreversible cheap api call', act('s15', t='api_call', cost_usd=900, reversible=False)),
        ('clamped to 10', act('s16', t='payment', cost_usd=50000, reversible=False)),
        ('unlisted type gets default floor', act('s17', t='launch_job')),
        ('unlisted type with high cost', act('s18', t='wire_transfer', cost_usd=12000)),
        ('low confidence 299 permille', act('s19', t='api_call', confidence_permille=299)),
        ('confidence 300 permille (not low)', act('s20', t='api_call', confidence_permille=300)),
        ('low confidence on a blocked action', act('s21', t='api_call', cost_usd=30000, confidence_permille=10)),
        ('explicit reversible true', act('s22', t='code_exec', reversible=True, cost_usd=0)),
        ('integer cost zero', act('s23', t='api_call', cost_usd=0)),
        ('target is ignored by scoring', act('s24', t='api_call', cost_usd=10, target='https://example.invalid/x')),
    ]
    pol = Policy()
    cases = []
    for name, a in A:
        d = Engine(pol).decide(a).to_dict()
        cases.append({'name': name, 'action': a, 'expect': d})
    # a second policy: float band edges, custom levels and frictions
    p2 = copy.deepcopy(DEFAULT_POLICY)
    p2['cost_bands'] = [{'max_usd': 99.5, 'score': 0}, {'max_usd': 250.25, 'score': 3}, {'max_usd': None, 'score': 9}]
    p2['action_floors'] = {'read': 0, 'email': 1}
    p2['default_floor'] = 7
    p2['irreversible_bonus'] = 1
    p2['levels'] = [{'name': 'green', 'max_score': 1, 'friction': 'allow'},
                    {'name': 'amber', 'max_score': 8, 'friction': 'prompt'},
                    {'name': 'red', 'max_score': 10, 'friction': 'block'}]
    p2['low_confidence'] = None
    B = [('read at 99.5', act('t1', cost_usd=99.5)), ('read at 99.51', act('t2', cost_usd=99.51)),
         ('email irreversible', act('t3', t='email', reversible=False)),
         ('email at 250.25', act('t4', t='email', cost_usd=250.25)),
         ('unlisted type', act('t5', t='other')), ('unlisted irreversible', act('t6', t='other', reversible=False)),
         ('large cost', act('t7', cost_usd=1e6)), ('confidence ignored without low_confidence', act('t8', confidence_permille=0))]
    pol2 = Policy(p2)
    cases2 = [{'name': n, 'action': a, 'expect': Engine(pol2).decide(a).to_dict()} for n, a in B]
    return [{'description': 'one action, fresh engine; default policy', 'policy': 'default', 'cases': cases},
            {'description': 'one action, fresh engine; a custom policy', 'policy': p2, 'cases': cases2}]


def sequences():
    esc = copy.deepcopy(DEFAULT_POLICY)
    esc['cascade']['escalate_to'] = 'prompt'
    cheap = copy.deepcopy(esc)
    cheap['cost_bands'] = [{'max_usd': 10, 'score': 0}] + cheap['cost_bands']
    S = []

    def case(name, steps, policy='default'):
        s = Session(Policy() if policy == 'default' else Policy(policy))
        out = []
        for st in steps:
            st = dict(st)
            st['expect'] = s.apply(st)
            out.append(st)
        S.append({'name': name, 'policy': policy, 'steps': out})

    ev = lambda a: {'op': 'evaluate', 'action': a}  # noqa: E731
    case('default policy: a cascade is flagged without friction',
         [ev(act(f'f{i}', ts_ms=i * 1000)) for i in range(5)])
    case('cascade: 4th action within 5 s with cumulative risk 8',
         [ev(act(f'c{i}', ts_ms=i * 1000)) for i in range(4)], esc)
    case('cascade window includes ts - window_ms exactly',
         [ev(act('w0', ts_ms=0)), ev(act('w1', ts_ms=1000)), ev(act('w2', ts_ms=2000)), ev(act('w3', ts_ms=5000))], esc)
    case('cascade window expired',
         [ev(act('x0', ts_ms=0)), ev(act('x1', ts_ms=1000)), ev(act('x2', ts_ms=2000)), ev(act('x3', ts_ms=7001))], esc)
    case('many actions but cumulative risk 0: no cascade',
         [ev(act(f'z{i}', ts_ms=i * 10, cost_usd=1)) for i in range(6)], cheap)
    case('cascade is per agent',
         [ev(act('p0', 'agent-a', ts_ms=0)), ev(act('p1', 'agent-b', ts_ms=1)), ev(act('p2', 'agent-a', ts_ms=2)),
          ev(act('p3', 'agent-b', ts_ms=3)), ev(act('p4', 'agent-a', ts_ms=4)), ev(act('p5', 'agent-a', ts_ms=5))], esc)
    case('cascade escalates a prompt only to prompt; a block stays block',
         [ev(act('e0', ts_ms=0)), ev(act('e1', ts_ms=1)), ev(act('e2', ts_ms=2)),
          ev(act('e3', t='api_call', cost_usd=3000, ts_ms=3)), ev(act('e4', t='api_call', cost_usd=30000, ts_ms=4))], esc)
    case('kill lifecycle and idempotency',
         [ev(act('k1')), {'op': 'start', 'action_id': 'k1'}, {'op': 'kill', 'action_id': 'k1', 'reason': 'stop', 'at_ms': 5},
          {'op': 'kill', 'action_id': 'k1', 'reason': 'again', 'at_ms': 6}, {'op': 'complete', 'action_id': 'k1'},
          {'op': 'start', 'action_id': 'k1'}])
    case('kill before the action registers (tombstone)',
         [{'op': 'kill', 'action_id': 'early', 'reason': 'pre-emptive', 'at_ms': 1}, ev(act('early', ts_ms=2)),
          {'op': 'start', 'action_id': 'early'}, {'op': 'kill', 'action_id': 'early', 'at_ms': 3}])
    case('kill after completion warns',
         [ev(act('done')), {'op': 'start', 'action_id': 'done'}, {'op': 'complete', 'action_id': 'done'},
          {'op': 'kill', 'action_id': 'done', 'at_ms': 9}, {'op': 'complete', 'action_id': 'done'}])
    case('start and complete of unknown actions',
         [{'op': 'start', 'action_id': 'ghost'}, {'op': 'complete', 'action_id': 'ghost'}])
    case('halt an agent: unfinished actions killed, new ones refused, release',
         [ev(act('h1', 'bot', ts_ms=0)), {'op': 'start', 'action_id': 'h1'}, ev(act('h2', 'bot', ts_ms=10000)),
          ev(act('h3', 'bot', ts_ms=20000)), {'op': 'start', 'action_id': 'h3'}, {'op': 'complete', 'action_id': 'h3'},
          ev(act('other', 'not-bot', ts_ms=20001)),
          {'op': 'kill_agent', 'agent_id': 'bot', 'reason': 'incident', 'at_ms': 30000},
          ev(act('h4', 'bot', ts_ms=40000)), {'op': 'start', 'action_id': 'h4'},
          {'op': 'kill_agent', 'agent_id': 'bot', 'at_ms': 41000},
          {'op': 'release_agent', 'agent_id': 'bot'}, {'op': 'release_agent', 'agent_id': 'bot'},
          ev(act('h5', 'bot', ts_ms=60000)), {'op': 'start', 'action_id': 'other'}])
    case('evaluate the same action id twice keeps its state',
         [ev(act('dup', ts_ms=0)), {'op': 'start', 'action_id': 'dup'}, ev(act('dup', ts_ms=60000)),
          {'op': 'kill', 'action_id': 'dup', 'at_ms': 60001}, ev(act('dup', ts_ms=120000))])
    case('low confidence and cascade together',
         [ev(act('l0', ts_ms=0)), ev(act('l1', ts_ms=1)), ev(act('l2', ts_ms=2)),
          ev(act('l3', ts_ms=3, confidence_permille=100))], esc)
    return {'description': 'stateful sessions (spec/SEMANTICS.md, "Session"); each step lists its exact expected output',
            'cases': S}


def audit_vectors():
    E1 = [{'event': 'decision', 'ts_ms': 1700000000000,
           'fields': {'action_id': 'a1', 'agent_id': 'bot', 'decision': 'prompt', 'score': 5, 'level': 'medium',
                      'reasons': ['GATE-LEVEL-MEDIUM'], 'cascade': False, 'target': None}},
          {'event': 'approval', 'ts_ms': 1700000001000, 'fields': {'approval_id': 'ap1', 'action_id': 'a1', 'outcome': 'approved', 'by': 'slack:U123'}},
          {'event': 'kill', 'ts_ms': 1700000002000, 'fields': {'action_id': 'a1', 'status': 'killed', 'first': True, 'reason': 'arrêt «urgent» \n2', 'by': 'operator'}}]
    E2 = [{'event': 'agent_halt', 'ts_ms': 0, 'fields': {'agent_id': 'bot', 'killed': ['x', 'y'], 'first': True, 'reason': '', 'by': ''}}]
    chains = []
    for name, ev in (('three events', E1), ('one event', E2), ('empty', [])):
        recs = chain(ev)
        chains.append({'name': name, 'events': ev, 'hashes': [r['hash'] for r in recs]})
    base = chain(E1)
    t = []
    r = copy.deepcopy(base); r[1]['outcome'] = 'rejected'; t.append({'name': 'field edited', 'records': r, 'bad_index': 1})
    r = copy.deepcopy(base); r[0], r[1] = r[1], r[0]; t.append({'name': 'records swapped', 'records': r, 'bad_index': 0})
    r = copy.deepcopy(base); del r[1]; t.append({'name': 'record removed', 'records': r, 'bad_index': 1})
    r = copy.deepcopy(base); r[2]['hash'] = '0' * 64; t.append({'name': 'hash replaced', 'records': r, 'bad_index': 2})
    r = copy.deepcopy(base); r[0]['prev'] = 'f' * 64; t.append({'name': 'genesis prev changed', 'records': r, 'bad_index': 0})
    return {'description': 'audit chains: record = fields + seq, ts_ms, event, prev; hash = sha256(canonical(record))',
            'chains': chains, 'tampered': t}


def policy_vectors():
    good = copy.deepcopy(DEFAULT_POLICY)
    cases = [{'name': 'default policy', 'valid': True, 'policy': good}]

    def bad(name, mut):
        p = copy.deepcopy(DEFAULT_POLICY)
        mut(p)
        cases.append({'name': name, 'valid': False, 'policy': p})
    bad('wrong schema', lambda p: p.update(schema='smartgate.policy/v2'))
    bad('empty cost bands', lambda p: p.update(cost_bands=[]))
    bad('last band not open', lambda p: p['cost_bands'].__setitem__(-1, {'max_usd': 1e9, 'score': 10}))
    bad('bands not increasing', lambda p: p['cost_bands'].__setitem__(1, {'max_usd': 500, 'score': 5}))
    bad('score above 10', lambda p: p['cost_bands'][0].__setitem__('score', 11))
    bad('score not an integer', lambda p: p['cost_bands'][0].__setitem__('score', 2.5))
    bad('floor out of range', lambda p: p['action_floors'].__setitem__('read', -1))
    bad('levels not ending at 10', lambda p: p['levels'][-1].__setitem__('max_score', 9))
    bad('unknown friction', lambda p: p['levels'][0].__setitem__('friction', 'warn'))
    bad('duplicate level name', lambda p: p['levels'][1].__setitem__('name', 'low'))
    bad('cascade window zero', lambda p: p['cascade'].__setitem__('window_ms', 0))
    bad('confidence threshold above 1000', lambda p: p['low_confidence'].__setitem__('below_permille', 1001))
    bad('unknown fallback', lambda p: p.update(fallback='maybe'))
    bad('approval timeout zero', lambda p: p['approval'].__setitem__('timeout_ms', 0))
    ok2 = copy.deepcopy(DEFAULT_POLICY)
    ok2['cascade'] = None
    ok2['low_confidence'] = None
    cases.append({'name': 'cascade and low_confidence switched off', 'valid': True, 'policy': ok2})
    return {'description': 'policies that every engine must accept (valid: true) or reject', 'cases': cases}


def write_all(check=False):
    files = {
        'canonical.json': canonical_vectors(),
        'scoring.json': None,
        'sequences.json': sequences(),
        'audit.json': audit_vectors(),
        'policies.json': policy_vectors(),
    }
    sc = scoring_vectors()
    files['scoring.json'] = {'description': sc[0]['description'], 'policy': 'default', 'cases': sc[0]['cases']}
    files['scoring-custom.json'] = {'description': sc[1]['description'], 'policy': sc[1]['policy'], 'cases': sc[1]['cases']}
    files['policy.default.json'] = DEFAULT_POLICY
    os.makedirs(OUT, exist_ok=True)
    bad = []
    for n, doc in files.items():
        text = json.dumps(doc, indent=2, ensure_ascii=False) + '\n'
        p = os.path.join(OUT, n)
        if check:
            if not os.path.exists(p) or open(p, encoding='utf-8').read() != text:
                bad.append(n)
        else:
            with open(p, 'w', encoding='utf-8', newline='\n') as f:
                f.write(text)
    return bad


if __name__ == '__main__':
    bad = write_all('--check' in sys.argv)
    if bad:
        print('vectors out of date:', ', '.join(bad))
        sys.exit(1)
    print('vectors ok' if '--check' in sys.argv else f'wrote {OUT}')
