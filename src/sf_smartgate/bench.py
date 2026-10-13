"""In-process benchmark: decision latency and the council's KPIs on the 70/20/10 traffic profile.

    sf-smartgate bench --n 20000 --json report.json

This measures the engine, registry, audit chain and metrics in one Python process (no network).
For the HTTP server under load use deploy/k6/smartgate.js. Numbers depend on the machine; the report
says which Python and platform produced them. The KPI values also depend on the traffic and the policy:
if the policy escalates the cascade rule, agents that send more than three actions within 5 s get prompts
for low-score actions; the report counts those separately ("score_below_3_from_cascade_rule").
"""
from __future__ import annotations

import json
import platform
import random
import threading
import time

from . import __version__
from .gate import Gate
from .registry import Killed

PROFILE = (('low', 0.70), ('medium', 0.20), ('high', 0.10))


def make_action(rng: random.Random, i: int, agents: int, ts: int) -> tuple[str, dict]:
    r = rng.random()
    kind = 'low' if r < 0.70 else 'medium' if r < 0.90 else 'high'
    a = {'action_id': f'b{i}', 'agent_id': f'agent-{rng.randrange(agents)}', 'ts_ms': ts}
    if kind == 'low':
        a.update(action_type=rng.choice(['read', 'api_call']), cost_usd=rng.randrange(0, 900))
    elif kind == 'medium':
        a.update(action_type=rng.choice(['file_write', 'api_call', 'db_write']), cost_usd=rng.randrange(1001, 5000))
    else:
        a.update(action_type=rng.choice(['payment', 'code_exec', 'delete']), cost_usd=rng.randrange(20001, 90000),
                 reversible=False)
    return kind, a


def run(n: int = 20000, agents: int = 5000, kills: int = 200, seed: int = 7) -> dict:
    rng = random.Random(seed)
    gate = Gate()
    lat, by_kind = [], {'low': [0, 0], 'medium': [0, 0], 'high': [0, 0]}
    prompts = prompts_low_score = prompts_low_score_cascade = 0
    t_start = time.perf_counter()
    for i in range(n):
        kind, a = make_action(rng, i, agents, i)       # 1 ms apart: little cascade traffic per agent
        t0 = time.perf_counter()
        d = gate.evaluate(a)
        lat.append((time.perf_counter() - t0) * 1000)
        by_kind[kind][0] += 1
        if d['decision'] != 'allow':
            by_kind[kind][1] += 1
        if d['decision'] == 'prompt':
            prompts += 1
            if d['score'] < 3:
                prompts_low_score += 1
                if d['cascade']:
                    prompts_low_score_cascade += 1
    elapsed = time.perf_counter() - t_start
    lat.sort()

    def pct(q):
        return round(lat[min(len(lat) - 1, int(round(q / 100 * (len(lat) - 1))))], 4)

    # kill switch: an action loops on checkpoints; another thread kills it; measure kill -> acknowledgement
    ack_ms, stopped = [], 0
    for k in range(kills):
        aid = f'k{k}'
        started, done = threading.Event(), {}

        def work():
            try:
                with gate.guard({'action_id': aid, 'agent_id': f'kill-test-{k}', 'action_type': 'read'}) as g:
                    started.set()
                    while True:
                        g.checkpoint()
                        time.sleep(0.0005)
            except Killed:
                done['t'] = time.perf_counter()

        th = threading.Thread(target=work)
        th.start()
        started.wait(5)
        t_kill = time.perf_counter()
        gate.kill(aid, 'bench')
        th.join(5)
        if 't' in done:
            stopped += 1
            ack_ms.append((done['t'] - t_kill) * 1000)
    ack_ms.sort()
    low_n, low_f = by_kind['low']
    return {
        'tool': 'sf-smartgate', 'version': __version__, 'python': platform.python_version(),
        'platform': platform.platform(), 'mode': 'in-process', 'actions': n, 'agents': agents,
        'decisions_per_second': round(n / elapsed, 1),
        'decision_latency_ms': {'p50': pct(50), 'p95': pct(95), 'p99': pct(99), 'max': round(lat[-1], 4)},
        'traffic': {k: v[0] for k, v in by_kind.items()},
        'friction_rate': {k: round(v[1] / v[0], 4) if v[0] else None for k, v in by_kind.items()},
        'prompts': {'total': prompts, 'score_below_3': prompts_low_score,
                    'score_below_3_from_cascade_rule': prompts_low_score_cascade},
        'kpi': {
            'friction_trigger_rate_low_impact': round(low_f / low_n, 4) if low_n else None,
            'false_positive_rate': round(prompts_low_score / prompts, 4) if prompts else 0.0,
            'override_success_ratio': round(stopped / kills, 4) if kills else None,
            'time_to_override_ms_p95': round(ack_ms[min(len(ack_ms) - 1, int(0.95 * (len(ack_ms) - 1)))], 3) if ack_ms else None,
        },
        'targets': {'decision_latency_ms_p95': '< 50', 'friction_trigger_rate_low_impact': '<= 0.10',
                    'false_positive_rate': '<= 0.05', 'override_success_ratio': '>= 0.99 within 5 s',
                    'time_to_override_ms': '< 1000'},
    }


def main(n, json_path=None):
    rep = run(n)
    text = json.dumps(rep, indent=2)
    if json_path:
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(text + '\n')
    print(text)
    return 0
