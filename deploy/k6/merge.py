"""Merge k6 --summary-export files from several workers into one JSON report.

    python deploy/k6/merge.py worker1.json worker2.json ... > report.json

Counts and rates are combined exactly; percentiles cannot be merged from summaries, so the report
gives each worker's p(95) and the worst of them.
"""
import json
import sys

out = {'workers': len(sys.argv) - 1, 'requests': 0, 'decisions': 0, 'evaluate_p95_ms': {}, 'rates': {}}
rates = {}
for path in sys.argv[1:]:
    m = json.load(open(path, encoding='utf-8'))['metrics']
    out['requests'] += m.get('http_reqs', {}).get('count', 0)
    out['decisions'] += m.get('smartgate_decisions', {}).get('count', 0)
    ev = m.get('http_req_duration{endpoint:evaluate}', {})
    out['evaluate_p95_ms'][path] = ev.get('p(95)')
    for k in ('smartgate_friction_low_impact', 'smartgate_prompt_score_below_3', 'smartgate_kill_success'):
        r = m.get(k)
        if r:
            p, f = rates.get(k, (0, 0))
            rates[k] = (p + r.get('passes', 0), f + r.get('fails', 0))
out['evaluate_p95_ms_worst'] = max((v for v in out['evaluate_p95_ms'].values() if v is not None), default=None)
out['rates'] = {k: round(p / (p + f), 4) if p + f else None for k, (p, f) in rates.items()}
print(json.dumps(out, indent=2))
