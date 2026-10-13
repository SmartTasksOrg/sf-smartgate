"""Prometheus metrics in the text exposition format, with no dependency.

smartgate_decision_latency_ms       histogram  time to decide one action (engine + registry + audit)
smartgate_decisions_total{decision,level} counter  allow / prompt / block, by impact level
smartgate_friction_triggers_total   counter    decisions that were prompt or block
smartgate_prompts_score_below_3_total counter  prompts for actions scored below 3 (the council's false-positive measure)
smartgate_kill_hits_total           counter    kills that stopped an action (first kill only)
smartgate_time_to_override_ms       histogram  kill request -> the action acknowledging it at a checkpoint
smartgate_approvals_total{outcome}  counter    approved / rejected / timeout
smartgate_fallback_total{mode}      counter    decisions taken without the server (client fallback)
redis_lock_wait_seconds             histogram  wait to acquire the Redis lock of an action or agent
"""
from __future__ import annotations

import threading

LATENCY_MS_BUCKETS = (0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 1000)
OVERRIDE_MS_BUCKETS = (10, 50, 100, 250, 500, 1000, 2500, 5000, 10000)
LOCK_S_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1, 5)


def _fmt(v: float) -> str:
    return repr(float(v)) if v != int(v) else str(int(v))


class Counter:
    def __init__(self, name, help_, labels=()):
        self.name, self.help, self.labels = name, help_, labels
        self._v: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def inc(self, amount=1, **labels):
        key = tuple(labels.get(k, '') for k in self.labels)
        with self._lock:
            self._v[key] = self._v.get(key, 0) + amount

    def value(self, **labels):
        return self._v.get(tuple(labels.get(k, '') for k in self.labels), 0)

    def expose(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} counter']
        items = sorted(self._v.items())
        if not items and not self.labels:
            items = [((), 0)]
        for key, v in items:
            lab = ','.join(f'{k}="{x}"' for k, x in zip(self.labels, key))
            out.append(f'{self.name}{{{lab}}} {_fmt(v)}' if lab else f'{self.name} {_fmt(v)}')
        return out


class Histogram:
    def __init__(self, name, help_, buckets):
        self.name, self.help, self.buckets = name, help_, tuple(buckets)
        self._counts = [0] * len(self.buckets)
        self._sum, self._n = 0.0, 0
        self._obs: list[float] = []          # kept for percentiles in the benchmark (bounded)
        self._lock = threading.Lock()

    def observe(self, v):
        with self._lock:
            for i, b in enumerate(self.buckets):
                if v <= b:
                    self._counts[i] += 1
            self._sum += v
            self._n += 1
            if len(self._obs) < 200000:
                self._obs.append(v)

    @property
    def count(self):
        return self._n

    def percentile(self, q):
        with self._lock:
            xs = sorted(self._obs)
        if not xs:
            return 0.0
        return xs[min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))]

    def expose(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} histogram']
        for b, c in zip(self.buckets, self._counts):
            out.append(f'{self.name}_bucket{{le="{_fmt(b)}"}} {c}')
        out.append(f'{self.name}_bucket{{le="+Inf"}} {self._n}')
        out.append(f'{self.name}_sum {_fmt(self._sum) if self._sum else 0}')
        out.append(f'{self.name}_count {self._n}')
        return out


class Metrics:
    def __init__(self):
        self.decision_latency = Histogram('smartgate_decision_latency_ms', 'Time to decide one action, in milliseconds.', LATENCY_MS_BUCKETS)
        self.decisions = Counter('smartgate_decisions_total', 'Decisions by result and impact level.', ('decision', 'level'))
        self.friction_triggers = Counter('smartgate_friction_triggers_total', 'Decisions that were prompt or block.')
        self.prompts_low_score = Counter('smartgate_prompts_score_below_3_total', 'Prompts for actions scored below 3.')
        self.kill_hits = Counter('smartgate_kill_hits_total', 'Kills that stopped an action (first kill only).')
        self.time_to_override = Histogram('smartgate_time_to_override_ms', 'Kill request to acknowledgement by the action, in milliseconds.', OVERRIDE_MS_BUCKETS)
        self.approvals = Counter('smartgate_approvals_total', 'Approval outcomes.', ('outcome',))
        self.fallback = Counter('smartgate_fallback_total', 'Decisions taken by a client without the server.', ('mode',))
        self.lock_wait = Histogram('redis_lock_wait_seconds', 'Wait to acquire a Redis lock, in seconds.', LOCK_S_BUCKETS)

    def expose(self) -> str:
        lines = []
        for m in (self.decision_latency, self.decisions, self.friction_triggers, self.prompts_low_score, self.kill_hits,
                  self.time_to_override, self.approvals, self.fallback, self.lock_wait):
            lines += m.expose()
        return '\n'.join(lines) + '\n'
