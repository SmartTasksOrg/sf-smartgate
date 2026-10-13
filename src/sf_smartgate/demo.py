"""``sf-smartgate --demo``: one agent, five actions, one approval, one kill, and the audit chain."""
from __future__ import annotations

import asyncio
import threading
import time

from . import __version__
from .audit import verify
from .gate import Blocked, Gate
from .policy import Policy, DEFAULT_POLICY
from .registry import Killed


def main() -> int:
    import copy
    doc = copy.deepcopy(DEFAULT_POLICY)
    doc['approval']['timeout_ms'] = 3000
    gate = Gate(Policy(doc))
    print(f'SmartGate {__version__} demo: agent "ops-bot", default policy\n')

    def show(label, action):
        d = gate.evaluate(action)
        print(f"  {label:<44} risk {d['score']:>2}/10  {d['level']:<6}  -> {d['decision']:<6} {' '.join(d['reasons'])}")
        return d

    print('1. Scoring (cost bands 1000 / 5000 / 20000 USD, action floors, +2 if irreversible)')
    show('read a ticket ($0)', {'action_id': 'd1', 'agent_id': 'ops-bot', 'action_type': 'read', 'ts_ms': 0})
    show('refund $3,200 through the payments API', {'action_id': 'd2', 'agent_id': 'ops-bot', 'action_type': 'api_call', 'cost_usd': 3200, 'ts_ms': 10000})
    show('drop table customers (irreversible)', {'action_id': 'd3', 'agent_id': 'ops-bot', 'action_type': 'delete', 'reversible': False, 'ts_ms': 20000})

    print('\n2. A medium action waits for a person (here a thread approves after 0.2 s)')

    def operator():
        time.sleep(0.2)
        for k in list(gate.store._d):
            if k.startswith('approval:') and gate.store._d[k]['state'] == 'pending':
                gate.approve(k.split(':', 1)[1], 'demo-operator')
    threading.Thread(target=operator).start()
    out = gate.run({'action_id': 'd4', 'agent_id': 'ops-bot', 'action_type': 'api_call', 'cost_usd': 2500, 'ts_ms': 30000},
                   lambda: 'refund sent')
    print(f'  approved by demo-operator -> action ran: {out}')

    print('\n3. Blocked actions never run')
    try:
        gate.run({'action_id': 'd5', 'agent_id': 'ops-bot', 'action_type': 'payment', 'cost_usd': 48000, 'ts_ms': 40000},
                 lambda: 'paid')
    except Blocked as e:
        print(f"  $48,000 payment -> Blocked ({', '.join(e.decision['reasons'])})")

    print('\n4. Kill switch: a running async action is cancelled at its next await')

    async def long_job():
        for _ in range(100):
            await asyncio.sleep(0.01)
        return 'finished'

    async def scenario():
        task = asyncio.ensure_future(gate.arun({'action_id': 'd6', 'agent_id': 'ops-bot', 'action_type': 'read', 'ts_ms': 50000}, long_job))
        await asyncio.sleep(0.05)
        t0 = time.perf_counter()
        r = gate.kill('d6', 'operator pressed kill', 'demo-operator')
        try:
            await task
        except Killed:
            print(f"  kill -> {r['status']} (first={r['first']}), job stopped after {(time.perf_counter() - t0) * 1000:.0f} ms")
        r2 = gate.kill('d6', 'again', 'demo-operator')
        print(f"  second kill -> {r2['status']} (first={r2['first']}): idempotent")
    asyncio.run(scenario())

    print('\n5. Halting the agent refuses everything it tries next')
    r = gate.kill_agent('ops-bot', 'incident', 'demo-operator')
    show('read a ticket, after the halt', {'action_id': 'd7', 'agent_id': 'ops-bot', 'action_type': 'read', 'ts_ms': 60000})
    gate.release_agent('ops-bot', 'demo-operator')

    ok, idx, msg = verify(gate.audit.records)
    print(f'\n6. Audit chain: {msg}')
    tampered = [dict(x) for x in gate.audit.records]
    tampered[2]['decision'] = 'allow'
    ok2, idx2, msg2 = verify(tampered)
    print(f'   after editing record 2: {msg2}')
    print('\nNext: sf-smartgate serve --insecure-dev   |   docs/   |   https://smarttasks.cloud')
    return 0 if ok and not ok2 and idx2 == 2 else 1
