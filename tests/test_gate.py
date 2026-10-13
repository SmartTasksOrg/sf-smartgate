import asyncio
import copy
import inspect
import threading
import time

import pytest

from sf_smartgate import DEFAULT_POLICY, Blocked, Gate, Killed, Policy, agent_context, checkpoint, impact_gate, install_asyncio, verify


def quick_policy(timeout_ms=2000, on_timeout='reject'):
    d = copy.deepcopy(DEFAULT_POLICY)
    d['approval'] = {'timeout_ms': timeout_ms, 'on_timeout': on_timeout}
    return Policy(d)


def act(i, **kw):
    a = {'action_id': i, 'agent_id': 'bot', 'action_type': 'api_call', 'ts_ms': hash(i) % 10 ** 6 * 10000}
    a.update(kw)
    return a


def answer_later(gate, approve=True, delay=0.05):
    def run():
        time.sleep(delay)
        for k, v in list(gate.store._d.items()):
            if k.startswith('approval:') and v['state'] == 'pending':
                (gate.approve if approve else gate.reject)(k.split(':', 1)[1], 'tester')
    t = threading.Thread(target=run)
    t.start()
    return t


def test_allow_runs_and_completes():
    g = Gate()
    assert g.run(act('a1'), lambda: 41 + 1) == 42
    assert g.registry.status('a1')['state'] == 'completed'
    assert verify(g.audit.records)[0]


def test_block_never_runs():
    g = Gate()
    ran = []
    with pytest.raises(Blocked):
        g.run(act('a2', cost_usd=50000), lambda: ran.append(1))
    assert ran == []


def test_prompt_approved_and_rejected():
    g = Gate(quick_policy())
    answer_later(g, True)
    assert g.run(act('a3', cost_usd=3000), lambda: 'ok') == 'ok'
    answer_later(g, False)
    with pytest.raises(Blocked) as e:
        g.run(act('a4', cost_usd=3000), lambda: 'no')
    assert e.value.why == 'rejected'
    assert g.metrics.approvals.value(outcome='approved') == 1


def test_prompt_times_out_to_reject_or_approve():
    g = Gate(quick_policy(100))
    with pytest.raises(Blocked):
        g.run(act('a5', cost_usd=3000), lambda: 'x')
    g2 = Gate(quick_policy(100, 'approve'))
    assert g2.run(act('a6', cost_usd=3000), lambda: 'x') == 'x'


def test_kill_while_waiting_for_approval():
    g = Gate(quick_policy(5000))
    threading.Timer(0.05, lambda: g.kill('a7', 'no')).start()
    t0 = time.monotonic()
    with pytest.raises(Blocked) as e:
        g.run(act('a7', cost_usd=3000), lambda: 'x')
    assert e.value.why == 'killed' and time.monotonic() - t0 < 2


def test_sync_kill_at_checkpoint():
    g = Gate()
    steps = []

    def work():
        for i in range(200):
            checkpoint()
            steps.append(i)
            time.sleep(0.005)
    threading.Timer(0.05, lambda: g.kill('a8', 'stop')).start()
    with pytest.raises(Killed):
        g.run(act('a8'), work)
    assert 0 < len(steps) < 200
    assert g.registry.status('a8')['state'] == 'killed'


def test_async_kill_cancels_at_next_await():
    g = Gate(kill_poll_ms=5)

    async def job():
        await asyncio.sleep(10)

    async def main():
        t = asyncio.ensure_future(g.arun(act('a9'), job))
        await asyncio.sleep(0.05)
        t0 = time.perf_counter()
        g.kill('a9')
        with pytest.raises(Killed):
            await t
        return time.perf_counter() - t0
    assert asyncio.run(main()) < 0.5


def test_decorator_keeps_signature_sync_and_async():
    g = Gate()

    @impact_gate(g, action_type='read', agent_id='bot')
    def f(x, y=2):
        """doc"""
        return x + y

    @impact_gate(g, action_type='api_call', cost=lambda amount, to: amount)
    async def pay(amount, to):
        return f'paid {amount} to {to}'

    assert f(1) == 3 and f.__doc__ == 'doc' and str(inspect.signature(f)) == '(x, y=2)'
    assert asyncio.run(pay(10, 'x')).startswith('paid')
    with pytest.raises(Blocked):
        asyncio.run(pay(30000, 'x'))


def test_asyncio_interceptor_refuses_and_cancels_tasks_of_a_halted_agent():
    g = Gate()

    async def main():
        ic = install_asyncio(g)

        async def forever():
            await asyncio.sleep(10)
        with agent_context('rogue'):
            t1 = asyncio.ensure_future(forever())
        await asyncio.sleep(0.01)
        r = g.kill_agent('rogue', 'incident')
        assert r['tasks_cancelled'] == 1
        with pytest.raises(asyncio.CancelledError):
            await t1
        with agent_context('rogue'):
            t2 = asyncio.ensure_future(forever())
        with pytest.raises(Killed):
            await t2
        with agent_context('fine'):
            assert await asyncio.ensure_future(asyncio.sleep(0, 'ok')) == 'ok'
        return ic
    asyncio.run(main())


def test_metrics_exposition_names():
    g = Gate()
    g.evaluate(act('m1'))
    g.evaluate(act('m2', cost_usd=50000))
    text = g.metrics.expose()
    for name in ('smartgate_decision_latency_ms_bucket', 'smartgate_kill_hits_total', 'smartgate_friction_triggers_total 1',
                 'smartgate_decisions_total{decision="block",level="high"} 1', 'smartgate_prompts_score_below_3_total 0', 'redis_lock_wait_seconds_count', 'smartgate_time_to_override_ms'):
        assert name in text, name


def test_notifier_failure_does_not_break_the_decision():
    class Bad:
        def notify(self, req):
            raise OSError('slack down')
    g = Gate(notifier=Bad())
    assert g.evaluate(act('n1', cost_usd=3000))['decision'] == 'prompt'


def test_rejection_is_not_overridden_by_on_timeout_approve():
    from sf_smartgate.approvals import Approvals
    from sf_smartgate.registry import MemoryStore
    clock = [0]
    ap = Approvals(MemoryStore(), clock=lambda: clock[0], timeout_ms=100, on_timeout='approve')
    rid = ap.create({'action_id': 'a', 'agent_id': 'b', 'score': 5, 'level': 'medium', 'reasons': []}, {})
    ap.reject(rid, 'person')
    clock[0] = 500
    assert ap.wait(rid) == 'rejected'
    rid2 = ap.create({'action_id': 'a2', 'agent_id': 'b', 'score': 5, 'level': 'medium', 'reasons': []}, {})
    clock[0] = 1000
    assert ap.approve(rid2, 'late')['state'] == 'timeout'      # too late: does not count as an approval
    assert ap.wait(rid2) == 'timeout-approved'


def test_slow_notifier_does_not_delay_the_decision():
    class Slow:
        def notify(self, req):
            time.sleep(2)
    g = Gate(notifier=Slow())
    t0 = time.monotonic()
    g.evaluate(act('slow1', cost_usd=3000))
    assert time.monotonic() - t0 < 0.5
