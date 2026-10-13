import threading
import time

import pytest

from sf_smartgate import Killed, MemoryStore, RedisStore, Registry
from sf_smartgate.metrics import Metrics


def test_exactly_one_first_kill_under_concurrency():
    r = Registry()
    r.register('a', 'bot')
    r.start('a')
    results = []
    ts = [threading.Thread(target=lambda: results.append(r.kill('a', 'x'))) for _ in range(50)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(1 for x in results if x['first']) == 1
    assert all(x['status'] == 'killed' for x in results)


def test_checkpoint_raises_and_records_time_to_override():
    m = Metrics()
    clock = [1000]
    r = Registry(clock=lambda: clock[0], metrics=m)
    r.register('a', 'bot')
    r.start('a')
    r.checkpoint('a')
    r.kill('a', 'stop')
    clock[0] = 1150
    with pytest.raises(Killed):
        r.checkpoint('a')
    assert m.time_to_override.count == 1 and m.kill_hits.value() == 1


class FakeRedis:
    """Enough of redis.Redis for RedisStore: get/set(nx, px)/sadd/smembers/eval."""

    def __init__(self):
        self.d, self.s, self.exp = {}, {}, {}
        self.lock = threading.Lock()

    def _gc(self, k):
        if k in self.exp and self.exp[k] < time.monotonic():
            self.d.pop(k, None)
            self.exp.pop(k, None)

    def get(self, k):
        with self.lock:
            self._gc(k)
            v = self.d.get(k)
            return v.encode() if isinstance(v, str) else v

    def set(self, k, v, nx=False, px=None):
        with self.lock:
            self._gc(k)
            if nx and k in self.d:
                return None
            self.d[k] = v
            if px:
                self.exp[k] = time.monotonic() + px / 1000
            return True

    def sadd(self, k, m):
        with self.lock:
            self.s.setdefault(k, set()).add(m.encode())

    def smembers(self, k):
        with self.lock:
            return set(self.s.get(k, set()))

    def eval(self, script, n, key, token):
        with self.lock:
            if self.d.get(key) == token:
                del self.d[key]
                return 1
            return 0


def test_redis_store_shares_state_between_registries():
    fr = FakeRedis()
    m = Metrics()
    a, b = Registry(RedisStore(fr), metrics=m), Registry(RedisStore(fr))
    a.register('x', 'bot')
    assert b.kill('x', 'from another server')['first'] is True
    assert a.is_killed('x')
    assert a.kill('x')['first'] is False
    assert b.kill_agent('bot')['killed'] == []
    assert a.is_halted('bot')
    assert m.lock_wait.count > 0
    assert not any(k.startswith('smartgate:lock:') for k in fr.d)


def test_redis_lock_times_out():
    fr = FakeRedis()
    st = RedisStore(fr)
    fr.set('smartgate:lock:action:x', 'someone', nx=True, px=10000)
    from sf_smartgate.registry import LockTimeout
    with pytest.raises(LockTimeout):
        with st.lock('action:x', timeout_ms=50):
            pass


def test_memory_store_returns_copies():
    s = MemoryStore()
    s.put('k', {'a': 1})
    v = s.get('k')
    v['a'] = 2
    assert s.get('k') == {'a': 1}
