"""Hooks: the decorator, the agent context and the asyncio task interceptor.

    gate = Gate()

    @impact_gate(gate, action_type="file_write", agent_id="report-bot")
    def write_report(path, text): ...

    @impact_gate(gate, action_type="payment", cost=lambda amount, to: amount)
    async def pay(amount, to): ...

    install_asyncio(gate)                 # every asyncio task created inside agent_context("bot")
    with agent_context("bot"): ...        # is refused while "bot" is halted and cancelled when it is
"""
from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import uuid
import weakref
from contextlib import contextmanager

from .gate import Gate
from .registry import Killed

_agent = contextvars.ContextVar('sf_smartgate_agent', default=None)


@contextmanager
def agent_context(agent_id: str):
    """Code (and asyncio tasks created) inside this block act for ``agent_id``."""
    tok = _agent.set(agent_id)
    try:
        yield
    finally:
        _agent.reset(tok)


def current_agent():
    return _agent.get()


def impact_gate(gate: Gate, action_type: str, agent_id: str | None = None, cost=None,
                reversible: bool = True, target=None, describe=None):
    """Gate every call of the decorated function (sync or async). The function's signature is kept.

    cost / target: a constant or a function of the call's arguments. describe: a function of the call's
    arguments returning extra action fields (overrides the others)."""

    def build(fn, args, kwargs):
        def val(x):
            return x(*args, **kwargs) if callable(x) else x
        a = {'action_id': uuid.uuid4().hex, 'agent_id': agent_id or _agent.get() or 'default',
             'action_type': action_type, 'reversible': reversible}
        c = val(cost)
        if c is not None:
            a['cost_usd'] = c
        t = val(target)
        a['target'] = t if t is not None else fn.__qualname__
        if describe is not None:
            a.update(describe(*args, **kwargs))
        return a

    def deco(fn):
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*args, **kwargs):
                return await gate.arun(build(fn, args, kwargs), fn, *args, **kwargs)
            return awrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return gate.run(build(fn, args, kwargs), fn, *args, **kwargs)
        return wrapper

    return deco


class AsyncioInterceptor:
    """A task factory: before a task created for an agent runs, SmartGate checks the agent is not
    halted; halting the agent later cancels its live tasks."""

    def __init__(self, gate: Gate):
        self.gate = gate
        self.tasks: dict[str, weakref.WeakSet] = {}
        self._prev = None

    def factory(self, loop, coro, **kw):
        agent = _agent.get()
        if agent is not None and self.gate.registry.is_halted(agent):
            coro.close()

            async def refused():
                raise Killed('task', f'agent {agent} is halted')
            t = asyncio.Task(refused(), loop=loop, **kw)
        elif self._prev is not None:
            t = self._prev(loop, coro, **kw)
        else:
            t = asyncio.Task(coro, loop=loop, **kw)
        if agent is not None:
            self.tasks.setdefault(agent, weakref.WeakSet()).add(t)
        return t

    def cancel_agent(self, agent_id: str) -> int:
        n = 0
        for t in list(self.tasks.get(agent_id, ())):
            if not t.done():
                t.cancel()
                n += 1
        return n


def install_asyncio(gate: Gate, loop: asyncio.AbstractEventLoop | None = None) -> AsyncioInterceptor:
    """Route every task on ``loop`` (default: the running loop) through SmartGate."""
    loop = loop or asyncio.get_running_loop()
    ic = AsyncioInterceptor(gate)
    ic._prev = loop.get_task_factory()
    loop.set_task_factory(ic.factory)
    orig = gate.kill_agent

    def kill_agent(agent_id, reason='', by=''):
        r = orig(agent_id, reason, by)
        r['tasks_cancelled'] = ic.cancel_agent(agent_id)
        return r
    gate.kill_agent = kill_agent
    return ic
