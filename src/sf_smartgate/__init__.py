"""SmartGate: decision friction and a human override for AI agents.

Score each action an agent is about to take (0-10), let low-impact actions through, ask a person
before medium ones, block high ones, and stop any action or agent with one kill call that is logged
in a tamper-evident audit chain.
"""
from ._version import __version__
from .audit import AuditLog, verify, verify_file
from .engine import Decision, Engine, score
from .gate import Blocked, Gate, checkpoint
from .hooks import agent_context, impact_gate, install_asyncio
from .policy import DEFAULT_POLICY, Policy, PolicyError
from .registry import Killed, MemoryStore, RedisStore, Registry

__all__ = ['__version__', 'AuditLog', 'Blocked', 'Decision', 'DEFAULT_POLICY', 'Engine', 'Gate', 'Killed',
           'MemoryStore', 'Policy', 'PolicyError', 'RedisStore', 'Registry', 'agent_context', 'checkpoint',
           'impact_gate', 'install_asyncio', 'score', 'verify', 'verify_file']
