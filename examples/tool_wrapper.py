"""Wrap any agent framework's tool callables with SmartGate, without importing the framework.

    tools = [gated(search, "read"), gated(send_email, "message_send", reversible=False)]
"""
from sf_smartgate import Gate, impact_gate

gate = Gate()


def gated(fn, action_type, agent_id="agent", **kw):
    """Return fn behind the gate; the wrapper keeps fn's name, docstring and signature, which most
    frameworks read to describe the tool to the model."""
    return impact_gate(gate, action_type=action_type, agent_id=agent_id, **kw)(fn)
