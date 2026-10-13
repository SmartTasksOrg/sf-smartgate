# Integrating SmartGate

## Python, in process

```python
from sf_smartgate import Gate, Policy, impact_gate, checkpoint, agent_context, install_asyncio

gate = Gate(Policy.load("policy.json"))          # or Gate() for the default policy

@impact_gate(gate, action_type="file_write", agent_id="report-bot")
def write_report(path, text): ...

@impact_gate(gate, action_type="api_call", cost=lambda amount, to: amount, reversible=False)
async def pay(amount, to): ...                   # a kill cancels it at its next await
```

- `action_type`, `agent_id`, `cost`, `target`, `reversible`: constants or functions of the call's arguments.
  `describe=` returns extra action fields (for example `confidence_permille`).
- A `block` raises `Blocked`; a `prompt` waits for an answer (policy `approval.timeout_ms`), then runs or
  raises `Blocked`; a kill raises `Killed` (at a checkpoint, or before start).
- `with gate.guard(action) as g: ... g.checkpoint()` is the same without a decorator.
- `install_asyncio(gate)` inside a running loop: tasks created under `with agent_context("bot"):` are refused
  while "bot" is halted, and cancelled when it is halted.

Long synchronous work needs `checkpoint()` calls between the steps that do damage. For code you cannot
change, run it in a subprocess and terminate the subprocess when `Killed` is raised in the parent.

## Python, against a server

```python
import os
from sf_smartgate.client import RemoteGate

gate = RemoteGate("https://smartgate.internal", agent_token=os.environ["SMARTGATE_AGENT_TOKEN"],
                  fallback="block_high", on_fallback=lambda action, decision, err: alert(err))
with gate.guard({"action_id": run_id, "agent_id": "bot", "action_type": "db_write", "cost_usd": 1200}) as g:
    step_one()
    g.checkpoint()
    step_two()
```

## HTTP middleware

`SmartGateWSGI(app, gate, describe)` and `SmartGateASGI(app, gate, describe)` gate the tool endpoints an
agent calls. `describe(environ_or_scope)` returns the action fields (without `action_id`) or `None` for
requests that need no gate. Refusals answer 403 (block or not approved) or 409 (killed).

## Other languages

Every port has the engine (for local decisions and tests) and a client. The Node.js client:

```js
const { SmartGateClient, Blocked, Killed } = require('./ports/node/src');
const gate = new SmartGateClient({ url: process.env.SMARTGATE_URL, agentToken: process.env.SMARTGATE_AGENT_TOKEN });
await gate.execute({ action_id, agent_id: 'bot', action_type: 'file_write' }, async (h) => {
  await writePart1();
  await h.checkpoint();
  await writePart2();
});
```

Go (`Client.Execute(action, func(checkpoint func() error) error)`), Rust (`client::Client`), Java, C#, PHP and
Ruby (`Client`) follow the same calls: evaluate, wait for the approval when the decision is `prompt`, report
start, checkpoint, report completion.

## Action descriptors

| Field | Meaning |
|---|---|
| `action_id` | unique per action; use it to kill the action |
| `agent_id` | the agent; use it to halt the agent |
| `action_type` | a type the policy knows (`read`, `api_call`, `file_write`, `message_send`, `db_write`, `code_exec`, `delete`) or your own |
| `cost_usd` | what the action can cost if it goes wrong |
| `reversible` | `false` adds the irreversible bonus |
| `confidence_permille` | 0–1000, the agent's own confidence |
| `target` | what it touches (logged) |
