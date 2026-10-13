# SmartGate

**Decision friction and a human override for AI agents.** SmartGate sits between an agent's decision
and its execution. It scores each action the agent is about to take (0–10), lets low-impact actions
through, asks a person before medium ones, blocks high ones, and gives people one call that stops an
action, or a whole agent, and records it in a tamper-evident audit chain.

- **Score:** cost bands, per-action-type floors, a bonus for irreversible actions, a cascade rule
  (many actions from one agent in a short window; flagged, or escalated if you choose) and a
  low-confidence rule, all in one JSON policy.
- **Friction:** `allow`, `prompt` (approve or reject by REST, CLI or Slack buttons) or `block`.
- **Override:** `POST /smartgate/kill` for one action or a whole agent; idempotent, authenticated,
  rate-limited, optionally limited to an IP allowlist.
- **Evidence:** every decision, approval and kill is a line in a SHA-256 hash chain;
  `sf-smartgate audit verify` finds the first edited line. Prometheus metrics, Grafana dashboard and
  alert rules for the council's targets are included.

```python
from sf_smartgate import Gate, impact_gate, checkpoint

gate = Gate()                                   # default policy, in-memory state

@impact_gate(gate, action_type="db_write", agent_id="billing-bot", cost=lambda amount, customer: amount)
def refund(amount, customer):
    ...                                         # runs only if allowed, or approved by a person
    checkpoint()                                # raises Killed here once someone has killed it
    ...
```

## Install

```bash
python -m pip install sf-smartgate
sf-smartgate --demo
```

Every file of `sf-smartgate` on PyPI is built and published by this repository's release workflow
(`.github/workflows/release.yml`, PyPI trusted publishing) and carries a provenance attestation that
names this repository and that workflow; PyPI shows it under "Verified details". The same workflow
records a GitHub attestation for the same files, which you can check with
`gh attestation verify <file> --repo SmartTasksOrg/sf-smartgate`. A release file without that
provenance is not ours, and neither is a package called `smartgate` (without `sf-`) on any registry.

Version 0.1.0 is the first release under this name. If pip cannot find it yet, that release has not
finished: install from a clone instead (Python 3.10 or later):

```bash
git clone https://github.com/SmartTasksOrg/sf-smartgate
cd sf-smartgate
python -m venv .venv
. .venv/bin/activate          # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install .
sf-smartgate --demo
```

The package has no runtime dependencies. Shared state for several servers needs the Redis client:
`python -m pip install "sf-smartgate[redis]"`.

## How it decides

The default policy (`sf-smartgate policy show`; `spec/conformance/policy.default.json`):

| Step | Default |
|---|---|
| Cost band (USD the action can cost if it goes wrong) | ≤ 1,000 → 2 · ≤ 5,000 → 5 · ≤ 20,000 → 8 · more → 10 |
| Floor per action type | `read` 0, `api_call` 0, `file_write` 2, `message_send` 3, `db_write` 3, `code_exec` 6, `delete` 6; any other type 4 |
| Irreversible (`"reversible": false`) | +2 |
| Level and friction | score ≤ 3 low → allow · ≤ 6 medium → prompt · ≤ 10 high → block |
| Cascade | more than 3 actions from one agent within 5 s with summed score above 7 → flagged (`GATE-CASCADE`, `cascade: true`); set `cascade.escalate_to` to `prompt` to ask a person |
| Low confidence | `confidence_permille` below 300 → at least prompt |
| Approval | waits up to 5 minutes, then rejects |
| Server unreachable (client side) | `allow`, logged and counted (see "Fallback") |

The cost bands, the cascade rule, the 0.3 confidence threshold and the fallback are the council's
decisions; the floors are starting values to calibrate for your agents. The cascade rule only flags by
default: with the default floors, four ordinary reads within five seconds already match it, so making it
ask a person (`"escalate_to": "prompt"`) needs a policy calibrated on your traffic. The exact rules are in
[spec/SEMANTICS.md](spec/SEMANTICS.md).

## How a kill stops an action

Be clear about what each kind of code allows:

| Where the action is | What a kill does |
|---|---|
| Not started (waiting for approval, or not yet registered) | It never starts. A kill for an unknown id is kept, so the action is refused when it arrives. |
| An `async def` run through SmartGate (`@impact_gate`, `gate.arun`) | The task is cancelled at its next `await`, within `kill_poll_ms` (default 20 ms). |
| A synchronous function | It stops at its next `checkpoint()`. Code without checkpoints runs to the end: Python cannot stop a thread from outside. |
| A remote agent using the client (`RemoteGate`, the ports) | It stops at its next `checkpoint()`, which asks the server. |
| A whole agent (`kill --agent`) | Its unfinished actions are killed, new ones are refused until it is released, and with `install_asyncio` its live asyncio tasks are cancelled. |

SmartGate only sees actions that go through it. An agent that calls an API directly, starts its own
subprocess or opens a socket bypasses it; run agents with only the credentials and network access that
the gated tools need. `sf_smartgate.rollback` helps leave nothing half-done (atomic file writes,
database transactions, compensation steps for API calls), but an external action that has already
happened, such as a sent message or a payment, may not be undoable.

## Server

```bash
export SMARTGATE_AGENT_TOKEN=...      # python -c "import secrets; print(secrets.token_urlsafe(32))"
export SMARTGATE_OPERATOR_TOKEN=...
sf-smartgate serve --host 127.0.0.1 --port 8711 --policy policy.json --audit audit.jsonl
```

| Endpoint | Token | Purpose |
|---|---|---|
| `POST /smartgate/evaluate` | agent | decide an action; opens an approval when the decision is `prompt` |
| `POST /smartgate/score` | agent | score without recording |
| `POST /smartgate/actions/{id}/start`, `/complete` | agent | report the lifecycle; `start` is refused for a blocked, unapproved or killed action |
| `GET /smartgate/actions/{id}` | agent | state, polled at checkpoints |
| `GET /smartgate/approvals/{id}` | agent | approval state |
| `POST /smartgate/approvals/{id}/approve`, `/reject` | operator | answer an approval |
| `POST /smartgate/kill` (`action_id` or `agent_id`) | operator | kill an action or halt an agent; `X-Request-ID` makes a retry of the same request return the first answer (another request with the same id gets 409) |
| `POST /smartgate/agents/{id}/release` | operator | release a halted agent |
| `POST /slack/actions` | Slack signature | Approve / Reject / Kill buttons |
| `GET /metrics`, `GET /healthz` | none | Prometheus metrics, liveness |

Full contract: [spec/openapi.yaml](spec/openapi.yaml). Operator endpoints are refused from outside
`SMARTGATE_KILL_ALLOW` (addresses or CIDRs, when set), then need the operator token, then are
rate-limited per source address: kills in their own bucket (`--kill-rate`, default 10 per minute),
approve, reject and release in another (60 per minute); failed token checks are limited too. The Slack
endpoint is protected by Slack's request signature instead of the allowlist (Slack calls from its own
addresses), so anyone who can press the buttons in your Slack channel can approve or kill. Requests are
limited to 64 KiB with a Content-Length (no chunked bodies), a 10 s socket timeout and 30 s per
connection, with at most 256 connections at once: put a proxy with its own connection limits in front so
that a flood of slow connections cannot hold up a kill. Each `action_id` is evaluated once; evaluate a
new id for a new attempt. The server refuses
to start without both tokens unless you pass `--insecure-dev`, which binds 127.0.0.1 only. It speaks
plain HTTP: put a TLS proxy in front of it. Behind a proxy every request comes from the proxy's address,
so set the rate limit and allowlist on the proxy too.

From the command line (`SMARTGATE_URL`, `SMARTGATE_OPERATOR_TOKEN`):

```bash
sf-smartgate kill --action a-123 --reason "wrong customer"
sf-smartgate kill --agent billing-bot --reason "incident 42"
sf-smartgate release billing-bot
sf-smartgate approve <approval_id>
sf-smartgate audit verify audit.jsonl
```

Agents in Python use `RemoteGate` (`sf_smartgate.client`); other languages use the ports below.

### Fallback

When a client cannot connect to the server it applies its fallback (the client's `fallback` argument,
or the policy's `fallback` field): `allow` (the council's decision: the agent keeps running, the event is
logged, counted in the client's own `smartgate_fallback_total` and passed to `on_fallback`), `block`, or
`block_high` (score locally with the policy, so give clients the server's policy file, and refuse what
would be blocked). With `allow`, nothing is gated while the server is down; the server-side
`SmartGateDown` alert fires after 30 s, and the fallback counter is only visible if your agent exports
its metrics. Choose `block_high` where that is not acceptable.

The fallback is only for a server that cannot be reached. If the request reached the server but no
answer came in time, the decision is unknown and the client blocks the action (`GATE-NO-ANSWER`); an
HTTP error from the server raises an error and the action does not run. An action admitted on the
fallback still asks the server at each checkpoint, so it is stopped by a kill sent once the server is
back (the kill answer says `"seen": false` when the server had never registered the
action).

## Deploy and measure

- `deploy/docker-compose.yml`: SmartGate with Redis (shared state, `smartgate:lock:<key>` locks with a
  5 s timeout), Prometheus with the alert rules (`deploy/prometheus/alerts.yml`) and Grafana with the
  dashboard. Fill `deploy/.env` from `deploy/.env.example` first.
- `sf-smartgate bench`: in-process latency and KPI report on the 70/20/10 traffic profile (JSON).
- `deploy/k6/smartgate.js`: HTTP load test with the council's thresholds (p95 < 50 ms, low-impact
  friction ≤ 10 %, prompts for score < 3 ≤ 5 %, kill success ≥ 99 %, kill to state < 1 s);
  `deploy/k6/merge.py` merges several workers' summaries.
- `deploy/failure/run.sh`: two servers on one Redis under k6 load while Redis is stopped for 20 s.

More: [docs/operations.md](docs/operations.md), [docs/integration.md](docs/integration.md),
[docs/policy.md](docs/policy.md).

## Ports

The same engine in seven more languages, held to the same vectors (`spec/conformance`, 88 cases: canonical
JSON, scoring, stateful sessions with kills and halts, audit chains, policy validation). Each port also
has a client for the server. None is published on a registry; build them from this repository.

| Language | Folder | Engine test | Client |
|---|---|---|---|
| Node.js 18+ | `ports/node` | `node test/conformance.js` | `SmartGateClient.execute(action, fn)` (the council's Node.js SDK) |
| Go 1.22+ | `ports/go` | `go test ./...` | `Client.Execute` |
| Rust | `ports/rust` | `cargo run --bin conformance` | `client::Client` (plain HTTP) |
| Java 17+ | `ports/java` | `./build.sh` then `Conformance` | `Client` (java.net.http) |
| C# / .NET 8 | `ports/csharp` | `dotnet run --project Conformance` | `Client` |
| PHP 8.1+ | `ports/php` | `php bin/conformance.php` | `Client` |
| Ruby 3+ | `ports/ruby` | `ruby bin/conformance.rb` | `Client` (Net::HTTP) |

`ports/conformance/run.sh` runs the vectors on every engine; `ports/conformance/interop.sh` starts the
Python server and checks every client against it. Porting rules: [spec/PORTING.md](spec/PORTING.md).

## Status

- **Version 0.1.0, experimental.** A decision engine, kill switch and approval flow with a reference
  server, seven ports and deployment files.
- **Published:** PyPI `sf-smartgate` (see Install). Nothing else is published.
- **Tested:** the Python tests (`tests/`) on Python 3.10, 3.12 and 3.13 and the install-line check gate
  every pull request (`.github/workflows/ci.yml`). The vectors on all eight engines and the client
  interop run in the `ports` job, which does not gate merges yet and had not run on GitHub before this
  release; locally (Linux) all eight engines passed all vectors and all seven clients passed interop.
- **Not tested:** the Docker image, the compose stack, the k6 scripts and the Redis failure harness
  have not been run by CI; Redis is tested with an in-process stand-in, Slack with recorded payloads,
  not against the real services; Windows and macOS.
- **Not done from the council's notes:** an OAuth2 scope model (bearer tokens instead), terminating a
  process or container on kill (cooperative checkpoints and asyncio cancellation instead), a
  `/smartgate/rollback` endpoint (library helpers instead), ELK shipping (JSON-lines audit file and
  Prometheus instead).
- **Security review:** none independent. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## The Smart* family

SmartGate is part of the Smart* family by SmartTasks Lab: [SmartDelegate](https://github.com/SmartTasksOrg/sf-smartdelegate)
(IAM for LLM agents), [SmartRoute](https://github.com/SmartTasksOrg/sf-smartroute),
[SmartSeal](https://github.com/SmartTasksOrg/sf-smartseal), [SmartPangolin](https://github.com/SmartTasksOrg/sf-smartpangolin),
[SmartCheck](https://github.com/SmartTasksOrg/sf-smartcheck), [SmartFabric](https://github.com/SmartTasksOrg/sf-smartfabric)
and the others listed on [smarttasks.cloud](https://smarttasks.cloud). Every family package is on PyPI under
its `sf-` name; a package without the `sf-` prefix is not ours.

## Contributing, security, licence

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
