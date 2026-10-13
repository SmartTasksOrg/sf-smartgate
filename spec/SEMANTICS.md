# SmartGate semantics (version 1)

This is the contract every SmartGate engine implements: the Python reference (`src/sf_smartgate/`) and
the ports (`ports/`). The vectors in `conformance/` are the test of it: an engine conforms when it
passes all of them. Where this text and the vectors disagree, the vectors win and this text is a bug.

## Action

An action descriptor is a JSON object:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `action_id` | non-empty string | required | unique per action |
| `agent_id` | non-empty string | required | the agent taking it |
| `action_type` | non-empty string | required | e.g. `read`, `api_call`, `file_write`, `message_send`, `db_write`, `code_exec`, `delete`, `payment` |
| `cost_usd` | number ≥ 0 | 0 | the business cost if the action goes wrong |
| `reversible` | boolean | true | false adds `irreversible_bonus` |
| `confidence_permille` | integer 0–1000 | absent | the agent's confidence; below the policy threshold asks a person |
| `ts_ms` | integer ≥ 0 | 0 (the Python `Gate` uses its clock) | milliseconds; used only by the cascade window |
| `target` | string | absent | what the action touches; logged, not scored |

Any other field is ignored. A descriptor that breaks these rules is rejected (HTTP 400).

## Policy

One JSON document, `schema: "smartgate.policy/v1"` (`policy.schema.json`; the default is
`conformance/policy.default.json`). Validation rules: `conformance/policies.json`.

## Score

1. `band` = the `score` of the first entry of `cost_bands` whose `max_usd` is null or `cost_usd <= max_usd`.
2. `floor` = `action_floors[action_type]`, or `default_floor` when the type is not listed (0 if absent).
3. `score = max(band, floor)`; if `reversible` is false, add `irreversible_bonus`.
4. Clamp to 0–10.

The default bands are the council's: ≤ 1,000 USD → 2, ≤ 5,000 → 5, ≤ 20,000 → 8, more → 10.

## Decision

1. `level` = the first entry of `levels` with `score <= max_score`; `friction` = its friction.
   `reasons = ["GATE-LEVEL-" + upper(level name)]`.
2. If `action_type` is not a key of `action_floors`, append `GATE-UNLISTED-TYPE` (no effect on friction).
3. **Cascade** (when `cascade` is not null): the agent's window is every earlier evaluated action of
   the same agent with `ts_ms >= this.ts_ms - window_ms`, plus this one. If the window has more than
   `max_actions` actions **and** the sum of their scores is more than `max_cumulative_risk`, then
   `cascade = true`, `friction = stronger(friction, escalate_to)` and `GATE-CASCADE` is appended.
   Every evaluated action enters its agent's history, whatever its decision.
4. **Low confidence** (when `low_confidence` is not null and `confidence_permille` is present): if
   `confidence_permille < below_permille`, `friction = stronger(friction, escalate_to)` and
   `GATE-LOW-CONFIDENCE` is appended.
5. If the agent is halted: `friction = block`, append `GATE-AGENT-HALTED`.
6. If the action is killed: `friction = block`, append `GATE-KILLED`.

`stronger` orders `allow < prompt < block`. The result is
`{action_id, agent_id, decision, score, level, reasons, cascade}` (the HTTP server adds
`approval_id` when the decision is `prompt`).

## Session (what the sequence vectors run)

A session is one engine plus one kill registry. Operations and their exact results:

| op | effect | result |
|---|---|---|
| `evaluate` | register the action (below), then decide it with `halted = agent halted`, `killed = registered state is killed` | the decision |
| `start` | `pending → running`; `running` stays `running` | `{action_id, started: true}`; `false` if unknown, killed or completed |
| `complete` | `pending`/`running → completed` | `{action_id, state}`; `state` is `unknown` for an unknown id |
| `kill` | see below | `{action_id, status, first}` (+ `warning`) |
| `kill_agent` | halt the agent; kill each of its actions, in sorted id order | `{agent_id, status: "halted", first, killed: [ids whose kill was first]}` |
| `release_agent` | un-halt | `{agent_id, status: "released", first}` (`first` true if it was halted) |

**Register**: an id seen before keeps its state (and its first agent). A new id is `pending`, or
`killed` when its agent is halted. An id that exists only as a tombstone (killed before it was
registered) takes the agent and stays `killed`.

**Kill**: an unknown id becomes a tombstone, `{status: "killed", first: true}`. A `pending` or
`running` action becomes `killed`, `first: true`. A `killed` action answers `first: false`. A
`completed` action is not changed: `{status: "completed", first: false, warning: "already_completed"}`.

## Canonical JSON

Used for the audit hash. Objects: keys are ASCII, sorted byte-wise, written without whitespace with
`,` and `:`. Strings: UTF-8; escape `"` `\` as `\"` `\\`, the controls U+0008, U+000C, U+000A, U+000D,
U+0009 as `\b` `\f` `\n` `\r` `\t`, every other character below U+0020 as `\u00xx` (lower-case hex);
write everything else as is (including `/`, `<`, `>`, `&`, U+007F, U+2028). Numbers: integers only.
`true`, `false`, `null`. Vectors: `conformance/canonical.json`.

## Audit chain

Record *n* = the event's fields + `seq` (= *n*), `ts_ms`, `event`, `prev` (the hash of record *n−1*;
64 zeros for record 0). `hash = lower-case hex SHA-256 of the canonical JSON of the record without
`hash``. A chain verifies when every record has `seq = n`, the right `prev` and the right `hash`;
verification reports the first record that fails. Vectors: `conformance/audit.json`.

## What is not in the vectors

Approvals, time-outs, the HTTP API, rate limits, Redis locks, Slack and metrics are runtime features of
the server and the Python package; they are covered by the Python tests, and the clients in the ports
are checked against a running server by `ports/conformance/interop.sh`.
