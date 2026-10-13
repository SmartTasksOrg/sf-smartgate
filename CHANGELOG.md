# Changelog

All notable changes to SmartGate are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semantic.

## Unreleased

## 0.1.0 — first release as `sf-smartgate`

Built from the SmartGate council specification (decision friction and human override for agentic systems).

### Added
- Decision engine: risk score 0–10 from cost bands (≤ 1,000 / 5,000 / 20,000 USD → 2 / 5 / 8, more → 10),
  action-type floors, an irreversible bonus; levels low / medium / high with allow / prompt / block; cascade
  rule (more than 3 actions from one agent within 5 s with summed score above 7; flags by default, can
  escalate); low-confidence rule
  (below 300 per mille). One JSON policy (`spec/policy.schema.json`).
- Kill switch: kill one action or halt an agent; idempotent; kills before registration are kept; state in
  memory or in Redis with per-key locks (`smartgate:lock:<key>`, 5 s timeout).
- Approvals for `prompt` decisions with a time-out (default 5 minutes, then reject); Slack Block Kit
  messages with Approve / Reject / Kill buttons and signature verification.
- Hooks: `@impact_gate` for sync and async functions (signature kept), `checkpoint()`, `Gate.arun`
  (cancels a coroutine on kill), an asyncio task factory that refuses and cancels the tasks of a halted
  agent, WSGI and ASGI middleware.
- Server (stdlib): evaluate, score, lifecycle, approvals, kill, release, Slack, `/metrics`, `/healthz`;
  agent and operator bearer tokens; IP allowlist, then token, then per-IP rate limits (kills separate)
  on operator endpoints; failed token checks rate-limited; request size, Content-Length and socket
  time-out limits; at most 256 requests at once; `start` refused for blocked, unapproved or killed
  actions; one evaluation per `action_id`; `X-Request-ID` bound to the request body; Slack clicks verified
  and de-duplicated; GET requests with a body refused; each connection closed after 30 s.
- Approvals expire on the server after the policy's time-out, for in-process and remote agents alike.
- Client with fallback `allow` (default), `block` or `block_high` when the server cannot be reached;
  `block` when a request got no answer; checkpoints keep asking the server after a fallback admission.
- Audit chain: SHA-256 over canonical JSON; `sf-smartgate audit verify`.
- Prometheus metrics, alert rules and a Grafana dashboard; Docker image and compose stack; k6 load test and
  a Redis failure harness; `sf-smartgate bench`.
- Rollback helpers: atomic and staged file writes, transactions, compensation steps.
- Ports (engine, conformance runner and client): Node.js, Go, Rust, Java, C#, PHP, Ruby. Shared vectors:
  88 cases in `spec/conformance/`.
- Release workflow: PyPI trusted publishing with provenance attestations, GitHub attestations, SHA256SUMS.
