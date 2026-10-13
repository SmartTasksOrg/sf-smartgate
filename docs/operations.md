# Operating SmartGate

## Run it

1. Generate two tokens: `python -c "import secrets; print(secrets.token_urlsafe(32))"` (agent, operator).
   Give agents only the agent token; keep the operator token for people and the incident tooling.
2. Start: `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build`, or
   `sf-smartgate serve` with `SMARTGATE_AGENT_TOKEN`, `SMARTGATE_OPERATOR_TOKEN` and, for more than one
   server, `SMARTGATE_REDIS_URL`.
3. Put a TLS proxy in front, with connection limits. Set `SMARTGATE_KILL_ALLOW` to the addresses people
   and tooling call from. Behind a proxy all operators share the proxy's address and so one kill bucket
   (`--kill-rate`, default 10 per minute): raise it for incident tooling that kills many actions.
4. Keep the audit file (`--audit`) on storage you trust, and copy it off the host regularly: the chain shows
   edits, not a truncated tail.

## Slack approvals

1. Create a Slack app for your workspace. Under **Interactivity & Shortcuts**, switch interactivity on and set
   the request URL to `https://<your SmartGate>/slack/actions`.
2. Either add an incoming webhook for the approvals channel (`SMARTGATE_SLACK_WEBHOOK_URL`), or give the bot
   the `chat:write` scope, invite it to the channel and set `SMARTGATE_SLACK_BOT_TOKEN` and
   `SMARTGATE_SLACK_CHANNEL`.
3. Copy the app's **Signing Secret** to `SMARTGATE_SLACK_SIGNING_SECRET`. Clicks without a valid signature,
   or older than 5 minutes, are refused.

Anyone in the channel can press the buttons; restrict the channel accordingly. The audit records the Slack
user id of each click.

## In an incident

```bash
export SMARTGATE_URL=https://smartgate.internal SMARTGATE_OPERATOR_TOKEN=...
sf-smartgate kill --agent billing-bot --reason "incident 42"     # halts the agent, kills its unfinished actions
sf-smartgate kill --action a-123 --reason "wrong customer"       # one action
sf-smartgate release billing-bot                                 # when it is safe again
sf-smartgate audit verify /data/audit.jsonl                      # check the record
```

A kill answers `first: true` the first time and `first: false` after that. Tooling that may retry should
send `X-Request-ID`: a retry with the same id and the same body gets the first answer again (with
`first: true`), and a different request with an id already used in the last 24 hours gets 409. The answer
has `"seen": false` when SmartGate had never registered the action; the kill is kept, so the action is
refused if it arrives, and an agent running on its fallback learns of it at its next checkpoint.

## Metrics and alerts

`/metrics` exposes the metrics listed in `src/sf_smartgate/metrics.py`; `deploy/prometheus/alerts.yml` has
the council's targets as alert rules (latency, low-impact friction, prompts for score < 3, time to override,
Redis lock contention, server down) and `deploy/grafana/dashboards/smartgate.json` the matching dashboard.

## Measure before you rely on it

- `sf-smartgate bench --json bench.json`: in-process latency and KPIs on the 70/20/10 profile.
- `k6 run ... deploy/k6/smartgate.js`: the HTTP server under load, with the council's thresholds.
- `deploy/failure/run.sh`: what agents see while Redis is down.

Record the results with the machine and version that produced them.
