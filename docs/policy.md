# Writing a policy

A policy is one JSON document (`spec/policy.schema.json`). Start from the default
(`sf-smartgate policy show > policy.json`), change it, then check it: `sf-smartgate policy check policy.json`.

- **cost_bands**: the first band whose `max_usd` is at least the action's `cost_usd` gives the score; the
  last band has `max_usd: null`. Put your own loss figures here (refund limits, contract values).
- **action_floors** / **default_floor**: the minimum score of an action type. A type you do not list gets
  `default_floor` (4 by default, so a person is asked) and the reason `GATE-UNLISTED-TYPE`.
- **irreversible_bonus**: added when an action says `"reversible": false`.
- **levels**: ordered by `max_score`, the last must end at 10; each has a friction.
- **cascade**: `window_ms`, `max_actions`, `max_cumulative_risk`, `escalate_to`; `null` switches it off.
  The default `escalate_to` is `allow`: the decision is flagged (`GATE-CASCADE`) and counted, nothing is
  asked. Look at how often your agents match it before you set `prompt`.
- **low_confidence**: `below_permille`, `escalate_to`; `null` switches it off.
- **approval**: `timeout_ms`, `on_timeout` (`reject` or `approve`).
- **fallback**: what clients do when the server is unreachable (`allow`, `block`, `block_high`).

Try a policy on real traffic before enforcing it: log the decisions (`sf-smartgate evaluate action.json
--policy policy.json` for single actions, or the audit file of a test run) and look at what would have been
prompted or blocked.
