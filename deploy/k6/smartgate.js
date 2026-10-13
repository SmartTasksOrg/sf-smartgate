// k6 load test for the SmartGate server: the council's 70/20/10 traffic profile against
// /smartgate/evaluate, plus a kill/acknowledge check, with JSON output.
//
//   k6 run -e SMARTGATE_URL=http://127.0.0.1:8711 -e SMARTGATE_AGENT_TOKEN=... -e SMARTGATE_OPERATOR_TOKEN=... \
//          -e RATE=5000 -e DURATION=5m --summary-export=k6-summary.json deploy/k6/smartgate.js
// For more than one machine, run the same script on each worker with RATE divided between them and
// merge the summaries (deploy/k6/merge.py). The operator rate limit (default 10/min per IP) also
// applies to the kill scenario: start the server with --kill-rate 1000 for a load test.
import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const URL = __ENV.SMARTGATE_URL || 'http://127.0.0.1:8711';
const AGENT = __ENV.SMARTGATE_AGENT_TOKEN;
const OPER = __ENV.SMARTGATE_OPERATOR_TOKEN;
const RATE = parseInt(__ENV.RATE || '500', 10);
const DURATION = __ENV.DURATION || '2m';

const friction = new Rate('smartgate_friction_low_impact');
const falsePositive = new Rate('smartgate_prompt_score_below_3');
const killOk = new Rate('smartgate_kill_success');
const ttoMs = new Trend('smartgate_kill_to_state_ms', true);
const decisions = new Counter('smartgate_decisions');

export const options = {
  scenarios: {
    decisions: { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DURATION,
      preAllocatedVUs: Math.min(2000, Math.max(50, RATE / 10)), maxVUs: Math.max(200, RATE), exec: 'decide' },
    kills: { executor: 'constant-arrival-rate', rate: 2, timeUnit: '1s', duration: DURATION, preAllocatedVUs: 5, exec: 'kill' },
  },
  thresholds: {
    'http_req_duration{endpoint:evaluate}': ['p(95)<50'],
    smartgate_friction_low_impact: ['rate<=0.10'],
    smartgate_prompt_score_below_3: ['rate<=0.05'],
    smartgate_kill_success: ['rate>=0.99'],
    smartgate_kill_to_state_ms: ['p(95)<1000'],
  },
};

const H = (t) => ({ headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${t}` } });
const pick = (xs) => xs[Math.floor(Math.random() * xs.length)];

function action(id) {
  const r = Math.random();
  const a = { action_id: id, agent_id: `k6-agent-${Math.floor(Math.random() * 5000)}` };
  if (r < 0.7) return [Object.assign(a, { action_type: pick(['read', 'api_call']), cost_usd: Math.floor(Math.random() * 900) }), 'low'];
  if (r < 0.9) return [Object.assign(a, { action_type: pick(['file_write', 'api_call', 'db_write']), cost_usd: 1001 + Math.floor(Math.random() * 3999) }), 'medium'];
  return [Object.assign(a, { action_type: pick(['payment', 'code_exec', 'delete']), cost_usd: 20001 + Math.floor(Math.random() * 70000), reversible: false }), 'high'];
}

export function decide() {
  const [a, kind] = action(`k6-${__VU}-${__ITER}-${Date.now()}`);
  const res = http.post(`${URL}/smartgate/evaluate`, JSON.stringify(a), Object.assign(H(AGENT), { tags: { endpoint: 'evaluate' } }));
  if (!check(res, { 'evaluate 200': (r) => r.status === 200 })) return;
  const d = res.json();
  decisions.add(1);
  if (kind === 'low') friction.add(d.decision !== 'allow');
  if (d.decision === 'prompt') falsePositive.add(d.score < 3);
}

export function kill() {
  const id = `k6-kill-${__VU}-${__ITER}-${Date.now()}`;
  http.post(`${URL}/smartgate/evaluate`, JSON.stringify({ action_id: id, agent_id: `k6-kill-${__VU}`, action_type: 'read' }), H(AGENT));
  http.post(`${URL}/smartgate/actions/${id}/start`, '{}', H(AGENT));
  const t0 = Date.now();
  const k = http.post(`${URL}/smartgate/kill`, JSON.stringify({ action_id: id, reason: 'k6' }), H(OPER));
  const st = http.get(`${URL}/smartgate/actions/${id}`, H(AGENT));
  const ok = k.status === 200 && st.status === 200 && st.json().state === 'killed';
  killOk.add(ok);
  if (ok) ttoMs.add(Date.now() - t0);
}
