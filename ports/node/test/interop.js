'use strict';
// Checks this client against a running SmartGate server.
// SMARTGATE_URL, SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN must be set (ports/conformance/interop.sh does it).
const { SmartGateClient, Blocked, Killed } = require('../src');

(async () => {
  const url = process.env.SMARTGATE_URL;
  const agent = new SmartGateClient({ url, agentToken: process.env.SMARTGATE_AGENT_TOKEN, pollMs: 20 });
  const oper = new SmartGateClient({ url, operatorToken: process.env.SMARTGATE_OPERATOR_TOKEN });
  const id = 'node-' + Date.now();
  const check = (cond, what) => { if (!cond) { console.log('FAIL', what); process.exit(1); } };

  const low = await agent.evaluate({ action_id: id + '-a', agent_id: 'node-bot', action_type: 'read' });
  check(low.decision === 'allow' && low.score === 2, 'low action allowed');
  try {
    await agent.execute({ action_id: id + '-b', agent_id: 'node-bot', action_type: 'delete', reversible: false }, async () => 'ran');
    check(false, 'high action blocked');
  } catch (e) { check(e instanceof Blocked, 'high action blocked'); }
  let steps = 0;
  setTimeout(() => oper.kill({ actionId: id + '-c', reason: 'interop' }), 150);
  try {
    await agent.execute({ action_id: id + '-c', agent_id: 'node-bot-2', action_type: 'read' }, async (h) => {
      for (let i = 0; i < 100; i++) { await h.checkpoint(); steps++; await new Promise((r) => setTimeout(r, 20)); }
    });
    check(false, 'kill reached the action');
  } catch (e) { check(e instanceof Killed && steps > 0 && steps < 100, 'kill reached the action'); }
  const again = await oper.kill({ actionId: id + '-c' });
  check(again.status === 'killed' && again.first === false, 'second kill is idempotent');
  const st = await agent.status(id + '-c');
  check(st.state === 'killed', 'server state killed');
  console.log('node client: interop ok');
})().catch((e) => { console.log('FAIL', e.message); process.exit(1); });
