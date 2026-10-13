'use strict';
// Client for the SmartGate server: the council's "Node.js SDK wrapper". Node 18+ (global fetch).
//
//   const gate = new SmartGateClient({ url, agentToken: process.env.SMARTGATE_AGENT_TOKEN });
//   await gate.execute({ action_id, agent_id, action_type: 'file_write' }, async (h) => {
//     ...; await h.checkpoint(); ...      // throws Killed once the action has been killed
//   });
//
// Fallback when the server cannot be reached (the connection fails): 'allow' (the council's default:
// logs, calls onFallback, runs), 'block', or 'block_high' (score locally with the server's policy).
// When the request may have reached the server but no answer came (timeout, reset), the decision is
// unknown: the client answers 'block' (GATE-NO-ANSWER), never the fallback; a connect timeout counts as
// no answer here (fetch does not tell them apart), which fails safe. HTTP errors throw.
// An action admitted on the fallback still asks the server at each checkpoint, so a kill reaches it
// once the server is back.
const { Killed } = require('./registry');
const { checkAction, score, levelOf } = require('./engine');
const { DEFAULT_POLICY, validate } = require('./policy');

class Blocked extends Error {
  constructor(decision, why = '') {
    super(`SmartGate blocked ${decision.action_id}: ${why || decision.decision} (risk ${decision.score}/10)`);
    this.decision = decision;
    this.why = why;
  }
}
class ServerError extends Error {
  constructor(status, body) { super(`SmartGate server answered ${status}: ${body}`); this.status = status; this.body = body; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CONNECT_ERRORS = new Set(['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH']);
const couldNotConnect = (e) => !!(e && e.cause && CONNECT_ERRORS.has(e.cause.code));
const effective = (ap) => ap.state === 'approved' || (ap.state === 'timeout' && ap.on_timeout === 'approve');

class SmartGateClient {
  constructor({ url, agentToken, operatorToken, timeoutMs = 2000, fallback, policy, onFallback, pollMs = 250 } = {}) {
    this.policy = validate(policy || DEFAULT_POLICY);
    fallback = fallback || this.policy.fallback || 'allow';
    if (!['allow', 'block', 'block_high'].includes(fallback)) throw new Error('fallback must be allow, block or block_high');
    this.url = String(url).replace(/\/+$/, '');
    Object.assign(this, { agentToken, operatorToken, timeoutMs, fallback, onFallback, pollMs });
  }

  async _call(method, path, body, token, headers = {}) {
    const h = { 'Content-Type': 'application/json', ...headers };
    if (token) h.Authorization = 'Bearer ' + token;
    const res = await fetch(this.url + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(this.timeoutMs) });
    const text = await res.text();
    if (!res.ok) throw new ServerError(res.status, text);
    return text ? JSON.parse(text) : {};
  }

  _fallback(action, err) {
    const a = checkAction({ ...action });
    const s = score(this.policy, a);
    const lv = levelOf(this.policy, s);
    const decision = this.fallback === 'block' || (this.fallback === 'block_high' && lv.friction === 'block') ? 'block' : 'allow';
    console.error(`SmartGate unreachable (${err.message}); fallback ${this.fallback} -> ${decision} for ${a.action_id}`);
    if (this.onFallback) { try { this.onFallback(a, decision, err); } catch (e) { /* an alert hook must not break the agent */ } }
    return { action_id: a.action_id, agent_id: a.agent_id, decision, score: s, level: lv.name,
      reasons: ['GATE-FALLBACK-' + this.fallback.toUpperCase().replace('_', '-')], cascade: false, fallback: true };
  }

  async evaluate(action) {
    try {
      return await this._call('POST', '/smartgate/evaluate', action, this.agentToken);
    } catch (e) {
      if (e instanceof ServerError) throw e;
      if (couldNotConnect(e)) return this._fallback(action, e);
      const a = checkAction({ ...action });
      console.error(`SmartGate did not answer (${e.message}); blocking ${a.action_id}`);
      return { action_id: a.action_id, agent_id: a.agent_id, decision: 'block', score: null, level: null, reasons: ['GATE-NO-ANSWER'], cascade: false };
    }
  }

  status(actionId) { return this._call('GET', `/smartgate/actions/${encodeURIComponent(actionId)}`, undefined, this.agentToken); }
  report(actionId, what) { return this._call('POST', `/smartgate/actions/${encodeURIComponent(actionId)}/${what}`, {}, this.agentToken); }
  approval(id) { return this._call('GET', `/smartgate/approvals/${encodeURIComponent(id)}`, undefined, this.agentToken); }

  async checkpoint(actionId) {
    let st;
    try {
      st = await this.status(actionId);
    } catch (e) {
      if (e instanceof ServerError && e.status !== 404) throw e;
      return; // unknown to the server (admitted on the fallback) or unreachable: keep going
    }
    if (st.state === 'killed') throw new Killed(actionId, st.reason || '');
  }

  // Evaluate, wait for approval if needed, run fn(handle), report completion. Returns fn's result.
  async execute(action, fn, { approvalTimeoutMs } = {}) {
    const d = await this.evaluate(action);
    if (d.decision === 'block') throw new Blocked(d);
    if (d.decision === 'prompt') {
      // the server expires the request after the policy's timeout; this limit only guards against a silent server
      const limit = Date.now() + (approvalTimeoutMs || (this.policy.approval || {}).timeout_ms || 300000) + 30000;
      let ap;
      for (;;) {
        ap = await this.approval(d.approval_id);
        if (ap.state !== 'pending') break;
        if (Date.now() > limit) throw new Blocked(d, 'timeout');
        await sleep(this.pollMs);
      }
      if (!effective(ap)) throw new Blocked(d, ap.state);
    }
    const fb = !!d.fallback;
    if (!fb) {
      const r = await this.report(d.action_id, 'start');
      if (!r.started) throw new Killed(d.action_id, 'killed before start');
    }
    const handle = { actionId: d.action_id, decision: d, checkpoint: () => this.checkpoint(d.action_id) };
    let killed = false;
    try {
      return await fn(handle);
    } catch (e) {
      killed = e instanceof Killed;
      throw e;
    } finally {
      if (!fb && !killed) { try { await this.report(d.action_id, 'complete'); } catch (e) { /* logged by the server state */ } }
    }
  }

  // operator side
  kill({ actionId, agentId, reason = '', requestId } = {}) {
    const body = { reason };
    if (actionId) body.action_id = actionId;
    if (agentId) body.agent_id = agentId;
    return this._call('POST', '/smartgate/kill', body, this.operatorToken, requestId ? { 'X-Request-ID': requestId } : {});
  }
  approve(id) { return this._call('POST', `/smartgate/approvals/${encodeURIComponent(id)}/approve`, {}, this.operatorToken); }
  reject(id) { return this._call('POST', `/smartgate/approvals/${encodeURIComponent(id)}/reject`, {}, this.operatorToken); }
}

module.exports = { SmartGateClient, Blocked, ServerError };
