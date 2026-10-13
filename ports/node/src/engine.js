'use strict';
const { FRICTIONS, validate, stronger, get, DEFAULT_POLICY } = require('./policy');

class ActionError extends Error {}
const isInt = (v) => typeof v === 'number' && Number.isInteger(v);

function checkAction(a) {
  if (a === null || typeof a !== 'object' || Array.isArray(a)) throw new ActionError('action must be an object');
  for (const k of ['action_id', 'agent_id', 'action_type']) {
    if (typeof a[k] !== 'string' || !a[k]) throw new ActionError(`action.${k} must be a non-empty string`);
  }
  const cost = get(a, 'cost_usd', 0);
  if (typeof cost !== 'number' || cost < 0) throw new ActionError('action.cost_usd must be a number >= 0');
  if (typeof get(a, 'reversible', true) !== 'boolean') throw new ActionError('action.reversible must be true or false');
  const c = get(a, 'confidence_permille', null);
  if (c !== null && (!isInt(c) || c < 0 || c > 1000)) throw new ActionError('action.confidence_permille must be an integer 0-1000');
  const ts = get(a, 'ts_ms', 0);
  if (!isInt(ts) || ts < 0) throw new ActionError('action.ts_ms must be an integer >= 0');
  const t = get(a, 'target', null);
  if (t !== null && typeof t !== 'string') throw new ActionError('action.target must be a string');
  return a;
}

function score(policy, a) {
  let s = policy.cost_bands[policy.cost_bands.length - 1].score;
  const cost = get(a, 'cost_usd', 0);
  for (const b of policy.cost_bands) {
    const m = get(b, 'max_usd', null);
    if (m === null || cost <= m) { s = b.score; break; }
  }
  const floors = get(policy, 'action_floors', {});
  const floor = Object.prototype.hasOwnProperty.call(floors, a.action_type) ? floors[a.action_type] : get(policy, 'default_floor', 0);
  s = Math.max(s, floor);
  if (get(a, 'reversible', true) === false) s += get(policy, 'irreversible_bonus', 0);
  return Math.max(0, Math.min(10, s));
}

function levelOf(policy, s) {
  for (const lv of policy.levels) if (s <= lv.max_score) return lv;
  return policy.levels[policy.levels.length - 1];
}

class Engine {
  constructor(policy) {
    this.policy = validate(policy || DEFAULT_POLICY);
    this.hist = new Map();
  }

  decide(action, { halted = false, killed = false } = {}) {
    const a = checkAction(action);
    const p = this.policy;
    const s = score(p, a);
    const lv = levelOf(p, s);
    let friction = lv.friction;
    const reasons = ['GATE-LEVEL-' + lv.name.toUpperCase()];
    if (!Object.prototype.hasOwnProperty.call(get(p, 'action_floors', {}), a.action_type)) reasons.push('GATE-UNLISTED-TYPE');
    let cascade = false;
    const c = get(p, 'cascade', null);
    const ts = get(a, 'ts_ms', 0);
    if (c !== null) {
      const h = (this.hist.get(a.agent_id) || []).filter((e) => e[0] >= ts - c.window_ms);
      h.push([ts, s]);
      this.hist.set(a.agent_id, h);
      if (h.length > c.max_actions && h.reduce((t, e) => t + e[1], 0) > c.max_cumulative_risk) cascade = true;
    }
    if (cascade) { friction = stronger(friction, c.escalate_to); reasons.push('GATE-CASCADE'); }
    const lc = get(p, 'low_confidence', null);
    const conf = get(a, 'confidence_permille', null);
    if (lc !== null && conf !== null && conf < lc.below_permille) {
      friction = stronger(friction, lc.escalate_to);
      reasons.push('GATE-LOW-CONFIDENCE');
    }
    if (halted) { friction = 'block'; reasons.push('GATE-AGENT-HALTED'); }
    if (killed) { friction = 'block'; reasons.push('GATE-KILLED'); }
    if (!FRICTIONS.includes(friction)) throw new Error('bad friction');
    return { action_id: a.action_id, agent_id: a.agent_id, decision: friction, score: s, level: lv.name, reasons, cascade };
  }
}

module.exports = { Engine, ActionError, checkAction, score, levelOf };
