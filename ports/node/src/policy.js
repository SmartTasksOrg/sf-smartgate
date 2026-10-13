'use strict';
const FRICTIONS = ['allow', 'prompt', 'block'];
const DEFAULT_POLICY = require('./policy.default.json');

class PolicyError extends Error {}

const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function int(v, what, lo, hi) {
  if (!isInt(v)) throw new PolicyError(`${what} must be an integer`);
  if ((lo !== undefined && v < lo) || (hi !== undefined && v > hi)) throw new PolicyError(`${what} must be between ${lo} and ${hi}`);
}
function friction(v, what) {
  if (!FRICTIONS.includes(v)) throw new PolicyError(`${what} must be one of ${FRICTIONS.join(', ')}`);
}
const get = (o, k, d) => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : d);

function validate(doc) {
  if (!isObj(doc)) throw new PolicyError('policy must be a JSON object');
  if (doc.schema !== 'smartgate.policy/v1') throw new PolicyError('schema must be "smartgate.policy/v1"');
  const bands = doc.cost_bands;
  if (!Array.isArray(bands) || bands.length === 0) throw new PolicyError('cost_bands must be a non-empty list');
  let last = null;
  bands.forEach((b, i) => {
    if (!isObj(b)) throw new PolicyError(`cost_bands[${i}] must be an object`);
    int(b.score, `cost_bands[${i}].score`, 0, 10);
    const m = get(b, 'max_usd', null);
    if (m === null) {
      if (i !== bands.length - 1) throw new PolicyError('only the last band may have max_usd null');
    } else {
      if (typeof m !== 'number') throw new PolicyError(`cost_bands[${i}].max_usd must be a number`);
      if (last !== null && m <= last) throw new PolicyError('cost_bands max_usd must increase');
      last = m;
    }
  });
  if (get(bands[bands.length - 1], 'max_usd', null) !== null) throw new PolicyError('the last band must have max_usd null');
  const floors = get(doc, 'action_floors', {});
  if (!isObj(floors)) throw new PolicyError('action_floors must be an object');
  for (const [k, v] of Object.entries(floors)) int(v, `action_floors.${k}`, 0, 10);
  int(get(doc, 'default_floor', 0), 'default_floor', 0, 10);
  int(get(doc, 'irreversible_bonus', 0), 'irreversible_bonus', 0, 10);
  const levels = doc.levels;
  if (!Array.isArray(levels) || levels.length === 0) throw new PolicyError('levels must be a non-empty list');
  let prev = -1;
  const names = new Set();
  levels.forEach((lv, i) => {
    if (!isObj(lv) || typeof lv.name !== 'string' || !lv.name) throw new PolicyError(`levels[${i}] needs a name`);
    if (names.has(lv.name)) throw new PolicyError(`level name ${lv.name} repeated`);
    names.add(lv.name);
    int(lv.max_score, `levels[${i}].max_score`, 0, 10);
    if (lv.max_score <= prev) throw new PolicyError('levels max_score must increase');
    prev = lv.max_score;
    friction(lv.friction, `levels[${i}].friction`);
  });
  if (prev !== 10) throw new PolicyError('the last level must have max_score 10');
  const c = get(doc, 'cascade', null);
  if (c !== null) {
    if (!isObj(c)) throw new PolicyError('cascade must be an object or null');
    int(c.window_ms, 'cascade.window_ms', 1);
    int(c.max_actions, 'cascade.max_actions', 1);
    int(c.max_cumulative_risk, 'cascade.max_cumulative_risk', 0);
    friction(c.escalate_to, 'cascade.escalate_to');
  }
  const lc = get(doc, 'low_confidence', null);
  if (lc !== null) {
    if (!isObj(lc)) throw new PolicyError('low_confidence must be an object or null');
    int(lc.below_permille, 'low_confidence.below_permille', 0, 1000);
    friction(lc.escalate_to, 'low_confidence.escalate_to');
  }
  const ap = get(doc, 'approval', {});
  if (!isObj(ap)) throw new PolicyError('approval must be an object');
  int(get(ap, 'timeout_ms', 300000), 'approval.timeout_ms', 1);
  if (!['reject', 'approve'].includes(get(ap, 'on_timeout', 'reject'))) throw new PolicyError('approval.on_timeout must be reject or approve');
  if (!['allow', 'block', 'block_high'].includes(get(doc, 'fallback', 'allow'))) throw new PolicyError('fallback must be allow, block or block_high');
  return doc;
}

const stronger = (a, b) => (FRICTIONS.indexOf(a) >= FRICTIONS.indexOf(b) ? a : b);

module.exports = { DEFAULT_POLICY, FRICTIONS, PolicyError, validate, stronger, get };
